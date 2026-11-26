// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! filesystem separation checks reject layouts that let content harvesting or
//! managed-directory writes consume store internals, cache files or signing
//! material.
//!
//! Source-dependent checks run before harvest and private material creation.
//! Fresh stores pass source separation before creation. Established stores select
//! retained publications without examining the source. Managed-path checks protect
//! cache, signing-seed and TLS-key custody on resume.
//!
//! Inbound names: `refuse_store_as_source`, `refuse_nesting`,
//! `refuse_cache_dir_nesting`, `refuse_key_seed_nesting`. `gran publish` calls
//! these checks plus `refuse_managed_paths` and `refuse_tls_key_directory`;
//! `gran harvest` calls the first two, and `gran recover` calls
//! `refuse_managed_paths`. `canonicalize_for_nest_check`
//! and `refuse_if_dangling` are this module's own: no PRODUCTION caller
//! outside it reaches either, though `tests.rs` calls
//! `canonicalize_for_nest_check` directly, which is why it is not private to
//! the four refusals.
//!
//! **Reach into the crate ROOT: NONE.** Nothing here names an item
//! defined in `main.rs`; the one in-crate dependency is the sibling
//! `crate::keys`.
//!
//! **"No reach into the root" is not "depends on nothing".** `keys`
//! in turn uses `crate::admission`, and this module also reaches
//! `granary_client`'s `MARKER_NAME` and `is_store_marker`, which are
//! another crate's and outside this crate's module graph entirely.

use std::path::Path;

use granary_client::{MARKER_NAME, is_store_marker};

use crate::keys::public_key_path;

#[cfg(test)]
mod tests;

/// Canonicalize a path that may not exist yet (the store dir is created
/// by `Store::open` only AFTER the nesting check passes): resolve the
/// nearest existing ancestor, then re-append the missing suffix.
///
/// **A `..` in the missing suffix can re-expose a component that DOES
/// exist**, and that component can be a symlink:
/// `<parent>/nonexistent/../alias/sub`,
/// where `alias` is a real symlink to the source, lexically fails at
/// `nonexistent`, and naively re-joining `alias` onto the resolved
/// parent WITHOUT re-canonicalizing it would leave the symlink
/// unfollowed — the returned path would then differ from the source's
/// own canonical path, and the nesting check would wrongly pass. Every
/// candidate this function builds (whether by lexically appending a
/// normal component or by popping one via `..`) is therefore
/// RE-CHECKED against the real filesystem: if it now exists, it is
/// re-canonicalized (following any symlink fully, exactly as
/// `canonicalize()` would if the whole original path had existed at
/// once); only a candidate that still does not exist is kept lexical.
/// Recursing this way is what makes the whole path a fixpoint: the
/// FIRST time a `..` cancels a nonexistent detour and lands back on
/// real ground, resolution starts again from there for everything
/// still to come.
///
/// **A candidate that cannot be re-resolved is not always a free
/// name.** `canonicalize()` also reports `NotFound` for a DANGLING
/// symlink, and keeping those lexical is the one answer
/// `create_dir_all` does not agree with. Its ancestor walk
/// creates the missing components of the SPELLED path bottom-up, so
/// the link's target is MATERIALIZED before the link is traversed, and
/// the scaffolding then lands through it. Measured on this machine
/// with `dang -> <p>/mysource/notyet` and the store spelled
/// `<p>/mysource/notyet/../../dang/sub`: `create_dir_all -> Ok(())`,
/// with `<p>/mysource/notyet/sub` created INSIDE the source. So a
/// candidate whose re-resolution fails `NotFound` while one of its
/// existing components is a symlink is REFUSED (fail closed) rather
/// than kept. The link's target is deliberately NOT resolved
/// lexically instead: that would be this function inventing a
/// resolution the kernel has not agreed to, on exactly the input
/// class it is here to distrust.
#[expect(
    clippy::disallowed_methods,
    reason = "canonicalize is a READ-ONLY path resolution used only to compare two paths for \
              nesting before anything is created — this recursive helper exists specifically \
              because canonicalize refuses a not-yet-existing path, walking up to the nearest \
              existing ancestor (and re-checking every candidate it builds along the way, in \
              case a `..` re-exposes one that exists after all) instead of writing anything"
)]
fn canonicalize_for_nest_check(path: &Path) -> std::io::Result<std::path::PathBuf> {
    use std::path::Component;
    match std::fs::canonicalize(path) {
        Ok(p) => Ok(p),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut comps = path.components();
            let last = comps.next_back();
            let parent = comps.as_path();
            let parent = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            let base = canonicalize_for_nest_check(parent)?;
            let candidate = match last {
                Some(Component::Normal(name)) => base.join(name),
                Some(Component::ParentDir) => match base.parent() {
                    Some(p) => p.to_owned(),
                    None => base,
                },
                _ => base, // `.`, root, prefix — nothing to append
            };
            // The candidate may exist now even though the ORIGINAL
            // whole path did not — see the doc above. Re-resolving
            // follows a symlink fully if one is there; a candidate
            // that still does not exist keeps its lexical form, but
            // ONLY once `refuse_if_dangling` has ruled out the other
            // reason canonicalize says NotFound.
            match std::fs::canonicalize(&candidate) {
                Ok(resolved) => Ok(resolved),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    refuse_if_dangling(&candidate)?;
                    Ok(candidate)
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

/// The fail-closed half of [`canonicalize_for_nest_check`]: `Ok(())`
/// only if `candidate`'s `NotFound` really means "this name is free".
///
/// Every existing component of `candidate` is `lstat`ed (never
/// followed). A symlink among them, on a path `canonicalize()` just
/// refused, is by definition a DANGLING one — the case
/// `create_dir_all` materializes rather than refuses (see the doc
/// above) — so it is reported as an error, and the nesting guards
/// surface it verbatim. `symlink_metadata` is the ban list's own
/// "safe half" of the fs class (lstat-backed, never follows), so this
/// needs no licence of its own.
///
/// Walking the WHOLE prefix rather than only the last component is
/// deliberate: the caller's `base` is canonical whenever it exists, so
/// today only the last component can be the link — but that is an
/// invariant of the caller, not of this function, and this guard's
/// correctness must not depend on its caller staying shaped a
/// certain way.
fn refuse_if_dangling(candidate: &Path) -> std::io::Result<()> {
    for prefix in candidate.ancestors() {
        match std::fs::symlink_metadata(prefix) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "path contains a dangling symlink at {} — refused rather than \
                         resolved, because creating through it would land files at the \
                         link's target instead of the spelled path",
                        prefix.display()
                    ),
                ));
            }
            // Exists and is not a link, or does not exist: neither is
            // the dangling case. Any OTHER error (a permission denial
            // partway up, say) is propagated, never swallowed into
            // "not a symlink".
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Refuse a SWAPPED invocation before anything touches the filesystem.
///
/// `gran harvest <source> <store>` and `gran publish <store> <source>
/// <volume>` take the same two paths in the OPPOSITE order. Nothing
/// distinguishes them positionally, and [`refuse_nesting`]
/// only rejects nesting — two siblings pass it — so a swapped
/// invocation makes `Store::open` scaffold `txn/`, `objects/`, `lock`
/// and the marker into the user's SOURCE TREE, then harvests the store
/// directory and publishes the CAS internals as volume content, which
/// the next (correct) invocation bakes into the manifest. Precisely the
/// silent wrongness `refuse_nesting` exists to prevent, reached through
/// the door it does not cover.
///
/// ONE check catches BOTH swaps, because both put the store in the
/// SOURCE position: harvesting a directory that is already a granary
/// store is never legitimate — it is the container of CAS internals,
/// not content. The marker is the signal `Store::open` itself trusts,
/// so this agrees with the store's own notion of identity rather than
/// guessing from directory shape.
pub(crate) fn refuse_store_as_source(source: &Path) -> Result<(), String> {
    // CONTENTS, not merely existence: a source tree may legitimately
    // contain an ordinary file named `granary-store`, and refusing it
    // would reject legal input — the failure mode a guard like this
    // must not have. `Store::open` trusts the marker's contents, so
    // this agrees with it rather than with its filename.
    if is_store_marker(&source.join(MARKER_NAME)) {
        return Err(format!(
            "{} is a granary STORE, not a source tree — check the argument \
             order: `gran harvest <source> <store>` but `gran publish \
             <store> <source> <volume>`",
            source.display()
        ));
    }
    Ok(())
}

/// Reject nesting BEFORE `Store::open` touches the filesystem: store
/// scaffolding created inside the source by a rejected run would be
/// silently baked into the next correct harvest's manifest — the exact
/// silent wrongness the guard exists to prevent. Either nesting direction
/// (store inside source, source inside store) is refused. `publish`
/// harvests, so it runs the same guard.
#[expect(
    clippy::disallowed_methods,
    reason = "canonicalize is read-only path resolution feeding a nesting COMPARISON, run \
              before Store::open or Cache::open ever create anything — the whole point of \
              this guard is to run before either side of the check exists as scaffolding"
)]
pub(crate) fn refuse_nesting(source: &Path, store_dir: &Path) -> Result<(), String> {
    let source_canon =
        std::fs::canonicalize(source).map_err(|e| format!("{}: {e}", source.display()))?;
    let store_canon = canonicalize_for_nest_check(store_dir)
        .map_err(|e| format!("{}: {e}", store_dir.display()))?;
    if store_canon.starts_with(&source_canon) || source_canon.starts_with(&store_canon) {
        return Err(format!(
            "store {} and source {} must not nest (one inside the other)",
            store_canon.display(),
            source_canon.display()
        ));
    }
    Ok(())
}

/// A `--cache-dir` nested with the source (or the store) is refused the
/// same way a store nested with the source is (`refuse_nesting`). The
/// hazard is specific to publish and to the ORDER of operations:
/// `cmd_publish` calls `Cache::open` — which writes the cache's marker,
/// lock, and index scaffolding into `--cache-dir` — BEFORE `prepare()`
/// harvests the source. A cache dir inside the source therefore publishes
/// its own files as volume content, and the resulting manifest describes
/// a source state that no longer exists once the post-commit cache writes
/// land. `None` (no `--cache-dir`) is always Ok.
#[expect(
    clippy::disallowed_methods,
    reason = "canonicalize is read-only path resolution feeding a nesting COMPARISON, run \
              before Cache::open writes its marker/lock/index scaffolding — same reasoning as \
              refuse_nesting, which this mirrors for --cache-dir"
)]
pub(crate) fn refuse_cache_dir_nesting(
    cache_dir: Option<&Path>,
    source: &Path,
    store_dir: &Path,
) -> Result<(), String> {
    let Some(cache_dir) = cache_dir else {
        return Ok(());
    };
    let cache_canon = canonicalize_for_nest_check(cache_dir)
        .map_err(|e| format!("{}: {e}", cache_dir.display()))?;
    let source_canon =
        std::fs::canonicalize(source).map_err(|e| format!("{}: {e}", source.display()))?;
    if cache_canon.starts_with(&source_canon) || source_canon.starts_with(&cache_canon) {
        return Err(format!(
            "cache dir {} and source {} must not nest — `Cache::open` writes the cache's \
             marker/lock/index before the source is harvested, so a nested cache dir would \
             publish its own files as volume content",
            cache_canon.display(),
            source_canon.display()
        ));
    }
    let store_canon = canonicalize_for_nest_check(store_dir)
        .map_err(|e| format!("{}: {e}", store_dir.display()))?;
    if cache_canon.starts_with(&store_canon) || store_canon.starts_with(&cache_canon) {
        return Err(format!(
            "cache dir {} and store {} must not nest (one inside the other)",
            cache_canon.display(),
            store_canon.display()
        ));
    }
    Ok(())
}

/// A `--key-seed` nested with the source, the STORE or the `--cache-dir`
/// is refused before [`crate::keys::load_or_create_key_with_identity`] creates either
/// the raw private seed or its public sidecar.
///
/// Three roots, three different hazards, and only the first is about
/// publishing:
///
/// - under the **source**, both key files are harvested and published
///   as volume content;
/// - under the **store**, and under the **cache dir**, the key files are
///   DELETED. Both roots sweep `txn/` of every regular file directly
///   under it — the store on an established open, the cache on every
///   writer open — so `--key-seed <store>/txn/seed` is created, signs
///   the publish, and is then unlinked with no diagnostic, and the next
///   run silently creates a different identity. Nothing about the
///   source is involved, which is why comparing only against
///   `--source` cannot see it.
///
/// Both path directions are checked for both files, exactly as
/// [`refuse_nesting`] does: the ordinary hazard is key material below a
/// root, while the reverse also refuses a root rooted at a path
/// reserved for either key file. `None` (no `--cache-dir`) simply drops
/// that root from the comparison.
#[expect(
    clippy::disallowed_methods,
    reason = "canonicalize is read-only path resolution feeding a nesting COMPARISON, run \
              before load_or_create_key_with_identity creates either key file — same \
              reasoning as refuse_nesting, which this mirrors for --key-seed"
)]
pub(crate) fn refuse_key_seed_nesting(
    key_seed: &Path,
    source: &Path,
    store_dir: &Path,
    cache_dir: Option<&Path>,
) -> Result<(), String> {
    let seed_canon = canonicalize_for_nest_check(key_seed)
        .map_err(|e| format!("{}: {e}", key_seed.display()))?;
    let public_path = public_key_path(key_seed);
    let public_canon = canonicalize_for_nest_check(&public_path)
        .map_err(|e| format!("{}: {e}", public_path.display()))?;
    // The source must already exist (it is about to be harvested); the
    // store and the cache dir may not (both are created by their own
    // `open`), so they take the not-yet-existing-path resolver, exactly
    // as `refuse_nesting`/`refuse_cache_dir_nesting` do.
    let source_canon =
        std::fs::canonicalize(source).map_err(|e| format!("{}: {e}", source.display()))?;
    let store_canon = canonicalize_for_nest_check(store_dir)
        .map_err(|e| format!("{}: {e}", store_dir.display()))?;
    let cache_canon = match cache_dir {
        Some(dir) => {
            Some(canonicalize_for_nest_check(dir).map_err(|e| format!("{}: {e}", dir.display()))?)
        }
        None => None,
    };

    let roots = [
        Some((&source_canon, "source")),
        Some((&store_canon, "store")),
        cache_canon.as_ref().map(|c| (c, "cache dir")),
    ];
    for (root_canon, what) in roots.into_iter().flatten() {
        if seed_canon.starts_with(root_canon)
            || root_canon.starts_with(&seed_canon)
            || public_canon.starts_with(root_canon)
            || root_canon.starts_with(&public_canon)
        {
            return Err(format!(
                "key seed {} and its public sidecar {} must not nest with {what} {} — key \
                 material under the source is published as volume content, and key material \
                 under the store or the cache dir is DELETED by that root's own txn/ sweep",
                seed_canon.display(),
                public_canon.display(),
                root_canon.display()
            ));
        }
    }
    Ok(())
}

/// Check managed roots and signing material without resolving the resume source.
/// The source operand has no meaning for retained publication recovery.
pub(crate) fn refuse_managed_paths(
    key: &Path,
    tls_key: Option<&Path>,
    store: &Path,
    cache: Option<&Path>,
) -> Result<(), String> {
    let store = canonicalize_for_nest_check(store)
        .map_err(|e| format!("store {}: {e}", store.display()))?;
    let cache = cache
        .map(canonicalize_for_nest_check)
        .transpose()
        .map_err(|e| format!("cache {}: {e}", cache.unwrap_or(Path::new("")).display()))?;
    if let Some(cache) = &cache
        && (cache.starts_with(&store) || store.starts_with(cache))
    {
        return Err(format!(
            "cache {} and store {} must not nest",
            cache.display(),
            store.display()
        ));
    }
    let signing = [key.to_owned(), public_key_path(key)];
    for (path, kind) in signing
        .iter()
        .map(|p| (p.as_path(), "signing material"))
        .chain(tls_key.map(|p| (p, "client TLS key")))
    {
        let path =
            canonicalize_for_nest_check(path).map_err(|e| format!("{}: {e}", path.display()))?;
        for root in std::iter::once(&store).chain(cache.iter()) {
            if path.starts_with(root) || root.starts_with(&path) {
                return Err(format!(
                    "{kind} {} must not nest with store or cache root {} — key material is DELETED by that root's txn/ sweep",
                    path.display(),
                    root.display()
                ));
            }
        }
    }
    Ok(())
}

/// Resolve the configured key's parent separately from its leaf. Excluding the
/// loaded inode alone cannot protect a replacement renamed to the configured name.
#[expect(
    clippy::disallowed_methods,
    reason = "read-only canonical source and configured key-parent comparison before harvest; fail closed without following the key leaf"
)]
pub(crate) fn refuse_tls_key_directory(source: &Path, key: Option<&Path>) -> Result<(), String> {
    let Some(key) = key else {
        return Ok(());
    };
    let source =
        std::fs::canonicalize(source).map_err(|e| format!("source {}: {e}", source.display()))?;
    let parent = key
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = std::fs::canonicalize(parent)
        .map_err(|e| format!("TLS key directory {}: {e}", parent.display()))?;
    if parent.starts_with(&source) {
        return Err(format!(
            "source {} contains the configured TLS key directory {}",
            source.display(),
            parent.display()
        ));
    }
    Ok(())
}
