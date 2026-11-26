// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for [`super`], at the sibling-directory address a
//! module's own tests.
//!
//! **Eleven rows, and not one of them straddles.** A name scan found eleven
//! candidates referencing a child item and ZERO of them also calling a residue
//! item — the cleanest test map of the three children cut out of `main.rs`,
//! and the reason is the production seam: this child's outbound reach is ZERO.
//!
//! **`refuse_key_seed_nesting_refuses_a_seed_under_the_store_or_the_cache`
//! came here, although the worked example this rule shipped with said it
//! STAYS.** Both are right: that example has the row asserting about
//! `refuse_key_seed_nesting` — then *"a residue item"* — while it merely calls
//! custody's `public_key_path` to build a path. The subject has not changed;
//! the subject MOVED, and the row follows the subject. **A worked example
//! names an item, not an address.**
#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use super::*;
use crate::tests::ScratchDir;
use granary_client::Store;
use std::path::PathBuf;

/// `gran harvest <source> <store>` and `gran publish <store>
/// <source> <volume>` take the same two paths in OPPOSITE order,
/// and `refuse_nesting` passes two siblings — so a swapped
/// invocation scaffolded a store into the user's source tree and
/// then published the CAS internals as volume content. Both swaps
/// put the store in the SOURCE position, so one check catches both.
#[test]
fn a_store_in_the_source_position_is_refused() {
    let dir = ScratchDir::new();
    let store_dir = dir.0.join("store");
    let source = dir.0.join("src");
    std::fs::create_dir_all(&store_dir).unwrap_or_else(|e| panic!("{e}"));
    std::fs::create_dir_all(&source).unwrap_or_else(|e| panic!("{e}"));

    // A real store: opened through the store module, so the marker
    // is whatever the store itself writes, never a literal here.
    drop(Store::open(&store_dir).unwrap_or_else(|e| panic!("{e}")));

    // Correct order passes.
    refuse_store_as_source(&source).unwrap_or_else(|e| panic!("a plain tree is a source: {e}"));
    // A source tree that merely CONTAINS a file of that name is
    // still a source tree — the reason existence alone is not the
    // test.
    let decoy = source.join(MARKER_NAME);
    std::fs::write(
        &decoy,
        "notes about my granary-store setup
",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    refuse_store_as_source(&source)
        .unwrap_or_else(|e| panic!("a file of that name is not a store: {e}"));
    std::fs::remove_file(&decoy).unwrap_or_else(|e| panic!("{e}"));
    // A store written under a different CHUNKER_SPEC (or STORE_VERSION)
    // is still a store — the marker's bytes embed both, so byte-equality
    // would miss it and walk back into the swapped-argument failure.
    let older = dir.0.join("older-store");
    std::fs::create_dir_all(&older).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(
        older.join(MARKER_NAME),
        "granary-store-version 0\nchunker some-older-spec\nhash blake3\n",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        refuse_store_as_source(&older).is_err(),
        "a store from another build must still be recognised as a store"
    );
    // Swapped order refuses, and says which way round the arguments go.
    let err =
        refuse_store_as_source(&store_dir).expect_err("a granary store is never a source tree");
    assert!(
        err.contains("is a granary STORE") && err.contains("argument"),
        "the message must name the swap, got: {err}"
    );
}

/// A `--cache-dir` nested with the source
/// would publish the cache's own scaffolding as volume content
/// (`Cache::open` writes it BEFORE `prepare()` harvests). Refused,
/// mirroring `refuse_nesting`. Positive controls (a sibling dir and
/// `None` accepted) prove the guard is not a blanket refusal.
#[test]
fn refuse_cache_dir_nesting_refuses_a_cache_inside_the_source_or_store() {
    let dir = ScratchDir::new();
    let source = dir.0.join("src");
    let store = dir.0.join("store");
    std::fs::create_dir_all(&source).unwrap_or_else(|e| panic!("{e}"));
    std::fs::create_dir_all(&store).unwrap_or_else(|e| panic!("{e}"));

    // Nested inside the source → refused, naming the hazard.
    let err = refuse_cache_dir_nesting(Some(&source.join("cache")), &source, &store)
        .expect_err("a cache dir inside the source must be refused");
    assert!(
        err.contains("must not nest"),
        "the refusal must name the nesting hazard: {err}"
    );

    // Nested inside the store → also refused.
    refuse_cache_dir_nesting(Some(&store.join("cache")), &source, &store)
        .expect_err("a cache dir inside the store must be refused");

    // A sibling dir (nested with neither) → accepted (positive control).
    refuse_cache_dir_nesting(Some(&dir.0.join("cache")), &source, &store)
        .expect("a cache dir beside the source and store must be accepted");

    // No `--cache-dir` at all → always Ok (positive control).
    refuse_cache_dir_nesting(None, &source, &store).expect("no cache dir must always be accepted");
}

/// A `--key-seed` under the STORE or the CACHE is refused the same
/// way one under the source is.
///
/// **The store and the cache both SWEEP `txn/`.** Point the seed at
/// `<store>/txn/seed` (or `<cache>/txn/seed`) and the sequence is:
/// the key is created there, it signs the publish, and then the
/// established-open sweep unlinks every regular file directly under
/// `txn/` — the private seed among them. The key is gone and the
/// operator is not told; the next publish silently creates a new
/// identity. Nothing about the source is involved, so a guard that
/// only compares against `--source` cannot see it.
///
/// The `.pub` sidecar is checked too, and both directions, because
/// the seed argument names two files and either of them landing
/// inside a swept directory is the same defect.
#[test]
fn refuse_key_seed_nesting_refuses_a_seed_under_the_store_or_the_cache() {
    let dir = ScratchDir::new();
    let source = dir.0.join("src");
    let store = dir.0.join("store");
    let cache = dir.0.join("cache");
    std::fs::create_dir_all(&source).unwrap_or_else(|e| panic!("{e}"));
    std::fs::create_dir_all(&store).unwrap_or_else(|e| panic!("{e}"));
    std::fs::create_dir_all(&cache).unwrap_or_else(|e| panic!("{e}"));

    let under_store = store.join("txn").join("seed");
    let err = refuse_key_seed_nesting(&under_store, &source, &store, Some(&cache)).expect_err(
        "a key seed inside the store must be refused — the store's txn/ sweep deletes it",
    );
    assert!(
        err.contains("must not nest"),
        "the refusal must name the nesting hazard: {err}"
    );
    assert!(
        std::fs::symlink_metadata(&under_store).is_err()
            && std::fs::symlink_metadata(public_key_path(&under_store)).is_err(),
        "and it must refuse BEFORE any key file exists — the guard creates nothing"
    );

    let under_cache = cache.join("txn").join("seed");
    refuse_key_seed_nesting(&under_cache, &source, &store, Some(&cache))
        .expect_err("a key seed inside the cache dir must be refused too");

    // The `.pub` sidecar is a second file at a second path: a seed
    // whose own path is clear while its sidecar is not must still
    // be refused.
    let sidecar_trap = dir.0.join("seedling");
    std::fs::create_dir_all(sidecar_trap.join(".pub")).unwrap_or_else(|e| panic!("{e}"));
    refuse_key_seed_nesting(
        &sidecar_trap.join("k"),
        &source,
        &store,
        Some(&sidecar_trap.join("k.pub")),
    )
    .expect_err("a cache dir AT the public sidecar's own path must be refused");

    // POSITIVE CONTROLS: a seed beside all three is accepted, and
    // so is one with no `--cache-dir` at all.
    refuse_key_seed_nesting(&dir.0.join("seed"), &source, &store, Some(&cache))
        .expect("a seed beside the source, store and cache must be accepted");
    refuse_key_seed_nesting(&dir.0.join("seed"), &source, &store, None)
        .expect("no cache dir must not change the answer for a clear seed");
}

/// A `..` in the missing suffix can route back INTO the source
/// through a nonexistent intermediate: a store argument spelled
/// `<parent>/nonexistent/../<source-name>/sub` LEXICALLY resolves
/// into the source tree, while its first `canonicalize()` attempt
/// fails at `nonexistent` before ever reaching the `..` that would
/// cancel it.
#[test]
fn refuse_nesting_catches_a_dotdot_through_a_nonexistent_intermediate() {
    let dir = ScratchDir::new();
    let source = dir.0.join("mysource");
    std::fs::create_dir_all(&source).unwrap_or_else(|e| panic!("{e}"));

    // Lexically: dir.0/nonexistent/../mysource/sub == dir.0/mysource/sub
    // — INSIDE the source. `nonexistent` never exists on disk, and
    // `dir.0` (the source's own parent) does.
    let sneaky_store = dir
        .0
        .join("nonexistent")
        .join("..")
        .join("mysource")
        .join("sub");

    let err = refuse_nesting(&source, &sneaky_store).expect_err(
        "a store spelled through a nonexistent/.. detour back into the source must be \
         refused as nested",
    );
    assert!(
        err.contains("must not nest"),
        "the refusal must name the nesting hazard: {err}"
    );
}

/// Companion to the test above, for the `a/../..` shape the same
/// finding named: TWO `..` components popping through TWO
/// nonexistent intermediates must land on the exact same canonical
/// path a real `canonicalize()` of the already-existing ancestor
/// gives — ground truth from the real filesystem, not a hand-rolled
/// expectation.
#[test]
fn canonicalize_for_nest_check_handles_multiple_dotdot_through_nonexistent_components() {
    let dir = ScratchDir::new();
    let real_base = std::fs::canonicalize(&dir.0).unwrap_or_else(|e| panic!("{e}"));

    // Lexically dir.0/x/y/../.. == dir.0; neither `x` nor `y` exists.
    let weird = dir.0.join("x").join("y").join("..").join("..");
    let resolved = canonicalize_for_nest_check(&weird).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        resolved, real_base,
        "dir.0/x/y/../.. must lexically cancel to dir.0, matching a real canonicalize() of \
         dir.0 itself"
    );
}

/// The harder shape the plain `..`-through-nonexistent row above
/// does not reach: `canonicalize_for_nest_check`'s
/// lexical `Component::Normal(name) => base.join(name)` arm assumes
/// `name` does not exist (true for the ORIGINAL failing path, false
/// once a `..` earlier in the path cancels a nonexistent component
/// and re-exposes one that DOES exist). A store spelled
/// `<parent>/nonexistent/../alias/sub`, where `alias` is a real
/// symlink to the source, lexically joins `alias` onto the
/// canonical parent WITHOUT re-resolving it — the symlink is never
/// followed, so the result differs from the source's own canonical
/// path and `starts_with` reads false. `Store::open` (or
/// `Cache::open`) then creates scaffolding through `alias`, landing
/// it inside the source for real.
#[test]
fn refuse_nesting_catches_a_dotdot_through_an_existing_symlink_alias() {
    let dir = ScratchDir::new();
    let source = dir.0.join("mysource");
    std::fs::create_dir_all(&source).unwrap_or_else(|e| panic!("{e}"));
    let alias = dir.0.join("alias");
    std::os::unix::fs::symlink(&source, &alias).unwrap_or_else(|e| panic!("{e}"));

    // Lexically: dir.0/nonexistent/../alias/sub == dir.0/alias/sub —
    // and `alias` is a REAL symlink to `source`, so the true target
    // is source/sub. `nonexistent` never exists on disk.
    let sneaky_store = dir
        .0
        .join("nonexistent")
        .join("..")
        .join("alias")
        .join("sub");

    let err = refuse_nesting(&source, &sneaky_store).expect_err(
        "a store spelled through a nonexistent/.. detour that re-exposes an existing \
         symlink alias of the source must be refused as nested",
    );
    assert!(
        err.contains("must not nest"),
        "the refusal must name the nesting hazard: {err}"
    );
}

/// Companion, at a DIFFERENT recursion depth than the test above —
/// the shape macOS's own `/tmp -> /private/tmp` has: a REAL
/// directory (`layer`, standing in for `/`) contains both the
/// nonexistent sibling the detour cancels AND a symlink (`alias`,
/// standing in for `/tmp`) whose TARGET is a SEPARATE real
/// directory the source lives under (standing in for
/// `/private/tmp`) — built with a scratch symlink, never the
/// system one. `layer` itself (real) is where the recursion's base
/// case stops, so simply reaching an ALREADY-real ancestor is not
/// what closes this — what closes it is that `alias`, discovered
/// only via the lexical join one level up from there, is
/// re-resolved as a candidate that now exists.
#[test]
fn refuse_nesting_catches_a_dotdot_through_a_tmp_like_symlinked_sibling() {
    let dir = ScratchDir::new();
    let layer = dir.0.join("layer"); // stands in for `/`
    std::fs::create_dir_all(&layer).unwrap_or_else(|e| panic!("{e}"));
    let source = dir.0.join("private-like").join("mysource"); // stands in for /private/tmp/...
    std::fs::create_dir_all(&source).unwrap_or_else(|e| panic!("{e}"));
    let alias = layer.join("tmp-alias-case"); // stands in for /tmp -> /private/tmp
    std::os::unix::fs::symlink(dir.0.join("private-like"), &alias)
        .unwrap_or_else(|e| panic!("{e}"));

    // layer/nonexistent/../tmp-alias-case/mysource/sub — `layer`
    // itself is real (the recursion's base case), `tmp-alias-case`
    // is a real symlink reached only via the lexical join.
    let sneaky_store = layer
        .join("nonexistent")
        .join("..")
        .join("tmp-alias-case")
        .join("mysource")
        .join("sub");

    let err = refuse_nesting(&source, &sneaky_store).expect_err(
        "a store spelled through a nonexistent/.. detour that re-exposes a tmp-like \
         symlinked sibling of an already-real ancestor must be refused as nested",
    );
    assert!(
        err.contains("must not nest"),
        "the refusal must name the nesting hazard: {err}"
    );
}

/// Re-resolving every candidate the recursive fallback builds is
/// not enough on its own: a candidate whose re-resolution reports
/// `NotFound` because the candidate IS A DANGLING SYMLINK would be
/// kept LEXICAL — indistinguishable, to that arm, from a name that
/// is simply absent. `create_dir_all` does not agree: its
/// ancestor walk creates the missing components of the SPELLED
/// path bottom-up, which MATERIALIZES the dangling link's target
/// before the link itself is traversed, and the scaffolding then
/// lands through the link.
///
/// Traced concretely for the store spelled
/// `<p>/mysource/notyet/../../dang/sub`, where `dang` is a symlink
/// to `<p>/mysource/notyet`: `mkdir` of the whole path fails
/// `ENOENT`, so std recurses on parents until `mkdir` of
/// `<p>/mysource/notyet` SUCCEEDS — `notyet` now exists, inside the
/// source — after which `<p>/…/dang` is `is_dir()` (it follows the
/// link to the just-created `notyet`) and the final `mkdir` of
/// `<p>/…/dang/sub` resolves THROUGH the link to
/// `<p>/mysource/notyet/sub`. Store scaffolding inside the source,
/// which is exactly what `refuse_nesting` exists to prevent.
///
/// Fix is fail-CLOSED, not a lexical resolution of the link's
/// target: a candidate that cannot be re-resolved AND has a
/// symlink among its existing components is REFUSED. Resolving the
/// target lexically instead would be guessing at a path the
/// kernel has not agreed to.
#[test]
fn refuse_nesting_catches_a_dotdot_onto_a_dangling_symlink() {
    let dir = ScratchDir::new();
    let source = dir.0.join("mysource");
    std::fs::create_dir_all(&source).unwrap_or_else(|e| panic!("{e}"));

    // `dang` is a real symlink whose TARGET does not exist — and
    // the target is inside the source.
    let dangling = dir.0.join("dang");
    std::os::unix::fs::symlink(source.join("notyet"), &dangling).unwrap_or_else(|e| panic!("{e}"));

    // Lexically dir.0/dang/sub; `notyet` never exists on disk, so
    // the whole path's first canonicalize() fails, and the `..`
    // pair pops back to dir.0 before re-exposing `dang`.
    let sneaky_store = source
        .join("notyet")
        .join("..")
        .join("..")
        .join("dang")
        .join("sub");

    let err = refuse_nesting(&source, &sneaky_store).expect_err(
        "a store spelled through a `..` detour onto a DANGLING symlink must be refused — \
         create_dir_all materializes the link's target and lands the scaffolding through it",
    );
    assert!(
        err.contains("dangling symlink"),
        "the refusal must name the dangling symlink, not some unrelated I/O error: {err}"
    );
}

/// The same fail-closed rule at the shallowest depth there is: the
/// store path's OWN final component is a dangling symlink. No `..`
/// detour, no recursion past one level — `canonicalize()` of the
/// whole path fails `NotFound` for a reason that is NOT "this name
/// is free", and `refuse_if_dangling` refuses to treat it as free.
#[test]
fn refuse_nesting_catches_a_dangling_symlink_as_the_store_path_itself() {
    let dir = ScratchDir::new();
    let source = dir.0.join("mysource");
    std::fs::create_dir_all(&source).unwrap_or_else(|e| panic!("{e}"));

    let store = dir.0.join("dangling-store");
    std::os::unix::fs::symlink(source.join("notyet"), &store).unwrap_or_else(|e| panic!("{e}"));

    let err = refuse_nesting(&source, &store).expect_err(
        "a store path that IS a dangling symlink must be refused, not treated as a free name",
    );
    assert!(
        err.contains("dangling symlink"),
        "the refusal must name the dangling symlink: {err}"
    );
}

/// The POSITIVE control for `refuse_if_dangling`: it refuses a
/// candidate that cannot be re-resolved AND has a symlink among
/// its existing components, so the half that needs proving is that
/// it does not reject legal input.
/// A symlink is not suspicious on its own — a symlinked
/// home directory is ordinary — and refusing one would reject
/// legal input, the failure mode a guard like this must not have.
///
/// Here BOTH arguments are spelled through a real symlink
/// (`home -> real-home`) pointing at a directory that EXISTS, with
/// a plain, non-nested store path that simply does not exist yet.
/// This must be ACCEPTED. What makes it accepted rather than
/// lucky: `canonicalize()` resolves `home` before the guard ever
/// runs, so the candidate the guard walks is the fully-resolved
/// `<p>/real-home/mystore`, in which no component is a link.
#[test]
fn refuse_nesting_accepts_a_store_spelled_through_a_live_symlinked_directory() {
    let dir = ScratchDir::new();
    let real_home = dir.0.join("real-home");
    std::fs::create_dir_all(&real_home).unwrap_or_else(|e| panic!("{e}"));
    let home = dir.0.join("home");
    std::os::unix::fs::symlink(&real_home, &home).unwrap_or_else(|e| panic!("{e}"));

    let source = home.join("mysource");
    std::fs::create_dir_all(&source).unwrap_or_else(|e| panic!("{e}"));
    // Sibling of the source, through the same symlink, not yet
    // created — exactly what `Store::open` is about to create.
    let store = home.join("mystore");

    refuse_nesting(&source, &store).unwrap_or_else(|e| {
        panic!(
            "a store beside the source under a LIVE symlinked directory must be accepted — \
             the dangling-symlink guard must not refuse an ordinary symlinked home: {e}"
        )
    });

    // And the guard did not merely skip: the store path resolves
    // through the link to its real location.
    let resolved = canonicalize_for_nest_check(&store).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        resolved,
        std::fs::canonicalize(&real_home)
            .unwrap_or_else(|e| panic!("{e}"))
            .join("mystore"),
        "the symlinked spelling must resolve to the real path, not stay lexical"
    );
}

/// A RELATIVE store/cache/seed spelling whose first component does
/// not exist yet — `gran harvest ./src new_store` — must resolve,
/// not error. The recursion bottoms out on a relative path by
/// replacing an empty parent with `.`, whose `canonicalize()` is the
/// process's current directory; the failure mode this pins is that
/// bottom falling through to `canonicalize("")`, which is
/// `NotFound`, turning every ordinary relative store argument into a
/// nesting-check refusal before anything is created.
///
/// Both directions are asserted from ONE cwd reading, and neither
/// creates anything: the accepted case is a relative name beside an
/// unrelated absolute source, and the NEGATIVE CONTROL is the same
/// relative name against the current directory as the source — where
/// it genuinely nests and must be refused. Without that control an
/// implementation that resolved relative paths to nonsense could
/// still pass the first half.
#[test]
fn a_relative_store_path_with_a_nonexistent_top_component_resolves() {
    let cwd = std::env::current_dir()
        .and_then(std::fs::canonicalize)
        .unwrap_or_else(|e| panic!("{e}"));
    #[expect(
        clippy::disallowed_methods,
        reason = "the lint row this licenses bans `std::process::id` as AMBIENT INPUT, because the preimage of a \
        hashed or signed value must take a `WriterIdentity` instead. Here it is a RELATIVE PATH NAME that must \
        NOT EXIST — the row asserts that a relative path whose first component is absent still resolves against \
        the current directory — and the pid is what makes the name unique enough for that precondition to hold \
        when two test binaries run at once in the same cwd. It names nothing on disk, reaches no hashed or \
        signed value, and the assertion below is on the RESOLVED path's shape rather than on the name itself"
    )]
    let relative = PathBuf::from(format!(
        "granary-nest-check-probe-{}/sub",
        std::process::id()
    ));
    assert!(
        std::fs::symlink_metadata(&relative).is_err(),
        "fixture precondition: the relative top component must NOT exist"
    );

    let resolved = canonicalize_for_nest_check(&relative).unwrap_or_else(|e| {
        panic!(
            "a relative path whose first component does not exist must resolve against the \
             current directory, not fail the nesting check: {e}"
        )
    });
    assert_eq!(
        resolved,
        cwd.join(&relative),
        "and it must resolve to the cwd-anchored path, not stay lexical or land elsewhere"
    );

    // ACCEPTED: an unrelated absolute source, so the relative store
    // nests with neither direction.
    let dir = ScratchDir::new();
    let source = dir.0.join("mysource");
    std::fs::create_dir_all(&source).unwrap_or_else(|e| panic!("{e}"));
    refuse_nesting(&source, &relative).unwrap_or_else(|e| {
        panic!("a relative store beside an unrelated source must be accepted: {e}")
    });

    // NEGATIVE CONTROL: the same relative name against the current
    // directory as the source — it really is inside it.
    let err = refuse_nesting(&cwd, &relative)
        .expect_err("a relative store INSIDE the source must still be refused as nested");
    assert!(
        err.contains("must not nest"),
        "the refusal must name the nesting hazard: {err}"
    );
}
