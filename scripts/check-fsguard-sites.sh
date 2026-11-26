#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# `crates/granary-client/clippy.toml` is a NESTED clippy config, and a
# nested config REPLACES the workspace root file for that crate IN ITS
# ENTIRETY — it does not merge. That file therefore has to carry (a) the
# WHOLE root `clippy.toml` verbatim (all seven top-level keys — dropping
# ANY one of them, not just a methods row, silently changes the client's
# whole lint regime) plus (b) the filesystem-ban rows the fsguard-sites
# audit adds. `cargo clippy -p granary-client` is the live code gate for
# whether the bans actually fire (already deny-warnings in CI and
# local-gates); this script is the CONFIG-INTEGRITY gate underneath it —
# it cannot see whether a ban fires, only whether the file that would
# make it fire still has the required shape.
#
# Checks:
#   1. WHOLE-CONFIG SUPERSET/EQUALITY — every root top-level key is
#      present in the client file, and the client has no EXTRA top-level
#      key. List-valued keys: `disallowed-macros` and `disallowed-types`
#      must be EXACT matches, by MULTISET (a set comparison passes a
#      DUPLICATED row silently) — nothing here touches either key, so any
#      difference is unexplained drift, not an audited addition. `disallowed-methods`
#      is a SUPERSET only here (root rows all present; the fs rows are
#      the audited extras, pinned exactly by check 2). Scalar keys (the
#      three allow-*-in-tests booleans): exact equality. A row missing
#      its `path` or `reason` key is a GRACEFUL error (exit 2), not a
#      raw `KeyError` traceback.
#   2. FS-ROW ANCHORING — this script carries the normative fs-ban list
#      as DATA (below), as full (path, reason) pairs, and asserts the
#      client's disallowed-methods list equals root's rows PLUS exactly
#      these fs rows, BY MULTISET (`collections.Counter`, not `set` —
#      the same duplicate-row gap check 1 closes, closed here too, since
#      this is the check that actually pins disallowed-methods exactly).
#   3. LICENSED-SITE COUNT and 4. BARE-ALLOW KILL SWITCH — ONE combined
#      Python pass over every `.rs` file under the target directory —
#      a lexer, not a line-scoped regex, for the reasons enumerated in
#      scripts/fsguard-scan.py's own header.
#      docs/coding-standards.md MUST-1: lint suppressions use
#      `#[expect(lint, reason = "...")]`, never a bare `#[allow]`. Check
#      3 counts every `#[expect(...)]`/`#![expect(...)]` attribute in
#      crates/granary-client/src/ whose lint LIST names
#      `clippy::disallowed_methods` or a lint GROUP that contains it;
#      check 4 refuses the gate if any `#[allow(...)]`/`#![allow(...)]`
#      attribute's lint list does, anywhere under the WHOLE crate
#      directory (src/, tests/, fuzz/, and anything added later) — the
#      scope the nested clippy.toml governs.
#      Check 4 also refuses an `#[expect(...)]` whose lint list names a
#      GROUP (`clippy::all`, `clippy::style`, `warnings`) rather than
#      the lint: spelled `expect`, but a file-scoped group `expect` is
#      a wholesale suppression whose expectation the hidden calls
#      themselves fulfil, so clippy stays silent — and counting it as a
#      licence would let one narrow site be swapped for it with
#      LICENSED_SITE_CRATES' count field never moving. Only the exact
#      `clippy::disallowed_methods` spelling counts toward check 3.
#      Check 4 is not merely a second opinion. `Cargo.toml`'s
#      `[lints.clippy]` denies `clippy::allow_attributes`, which closes
#      the OUTER `#[allow]` shape at the compiler, after macro
#      expansion, for every target of the crate; but an INNER
#      `#![allow(...)]` on a module produces no diagnostic from it at
#      all (measured), so for that shape this scanner is the only check.
#   5. LINT LEVEL — checks 1-4 anchor the ban ROWS and the source
#      ATTRIBUTES, and neither of them says at what LEVEL clippy
#      applies the ban. `granary-client` carries its OWN `[lints]`
#      table (it diverges from the workspace on `unsafe_code`), so ONE
#      line of `crates/granary-client/Cargo.toml` —
#      `disallowed_methods = "allow"` — switches the whole fs ban off
#      for the whole crate with every other check still green and no
#      diagnostic anywhere: the same class as the inner
#      `#![allow(clippy::all)]` check 4 refuses. This check parses that
#      manifest and refuses (a) a `[lints]` table of the inherited
#      `workspace = true` form — it puts the ban's level in a file this
#      gate does not read, and a crate whose lint table is the
#      workspace's is not the crate this gate audits; (b)
#      `lints.clippy.disallowed_methods` at anything but `deny` —
#      ABSENT included, since clippy's default is `warn` and a local
#      `cargo clippy` without `CARGO_BUILD_WARNINGS=deny` would then
#      only warn about a bare filesystem call, and `forbid` included,
#      since it refuses every licensed `#[expect]` site instead of
#      honouring it; (c) the keys `all` and `style` under
#      `lints.clippy` AT ANY LEVEL — the two lint GROUPS that contain
#      `disallowed_methods`, whose effect on it turns on an emission
#      order cargo does not specify (measured, at the check's own
#      comment); and (d) `allow_attributes` /
#      `allow_attributes_without_reason` at anything but `deny`, or
#      absent — MUST-1 lives in this table rather than on the crate
#      roots precisely because a crate-root attribute does not reach
#      `tests/`.
#      `deny` is required for `disallowed_methods` EXACTLY, while the
#      two MUST-1 keys accept `deny` OR `forbid`: forbid is strictly
#      stronger there (nothing legitimately `#[expect]`s them), and on
#      `disallowed_methods` it would refuse every licensed site in the
#      CRATE — more than the src/-only count EXPECTED_LICENSED_SITES
#      pins, since a `[lints.clippy]` level reaches tests/ and fuzz/
#      too. It
#      also refuses (e) the `restriction` group key at any level — the
#      group that CONTAINS both MUST-1 lints, so one line under
#      `[lints.clippy]` overrides both denies while they still read
#      "deny".
#      It also reads the repo-root cargo config — BOTH the
#      `.cargo/config.toml` spelling and the legacy extensionless
#      `.cargo/config`, since cargo reads both — and refuses (i) any
#      rustflag under `build` or a `target.*` that sets or caps a lint
#      LEVEL other than `-D`/`-F` (`-A`, `--allow`, `-W`, `--warn`,
#      `--force-warn`, `--cap-lints`, joined and split spellings alike;
#      config rustflags come after the manifest's and rustc takes the
#      last level, so any of them silences the ban from a checked-in
#      file), (ii) `build.warnings = "allow"`, (iii) any `[env]` key
#      among RUSTFLAGS, CARGO_ENCODED_RUSTFLAGS, CARGO_BUILD_RUSTFLAGS,
#      CARGO_BUILD_WARNINGS, CLIPPY_ARGS, CLIPPY_CONF_DIR, RUSTC,
#      RUSTC_WRAPPER, RUSTC_WORKSPACE_WRAPPER, at any value, (iv) any
#      rustflags element beginning with `@` — a rustc RESPONSE FILE,
#      whose contents are the lint flags and are not visible here at
#      all, (v) `build.rustc`, `build.rustc-wrapper` and
#      `build.rustc-workspace-wrapper` — `cargo clippy` IS a
#      workspace-wrapper selection, so a checked-in one turns the lane
#      into a plain `cargo check` — and (vi) any `[alias]` entry, since
#      `clippy` is an EXTERNAL subcommand and cargo resolves aliases
#      first, so `[alias] clippy = [...]` is honoured by every
#      `cargo clippy` in CI and local-gates.
#   5b. CONFIG DISCOVERY — reading the repo-root configs is not the
#      same as knowing which config cargo and clippy will read. Cargo
#      walks `.cargo/config*` up from the CURRENT DIRECTORY, and clippy
#      takes the NEAREST `clippy.toml` at or above the compiled crate's
#      manifest dir, so a `crates/granary-client/.cargo/config.toml` or
#      a `crates/granary-client/fuzz/clippy.toml` decides the answer for
#      a run this gate never looks at. Both are refused by EXISTENCE
#      (`git ls-files` plus a `find` that prunes real cargo build
#      directories), since neither has a legitimate use here. The clippy
#      half covers the WHOLE tree, not just granary-client: CI clippys
#      the granary-core and granary-store fuzz workspaces too, and a
#      nested config REPLACES the root file's rows for the crate it is
#      nearest to. Three clippy configs are allowed: `clippy.toml` at the
#      repo root, in `crates/granary-client/`, and in `crates/granary-cli/`.
#   6. SOURCE CLOSURE — the premise checks 3 and 4 rest on, made true by
#      a gate rather than by a comment. Under the whole crate directory:
#      no `macro_rules!` (an arm can assemble the lint PATH from tokens,
#      which no surface scanner can ever match), no `#[path]` module, no
#      `include!` (`include_str!`/`include_bytes!` are data and stay
#      allowed), and no symlinked file (`find -type f` skips one, rustc
#      follows it). Plus the crate's direct dependency set, pinned: a
#      proc-macro dependency emits attributes that exist only after
#      expansion, and nothing short of a full resolve says which kind a
#      new entry is.
#   7. `--self-test` — positive controls proving every check above can
#      actually fail. See the control list inline below; each is named
#      for what it isolates.
#   8. RESOLUTION — whether a ban
#      row's path resolves. An unresolved
#      entry needs explicit checking: a
#      configuration diagnostic is not
#      itself proof that the normal build
#      will refuse. `check_resolution`
#      invokes the crate's own clippy
#      with JSON diagnostics and reads
#      compiler-message entries. It
#      captures stderr as well, and it
#      does not substitute a different
#      config directory: that would test
#      a configuration the real build
#      need not read. Both directions
#      inspect the same config file as
#      the static checks. The diagnostic
#      is read from the JSON stream
#      rather than assuming it will
#      appear on stderr when JSON output
#      is requested.
#      (a) DORMANCY — any row NOT marked `allow-invalid = true` that
#      clippy reports unresolvable is refused, naming it; since
#      `allow-invalid` suppresses that diagnostic unconditionally
#      (verified: a real, resolvable row given `allow-invalid = true`
#      still gets banned with no config warning at all — the flag has no
#      effect once a path resolves), any diagnostic on an as-is run is
#      proof enough that an unflagged row went dormant. (b) RE-ARM
#      FALLING DUE — for rows marked
#      `allow-invalid = true`, this check
#      strips that flag from the REAL tracked
#      config file, reruns clippy, and restores
#      the saved bytes under RETURN and
#      EXIT/INT/TERM traps. A RETURN trap alone
#      does not fire on SIGINT/SIGTERM. Copying
#      the saved file back preserves uncommitted
#      contents, unlike restoring from Git.
#      A flagged row that produces no config
#      warning when unflagged has started
#      resolving; the flag is stale and the
#      row is named. The config-loader
#      diagnostic does not require a source-code
#      call to the path, and a warning does
#      not block the remaining diagnostics,
#      allowing all rows to be read from
#      one invocation per direction.
#      NO EXPLICIT FORCING STEP is used. The
#      recorded toolchain observation is that
#      changing the config causes recompilation,
#      while a cached clippy invocation replays
#      its diagnostics. The check captures and
#      examines the output in either case; a
#      cached invocation must not be treated as
#      empty merely because it prints no new
#      "Checking" line. Repeated calls on the same
#      config are exercised by the self-test.
#      `crates/granary-client/clippy.toml` is checked via `-p
#      granary-client` (the crate its nested config governs); the root
#      `clippy.toml` is checked via `-p granary-store` PLUS a SECOND,
#      confirmatory crate (`-p granary-conformance --tests`) — see
#      `ROOT_RESOLUTION_CRATE`'s own comment for why a single crate
#      cannot cover this config's `rand::*` rows at all without either
#      missing them entirely or misfiring on rows this project has
#      already decided, in `clippy.toml` itself, to keep flagged.
#      Every resolution verdict reports considered and evaluated rows; a
#      direction with considered rows but zero evaluated rows refuses.
#   9. INHERITED CLI VERDICT — require byte-identical CLI and client configs
#      and check granary-cli's and granary-client's dependency closures with
#      `check_closure_premise`; print the verdict after both client and root resolution pass.
#
# REQUIRES PYTHON 3.11 OR NEWER on `python3`: the config checks parse
# TOML with `tomllib`, which is stdlib only from 3.11. The version is
# checked in the program itself and refused by name (exit 2) rather than
# left to surface as a `ModuleNotFoundError` traceback — the self-hosted
# CI runners' python version is not pinned anywhere, so the requirement
# is stated as an executable check.
#
#   scripts/check-fsguard-sites.sh              run the gate
#   scripts/check-fsguard-sites.sh --self-test  prove it can fail
set -euo pipefail

# ARGUMENT VALIDATION happens before
# top-level setup. Only no argument or
# exactly `--self-test` is accepted. A
# misspelled self-test flag must not
# silently run the ordinary gate and report
# success after running no self-test
# controls. Refusing unknown instructions
# also keeps setup failures from obscuring
# the argument error: the diagnostic names
# the instruction the caller actually
# supplied. The guard checks both arity
# and the single permitted spelling.
#
# This argv guard is local to the script.
# The vfs gates exercise their corresponding
# guards with `selftest_argv_guard`; the
# repeated guard code does not require adding
# another sourced helper to each gate.
if [[ $# -gt 1 || ( $# -eq 1 && "${1:-}" != "--self-test" ) ]]; then
  echo "fsguard-sites: unrecognised argument(s): $* — the only accepted form is '--self-test' (or no argument, to run the gate). Refused rather than silently running the gate and reporting green." >&2
  exit 2
fi


ROOT_CLIPPY="clippy.toml"
CLIENT_CLIPPY="crates/granary-client/clippy.toml"
# check_resolution's crate for CLIENT_CLIPPY: the crate its own nested
# config governs, the only one that ever reads it.
#
# For ROOT_CLIPPY, ONE crate cannot cover this config's seven `rand::*`
# rows (six `disallowed-methods`, one `disallowed-types`) at all:
# resolvability is NOT uniform across the crates this config governs.
# `rand` 0.10.2 (pulled transitively by object_store, a NORMAL
# dependency) makes six of seven resolve for granary-store (and
# granary-server, granary-sim) but not `rand::rngs::OsRng`, which that
# version dropped. `rand` 0.9.5 (pulled transitively by proptest, a
# DEV-dependency of granary-conformance/-net/-bench) is reachable only
# once dev-dependencies are linked — `--lib` never does that — and
# resolves `OsRng` plus `rand::rng` but none of the other five methods.
# `granary-core`/`granary-fuse` reach neither version at all.
#
# A crate that reaches neither `tokio` nor `rand`
# cannot establish that their ban rows are live
# or clean. Its clippy output can contain no
# unresolved-path warning for a row it never
# evaluates. Resolution therefore needs both a
# dependency-reach oracle and explicit considered/evaluated
# counts; a zero-coverage direction refuses.
#
# The primary and confirmatory crates
# serve different resolution checks:
#   - `ROOT_RESOLUTION_CRATE="granary-store"` is the PRIMARY crate, used
#     for BOTH directions. It reaches `tokio` (a normal dependency) —
#     the dormancy direction evaluates all nine `tokio::*` / three
#     `tokio::{select,join,try_join}` rows. It also reaches `rand` 0.10.2 —
#     real, non-zero
#     re-arm coverage on six of seven rows (real, not silently skipped).
#   - `ROOT_RESOLUTION_CRATE_SECONDARY="granary-conformance"` is a
#     confirmatory SECOND crate, used ONLY for the re-arm direction and
#     ONLY run via `--tests` (never `--lib` — see check_resolution's own
#     comment on why), to reach `rand` 0.9.5 through proptest's
#     dev-dependency. It is the cheapest of the three `-conformance/
#     -net/-bench` crates to compile (`granary-core` + `nix` only).
#
# A row is refused as RE-ARM only when it resolves under the PRIMARY
# crate AND the secondary crate does not independently confirm it is
# still needed (i.e. the secondary either also resolves it — see below
# — or does not reach it at all, in which case this check cannot rule
# out that the row is workspace-wide stale and refuses conservatively,
# as required for a zero-coverage direction). A row that resolves
# under BOTH crates is NOT refused. The `rand::rng` row deliberately keeps
# `allow-invalid = true` for uniformity with its still-needed siblings,
# despite resolving everywhere checked, as `clippy.toml` documents.
# check_resolution reports this uniformity choice as a visible, named
# ADVISORY; it does not treat the choice as a gap requiring refusal.
CLIENT_RESOLUTION_CRATE="granary-client"
# Declare the cli's config and package HERE with their sibling constants,
# rather than at the call site, so `grep -n '^NAME='` locates each
# declaration in this block.
CLI_CLIPPY="crates/granary-cli/clippy.toml"
CLI_RESOLUTION_CRATE="granary-cli"
# Packages the cli may reach that granary-client does not. It is its OWN
# package and nothing else: no dependency may be exclusive to the cli
# under this expectation. Anything else here is a COVERAGE
# DECISION — an extra package can make an `allow-invalid` row resolve under
# the cli while it stays dormant under the client — so it is declared in a
# diff rather than absorbed silently.
CLI_ONLY_PACKAGES_EXPECTED=("granary-cli")
# CLIENT_RESOLUTION_CRATE stays a SCALAR: the cli inherits the client's
# resolution verdict through config identity and dependency-closure checks.
# CRATE_SRC, CRATE_DIR, CLIENT_MANIFEST and EXPECTED_LICENSED_SITES are
# separate coverage inputs below; CLIENT_CLIPPY is above this line.
# Checking CLIENT_CLIPPY alone does not establish coverage of the cli's
# config: that requires the identity check described below.
#
# `crates/granary-cli/clippy.toml` is NOT a
# check_resolution subject, and `granary-cli` is not a crate this check
# ever names.
#
# THE INVARIANT THAT FORCES IT, which nothing in this file stated before:
# the <config-path> and <crate-pkg> arguments MUST CORRESPOND. Clippy takes
# the NEAREST clippy.toml at or above the compiled crate's manifest dir and
# uses only that file (the DISCOVERY message in check_stray_configs says so,
# and it is re-measured: a two-member probe workspace where only one member
# carries a nested config saw each crate resolve its OWN file's rows and
# neither see the other's). So compiling `granary-cli` can only ever check
# `crates/granary-cli/clippy.toml` — it can never stand in for the client's.
# The same invariant is why the SECONDARY crate works: granary-conformance
# has no nested config, so it reads the ROOT config, which IS the file under
# test there.
#
# WHY EXCLUSION RATHER THAN A SELECTOR. `granary-cli` will be bin-only, and
# `cargo clippy -p <pkg> --lib` on a BIN-ONLY package exits 101 with
# `error: no library targets found in package` and an EMPTY JSON stream.
# MEASURED ON THE CLASS, NOT ON THIS PACKAGE: the probe was a throwaway
# bin-only crate, because `granary-cli` does not exist yet — and a probe
# run against the absent name today would exit 101 for a DIFFERENT reason
# (`package ID specification ... did not match any packages`), which is why
# it is not cited here as if it were the same measurement. Either way the
# naive "just add the row" lands in the HARNESS branch below and is refused,
# never silent. And a cli row would
# buy nothing: the cli's bin loads granary_client's whole transitive closure,
# so no row can resolve under the cli and not under the client; every
# `allow-invalid` row here is a root-SHARED `rand::*` row, already deferred
# at the client's own call, so a cli call would strip a second real tracked
# file and re-lint a 13,000-line bin to evaluate ZERO rows.
#
# WHAT CARRIES THE INHERITANCE INSTEAD: check_config_identity requires the
# cli's config to be byte-identical to the client's, and
# check_closure_premise requires the cli's closure to contain the client's.
# Both are defined BELOW, beside check_resolution, and are cheap and static.
# They are CALLED at check 9, gated on the cli config's EXISTENCE, so the
# presence of that config engages both checks automatically. Their
# controls (Q7, Q8) drive them from FIXTURES, so the mechanism is tested
# independently of whether the cli config exists in the checked tree.
#
# IF check_closure_premise EVER REFUSES, WHICH REFUSAL IT IS DECIDES THE
# FIX — and only one of the three means the ruling has expired:
#   SUPERSET, rc 1 — the premise is genuinely gone: granary-cli no longer
#     reaches something granary-client does. THIS is the one where the
#     named successor applies: give granary-cli its own check_resolution
#     row, `--bins` paired with `-e normal,build` (the bin analogue of the
#     --lib pairing below), never `--all-targets`, whose test targets link
#     dev-dependencies the primary tree's edge set does not.
#   HARNESS, rc 2, from a `cargo tree` failure — a registry or lock
#     problem. Fix the environment; the ruling is untouched.
#   HARNESS, rc 2, from the same-package guard — a mistyped call site
#     passing one package in both seats. Fix the call, one line. Do NOT
#     build a check_resolution row for this; it is the expensive change
#     the paragraph above exists to argue against.
ROOT_RESOLUTION_CRATE="granary-store"
ROOT_RESOLUTION_CRATE_SECONDARY="granary-conformance"
# The COUNT is scoped to src/ — the constant below enumerates production
# sites, and `tests/*.rs` deliberately use file-scoped `#![expect]`s that
# it does not describe.
#
# EVERY SELF-TEST FIXTURE BUILT FROM `$CRATE_SRC` MUST COPY IT
# RECURSIVELY. `cp -R "$CRATE_SRC"/. "$dir/"` — the trailing `/.` copies
# CRATE_SRC's CONTENTS, subdirectories included, into an already-`mkdir
# -p`'d `$dir` without nesting a `src/` level under it, which a bare
# `cp -R "$CRATE_SRC" "$dir"` would do to an existing `$dir` and which the
# scanner's `--crate-dir "$dir"` invocation must not see. The FLAT form,
# `cp -R "$CRATE_SRC"/*.rs "$dir/"`, is the trap: the glob expands only to
# files directly inside `$CRATE_SRC`, silently dropping every file under a
# subdirectory, including `cache/space.rs` and EVERY `<module>/tests.rs`
# body there is, and the fixture's COUNT then reads however
# many licences happen to sit at the top level — right by ACCIDENT while
# no subdirectory carries one, wrong the moment one does, with no signal
# at the point it goes wrong. See control T6 below, which plants a
# licence one level down specifically so this cannot regress unnoticed.
CRATE_SRC="crates/granary-client/src"
# The KILL SWITCH is scoped to the WHOLE CRATE DIRECTORY, because that is
# the scope the nested clippy.toml governs: clippy resolves its config
# from the compiled crate's manifest directory upward, so
# `crates/granary-client/clippy.toml` is also the config for the `fuzz/`
# crate nested inside it, and would be for any `benches/`, `examples/` or
# `build.rs` added later. A bare `#[allow]` in any of them switches the
# fs ban off for real code the same as one in `src/` does, and scanning
# only src/ and tests/ would never look.
CRATE_DIR="crates/granary-client"
# Declare the cli's pair beside the client's pair, as with CLI_CLIPPY:
# keep each constant with its siblings so `grep -n '^NAME='` locates
# its declaration in the same block.
# `granary-cli` has NO nested fuzz workspace, so it has
# no fuzz triple to match CLIENT_FUZZ_* below.
CLI_CRATE_DIR="crates/granary-cli"
CLI_SRC="crates/granary-cli/src"

# The lint LEVEL is a property of the CRATE'S OWN manifest, not of
# either clippy.toml. granary-client cannot inherit `[workspace.lints]`
# (it needs `unsafe_code = "deny"` where the workspace forbids), so the
# level that decides whether the anchored ban rows are errors or nothing
# at all lives in this file.
CLIENT_MANIFEST="crates/granary-client/Cargo.toml"
CLI_MANIFEST="crates/granary-cli/Cargo.toml"

# THE PRIMARY LINT-MANIFEST TABLE — every crate whose OWN manifest
# decides the level for code the nested clippy.toml governs. One entry
# per crate, and the gate runs check 5 once per entry.
#
# EVERY CRATE'S MANIFEST MUST BE REACHED BY THIS LOOP: otherwise its
# whole filesystem ban can be switched off while the gate prints green.
# Reading only the client's manifest cannot detect
# `disallowed_methods = "allow"` in
# `crates/granary-cli/Cargo.toml`. A licensed-site count for that crate
# does not establish that the lint binds its code; check 5 must also
# verify the lint level in that crate's own manifest.
#
# Byte-identity of the two clippy.toml files (check 9) does NOT cover
# this: the config says WHICH methods are banned, the manifest says at
# what LEVEL, and a `deny` turned `allow` in the manifest makes a
# perfectly identical config decoration.
#
# The fuzz workspaces are NOT here. They are `secondary`: absence of a
# [lints] table is the sanctioned state there, so they have their own
# loop with its own mode, below.
PRIMARY_LINT_MANIFESTS=(
  "$CLIENT_MANIFEST"
  "$CLI_MANIFEST"
)
# A lint-level rustflag, or a lint-shaped [env] key, in a checked-in
# cargo config decides the level whatever the manifests say. Cargo reads
# BOTH spellings of the file — the `.toml` one and the legacy
# extensionless `.cargo/config`, warning when both exist and preferring
# the `.toml` — so both are passed to the check when present. An ABSENT
# file is legitimate and is not a finding: the check is given the
# literal "none" rather than a path that is not there, so "the file is
# missing" and "the file is unreadable" stay distinguishable.
CARGO_CONFIG=".cargo/config.toml"
CARGO_CONFIG_LEGACY=".cargo/config"
CARGO_CONFIG_ARGS=()
if [[ -f "$CARGO_CONFIG" ]]; then
  CARGO_CONFIG_ARGS+=("$CARGO_CONFIG")
fi
if [[ -f "$CARGO_CONFIG_LEGACY" ]]; then
  CARGO_CONFIG_ARGS+=("$CARGO_CONFIG_LEGACY")
fi
if [[ "${#CARGO_CONFIG_ARGS[@]}" -eq 0 ]]; then
  CARGO_CONFIG_ARGS=("none")
fi
# The single-config spelling the self-test's manifest controls pass, so
# that a manifest mutation is the only difference between them and a
# passing run.
CARGO_CONFIG_ARG="${CARGO_CONFIG_ARGS[0]}"

# check-unsafe-sites.sh shape: a deliberate constant, bumped only with a
# reason. It describes the tree AS IT IS, per file, so that a moved
# number can be checked against something other than its own history:
#
#   main.rs    17   cache.rs   13   fsguard.rs  7   store.rs   6
#   harvest.rs  3   verify.rs   3   head.rs     2   retry.rs   2
#   fetcher.rs  2   resolve.rs  1   mount.rs    2
#
# Eleven of the fifty-eight are WHOLESALE TEST-MODULE exemptions — one
# `#[expect]` per file on its `mod tests` item, in each of the eleven
# files above. All eleven carry the same canonical reason; the rule they
# invoke is stated once, in the nested clippy.toml's header. Every file
# has exactly one, which is why resolve.rs (no other licence at all)
# appears here with 1.
#
# The other FORTY-SEVEN are individually-audited fn/site-level
# `#[expect]`s: main.rs 16, cache.rs 12, fsguard.rs 6, store.rs 5,
# harvest.rs 2, verify.rs 2, retry.rs 1, head.rs 1, fetcher.rs 1,
# mount.rs 1. Most cover filesystem calls. SEVENTEEN cover a
# NON-FILESYSTEM row of the same lint, counted by CALL rather than by
# attribute (one `#[expect]` on a fixture's `fn new()` covers its
# `create_dir_all` AND its pid, so the two counts are not the same
# number), and they are enumerated because a reader counting fs calls
# would otherwise come up short:
# Cited by NAME rather than by line: a line number in a comment is stale
# the first time anyone rewrites a reason string above it, and one of
# these already was.
#   - retry/tests.rs's `tokio::spawn`, narrowly licensed for an h2 test peer
#     in a transport layer the sim replaces rather than drives;
#   - main.rs's `WallClock::now`, the crate's one licensed
#     `SystemTime::now` — the Clock seam's own implementation;
#   - FOURTEEN `std::process::id` calls. TWO are production:
#     cache/write.rs's `unique_txn_name` and store.rs's `atomic_write`
#     (both staging names, where the pid is what stops two processes
#     colliding); the writer identity reads no pid, being drawn from the
#     cryptographic-randomness seam. The other TWELVE are test
#     fixtures, one per test module, each the `ScratchDir::new` that
#     builds that module's scratch name — `granary-cache-test-`,
#     `granary-fsguard-test-`, `granary-store-test-`,
#     `granary-fetcher-test-`, `granary-harvest-test-`,
#     `granary-head-test-`, `granary-verify-test-`,
#     `granary-mount-test-` (the mount session's own
#     harvest-source/store/cache scratch dirs, over the real filesystem
#     rather than in-memory fakes) — plus main.rs FOUR times:
#     `granary-client-main-test-` (the test scratch dir),
#     `granary-client-main-seed-test-` (the seed fixture's directory
#     under HOME), `granary-nest-check-probe-` (the relative path
#     whose name must NOT exist) and `granary-mount-preflight-test-`
#     (the mountpoint pre-flight's own scratch dirs:
#     missing/plain-file/symlink/non-empty fixtures over the real
#     filesystem, since the pre-flight checks the real filesystem and
#     an in-memory fake would not exercise it).
#     A wholesale FILESYSTEM licence does not justify exempting the
#     ambient-input rows that share the lint. Every one of the fourteen
#     is therefore NARROW — on a `fn` or on the `let` itself, never on
#     the module — which is what the oracle below requires, and what
#     the claim here is.
#     WHAT IS NOT CLAIMED is that each states a pid-specific reason.
#     Nine of the eleven fixtures do. TWO do not: the `granary-head-test-`
#     and `granary-verify-test-` sites carry only the canonical
#     wholesale fs reason ("test module: fixtures use bare fs calls on
#     their own scratch directories"), which does not mention the pid at
#     all. They are pre-existing and were left untouched: scoped right,
#     reading as if licensed for something else.
#
#     WHAT HOLDS THAT LINE, AND HOW FAR IT REACHES. `--banned-rows` in
#     scripts/fsguard-scan.py refuses a call written as a PATH
#     (`tokio::spawn(...)`, `SystemTime::now()`) and an IMPORT of one
#     (`use std::process::id as p;`), under a whole-module licence, with
#     a control behind each. It is a TEXT oracle: it does not resolve
#     names, so a RECEIVER spelling — `set.spawn(...)` for
#     `tokio::task::JoinSet::spawn`, `handle.spawn(...)` for
#     `tokio::runtime::Handle::spawn`, `local.spawn_local(...)` — names
#     no path at its call site and is invisible to it. Under a
#     whole-module licence clippy is silent about those too, so nothing
#     refuses them. That is not a gap with a control; it is the reason
#     a whole-module licence is the wrong shape. Every licence should be
#     a narrow per-site one, where clippy itself still decides every row
#     it does not cover — the register carries "no whole-module licences
#     at all" as the structural fix, and until that lands the nineteen
#     below are what the oracle is for.
#
# The guard module uses per-site licences for
# its primitives and tests. A whole-module
# exemption would let a new bare filesystem
# call inherit permission without moving the
# site count. Per-site licences make additions
# visible to the count and to inspection.
#
# The cache module's twelve non-wholesale licences are a MODULE figure:
# SIX in cache.rs, TWO in cache/paths.rs, TWO in cache/write.rs, ONE
# in cache/marker.rs and ONE in cache/tests.rs. All twelve belong to
# the same module. They include `unlink_object_leaf` in cache/paths.rs,
# which owns the
# pairing of "classify the fanout, then unlink" for every
# object path — `insert`, `Cache::get` and `evict_oversized` route
# through it and carry no licence of their own, which is why a module
# that does most of the deleting has fewer licences than main.rs.
# The mount session added two: `WriterState::reset_mount_anchor` (`gran mount
# --reset-floor`'s only effect — `remove_file` by name on the
# mount-private anchor) and `WriterState::evict_root_bytes` (cache repair —
# `remove_file` by name on a cached root that failed the reader's own
# verifier). Both are associated functions, not methods (`unused_self`
# under this crate's pedantic table): neither touches any
# `WriterState` field.
#
# mount.rs's one non-wholesale licence is its `ScratchDir::new`'s pid
# site — the mount session's own tests are the first in
# this crate to need real harvest-source/store/cache directories rather
# than the in-memory `RootStore`/`BinStore` fakes resolve.rs's tests get
# away with, so it needed a `ScratchDir` where resolve.rs's test module
# does not.
#
# main.rs's three new licences (`gran mount`'s parsing,
# argv[0] dispatch, mountpoint pre-flight and exit-code mapping) are the
# pre-flight's own: `refuse_if_already_mounted`'s inner `canonical()`
# helper (`std::fs::canonicalize`, resolving a mountpoint already proved
# to exist by `symlink_metadata` immediately above it, so its real path
# can be compared against `/proc/self/mountinfo`'s field 5 — Linux-only,
# so this site is untestable on this crate's own macOS development box);
# `refuse_if_nonempty` (`std::fs::read_dir`, no fsguard primitive lists
# directory entries); and `MountScratchDir::new`'s pid site, the fourth
# instance of the `std::process::id`-as-scratch-dir-name pattern in this
# file, enumerated above. The mountpoint pre-flight is filesystem code
# by its very nature (the mountpoint exists, is a directory, is
# not already a mount, and is empty unless `--force`"), which is why it
# is the one task in this crate the fs-ban binds hardest.
#
# `tests/*.rs` integration-test files are OUTSIDE crates/granary-client/
# src/ and use file-scoped `#![expect]` instead — not counted here by
# design (the kill switch, which runs over the whole crate directory,
# still covers them). Six of them additionally carry a narrow
# `ScratchDir::new` pid licence of their own, for the same reason the
# src/ ones do; being outside src/ they do not move this number.
#
# `cmd_umount_linux` licenses a canonicalize
# call for the operator's mountpoint argument,
# matching the kernel-resolved TARGET value
# returned by findmnt. It is the same kind
# of path comparison performed by
# `refuse_if_already_mounted` at mount time.
# The site is Linux-only, so a macOS-only
# run cannot exercise that path; the
# licence belongs to the CLI source count.
# The wire-byte snapshot writers add FOUR new licences (added on
# top of the count above): fsguard.rs's `create_regular_exclusive` and
# `publish_regular` — two new guarded primitives the client-kind
# snapshot writer needs for its write-then-rename publish (an O_EXCL
# create, then a re-verified rename), added rather than reusing
# `create_regular_lock` because a lock deliberately allows re-opening an
# EXISTING name and this write must refuse one; wire_snapshot.rs's own
# `mod tests` wholesale exemption (its fixtures touch a real scratch
# directory, the same shape every other test module's wholesale licence
# covers); and that module's own `ScratchDir`-style pid site, another
# instance of the `std::process::id`-as-scratch-dir-name pattern
# enumerated above.
# One more site joins the pattern: wire_snapshot.rs's
# `write_body_and_publish` does a best-effort
# `std::fs::remove_file(&tmp)` on its own failure path, cleaning up the
# temp file it just created itself moments earlier via
# `fsguard::create_regular_exclusive` — the identical shape and reason
# `store.rs::atomic_write`'s own pre-existing licensed site already
# carries for its own txn-staged temp.
# >>> THE BREAKDOWN ABOVE COMBINES TWO CRATES' LICENCES. <<<
# `main.rs` and the three `CARGO_BIN_EXE_gran` integration suites belong
# to `crates/granary-cli`. The 64-licence breakdown attributes 46 to
# `crates/granary-client/src` and 18 to `crates/granary-cli/src`, before
# the additional file-scoped test licences itemized below. Each crate's
# count must be measured in its own source root, not inferred by subtraction.
# A TOTAL of 64 cannot establish that allocation: check_all_licensed_sites
# must compare PER ROW and never a sum — a sum-comparing implementation
# accepts a wrong split.
#
# >>> ACCOUNT FOR `keys/tests.rs` AS ONE FILE-SCOPED TEST LICENCE. <<<
# `crates/granary-cli/src/keys.rs` owns the subject tested in
# `keys/tests.rs`; a module's unit tests belong in its own tests file.
# Bare filesystem calls on a test body's own scratch directories are
# licensed once at file scope. `tests.rs` and `keys/tests.rs` therefore
# carry TWO such licences, with the identical reason string. The extra
# file contributes one to the cli baseline: 18 + 1 = 19, and 46 + 19 = 65
# for the workspace subtotal. This accounts for the same rows over the
# same test code without increasing the permission each licence grants.
#
# The distinction this count cannot make on its own is exactly why that is
# written down: the count says how many licences exist, never how much each
# one covers. A future rise wants the same sentence — which file, and why a
# file rather than a site — or it is a permission arriving unexamined.
#
# >>> ACCOUNT FOR `attach/tests.rs` AS ONE FILE-SCOPED TEST LICENCE. <<<
# `crates/granary-cli/src/attach.rs` owns the mount/umount attachment
# lifecycle. Its 142 test rows belong in `attach/tests.rs` because that
# is the subject they assert about; incidental calls to another subject
# do not determine ownership. Each module's tests live in its own file.
# A test body's bare filesystem calls on its own scratch directories are
# licensed ONCE at file scope. Across THREE files there are three licences,
# each with the identical reason string and no wider permission over the
# test code. The cli subtotal is 19 + 1 = 20; the workspace subtotal is 66.
#
# The property to check when splitting a test body is LITERAL PRESERVATION:
# no assertion text may be lost. For this allocation, the only additional
# strings are the test file's own licence reason and a `cfg` on one import.
# The production half is licence-count-NEUTRAL for the same reason:
# its `#[expect]` sites belong to the items they annotate and are not new
# permissions. A rise that cannot be explained that way is a permission.
#
# These claims must be checkable from the source files: inspect the test
# assertions, the file-scoped reason strings, and the production items'
# own `#[expect]` attributes. A file extent or a commit identifier alone
# cannot tell a reader which permission each counted licence grants.
# The accounting must name the files and the scope of their licences.
#
# >>> ACCOUNT FOR `path_separation/tests.rs` AS ONE FILE-SCOPED LICENCE. <<<
# `crates/granary-cli/src/path_separation.rs` owns filesystem-separation
# refusals, and its eleven test rows belong in `path_separation/tests.rs`.
# This fourth test file contributes one file-scoped licence with the
# identical reason string over the same test rows and code. The cli
# subtotal is 20 + 1 = 21; the workspace subtotal is 46 + 21 = 67.
# The PRODUCTION half is count-neutral: `path_separation.rs` carries
# FOUR `#[expect(clippy::disallowed_methods, ...)]` sites on four of its
# six items. Those licences remain attached to their items within the
# same scanned root ($CLI_SRC), so file placement does not add permission.
# All FOUR production licences still belong in the count.
# Count-neutral production code can carry existing licences; it does not
# mean that the child has no production licences.
#
# EVERY child cut out of a test-carrying crate root raises this count by
# exactly one when its test body requires the same bare-filesystem licence:
# the child's tests belong in its own `tests.rs`, and their bare fs calls
# are licensed once at FILE scope. The crate root's own disposition
# directive names SEVEN more children:
# origin, wire_snapshot, publish, cat, thresh, harvest, verify.
# Re-read that directive when assessing the remaining subjects; it is
# attached to the source whose disposition it describes.
# Check this list against it instead of editing the names from memory.
# **A rise of one per child is expected and still owes an explanation of
# which test file carries the licence; a rise of more than one is a real
# permission and must be read as one.**
#
# >>> ACCOUNT FOR `admission/tests.rs` AS ONE FILE-SCOPED TEST LICENCE. <<<
# `crates/granary-cli/src/admission.rs` owns execution admission and the
# process-identity snapshot; its two test rows belong in `admission/tests.rs`.
# That file contributes one licence with the identical reason string:
# the cli subtotal is 21 + 1 = 22 and the workspace subtotal is 46 + 22 = 68.
# The PRODUCTION half is count-neutral because `admission.rs`'s three
# items carry no `#[expect(clippy::disallowed_methods)]` at all.
# Its `unsafe` libc calls carry a DIFFERENT expectation, which this scan
# does not count. The production items therefore contribute no licences
# to this count and require no additional disallowed-methods permission.
#
# >>> ACCOUNT FOR A GRANDCHILD'S TEST FILE AS WELL AS ROOT CHILDREN'S. <<<
# `crates/granary-cli/src/attach/mount_table.rs` owns the kernel's mount
# table, a separate subject from `attach.rs`'s attachment lifecycle.
# Children live under their parent's sibling directory, and the same
# arrangement applies recursively when a child has children of its own.
# Each module's tests live in its own tests file, so this grandchild's
# tests belong at `attach/mount_table/tests.rs`, two levels below `src/`.
# Its file-scoped licence has the identical reason string and contributes
# one; with the witness below the cli subtotal is 24, the workspace 70.
# This is the fifth additional test file accounted for here; its licence
# does not widen the permission over the test code. A grandchild can
# therefore add one to the count too: the list of pending root children
# above is not an upper bound on further file-scoped test licences.
# The PRODUCTION half is four sites across the parent and child:
# `attach.rs` carries two, and `mount_table.rs` carries the licence on the
# `canonical` helper inside `refuse_if_already_mounted`'s Linux arm.
# The fourth is `main.rs`'s `conformance_stderr_checkpoint`, a witness
# file write that exists only under the `conformance-breakage` feature,
# which the release build refuses to compile.
# All four remain with their items inside the same scanned root ($CLI_SRC).
#
# >>> ACCOUNT FOR THE WRITER IDENTITY: IT READS NO PID. <<<
# `gran publish` draws its writer identity from the cryptographic-
# randomness seam (`granary_net::secure_random::OsSecureRandom`), so no
# item in `main.rs` reads `std::process::id` and none carries a licence
# for it. The running total above, 24, is therefore one less: the cli
# count is 23; publication storage's client subtotal is accounted for below.
#
# >>> ACCOUNT FOR PUBLICATION STORAGE'S FOUR LICENSED SITES. <<<
# `crates/granary-client/src/publication_store.rs` carries three item licences:
# - `scope_directories`: enumerate the guarded publications directory; only
#   scope-named children are opened and checked before record access.
# - `Disk::ensure_directory`: create one private directory and validate the
#   guarded open, including AlreadyExists.
# - `Disk::rename`: atomic replacement in the private scope directory under
#   the store lock, after exclusive creation, write and file sync.
# `crates/granary-client/src/publication_store/tests.rs` contributes one
# file-scoped licence for bare filesystem calls on test-owned scratch paths.
# Those four sites make the client subtotal 46 + 4 = 50.
# `publication_store.rs` also licenses `remove_temporaries`: under the store
# lock, enumerate a checked scope and unlink only exact store temporary names,
# without following leaves or recursing. This adds one: 50 + 1 = 51 client.
# The cli count is 23; the workspace total is 51 + 23 = 74.
# Publication archives add two production licences: `Disk::unlink` in
# `publication_store.rs` unlinks only the exact duplicate live name after
# archive durability, or the descriptor-checked same-inode pair after protected
# custody and requested incomplete content validation; `PublicationStore::catalogue`
# in `publication_store/archive.rs` enumerates guarded private scopes and
# validates every reserved claimant before selection. The client is 51 + 2 = 53.
# `publication_store/tests/archive.rs` carries 94 call-site licences for
# fixture reads and filesystem operations in test-owned private scratch
# directories: the 88 counted here, and its six read-inspection rows counted
# with the landed-refresh classifier's below. Each licence names exactly `clippy::disallowed_methods` and
# stays on its call statement; there is no module-scoped archive-test licence.
# The five added test licences cover refused same-inode retries and native
# descriptor-relative rename resolution: 83 + 5 = 88 archive-test sites.
# Publication and archive operations account for 53 + 88 = 141 client sites;
# the overlay operations below bring the client total to 151.
# Overlay custody adds one guarded update-open, four disk-adapter operations
# (enumeration, child creation, checked rename and checked unlink), and five
# function-scoped owned-fixture licences. Each operation rechecks the protected ancestry/leaf.
# The writable mount start adds five production licences, each read-only or a
# bounded wait: the signing seed's existing-parent canonicalisation, the
# mountpoint's enumeration as an already-checked real directory, the mountpoint's
# ordinary parent for the mount-table comparison, the coordinator's waiting
# adapter, and the managed-path comparisons made before any writable state
# exists.
# The credential module's test licence covers its live source inventory and
# descriptor-identity fixture; it reads no credential file.
# Synchronization adapters add five narrow licences: one monotonic sample,
# scheduling time, supervised spawn, supervised blocking work and retry sleep.
# Their call sites are sync/clock.rs and sync/runtime.rs; the runtime observes
# both joins, and every licence is attached to its adapter method.
# 151 + 5 + 1 + 5 = 162.
# Corruption and eviction fixtures carry three function-scoped licences for
# rewriting or removing only their exclusively owned immutable CAS leaves.
# Their scratch resolves at runtime beneath the workspace target directory;
# these licences grant no production filesystem permission.
# The commit-budget tests carry two function-scoped licences for reading the
# durable retained record inside their owned fixture, and the generic-resume
# custody test three (its scratch's creation and removal, and the test that
# damages only its own fixture files): 165 + 2 + 3 = 170. The head
# observer's boundary tests carry one function-scoped licence: a real-time
# bound for a test thread waiting on a paused runtime it cannot advance
# (writable_start/sync/tests.rs). The live driver's loop rows carry one
# function-scoped licence: a real-time bound for the test thread that catches
# a parked or spinning loop (mount/tests/writable/commit_lane/view_install.rs).
# The landed-refresh classifier's rows carry three function-scoped licences:
# reading their test-owned scratch store's publication directories,
# planting one leftover temporary in it, and damaging one record in it
# (overlay_store/tests/coordination/engine/commits.rs). The publication
# store's read-inspection rows carry six, each confined to its test-owned
# private scratch directory (publication_store/tests/archive.rs):
# 171 + 3 + 6 = 180.
# The disk-loss recovery rows carry three: two that run synchronous recovery
# on their own runtime while an asynchronous commit or refresh fixture stays
# live (overlay_store/tests/coordination/engine/commits.rs and
# commits/refresh.rs), and one that plants a corrupt regular CAS leaf in its
# fixture to prove recovery's operator-actionable refusal (commits/selected.rs):
# 180 + 3 = 183.
# The stored-landing replay row carries one function-scoped licence for
# replacing or removing retained evidence in its test-owned scratch store
# (overlay_store/tests/coordination/engine/commits/refresh.rs):
# 183 + 1 = 184.
# The unmerged custody rows carry seven test-only licences: one held-leaf race
# hook and six functions that construct, bound-read, count, and adversarially
# alter their private disk fixtures (overlay_store/unmerged.rs and
# overlay_store/tests/unmerged.rs). None reaches production code. All client
# sites outside the shared writable support total 184 + 7 = 191.
# The shared writable support carries eighteen site licences: four for its
# plain publication scratch and pinned fusectl descriptor, six for Paths and
# signing-key custody, two for publication inputs, two for the generated seed,
# three for retained journal/staging/ownership evidence, and one positive
# fixture control. Thus 191 + 18 = 209.
# The support-bundle refusal classification test (overlay_store/tests/bundle.rs)
# carries two: its source walk and the test that reads every scanned file, so
# an unclassified overlay refusal literal fails the build. 209 + 2 = 211.
# Private-archive publication adds four narrow licences: the production
# no-replace link and owned unlink, plus one fixture licence in each of its
# walk and publish test modules. Thus 211 + 4 = 215.
# Its mountpoint proof is count-neutral: it routes the path through the existing
# no-follow descriptor walk and reads metadata only from the held descriptors,
# so it adds no bare filesystem call that requires a fifth licence.
# The ignored Q3 client child carries one whole-module test licence for its
# private handoff, narrow licences for guarded root create-or-open and its scratch
# control, plus process-id, monotonic-stopwatch and wall-clock licences so a
# scheduled intent retry comes due. Thus 215 + 6 = 221.
# Discard fixtures license scratch path resolution, snapshots, rebinding and
# crash restore, plus Linux mode and three post-preflight destination plants.
# The mount-level discard and reconcile rows license resolving the fixture's
# store to its physical path, which the discard selection binds.
# Thus 229 + 1 = 230.
# The recover refusal-report row licenses reading its fixture archive and
# changing its mode, in the row and in the event layer that unprotects it
# after durable completion. Thus 230 + 2 = 232.
# The power-loss rows license one fixture: it writes the simulator's durable
# overlay tree onto the test-owned scratch store before the offline discard
# reads it. Thus 232 + 1 = 233.
EXPECTED_LICENSED_SITES=233
# The CLI licences cover protected input/path comparisons, owned test fixtures,
# logging setup, control runtime namespace observation, and the endpoint's
# checked directory creation, lock open and inode-owned cleanup. The recovery
# guide fixture carries one whole-module test licence for its owned scratch tree.
# `support_bundle/tests.rs` adds one whole-module test licence for filesystem
# operations confined to its owned scratch tree. It reuses `tests.rs`'s
# `ScratchDir`, so the pid used for cross-process uniqueness remains under that
# helper's existing narrow ambient-input licence rather than this filesystem
# licence. This raises the CLI source count from 47 to 48.
# The metrics exporter adds one licence for the nonblocking open of its public
# TLS certificate. The read uses that same descriptor after checking its type.
# Its tests add one file-scoped licence for custody fixtures in their owned
# scratch directory. These two licences raise the CLI source count to 50.
# Each production site states its custody rule; test licences cover only their
# owned fixtures.
EXPECTED_CLI_LICENSED_SITES=50

# THE LICENSED-SITE SCAN, AS A TABLE — one row per crate, `|`-separated:
#
#   <crate-dir>|<src-root>|<expected src/ licensed-site count>
#
# Keep one row for each crate, including `granary-client` and `granary-cli`,
# with each row supplied by that crate's own directory, source-root and
# expected-count constants. AUDITED_CLOSURE_CRATES below follows the same
# per-crate arrangement. The three fields have different scopes:
# the crate directory is the kill switch's whole-crate scope,
# the source root is the COUNT's narrower scope, and the client's count is
# `EXPECTED_LICENSED_SITES`, whose name carries no crate and whose value
# is a bare integer. A search for the client's path or package name
# therefore cannot discover that count constant.
#
# THE COUNT IS PER-CRATE AND MUST STAY PER-CRATE. It splits
# 208 client / 46 cli, with a workspace total of 254. An
# implementation that compared a SUM would accept a wrong split. One
# `report_count` call per row, never one over the total.
#
# The scalars MUST APPEAR AS A ROW — the self-test builds its fixtures
# from them (31 of CRATE_SRC's 38 references are in there), so a drift
# between the two would have the controls exercising a crate the gate does
# not scan. Control D13c asserts it, by SEARCHING the table rather than
# pinning an index: which row the client occupies is a formatting choice,
# and W2f's own awk injects a scratch row above it.
LICENSED_SITE_CRATES=(
  "$CRATE_DIR|$CRATE_SRC|$EXPECTED_LICENSED_SITES"
  "$CLI_CRATE_DIR|$CLI_SRC|$EXPECTED_CLI_LICENSED_SITES"
)

# The normative fs-ban list — must equal EXACTLY the "route filesystem
# access through fsguard..." rows in $CLIENT_CLIPPY, PATH AND REASON, no
# more, no fewer. Every row shares one reason string; if a future edit
# gives any fs row a DIFFERENT reason, this becomes a per-row reason map
# instead of one shared constant. Keep this array and the clippy.toml
# rows in lockstep on any change to either — the anchoring check below
# compares them BOTH directions, so a row added to one file alone fails
# the gate.
FS_ROW_REASON="route filesystem access through fsguard, or license the site with #[expect] and a written reason"
FS_ROWS=(
  "std::fs::create_dir_all"
  "std::fs::create_dir"
  "std::fs::exists"
  "std::fs::metadata"
  "std::fs::remove_file"
  "std::fs::remove_dir"
  "std::fs::remove_dir_all"
  "std::fs::rename"
  "std::fs::set_permissions"
  "std::fs::write"
  "std::fs::read"
  "std::fs::read_to_string"
  "std::fs::read_dir"
  "std::fs::canonicalize"
  "std::fs::hard_link"
  "std::fs::read_link"
  "std::fs::copy"
  "std::fs::File::open"
  "std::fs::File::create"
  "std::fs::File::create_new"
  "std::fs::File::options"
  "std::fs::OpenOptions::new"
  "std::fs::OpenOptions::open"
  "std::fs::DirBuilder::new"
  "std::fs::DirBuilder::create"
  "std::fs::soft_link"
  "std::path::Path::exists"
  "std::path::Path::try_exists"
  "std::path::Path::is_file"
  "std::path::Path::is_dir"
  "std::path::Path::metadata"
  "std::path::Path::canonicalize"
  "std::path::Path::read_dir"
  "std::path::Path::read_link"
  "std::os::unix::fs::symlink"
  "std::os::unix::fs::chown"
  "std::env::set_current_dir"
  "tokio::fs::read"
  "tokio::fs::read_to_string"
  "tokio::fs::write"
  "tokio::fs::create_dir"
  "tokio::fs::create_dir_all"
  "tokio::fs::remove_file"
  "tokio::fs::remove_dir"
  "tokio::fs::remove_dir_all"
  "tokio::fs::rename"
  "tokio::fs::copy"
  "tokio::fs::hard_link"
  "tokio::fs::symlink"
  "tokio::fs::metadata"
  "tokio::fs::canonicalize"
  "tokio::fs::read_dir"
  "tokio::fs::read_link"
  "tokio::fs::set_permissions"
  "tokio::fs::try_exists"
  "tokio::fs::File::open"
  "tokio::fs::File::create"
  "tokio::fs::File::create_new"
  "tokio::fs::File::options"
  "tokio::fs::OpenOptions::new"
  "tokio::fs::OpenOptions::open"
  "tokio::fs::DirBuilder::new"
  "tokio::fs::DirBuilder::create"
)

# ------------------------------------------------------------- checks 1+2
# One python3/tomllib invocation does both the whole-config
# superset/equality check and the fs-row anchoring check, against
# whatever root/client paths it is given — the self-test points this at
# mutated copies. Row multisets (`collections.Counter`), not sets — a
# duplicated row passes a set comparison silently. A row missing
# `path` or `reason` is validated explicitly and
# reported as a clean error (exit 2), never a raw `KeyError` traceback.
# A tripped `assert` inside the self-test's own fixture mutation (a
# malformed fixture, not a real check failure) prints a clear
# diagnostic and exits 3, distinct from both.
# A THIRD argument overrides the normative fs-row list with a file of
# paths, one per line. Only the self-test passes it, and only to prove
# that a mutation of the EXPECTED side is caught too — the gate itself
# always uses the FS_ROWS array below it.
check_config() {
  local root="$1" client="$2" rows_override="${3:-}"
  local fs_rows_file
  fs_rows_file="$(mktemp)"
  trap 'rm -f "$fs_rows_file"' RETURN
  if [[ -n "$rows_override" ]]; then
    cat "$rows_override" > "$fs_rows_file"
  else
    printf '%s\n' "${FS_ROWS[@]}" > "$fs_rows_file"
  fi
  python3 - "$root" "$client" "$fs_rows_file" "$FS_ROW_REASON" <<'PYEOF'
import sys

# `tomllib` is stdlib only from PYTHON 3.11. On anything older the
# import raises `ModuleNotFoundError`, which is a traceback and a
# nonzero exit — the gate would fail, but with a message that reads like
# a broken script rather than a missing prerequisite. Named explicitly,
# BEFORE the import, and with the same exit 2 the other MALFORMED/
# environment refusals use. (The self-hosted CI runners' python version
# is not pinned anywhere, so this is the one place the requirement is
# stated as an executable check rather than an assumption.)
if sys.version_info < (3, 11):
    print(
        "HARNESS: this gate parses TOML with `tomllib`, which needs python 3.11 or newer "
        f"(found {sys.version_info.major}.{sys.version_info.minor}). Install a newer python3, "
        "or run the gate on a host that has one.",
        file=sys.stderr,
    )
    sys.exit(2)

import tomllib  # noqa: E402 — deliberately after the version guard above
from collections import Counter  # noqa: E402

root_path, client_path, fs_rows_path, fs_reason = sys.argv[1:5]

try:
    with open(root_path, "rb") as f:
        root = tomllib.load(f)
    with open(client_path, "rb") as f:
        client = tomllib.load(f)
    with open(fs_rows_path, encoding="utf-8") as f:
        # A COUNTER, not a set. The set silently collapsed a path
        # duplicated in FS_ROWS itself, so the gate's own normative list
        # could hold the same row twice and still match a client config
        # holding it once — duplicate detection only ever worked on the
        # CLIENT side. Both sides are multisets now.
        fs_paths = Counter(line.strip() for line in f if line.strip())
except Exception as e:  # noqa: BLE001 — this IS the top-level harness boundary
    print(f"HARNESS: could not read one of the config files: {e}", file=sys.stderr)
    sys.exit(3)

# A TUPLE, not a set: the iteration below decides which malformed row is
# reported FIRST, and a set's order is a hash artefact — the same broken
# file could name a different key on a different run or a different
# python, which is not a property a gate's output may have.
ROW_KEYS = ("disallowed-methods", "disallowed-macros", "disallowed-types")


def row_key(row, source):
    """The row's FULL canonical form — every field, not just (path,
    reason) — as a sorted, hashable tuple of (field, value) pairs.
    EVERY field, because a (path, reason)-only comparison silently drops
    the others: flipping `allow-invalid = true` off a real client row
    changes what clippy does and would otherwise compare equal.
    Graceful exit(2), never a raw KeyError traceback, for a row missing
    'path' or 'reason'; any other field (only `allow-invalid` exists
    today) is optional and carried through as-is.

    The canonical form must also be HASHABLE — every caller feeds it to
    a `Counter`. A row whose field holds a TOML array or inline table
    (`allow-invalid = [1]`) yields a tuple containing a list, and the
    `Counter` construction then raises a raw
    `TypeError: unhashable type` traceback out of the gate — the same
    ungraceful exit the missing-key case is routed away from.
    Routed through the SAME MALFORMED exit-2 path, by attempting the
    hash here where the row can still be named."""
    if not isinstance(row, dict) or "path" not in row or "reason" not in row:
        print(
            f"MALFORMED: a row in {source} is missing 'path' and/or 'reason': {row!r}",
            file=sys.stderr,
        )
        sys.exit(2)
    key = tuple(sorted(row.items()))
    try:
        hash(key)
    except TypeError:
        print(
            f"MALFORMED: a row in {source} has a non-scalar field value (a TOML array or "
            f"inline table); every field of a ban row must be a scalar: {row!r}",
            file=sys.stderr,
        )
        sys.exit(2)
    return key


def row_path(row_tuple):
    """Recover just the 'path' field from a row_key() tuple, for error
    messages that only want to name the row, not dump every field."""
    return dict(row_tuple)["path"]


# A shared key's TYPE must agree between the two files, checked BEFORE
# anything iterates it. Without this, a client `disallowed-types = "x"`
# — a STRING where the root has a list — turns the superset loop's
# `row not in client_list` into a SUBSTRING test, which passes for
# reasons that have nothing to do with the rows; an integer raises a
# bare `TypeError` traceback out of the gate; and a ROW_KEYS string is
# iterated one CHARACTER at a time and reported as a row missing its
# 'path'. None of those is a refusal a reader can act on. Both
# directions, and the type actually found is named.
for key in sorted(set(root) & set(client)):
    if isinstance(root[key], list) != isinstance(client[key], list):
        print(
            f"MALFORMED: top-level key {key!r} is a {type(root[key]).__name__} in "
            f"{root_path} but a {type(client[key]).__name__} in {client_path}. The two "
            "files must agree on a key's shape before any comparison of its contents "
            "means anything.",
            file=sys.stderr,
        )
        sys.exit(2)

for key in ROW_KEYS:
    for row in root.get(key, []):
        row_key(row, f"root {key}")
    for row in client.get(key, []):
        row_key(row, f"client {key}")

errors = []

EXACT_LIST_KEYS = {"disallowed-macros", "disallowed-types"}

# ---- check 1: whole-config superset/equality ----
client_keys = set(client.keys())
root_keys = set(root.keys())
for key in sorted(root_keys - client_keys):
    errors.append(f"SUPERSET: root top-level key {key!r} is absent from the client config")
for key in sorted(client_keys - root_keys):
    errors.append(f"SUPERSET: client has an unexpected extra top-level key {key!r}")

for key, value in root.items():
    if key not in client:
        continue  # already reported above
    if key in ROW_KEYS:
        client_list = client[key]
        client_counter = Counter(row_key(r, f"client {key}") for r in client_list)
        if key in EXACT_LIST_KEYS:
            root_counter = Counter(row_key(r, f"root {key}") for r in value)
            if client_counter != root_counter:
                missing = root_counter - client_counter
                extra = client_counter - root_counter
                for row_tuple, n in sorted(missing.items()):
                    errors.append(
                        f"SUPERSET: {key} row from root missing in client (x{n}): "
                        f"{row_path(row_tuple)!r}"
                    )
                for row_tuple, n in sorted(extra.items()):
                    errors.append(
                        f"SUPERSET: {key} has a client-only or duplicated row with no root "
                        f"counterpart, or a real row with a field EDITED (no sanctioned edit "
                        f"touches {key}, x{n} extra): {row_path(row_tuple)!r}"
                    )
        else:
            # disallowed-methods: superset only here — check 2 pins the
            # exact multiset including the audited fs-row extras.
            for row in value:
                k = row_key(row, f"root {key}")
                if client_counter[k] < 1:
                    errors.append(
                        f"SUPERSET: {key} row from root missing in client: {row_path(k)!r}"
                    )
    elif isinstance(value, list):
        client_list = client[key]
        for row in value:
            if row not in client_list:
                errors.append(f"SUPERSET: {key} row from root missing in client: {row!r}")
    else:
        if client[key] != value:
            errors.append(
                f"SUPERSET: scalar key {key!r} differs — root={value!r} client={client[key]!r}"
            )

# ---- check 2: fs-row anchoring (disallowed-methods only, FULL rows, multiset) ----
root_methods = Counter(row_key(r, "root disallowed-methods") for r in root.get("disallowed-methods", []))
client_methods = Counter(row_key(r, "client disallowed-methods") for r in client.get("disallowed-methods", []))
# Built in the SAME canonical form row_key() produces (sorted field-value
# pairs), not a plain (path, reason) 2-tuple — otherwise this Counter
# would never equal root_methods/client_methods's keys at all, since
# those carry every field.
expected_fs = Counter()
for p, n in fs_paths.items():
    expected_fs[row_key({"path": p, "reason": fs_reason}, "fs-row data")] += n
expected_methods = root_methods + expected_fs

if client_methods != expected_methods:
    missing = expected_methods - client_methods
    extra = client_methods - expected_methods
    for row_tuple, n in sorted(missing.items()):
        errors.append(
            f"ANCHOR: expected disallowed-methods row missing from client (x{n}): "
            f"{row_path(row_tuple)!r} (full row: {dict(row_tuple)!r})"
        )
    for row_tuple, n in sorted(extra.items()):
        errors.append(
            f"ANCHOR: client disallowed-methods row not accounted for by root+fs-rows "
            f"(x{n} more than expected): {row_path(row_tuple)!r} (full row: {dict(row_tuple)!r})"
        )

if errors:
    for e in errors:
        print(e, file=sys.stderr)
    sys.exit(1)
PYEOF
}

# ------------------------------------------------------------- check 5
# The LEVEL check. Takes the manifest path and then EVERY cargo-config
# path to read (or the single literal "none"), so the self-test can
# point it at COPIES the way check_config does. Cargo reads both the
# `.cargo/config.toml` spelling and the legacy extensionless
# `.cargo/config` — it warns when both exist and prefers the `.toml` —
# so the caller passes whichever are present and this program refuses
# findings in ANY of them, naming the file. Same python3/tomllib program
# shape as check_config: a version guard first, a HARNESS exit 3 for a
# file it cannot read, and every finding collected into one list so a
# run names everything wrong at once rather than the first thing.
# check_lint_level <mode> <manifest> <cargo-config...|none>
#
# mode = primary   the audited crate's own manifest: the [lints] table
#                  MUST exist, MUST set disallowed_methods to deny, and
#                  MUST carry the two MUST-1 keys. Absence is a finding,
#                  because this is the file that decides the level.
# mode = secondary a manifest cargo also clippys — the four fuzz
#                  WORKSPACES. Each is its own workspace with its own
#                  lockfile, and the client's is governed by the same
#                  nested clippy.toml, so a [lints.clippy] table added to
#                  one of them switches the ban off for code CI really
#                  compiles. None of the three has such a table today,
#                  and clippy's default warn plus the lanes'
#                  CARGO_BUILD_WARNINGS=deny is what makes the ban bite
#                  there — so ABSENCE is the sanctioned state and only a
#                  table that WEAKENS the ban is refused.
check_lint_level() {
  local mode="$1" manifest="$2"
  shift 2
  python3 - "$mode" "$manifest" "$@" <<'PYEOF'
import sys

# Same prerequisite, same refusal, as check_config's program: `tomllib`
# is stdlib only from PYTHON 3.11, and a missing prerequisite must read
# as one rather than as a broken script.
if sys.version_info < (3, 11):
    print(
        "HARNESS: this gate parses TOML with `tomllib`, which needs python 3.11 or newer "
        f"(found {sys.version_info.major}.{sys.version_info.minor}). Install a newer python3, "
        "or run the gate on a host that has one.",
        file=sys.stderr,
    )
    sys.exit(2)

import tomllib  # noqa: E402 — deliberately after the version guard above

mode = sys.argv[1]
manifest_path = sys.argv[2]
cargo_config_paths = [p for p in sys.argv[3:] if p != "none"]
if mode not in ("primary", "secondary"):
    print(f"HARNESS: unknown mode {mode!r}", file=sys.stderr)
    sys.exit(3)
required = mode == "primary"


# CARGO TREATS `-` AND `_` IN A CONFIG KEY AS THE SAME KEY. `rustc_wrapper`
# and `rustc-wrapper` are one setting to cargo and two different strings
# to a `key in table` test, so a checked-in `[build] rustc_wrapper = "x"`
# is honoured by every build while a gate matching only the dash form
# reports the file clean. rustc normalises lint names the same way, so
# `[lints.clippy] disallowed-methods = "allow"` is a real `-A
# clippy::disallowed-methods` beside a `disallowed_methods = "deny"` the
# gate reads and approves.
#
# So every key this check matches is normalised FIRST, and both
# spellings are kept: `spellings()` returns EVERY raw key that
# normalises to the one asked for, and the rules below run over all of
# them. Collapsing to one would silently drop the second — which is the
# hole, one layer in.
def norm_key(k):
    return k.replace("-", "_")


def spellings(table, key):
    """Every (raw_key, value) in `table` whose key normalises to `key`."""
    if not isinstance(table, dict):
        return []
    want = norm_key(key)
    return [(k, v) for k, v in table.items() if norm_key(k) == want]


def has_key(table, key):
    return bool(spellings(table, key))


def get_table(table, key):
    """The first value under any spelling of `key`, or None."""
    got = spellings(table, key)
    return got[0][1] if got else None

try:
    with open(manifest_path, "rb") as f:
        manifest = tomllib.load(f)
except Exception as e:  # noqa: BLE001 — this IS the top-level harness boundary
    print(f"HARNESS: could not read {manifest_path}: {e}", file=sys.stderr)
    sys.exit(3)

cargo_configs = []
for cargo_config_path in cargo_config_paths:
    try:
        with open(cargo_config_path, "rb") as f:
            cargo_configs.append((cargo_config_path, tomllib.load(f)))
    except Exception as e:  # noqa: BLE001 — same boundary
        # NOT treated as "no cargo config": the caller said this file is
        # there, so failing to read it is a refusal, never a pass.
        print(f"HARNESS: could not read {cargo_config_path}: {e}", file=sys.stderr)
        sys.exit(3)

# Say what was read. "No cargo config at all" and "a config that was
# read and had nothing in it" are different states, and a check that
# prints neither cannot be told apart from one that silently skipped
# the file.
print("CONFIGS-READ: " + (", ".join(cargo_config_paths) if cargo_config_paths else "(none)"))
# The manifest this run actually validated, named by the program that
# validated it. The gate quotes it, so the name in the summary is
# produced BY the check rather than beside it: a loop that stopped
# calling check_lint_level would keep printing manifest names from its
# own bookkeeping and prove nothing.
print(f"MANIFEST-VALIDATED: {manifest_path}")

errors = []

# ---- the crate's own lint table ----
def resolve_level(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return get_table(value, "level")
    return None


lints = get_table(manifest, "lints")
clippy = {}
have_clippy_table = False
if not isinstance(lints, dict):
    if required:
        errors.append(
            f"LEVEL: {manifest_path} has no [lints] table. This crate carries its own lint table "
            "by design — it diverges from the workspace on `unsafe_code` — and a crate without one "
            "is not the crate this gate audits."
        )
elif has_key(lints, "workspace"):
    errors.append(
        f"LEVEL: {manifest_path}'s [lints] is the inherited form "
        f"(workspace = {str(get_table(lints, 'workspace')).lower()}). The ban's level then lives "
        "in a [workspace.lints] table this gate does not read, so the level it audits and the "
        "level cargo applies are two different things."
    )
else:
    table = get_table(lints, "clippy")
    if isinstance(table, dict):
        clippy = table
        have_clippy_table = True
    elif required:
        errors.append(
            f"LEVEL: {manifest_path} has no [lints.clippy] table, so nothing in it sets the "
            "level of the filesystem ban."
        )

KEY = "disallowed_methods"
# EVERY spelling, not the first one found: `disallowed-methods` and
# `disallowed_methods` are one lint to rustc and two keys to a dict, so a
# manifest can carry a `deny` this gate reads and an `allow` cargo emits
# after it.
if has_key(clippy, KEY):
    for raw_key, value in spellings(clippy, KEY):
        level = resolve_level(value)
        if level != "deny":
            errors.append(
                f"LEVEL: lints.clippy.{raw_key} in {manifest_path} resolves to level {level!r} "
                f"(the value found is {value!r}); it must be `deny`. Anything weaker switches the "
                "whole filesystem ban off for the whole crate in one line, and `forbid` is not "
                "stronger here — it refuses every licensed #[expect] site instead of honouring it."
            )
elif have_clippy_table and required:
    # Only when a real [lints.clippy] table was found — otherwise the
    # refusal above already names the bigger problem, and a second line
    # saying the key is missing from a table that is missing is noise.
    errors.append(
        f"LEVEL: lints.clippy.{KEY} is ABSENT from {manifest_path}. clippy's own default for "
        "it is `warn`, so a bare filesystem call would only warn under a local `cargo clippy` "
        "run without CARGO_BUILD_WARNINGS=deny — advice, not a ban."
    )

# docs/coding-standards.md MUST-1 moved OFF the two crate-root
# attributes and into this table, because a crate-root attribute covers
# only its own target: `lib.rs` plus `main.rs` left the eight
# `tests/*.rs` integration crates — and any bench, example or build
# script added later — with nothing refusing a bare `#[allow]` or a
# reasonless `#[expect]`. A [lints] table covers every target at once,
# which is what makes it worth anchoring here: the move is one line
# from being undone, in a file whose other lines this check already
# reads.
# `forbid` is accepted HERE and refused for `disallowed_methods`, and
# the asymmetry is the point rather than an inconsistency. There is no
# legitimate `#[expect(clippy::allow_attributes)]` anywhere in this
# crate, so forbidding those two is strictly stronger: it also refuses
# an inner `#![allow]` that would otherwise undo them. `forbid` on
# `disallowed_methods` would refuse every licensed `#[expect]` site in
# the CRATE instead of honouring them — more than the src/-only count
# EXPECTED_LICENSED_SITES pins, because this table's level reaches
# tests/ and fuzz/ as well. Not a stronger ban but a broken build.
for must1 in ("allow_attributes", "allow_attributes_without_reason"):
    if has_key(clippy, must1):
        for raw_key, value in spellings(clippy, must1):
            level = resolve_level(value)
            if level not in ("deny", "forbid"):
                errors.append(
                    f"LEVEL: lints.clippy.{raw_key} in {manifest_path} resolves to level {level!r} "
                    f"(the value found is {value!r}); it must be `deny` or `forbid` (`forbid` is "
                    "strictly stronger here — there is no legitimate #[expect] of it in this "
                    "crate, so nothing is refused that should be honoured). It is what enforces "
                    "docs/coding-standards.md MUST-1 (every suppression is an #[expect] with a "
                    "reason) across EVERY target of the crate, tests/ included."
                )
    elif have_clippy_table and required:
        errors.append(
            f"LEVEL: lints.clippy.{must1} is ABSENT from {manifest_path}. Without it a bare "
            "#[allow] — or a reasonless #[expect] — compiles silently in this crate's "
            "tests/, benches and examples, which no crate-root attribute covers."
        )

# `all` and `style` are the two lint GROUPS that contain
# `disallowed_methods`. Whether a group key beats the specific `deny`
# beside it comes down to which flag cargo emits LAST, and for two keys
# of the SAME priority cargo does not specify that order. Measured on
# the pinned toolchain, against a bare `std::fs::create_dir_all` call:
#   all   = "allow"                          -> ban SILENCED (emitted last)
#   all   = { level = "allow", priority=-1 } -> ban still fires
#   style = "allow"                          -> ban still fires
#   style = { level = "allow", priority= 1 } -> ban SILENCED (emitted last)
# Two of the four switch the ban off, and which two is not a property
# of the level — it is a property of an order nothing promises and a
# cargo bump may reshuffle. So the KEY is refused wherever it appears,
# at any level, rather than judged by the level it carries. Neither is
# present today; a future need for one is a deliberate edit of this
# gate, with a reason.
for group in ("all", "style"):
    for raw_key, value in spellings(clippy, group):
        errors.append(
            f"LEVEL: lints.clippy.{raw_key} is set to {value!r} in {manifest_path}. "
            f"`{group}` is a lint GROUP that CONTAINS {KEY}, so its level governs the "
            "filesystem ban without ever naming it — refused at ANY level."
        )

# `restriction` is the third group with a say here, and it reaches the
# OTHER two keys this check anchors: `allow_attributes` and
# `allow_attributes_without_reason` are both `clippy::restriction`
# lints, so `restriction = { level = "allow", priority = 1 }` under
# [lints.clippy] overrides both manifest denies while they still READ
# `"deny"` two lines above it. Refused at ANY level, for the same reason
# `all` and `style` are: which of two same-priority keys cargo emits
# last is not specified, so the level is not what decides the effect.
for raw_key, value in spellings(clippy, "restriction"):
    errors.append(
        f"LEVEL: lints.clippy.{raw_key} is set to {value!r} in "
        f"{manifest_path}. `restriction` is the lint GROUP that contains "
        "`allow_attributes` and `allow_attributes_without_reason`, so its level governs "
        "docs/coding-standards.md MUST-1 without ever naming either key — refused at ANY "
        "level."
    )

# ---- the checked-in cargo config ----
def rustflags_elements(table, label):
    """Every rustflags element in `table`, tagged with where it came
    from. Cargo accepts BOTH a list and a whitespace-separated string
    for this key, and splits the string itself — a check that only
    understood the list form would read the string form as no flags at
    all, which is the pass-without-the-property shape this whole gate
    exists to refuse."""
    flags = get_table(table, "rustflags")
    if flags is None:
        return []
    if isinstance(flags, str):
        return [(label, part) for part in flags.split()]
    if isinstance(flags, list):
        return [(label, str(part)) for part in flags]
    return [(label, str(flags))]


# Every rustflag that sets or caps a lint LEVEL, other than the two that
# can only make the ban STRONGER. `cap-lints` was the only one refused
# before, and it was never the only way through: rustc takes the LAST
# level given for a lint, and a config's rustflags come AFTER the flags
# cargo derives from the manifest's [lints] table — so `-A
# clippy::disallowed_methods`, `-Aclippy::all` and `-Wclippy::all` all
# demote or silence the ban from a checked-in file, and `--force-warn`
# overrides attributes and every other CLI level besides. `-D`/`-F`
# (`--deny`/`--forbid`) are left alone: they cannot weaken anything. So
# are non-lint flags — the real file's `-C target-feature=+crt-static`
# is the positive control for that half.
LEVEL_FLAG_HEADS = ("--force-warn", "--cap-lints", "--allow", "--warn")

# The SHORT head each long spelling is: rustc takes `--allow foo` and
# `-A foo` as the same flag, and the split forms (`--allow` with the
# lint in the NEXT element) reach the compiler identically. The check
# below matched `-A`/`-W` as bare elements and the long forms only when
# they carried `=`, so `rustflags = ["--allow", "clippy::disallowed_methods"]`
# — the split long spelling — named a lint level nothing here saw.
LONG_TO_SHORT = {"--allow": "-A", "--warn": "-W"}


def lint_level_flag(element):
    """The lint-LEVEL flag `element` carries, or None. Handles the
    joined (`-Afoo`, `--allow=foo`) and split (`-A` as its own element,
    with the lint following) spellings alike — a split flag is refused
    on its own element, so the lint name never has to be parsed.

    A RESPONSE FILE is refused whatever it contains. `@file` tells rustc
    to read its arguments from that file, so `rustflags = ["@fsguard.rsp"]`
    with `--force-warn=clippy::disallowed-methods` inside it carries a
    lint level that no element here LOOKS like. This check cannot follow
    the indirection — the file may not exist at gate time, may be
    generated, may be outside the repo — so the indirection itself is
    the finding.

    A `-Z` FLAG is refused for the same class of reason. `-Z` is rustc's
    unstable-options door, and `-Zcrate-attr=allow(clippy::all)` injects
    an inner attribute into EVERY crate root the flag reaches — a
    file-scoped suppression that appears in no source file this gate
    scans and in no lint table it reads. `-Zcrate-attr` is only the
    sharpest of them; the whole namespace is unstable by definition, so
    the head is refused rather than any list of its options."""
    e = element.strip()
    if not e:
        return None
    head = e.split(None, 1)[0]
    if head.startswith("@"):
        return "@ (a rustc response file)"
    for flag in LEVEL_FLAG_HEADS:
        if head == flag or head.startswith(flag + "="):
            # Reported as the SHORT head where one exists, so the two
            # spellings of one flag read as one finding rather than two
            # unrelated ones.
            return LONG_TO_SHORT.get(flag, flag)
    if head in ("-A", "-W"):
        return head
    if len(head) > 2 and head[:2] in ("-A", "-W"):
        return head[:2]
    # `-Z`, joined (`-Zcrate-attr=…`) or split (`-Z` with the option
    # following). Refused as a head, so the option name never has to be
    # enumerated.
    if head == "-Z" or head.startswith("-Z"):
        return "-Z (rustc unstable options — -Zcrate-attr injects a crate-root #![allow])"
    if "cap-lints" in e:
        # `-Ccap-lints=allow` and `-C cap-lints=allow`, the packed
        # spellings of the same cap.
        return "cap-lints"
    return None


# A checked-in `[env]` table is cargo's own way of setting environment
# variables for every build in the workspace, and each key here decides
# what the lint level ends up being.
#
# WHICH OF THEM ACTUALLY REACH THE COMPILER, stated exactly rather than
# implied by the list: `[env]` applies to the processes cargo SPAWNS,
# and cargo reads RUSTFLAGS / CARGO_ENCODED_RUSTFLAGS /
# CARGO_BUILD_RUSTFLAGS / CARGO_BUILD_WARNINGS from its OWN environment,
# which `[env]` does not set. Refusing those four is fail-closed
# belt-and-braces — cheap, and it costs nothing if cargo's precedence
# ever changes. The ones that genuinely land on the tool are
# CLIPPY_CONF_DIR (clippy-driver reads it to find its config),
# CLIPPY_ARGS (cargo-clippy passes it through to every driver
# invocation), and the three RUSTC selectors below.
#
# RUSTC / RUSTC_WRAPPER / RUSTC_WORKSPACE_WRAPPER are the sharpest of
# them: `cargo clippy` works by setting RUSTC_WORKSPACE_WRAPPER to
# `clippy-driver` itself, so a checked-in value for it REPLACES the
# driver and turns the whole clippy lane into a plain `cargo check` —
# every lint gone, exit 0, nothing said.
# RUSTC_BOOTSTRAP is the last of them, and the one that makes `-Z`
# reachable at all: a stable toolchain refuses unstable options, and
# `RUSTC_BOOTSTRAP=1` turns them on. A checked-in value for it is the
# other half of the `-Z` refusal above — either alone is enough to
# refuse, and both are needed for the attack to work.
ENV_KEYS = (
    "RUSTC_BOOTSTRAP",
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_WARNINGS",
    "CLIPPY_ARGS",
    "CLIPPY_CONF_DIR",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
)

# The `[build]` spellings of the same three selectors. Cargo reads these
# from the config file itself, so unlike four of the [env] keys above
# they reach the compiler with certainty.
BUILD_COMPILER_KEYS = ("rustc", "rustc-wrapper", "rustc-workspace-wrapper")

for cargo_config_path, cargo_config in cargo_configs:
    elements = []
    build = get_table(cargo_config, "build")
    if isinstance(build, dict):
        for raw_key, _ in spellings(build, "rustflags"):
            elements.extend(rustflags_elements({raw_key: build[raw_key]}, f"build.{raw_key}"))
        for raw_key, value in spellings(build, "warnings"):
            if value == "allow":
                errors.append(
                    f"LEVEL: build.{raw_key} is set to 'allow' in {cargo_config_path}. The clippy "
                    "lane's teeth are CARGO_BUILD_WARNINGS=deny; a checked-in file that answers "
                    "'allow' takes them out for every developer and every lane that does not "
                    "override it."
                )
        for build_key in BUILD_COMPILER_KEYS:
            for raw_key, value in spellings(build, build_key):
                errors.append(
                    f"LEVEL: build.{raw_key} is set to {value!r} in "
                    f"{cargo_config_path}. It selects the compiler every build in this "
                    "workspace runs — and `cargo clippy` IS a wrapper selection "
                    "(RUSTC_WORKSPACE_WRAPPER = clippy-driver), so a checked-in value here "
                    "can turn the clippy lane into a plain `cargo check`: no lints, exit 0, "
                    "nothing said. Refused at any value."
                )
    # `[alias]` can redefine `clippy` itself. `cargo clippy` is an
    # EXTERNAL subcommand, and cargo resolves aliases BEFORE looking for
    # one, so `[alias] clippy = ["clippy", "--", "-A",
    # "clippy::disallowed_methods"]` is honoured by every `cargo clippy`
    # in CI and in local-gates — including the ones that gate this very
    # repo. The repo has no `[alias]` table at all, so refusing the key
    # outright costs nothing and needs no judgement about a value.
    alias = get_table(cargo_config, "alias")
    if isinstance(alias, dict):
        for alias_name, alias_value in alias.items():
            errors.append(
                f"LEVEL: [alias] {alias_name} = {alias_value!r} in {cargo_config_path}. A "
                "checked-in alias redefines what a cargo subcommand DOES for every developer "
                "and every lane — `clippy` included, since it is an external subcommand and "
                "aliases are resolved first. This repo has no [alias] table; any entry is "
                "refused."
            )
    target = get_table(cargo_config, "target")
    if isinstance(target, dict):
        for name, sub_table in target.items():
            if isinstance(sub_table, dict):
                for raw_key, _ in spellings(sub_table, "rustflags"):
                    elements.extend(
                        rustflags_elements(
                            {raw_key: sub_table[raw_key]}, f"target.{name}.{raw_key}"
                        )
                    )
    for label, element in elements:
        flag = lint_level_flag(element)
        if flag is not None:
            errors.append(
                f"LEVEL: {label} in {cargo_config_path} carries {element!r} — the lint-level "
                f"flag `{flag}`. Config rustflags come AFTER the flags cargo derives from the "
                "manifest's [lints] table and rustc takes the LAST level for a lint, so a "
                "checked-in one silences or demotes the filesystem ban whatever the manifest "
                "says. Only `-D`/`-F` and non-lint flags belong here."
            )
    env = get_table(cargo_config, "env")
    if isinstance(env, dict):
        for env_key in ENV_KEYS:
            for raw_key, value in spellings(env, env_key):
                errors.append(
                    f"LEVEL: env.{raw_key} is set to {value!r} in {cargo_config_path}. "
                    "A checked-in [env] table applies to every build in the workspace, and "
                    "this key decides what the lint level ends up being — this gate cannot "
                    "evaluate what a value does, so any value is refused. A lint environment "
                    "belongs in [lints], where the checks above can read it."
                )

if errors:
    for e in errors:
        print(e, file=sys.stderr)
    sys.exit(1)
PYEOF
}

# ------------------------------------------------------------- check 8
# RESOLUTION. Full design and its evidence are in the header. Runs the
# crate's OWN `cargo clippy -p <crate> --lib --message-format=json` —
# NEVER `CLIPPY_CONF_DIR` (refused above, check 5b, as an evasion
# vector; a gate built on the thing it refuses is an own-goal) — reads
# BOTH the JSON stream and stderr for the config-loader's own
# `<path>` does not refer to a reachable <function|macro|type>`
# diagnostic (never a registered lint: `code.code` is `null`), and
# checks two directions against the SAME config file:
#   (a) DORMANCY — any row NOT marked `allow-invalid = true` that
#       clippy reports unresolvable, on the config AS IS.
#   (b) RE-ARM FALLING DUE — any row marked `allow-invalid = true`
#       whose path NOW resolves, checked by temporarily stripping
#       exactly that flag from the REAL tracked config file, rerunning
#       clippy, and restoring the original bytes — inverse edit, never
#       `git checkout --`, under RETURN *and* EXIT/INT/TERM traps (see
#       below) so a crash — or a signal — mid-run still restores it.
#
# COVERAGE, not just verdict. A row this check never actually reaches
# (its crate name absent from the tested crate's OWN dependency graph)
# is silently indistinguishable, by clippy's output alone, from a row
# that genuinely resolves — clippy warns on neither. `segment_in_tree`
# below is the independent oracle (`cargo
# tree`, captured WITHOUT a pipe so a
# failure — lock contention or an offline
# registry — is refused as a HARNESS
# finding rather than read as "absent").
# Both directions count CONSIDERED rows
# against EVALUATED rows that the tested
# crates actually reach. A direction that
# considers rows but evaluates none is
# refused outright. A crate choice that
# cannot see a row does not establish
# that it was checked and found clean.
# Rows deferred to a shared config need
# that config's own call to reach them.
#
# A SECOND, confirmatory crate (`second_crate`, `check_resolution`'s
# fourth argument) exists only for direction (b), only because ONE
# config here (`clippy.toml`) governs crates whose `rand` resolvability
# genuinely differs (see `ROOT_RESOLUTION_CRATE`'s own comment) — a row
# resolving under the PRIMARY crate is refused as RE-ARM unless the
# secondary crate reaches the same row and shows it is STILL needed
# there (still unresolved) or ALSO resolves there (see ADVISORY below).
# If the secondary crate cannot reach the row at all, this check falls
# back to the single-crate verdict — conservative, matching what this
# check has always done when no secondary crate is given.
#
# resolution_extract_unresolved <json-file> <out-file> <crate-pkg>
# Writes one unresolved path per line to <out-file>, reading a
# `cargo clippy --message-format=json` capture for the config-loader's
# `does not refer to a reachable` diagnostic. A bash FUNCTION, not a
# `< <(...)` process substitution some caller reads with `while read` —
# that swallows the producer's own exit status entirely (this file's
# own check_stray_configs names the identical fail-open for `find`), so
# a crash in the python below would read as "zero unresolved paths",
# the same shape as "nothing is dormant". The python's exit code IS
# Filter JSON compiler messages by `manifest_path`
# to the requested crate's Cargo.toml. Clippy
# also compiles dependencies and can replay
# their diagnostics; an unfiltered stream
# could attribute a dependency's unresolved-path
# message to the crate under test, even
# when that dependency uses a different
# config. The predicate below checks both
# the message shape and the manifest suffix.
resolution_extract_unresolved() {
  local json_file="$1" out_file="$2" crate="$3"
  python3 - "$json_file" "$crate" > "$out_file" <<'PYEOF'
import sys, json, re
pat = re.compile(r"^`([^`]+)` does not refer to a reachable (?:function|macro|type)$")
crate = sys.argv[2]
suffix = f"/crates/{crate}/Cargo.toml"
with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            m = json.loads(line)
        except json.JSONDecodeError:
            continue
        if m.get("reason") != "compiler-message":
            continue
        manifest = m.get("manifest_path") or ""
        if not manifest.endswith(suffix):
            continue
        text = (m.get("message") or {}).get("message") or ""
        mm = pat.match(text)
        if mm:
            print(mm.group(1))
PYEOF
}

# segment_in_tree <tree-text> <path>
# True if <path>'s leading `::`-segment (its crate name) appears in
# <tree-text> (a `cargo tree` capture — see its callers for how that
# text is produced and how a `cargo tree` FAILURE is refused before
# this is ever called, never folded into "absent"). `std`/`core`/
# `alloc` are never Cargo dependencies and are always linked, so they
# short-circuit true rather than reading as permanently absent.
# A path names the crate as Rust spells it (`aws_lc_rs`); `cargo tree`
# prints the PACKAGE name (`aws-lc-rs`). Either spelling of the segment
# matches, so a hyphenated package's rows are evaluated rather than
# counted as unreachable.
segment_in_tree() {
  local tree_text="$1" path="$2" seg
  seg="${path%%::*}"
  if [[ "$seg" == "std" || "$seg" == "core" || "$seg" == "alloc" ]]; then
    return 0
  fi
  grep -qE "^(${seg}|${seg//_/-}) v" <<<"$tree_text"
}

# check_config_identity <copy> <original>
# `crates/granary-cli/clippy.toml` MUST be a byte-identical copy of the
# client's config. The stray-config allow-list below is a bare
# `case ... continue` that compares no bytes, so allow-listing alone
# accepts a config by NAME even when its contents differ.
# This check enforces byte identity, which is a premise of the cli
# config's INHERITED resolution verdict; CLIENT_RESOLUTION_CRATE above
# explains the accompanying dependency-closure premise.
#
# BYTES, via `cmp` — deliberately NOT check_config's row-canonical
# comparison: even comment-only or whitespace divergence violates byte
# identity. A symlink or an absent file is refused BEFORE cmp:
# `cmp` on a symlink compares the TARGET, which is not the file this gate
# audited, and an absent file must never read as "identical to nothing".
check_config_identity() {
  local copy="$1" original="$2"
  # The same degenerate call check_closure_premise refuses: `cmp -s X X`
  # exits 0, so passing the same file twice reports the two configs'
  # byte-identity premise verified having compared a file to itself.
  if [[ -L "$copy" || -L "$original" ]]; then
    echo "IDENTITY: $copy or $original is a SYMLINK — refused; the bytes clippy loads are not the bytes compared" >&2
    return 1
  fi
  # ORDERED AFTER THE SYMLINK CHECK ON PURPOSE: a symlink to the original
  # IS the same inode, so `-ef` would fire first and report "same file"
  # for what is really the symlink case — the more specific diagnosis has
  # to come first or the symlink control can never see its own message.
  # `-ef` as well as a string compare: `./x` and `x`, a hard link, and an
  # `a/../a/x` spelling are all the SAME FILE, and cmp would compare it to
  # itself and exit 0 — the outcome this guard exists to prevent. The string
  # test stays because `-ef` cannot fire when the file is absent. Returns 2,
  # not 1: a mistyped call site is a HARNESS fault, the class
  # check_closure_premise already gives 2 to.
  if [[ "$copy" == "$original" ]] || [[ -e "$copy" && "$copy" -ef "$original" ]]; then
    echo "IDENTITY: check_config_identity called with the same file in both seats ($copy) — a file is identical to itself, so this proves nothing; refused rather than reporting the premise verified" >&2
    return 2
  fi
  if [[ ! -f "$copy" || ! -f "$original" ]]; then
    echo "IDENTITY: $copy or $original is MISSING — refused rather than reading an absent file as identical to nothing" >&2
    return 2
  fi
  local diff_first=""
  if ! diff_first="$(cmp "$copy" "$original" 2>&1)"; then
    echo "IDENTITY: $copy is not byte-identical to $original. Its resolution verdict is INHERITED from $original's and cannot be while they differ: $(head -1 <<<"$diff_first")" >&2
    return 1
  fi
  # A verdict with no coverage clause is indistinguishable from a deleted
  # call in a green log — check_closure_premise prints its package count
  # for the same reason.
  echo "IDENTITY: $copy is byte-identical to $original ($(wc -c <"$copy" | tr -d '[:space:]') bytes)"
  return 0
}

# check_closure_premise <inheritor-pkg> <source-pkg> [expected-inheritor-only...]
#
# THE INHERITANCE PREMISE, BOTH DIRECTIONS:
# check_resolution's two directions need
# OPPOSITE containments, so checking one
# containment alone cannot establish both premises:
#
#   DORMANCY refuses a row that does NOT resolve. It needs
#   inheritor SUPSET source: everything the source reaches, the inheritor
#   reaches, so a row live under the source is live under the inheritor and
#   the source's verdict is the stricter one. `comm -23` below.
#
#   RE-ARM refuses an `allow-invalid` row that DOES resolve. It needs the
#   OPPOSITE, source SUPSET inheritor: an EXTRA package reachable only from
#   the inheritor can make a flagged row resolve there while it stays
#   dormant under the source, and the source's call cannot see it. The
#   escape hatch then sits stale in the inheritor's byte-identical copy
#   with nothing evaluating it. `comm -13` below.
#
# So a one-directional check licenses exactly half the verdict it is
# quoted for. The inheritor-only side is not empty by nature — the
# inheritor is its own package — so it takes an EXPECTED list, and
# anything outside that list is refused BY NAME rather than absorbed.
# Widening that list is a decision about coverage and is meant to be
# visible in a diff.
#
# A `cargo tree` failure is this function's OWN exit status (2, HARNESS),
# never folded into "nothing is missing". `--locked`: without it a stale
# Cargo.lock is silently REWRITTEN here, mid-gate, and neither the pre-run
# cleanliness guard nor the EXIT trap covers the lockfile; with it the same
# condition becomes a named HARNESS refusal. The diagnostics below quote
# the command AS RUN, `--locked` included, so an operator pasting it
# reproduces the failure instead of silently repairing it.
check_closure_premise() {
  local inheritor="$1" source="$2"
  shift 2
  local -a expected_extra=("$@")
  local src_tree="" inh_tree="" rc=0 src_sorted="" inh_sorted="" missing="" extra="" comm_rc=0 n=0
  if [[ "$inheritor" == "$source" ]]; then
    echo "HARNESS: check_closure_premise called with the same package in both seats ($inheritor) — a crate contains itself, so this proves nothing; refused rather than reporting full coverage" >&2
    return 2
  fi
  src_tree="$(cargo tree --locked -p "$source" -e normal,build --prefix none 2>/dev/null)" || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    echo "HARNESS: \`cargo tree --locked -p $source -e normal,build\` exited $rc — refused rather than reading a failed tree as \"nothing is missing\"" >&2
    return 2
  fi
  inh_tree="$(cargo tree --locked -p "$inheritor" -e normal,build --prefix none 2>/dev/null)" || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    echo "HARNESS: \`cargo tree --locked -p $inheritor -e normal,build\` exited $rc — refused rather than reading a failed tree as \"nothing is missing\"" >&2
    return 2
  fi
  # Sorted ONCE each and reused by both directions and the count, so the
  # `sed` expression and the collation cannot drift between them.
  # LC_ALL=C on the sorts AND the comm: `comm` assumes its inputs are
  # sorted in the collation IT reads, and under a locale whose LC_COLLATE
  # orders `-`/`_`/case differently it both invents and drops lines AND
  # EXITS 0. "Sort both sides" only holds if the two agree on what sorted
  # means.
  src_sorted="$(sed 's/ (\*)$//' <<<"$src_tree" | LC_ALL=C sort -u)"
  inh_sorted="$(sed 's/ (\*)$//' <<<"$inh_tree" | LC_ALL=C sort -u)"

  missing="$(LC_ALL=C comm -23 <(printf '%s\n' "$src_sorted") <(printf '%s\n' "$inh_sorted"))" || comm_rc=$?
  if [[ "$comm_rc" -ne 0 ]]; then
    echo "HARNESS: \`comm -23\` exited $comm_rc comparing the two closures — refused rather than reading an empty difference as \"nothing is missing\"" >&2
    return 2
  fi
  if [[ -n "$missing" ]]; then
    echo "PREMISE: $inheritor's dependency closure no longer contains $source's, so the DORMANCY half of the inherited verdict does not hold. Reachable from $source and NOT from $inheritor:" >&2
    while IFS= read -r line; do [[ -n "$line" ]] && echo "  $line" >&2; done <<<"$missing"
    echo "  Give $inheritor its own check_resolution row (--bins, paired with tree -e normal,build) instead of widening this check." >&2
    return 1
  fi

  comm_rc=0
  extra="$(LC_ALL=C comm -13 <(printf '%s\n' "$src_sorted") <(printf '%s\n' "$inh_sorted"))" || comm_rc=$?
  if [[ "$comm_rc" -ne 0 ]]; then
    echo "HARNESS: \`comm -13\` exited $comm_rc comparing the two closures — refused rather than reading an empty difference as \"nothing unexpected\"" >&2
    return 2
  fi
  local unexpected="" line e known
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    known=no
    for e in ${expected_extra+"${expected_extra[@]}"}; do
      # Compare the PACKAGE NAME only — a `cargo tree` line is `name vX.Y.Z
      # (path)`, so a version bump must not read as a new package, and a
      # SUBSTRING test must never be used: `granary-cli` is a proper prefix
      # of `granary-client`.
      [[ "${line%% *}" == "$e" ]] && { known=yes; break; }
    done
    [[ "$known" == yes ]] || unexpected="$unexpected$line"$'\n'
  done <<<"$extra"
  if [[ -n "$unexpected" ]]; then
    echo "PREMISE: $inheritor reaches packages $source does not, so the RE-ARM half of the inherited verdict does not hold — an allow-invalid row can resolve under $inheritor while staying dormant under $source, and nothing would evaluate it. Reachable from $inheritor and NOT from $source, beyond the expected set:" >&2
    while IFS= read -r line; do [[ -n "$line" ]] && echo "  $line" >&2; done <<<"$unexpected"
    echo "  Either give $inheritor its own check_resolution row, or add the package to this call's expected list with a written reason." >&2
    return 1
  fi

  n="$(printf '%s\n' "$src_sorted" | wc -l | tr -d '[:space:]')"
  echo "PREMISE: $inheritor contains $source ($n packages; 0 source-only, 0 unexpected inheritor-only)"
  return 0
}

# check_resolution <config-path> <crate-pkg> [<shared-config-path>] [<second-crate-pkg>]
check_resolution() {
  local config="$1" crate="$2" shared_config="${3:-}" second_crate="${4:-}"
  local backup json_asis err_asis json_stripped err_stripped allow_list no_allow_list
  local unresolved_asis unresolved_stripped shared_list
  local json_stripped2 err_stripped2 unresolved_stripped2
  backup="$(mktemp)" || return 2
  json_asis="$(mktemp)" || return 2
  err_asis="$(mktemp)" || return 2
  json_stripped="$(mktemp)" || return 2
  err_stripped="$(mktemp)" || return 2
  allow_list="$(mktemp)" || return 2
  no_allow_list="$(mktemp)" || return 2
  unresolved_asis="$(mktemp)" || return 2
  unresolved_stripped="$(mktemp)" || return 2
  shared_list="$(mktemp)" || return 2
  json_stripped2="$(mktemp)" || return 2
  err_stripped2="$(mktemp)" || return 2
  unresolved_stripped2="$(mktemp)" || return 2
  cp "$config" "$backup" || return 2
  # RETURN *and* EXIT/INT/TERM, not RETURN
  # alone: a RETURN trap fires on function
  # return, not SIGINT/SIGTERM. An interruption
  # while the config is stripped would
  # otherwise leave the tracked file missing
  # its `allow-invalid` markers. Whichever
  # trap fires first clears all four so the
  # remaining traps do not repeat the
  # restore. INT/TERM additionally exit
  # with the conventional 128+signal code,
  # stopping the interrupted call. The
  # gate captures this function in its
  # own command-substitution subshell, so
  # the traps are scoped there. Restoration
  # copies the saved file, preserving the
  # contents present before the check.
  # shellcheck disable=SC2064
  local restore_cmd="trap - RETURN EXIT INT TERM; cp '$backup' '$config'; rm -f '$backup' '$json_asis' '$err_asis' '$json_stripped' '$err_stripped' '$allow_list' '$no_allow_list' '$unresolved_asis' '$unresolved_stripped' '$shared_list' '$json_stripped2' '$err_stripped2' '$unresolved_stripped2'"
  trap "$restore_cmd" RETURN
  trap "$restore_cmd; exit 130" INT
  trap "$restore_cmd; exit 143" TERM
  trap "$restore_cmd" EXIT

  local -a errors=()
  local -a notes=()

  # Independent-oracle trees are captured ONCE per
  # crate, WITHOUT a pipe. A failed `cargo tree` must
  # be read through its own exit status: reading
  # only a downstream grep status could mistake a
  # failed dependency query for an absent segment.
  # `-e normal,build` is the PRIMARY crate's edge set — it must match
  # `--lib`'s own scope, which never links a dev-dependency. The
  # secondary crate is tested via `--tests` (see below), which DOES
  # link dev-dependencies, so its tree is read with `-e
  # normal,build,dev` to match — using the `--lib` edge set there would
  # make every dev-only row (this config's whole reason for having a
  # second crate at all) read as "absent" again.
  local primary_tree="" primary_tree_rc=0
  primary_tree="$(cargo tree -p "$crate" -e normal,build --prefix none 2>/dev/null)" || primary_tree_rc=$?
  if [[ "$primary_tree_rc" -ne 0 ]]; then
    errors+=("HARNESS: \`cargo tree -p $crate\` exited $primary_tree_rc — refused rather than reading a failed tree as \"no dependency reaches this row\"")
  fi
  local second_tree="" second_tree_rc=0
  if [[ -n "$second_crate" && "$primary_tree_rc" -eq 0 ]]; then
    second_tree="$(cargo tree -p "$second_crate" -e normal,build,dev --prefix none 2>/dev/null)" || second_tree_rc=$?
    if [[ "$second_tree_rc" -ne 0 ]]; then
      errors+=("HARNESS: \`cargo tree -p $second_crate\` exited $second_tree_rc — refused rather than reading a failed tree as \"no dependency reaches this row\"")
    fi
  fi

  local rc_allow_list=0
  if [[ "${#errors[@]}" -eq 0 ]]; then
    python3 - "$config" > "$allow_list" 2>/dev/null <<'PYEOF' || rc_allow_list=$?
import sys
if sys.version_info < (3, 11):
    sys.exit(2)
import tomllib
with open(sys.argv[1], "rb") as f:
    cfg = tomllib.load(f)
# All three row-list keys, not just disallowed-methods: `allow-invalid`
# is a per-row escape hatch clippy honours identically on any of them,
# and disallowed-types already carries one (rand::rngs::OsRng).
for key in ("disallowed-methods", "disallowed-macros", "disallowed-types"):
    for row in cfg.get(key, []):
        if isinstance(row, dict) and row.get("allow-invalid") is True:
            p = row.get("path")
            if isinstance(p, str):
                print(p)
PYEOF
    # The DORMANCY considered-set: every row in the SAME three keys
    # that does NOT carry `allow-invalid = true` — the exact complement
    # of allow_list above, read from the same file in the same pass
    # shape so the two can never drift against each other.
    python3 - "$config" > "$no_allow_list" 2>/dev/null <<'PYEOF' || true
import sys
if sys.version_info < (3, 11):
    sys.exit(0)
import tomllib
with open(sys.argv[1], "rb") as f:
    cfg = tomllib.load(f)
for key in ("disallowed-methods", "disallowed-macros", "disallowed-types"):
    for row in cfg.get(key, []):
        if isinstance(row, dict) and row.get("allow-invalid") is not True:
            p = row.get("path")
            if isinstance(p, str):
                print(p)
PYEOF
  fi

  # A THIRD arg names the OTHER config this one's ROOT-DERIVED rows must
  # be byte-identical to (check_config's own anchoring/superset check
  # enforces that identity independently, so a divergence here is
  # already refused before this function ever runs). Rows shared with
  # it are excluded from THIS call's re-arm direction — measured, and
  # load-bearing: `crates/granary-client/clippy.toml` copies the root
  # `rand::*` rows verbatim, but resolvability is NOT crate-invariant —
  # `rand` 0.10.2 (object_store, transitive) makes them resolve for
  # EVERY consumer of granary-client's OWN nested config, while other
  # ROOT consumers (granary-conformance/-net/-bench) still cannot
  # resolve most of them. Testing granary-client a second time for rows
  # already judged via the root config's own check would report a
  # "re-arm falling due" that is true for granary-client alone and
  # false for the shared flag's real, workspace-wide question — the
  # exact false-positive this call is testing FOR, not against. These
  # rows are DEFERRED, not skipped-and-forgotten: the root config's own
  # call (below, via `ROOT_RESOLUTION_CRATE`/`_SECONDARY`) is the one
  # that actually evaluates them, and the coverage line reports the
  # deferral by count rather than folding it silently into "0/0".
  if [[ "${#errors[@]}" -eq 0 && -n "$shared_config" ]]; then
    python3 - "$shared_config" > "$shared_list" 2>/dev/null <<'PYEOF' || true
import sys
if sys.version_info < (3, 11):
    sys.exit(0)
import tomllib
with open(sys.argv[1], "rb") as f:
    cfg = tomllib.load(f)
for key in ("disallowed-methods", "disallowed-macros", "disallowed-types"):
    for row in cfg.get(key, []):
        if isinstance(row, dict) and row.get("allow-invalid") is True:
            p = row.get("path")
            if isinstance(p, str):
                print(p)
PYEOF
  fi

  local dorm_considered=0 dorm_evaluated=0
  local rearm_total=0 rearm_deferred=0 rearm_considered=0 rearm_evaluated=0
  local rearm_uniform=0 rearm_confirmed=0

  if [[ "${#errors[@]}" -gt 0 ]]; then
    :  # cargo tree already failed above; nothing further can run safely
  elif [[ "$rc_allow_list" -ne 0 ]]; then
    errors+=("HARNESS: could not parse $config as TOML (needs python 3.11+ for tomllib) — refused before running clippy at all")
  else
    local rc_asis=0
    cargo clippy -p "$crate" --lib --message-format=json \
      > "$json_asis" 2> "$err_asis" || rc_asis=$?
    if [[ "$rc_asis" -ne 0 ]]; then
      errors+=("HARNESS: \`cargo clippy -p $crate --lib\` exited $rc_asis checking $config — refused, never read as a clean resolution result. Tail of stderr: $(tail -3 "$err_asis" | tr '\n' ' ')")
    else
      local rc_extract=0
      resolution_extract_unresolved "$json_asis" "$unresolved_asis" "$crate" || rc_extract=$?
      if [[ "$rc_extract" -ne 0 ]]; then
        errors+=("HARNESS: could not parse $json_asis (the clippy JSON stream for $crate) — refused rather than reading a parser crash as zero findings")
      else
        # ---- direction (a): DORMANCY, with coverage ----
        local p
        while IFS= read -r p; do
          [[ -z "$p" ]] && continue
          dorm_considered=$((dorm_considered + 1))
          if segment_in_tree "$primary_tree" "$p"; then
            dorm_evaluated=$((dorm_evaluated + 1))
            if grep -qxF "$p" "$unresolved_asis"; then
              errors+=("DORMANT: $config row '$p' does not resolve under \`cargo clippy -p $crate\` and is not marked allow-invalid = true — refused, before CI ever sees it")
            fi
          fi
        done < "$no_allow_list"
        if [[ "$dorm_considered" -gt 0 && "$dorm_evaluated" -eq 0 ]]; then
          errors+=("HARNESS: ZERO-COVERAGE — $config dormancy direction considered $dorm_considered row(s) but \`cargo clippy -p $crate\`'s own dependency graph reaches none of them — refused rather than printing a verdict for zero rows checked")
        fi

        # Captured, never guessed: on the pinned 1.97.1 this is always
        # empty (the JSON stream carries every compiler-message once
        # --message-format=json is set), and a future toolchain that
        # moved it would be caught here rather than silently trusted.
        if grep -Eq '`[^`]+` does not refer to a reachable (function|macro|type)' "$err_asis"; then
          errors+=("HARNESS: $config — the config-loader diagnostic appeared on STDERR for $crate, not only the JSON stream this check reads; the toolchain's behaviour has changed and this check needs updating, not trusting")
        fi

        # ---- direction (b): only meaningful if something is flagged ----
        if [[ -s "$allow_list" ]]; then
          rearm_total="$(wc -l < "$allow_list" | tr -d '[:space:]')"
          local expected_n got_n stripped_n rc_stripped=0
          expected_n="$rearm_total"
          got_n="$(grep -c ', allow-invalid = true' "$config" || true)"
          python3 - "$config" <<'PYEOF'
import re, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    text = f.read()
text2 = re.sub(r", allow-invalid = true", "", text)
with open(path, "w", encoding="utf-8") as f:
    f.write(text2)
PYEOF
          stripped_n="$(grep -c ', allow-invalid = true' "$config" || true)"
          if [[ "$stripped_n" -ne 0 ]] || [[ "$got_n" -ne "$expected_n" ]]; then
            errors+=("HARNESS: $config — expected to strip $expected_n allow-invalid marker(s) (found $got_n textually, $stripped_n remain) — refused rather than testing a partially-stripped config")
            cp "$backup" "$config" || errors+=("HARNESS: could not restore $config from its backup — refused; the file may be left with allow-invalid markers stripped, which SILENTLY DISABLES the rows they mark")
          else
            cargo clippy -p "$crate" --lib --message-format=json \
              > "$json_stripped" 2> "$err_stripped" || rc_stripped=$?
            if [[ "$rc_stripped" -ne 0 ]]; then
              errors+=("HARNESS: \`cargo clippy -p $crate --lib\` exited $rc_stripped with allow-invalid stripped from $config — refused, never read as a clean resolution result. Tail of stderr: $(tail -3 "$err_stripped" | tr '\n' ' ')")
              cp "$backup" "$config" || errors+=("HARNESS: could not restore $config from its backup — refused; the file may be left with allow-invalid markers stripped, which SILENTLY DISABLES the rows they mark")
            else
              local rc_extract2=0
              resolution_extract_unresolved "$json_stripped" "$unresolved_stripped" "$crate" || rc_extract2=$?
              if [[ "$rc_extract2" -ne 0 ]]; then
                errors+=("HARNESS: could not parse $json_stripped (the stripped-config clippy JSON stream for $crate) — refused rather than reading a parser crash as zero findings")
                cp "$backup" "$config" || errors+=("HARNESS: could not restore $config from its backup — refused; the file may be left with allow-invalid markers stripped, which SILENTLY DISABLES the rows they mark")
              else
                local rc_stripped2=0 rc_extract3=0
                if [[ -n "$second_crate" ]]; then
                  # SAME stripped file, no re-strip needed: clippy takes
                  # its config from the crate's own directory upward,
                  # and $second_crate reads this SAME $config (they
                  # share a config file by construction — the whole
                  # reason a secondary crate is needed at all).
                  cargo clippy -p "$second_crate" --tests --message-format=json \
                    > "$json_stripped2" 2> "$err_stripped2" || rc_stripped2=$?
                  if [[ "$rc_stripped2" -ne 0 ]]; then
                    errors+=("HARNESS: \`cargo clippy -p $second_crate --tests\` exited $rc_stripped2 with allow-invalid stripped from $config — refused, never read as a clean resolution result. Tail of stderr: $(tail -3 "$err_stripped2" | tr '\n' ' ')")
                  else
                    resolution_extract_unresolved "$json_stripped2" "$unresolved_stripped2" "$second_crate" || rc_extract3=$?
                    if [[ "$rc_extract3" -ne 0 ]]; then
                      errors+=("HARNESS: could not parse $json_stripped2 (the stripped-config clippy JSON stream for $second_crate) — refused rather than reading a parser crash as zero findings")
                    fi
                  fi
                fi

                # Restored NOW, ahead of the RETURN trap: a caller
                # stacking two check_resolution calls (both configs,
                # one crate each) must never see a half-stripped file
                # from THIS call while the NEXT one runs. The trap's
                # own restore is then a harmless no-op double-check,
                # never the only path to clean.
                cp "$backup" "$config" || errors+=("HARNESS: could not restore $config from its backup — refused; the file may be left with allow-invalid markers stripped, which SILENTLY DISABLES the rows they mark")

                if [[ "$rc_stripped2" -eq 0 && "$rc_extract3" -eq 0 ]] || [[ -z "$second_crate" ]]; then
                  while IFS= read -r p; do
                    [[ -z "$p" ]] && continue
                    # Skip a row this config shares (byte-identical, per
                    # check_config's own anchoring) with $shared_config —
                    # its re-arm question is judged ONCE, via that OTHER
                    # config's own check_resolution call against ITS
                    # representative crate(s), not here against this one.
                    if [[ -s "$shared_list" ]] && grep -qxF "$p" "$shared_list"; then
                      rearm_deferred=$((rearm_deferred + 1))
                      continue
                    fi
                    rearm_considered=$((rearm_considered + 1))

                    # clippy.toml's OWN header states the mechanism this
                    # guards: "entries referencing absent crates sit
                    # dormant... the path resolves against nothing and the
                    # entry is silently skipped" — NO warning either way,
                    # which is INDISTINGUISHABLE from "genuinely resolves"
                    # by absence-from-unresolved alone (measured: this is
                    # exactly what happened testing granary-core against
                    # `rand::*` before this guard existed — a false REARM
                    # on every one of seven rows, or, chosen the other way,
                    # a silent ZERO-COVERAGE "ok"). So a row's crate name
                    # must be confirmed PRESENT in the tested crate's own
                    # dependency closure (`segment_in_tree`, `cargo tree`
                    # the independent oracle) before its absence from an
                    # unresolved-list is trusted as "resolves".
                    local p_reached=0 s_reached=0 p_resolved=0 s_resolved=0
                    if segment_in_tree "$primary_tree" "$p"; then
                      p_reached=1
                      grep -qxF "$p" "$unresolved_stripped" || p_resolved=1
                    fi
                    if [[ -n "$second_crate" ]] && segment_in_tree "$second_tree" "$p"; then
                      s_reached=1
                      grep -qxF "$p" "$unresolved_stripped2" || s_resolved=1
                    fi

                    if [[ "$p_reached" -eq 0 && "$s_reached" -eq 0 ]]; then
                      continue  # neither tested crate's graph reaches this row at all
                    fi
                    rearm_evaluated=$((rearm_evaluated + 1))

                    if [[ "$p_resolved" -eq 1 && "$s_resolved" -eq 1 ]]; then
                      # Resolves under EVERY crate this call tested. Not a
                      # coverage gap and not silently absorbed into "ok"
                      # either: named, visible, non-fatal — see the
                      # header and clippy.toml's own comment on this row.
                      rearm_uniform=$((rearm_uniform + 1))
                      notes+=("ADVISORY (not refused): $config row '$p' is marked allow-invalid = true and resolves under BOTH \`cargo clippy -p $crate\` and \`cargo clippy -p $second_crate --tests\` — clippy.toml's own comment on this row already documents keeping it flagged for uniformity with its still-needed siblings; this check surfaces it rather than silently agreeing with RESOLUTION: ok")
                    elif [[ "$p_resolved" -eq 1 && "$s_reached" -eq 0 ]]; then
                      # Resolves under the primary crate and the
                      # secondary either was not given or cannot reach
                      # this row at all — cannot rule out a workspace-
                      # wide stale flag, so this falls back to the
                      # single-crate verdict this check has always used.
                      errors+=("REARM: $config row '$p' is marked allow-invalid = true but now resolves under \`cargo clippy -p $crate\` (verified by temporarily stripping the flag from the real file and restoring it) — remove the escape hatch, the ban is already live")
                    elif [[ "$p_resolved" -eq 1 || "$s_resolved" -eq 1 ]]; then
                      # Resolves under exactly one of the two tested
                      # crates: the OTHER one confirms it is still
                      # needed there — the documented, accepted,
                      # cross-crate heterogeneity, not a re-arm.
                      rearm_confirmed=$((rearm_confirmed + 1))
                    else
                      # Reached but unresolved under every crate tested:
                      # correctly still dormant everywhere this check
                      # can see.
                      rearm_confirmed=$((rearm_confirmed + 1))
                    fi
                  done < "$allow_list"
                fi
              fi
            fi
          fi
        fi
      fi
    fi
  fi

  if [[ "$rearm_considered" -gt 0 && "$rearm_evaluated" -eq 0 ]]; then
    errors+=("HARNESS: ZERO-COVERAGE — $config re-arm direction considered $rearm_considered row(s) (crate=$crate${second_crate:+, secondary=$second_crate}) but evaluated none of them (neither crate's dependency graph reaches them) — refused rather than printing a verdict for zero rows checked")
  fi

  echo "COVERAGE $config via $crate${second_crate:+ + $second_crate --tests}: dormancy ${dorm_evaluated}/${dorm_considered}; re-arm ${rearm_evaluated}/${rearm_considered} (deferred=${rearm_deferred}, confirmed-still-needed=${rearm_confirmed}, uniform-advisory=${rearm_uniform})"
  if [[ "${#notes[@]}" -gt 0 ]]; then
    printf '%s\n' "${notes[@]}"
  fi

  if [[ "${#errors[@]}" -gt 0 ]]; then
    printf '%s\n' "${errors[@]}" >&2
    return 1
  fi
  return 0
}

# ------------------------------------------------------- checks 3 + 4
# A LINE-SCOPED REGEX CANNOT DO THIS JOB. Each shape below is legal
# Rust that such a matcher misses entirely:
#   - a rustfmt-shaped MULTI-LINE `#[allow(\n    clippy::disallowed_methods,\n
#     ...\n)]` — the lint name never appears on the `#[allow(` line.
#   - `#[allow(unused_variables, clippy::disallowed_methods)]` (a SECOND
#     lint sharing the attribute) evades a regex anchored to "the lint
#     immediately after `allow(`" the same way
#     `#[expect(clippy::too_many_lines, clippy::disallowed_methods, ...)]`
#     silently ADDS a licence without moving the count.
# - Reading raw source would count
# commented-out attributes and attribute
# spellings inside string literals.
# The scanner blanks comments and
# strings while preserving newlines
# before inspecting attributes. It
# then examines the captured lint
# list, including lints after the first
# entry. This separates executable
# attribute syntax from text that
# merely describes it and keeps line
# numbers available for diagnostics.
#
# Reads NUL-separated paths from stdin (`find -print0`) in ONE process
# — never `find | xargs python3`, which can split into multiple
# xargs-batched invocations, each printing its own `COUNT` line and
# corrupting a `$(...)` capture into more than one number.
# A cargo BUILD DIRECTORY is pruned, and only a real one: the prune
# fires for a directory named `target` that contains cargo's own
# `CACHEDIR.TAG`, never for one that merely has the name. Generated
# sources under a build dir are not this crate's source and would make
# the gate's answer depend on whether anyone had run `cargo fuzz`
# lately; a `src/target/` someone hid a file in has no CACHEDIR.TAG and
# is still scanned.
# THE one definition of "walk this tree, skipping cargo build
# directories". Every caller needs it — the source scan, the
# source-closure scan, the symlink walk, the stray-config walk and the
# self-test's crate copies — and each supplies its own tail expression.
# A comment claiming five copies cannot drift is not a mechanism; a
# single function is.
#
# WHAT IS PRUNED IS A CARGO TARGET ROOT, not a directory named `target`.
# Both conditions have to hold: the directory carries cargo's own
# `CACHEDIR.TAG`, AND its PARENT holds a `Cargo.toml` — which is what
# makes it the build directory of a package rather than a directory
# somebody put a tag in. The repo root's `target/` and each fuzz
# workspace's satisfy both; nothing else in this tree does.
#
# The tag alone is not enough, and the gap is reachable from inside the
# crate: `crates/granary-client/src/target/CACHEDIR.TAG` plus a
# `mod target;` in lib.rs makes rustc compile every `.rs` under
# `src/target/` while a tag-only prune hides all of them from the
# licensed-site count, the bare-allow kill switch and the source-closure
# scan at once. `src/` holds no `Cargo.toml`, so the parent test refuses
# to prune it — and the source-closure walk refuses the directory
# outright, so it is a finding rather than merely a scanned tree.
#
# BOTH FILES MUST BE REAL, AND THE TEST IS LSTAT. `test -e` and `test -f`
# FOLLOW a symlink, so `src/Cargo.toml -> ../Cargo.toml` answers "yes,
# there is a manifest beside src/target" and hands the prune back the
# whole hole one level down: `src/target/CACHEDIR.TAG` beside it, a
# `mod target;` in a scanned module, and rustc compiles
# `src/target/mod.rs` — a whole-file `#![expect]`, bare suppressions and
# banned calls included — while every scan here prunes it. `find`'s own
# `-type f` never matches a link, so nothing else caught it either.
# `[ ! -L p ] && [ -f p ]` is lstat followed by stat: the first refuses
# a link at that name whatever it points at, the second refuses a
# directory or a device wearing the name. The `..` in the parent test is
# safe here because `-type d` already established that `target` is a
# real directory rather than a link the kernel would resolve through.
find_pruned() {
  local root="$1"
  shift
  find "$root" \
    \( -type d -name target \
       -exec sh -c '
           [ ! -L "$1/CACHEDIR.TAG" ] && [ -f "$1/CACHEDIR.TAG" ] &&
           [ ! -L "$1/../Cargo.toml" ] && [ -f "$1/../Cargo.toml" ]
         ' _ '{}' \; \
       -prune \) -o \
    \( -type d \
       -exec sh -c '
           [ "$1" != "$2" ] && { [ -e "$1/.git" ] || [ -L "$1/.git" ]; }
         ' _ '{}' "$root" \; \
       -prune \) -o \
    "$@"
}
# THE SECOND PRUNE excludes nested checkouts
# while keeping the walk root in scope.
#
# A linked worktree carries a `.git`
# file; a nested clone or submodule
# can carry a `.git` directory or file.
# The walk recognises either marker
# below its root and prunes that
# separate checkout. Otherwise its
# own clippy and Cargo configuration
# files could appear to be stray
# configurations of the enclosing
# tree. The predicate also
# recognises a symlink marker, while
# excluding the root from this prune.
#
# Adding a worktree's config path to the
# enclosing allow-list would permanently
# accept a second configuration by name.
# Pruning at the separate checkout boundary
# instead leaves the enclosing tree's
# config rules intact. Each checkout can
# run its own gate against its own files;
# a nearby config outside that boundary
# remains subject to the enclosing gate.
#
# `"$1" != "$2"` excludes the walk root,
# which carries `.git` itself; without it
# the prune takes the whole tree and
# the gate inspects nothing.
# Control W1 plants a nested checkout
# whose config must be IGNORED, plus
# a stray config beside it that must
# still be CAUGHT. Its positive half
# distinguishes pruning a separate
# checkout from pruning everything under
# a directory named `worktrees`: the stray
# config has no `.git` boundary of its own,
# so the enclosing gate must still see it.

# ONE place that runs a pruned walk and refuses when `find` itself could
# not complete. A failing `find` writes nothing and exits nonzero; read
# through a pipe or a process substitution that status disappears and
# the empty output reads as "no files here" — the gate blessing a tree
# it never looked at. Every consumer takes its list from a FILE this
# fills and acts on the status it returns: 0 = the walk completed, 2 =
# it did not, never 1, so "could not run" stays distinct from "found
# something".
#
#   walk_or_die <outfile> <label> <root> <find-tail...>
walk_or_die() {
  local out="$1" label="$2" root="$3"
  shift 3
  local rc=0
  find_pruned "$root" "$@" > "$out" || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    echo "fsguard-sites: the $label walk of $root failed (find exit $rc) — refused, never treated as clean" >&2
    return 2
  fi
  return 0
}

# `--banned-rows $ROOT_CLIPPY`: the scanner also reports a call to a
# NON-FILESYSTEM row of the lint sitting under a whole-module
# `#[expect(clippy::disallowed_methods, …)]` with no narrow licence of
# its own. The row set is the repo-root config's own
# `disallowed-methods` list, read at run time rather than restated —
# and that list IS the client file's non-fs half, because check 1
# requires every root row to be present in the client file and check 2
# pins the client's list to root's rows plus exactly the audited fs
# rows. Passing the file rather than a list is what keeps the two from
# drifting.
scan_fs_sites() {
  local list rc=0 rows="${2:-$ROOT_CLIPPY}"
  list="$(mktemp)" || return 2
  walk_or_die "$list" ".rs source" "$1" \( -name '*.rs' -print0 \) || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    rm -f "$list"
    return "$rc"
  fi
  # `--crate-dir` is the SCAN ROOT: the file-scoped-licence rule reads
  # the first path component after it, so `tests/` and `fuzz/` are the
  # crate's own two roots rather than any directory that happens to be
  # named that.
  python3 "$(dirname "${BASH_SOURCE[0]}")/fsguard-scan.py" \
    --banned-rows "$rows" --crate-dir "${1%/}" < "$list"
  rc=$?
  rm -f "$list"
  return "$rc"
}

# scan_or_die is the ONLY sanctioned way to call scan_fs_sites — never
# call scan_fs_sites directly inside another command's argument list
# — bash's `set -e`
# does NOT trip when a FAILING command substitution is nested as an
# ARGUMENT to another command — `f "$(g)"` where `g` fails still runs
# `f` (with whatever partial/empty output `g` produced) and the script
# carries on as if nothing happened; only a BARE, single-level
# `scan_or_die` captures the scanner's
# status explicitly before returning
# text. A nested substitution passed as
# another command's argument can lose a
# scanner failure when the outer command
# succeeds, leaving empty text that looks
# clean. The wrapper disables errexit
# for the capture, checks the result,
# and exits with the harness-refusal
# status on failure. Downstream count
# and hit extractors consume that validated
# string instead of running the scanner
# in another nested substitution.
scan_or_die() {
  local dir="$1" rows="${2:-$ROOT_CLIPPY}"
  local out rc
  set +e
  out="$(scan_fs_sites "$dir" "$rows")"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "fsguard-sites: the scanner failed while scanning $dir (exit $rc) — refused, never treated as clean:" >&2
    echo "$out" >&2
    exit 2
  fi
  printf '%s' "$out"
}

scanned_count() {
  grep -m1 '^COUNT ' <<<"$1" | awk '{print $2}'
}

scanned_allow_hits() {
  grep '^ALLOW ' <<<"$1" | sed 's/^ALLOW //' || true
}

scanned_reach_hits() {
  grep '^REACH ' <<<"$1" | sed 's/^REACH //' || true
}

# How many WHOLE-MODULE licences the scan found. The POSITIVE observable
# for the reach half: "no findings" over ZERO licences is not a result,
# it is a scan where the machinery never ran, and the gate says the
# number out loud so a control can require it to be above zero.
scanned_licence_count() {
  grep -m1 '^LICENCES ' <<<"$1" | awk '{print $2}'
}

# report_count/report_bare_allow are the ONE comparison the real gate
# and the self-test's controls both call — a self-test that reimplements
# a comparison separately proves nothing about the gate's ACTUAL
# refusal message or logic.
report_count() {
  local got="$1" expected="$2" dir="$3"
  # A NON-EMPTY RUN OF DIGITS, checked before any arithmetic. `[[ -ne ]]`
  # evaluates an empty string as 0, so a scan that produced no COUNT line
  # at all — a crashed scanner, a missing src/ — satisfied an expectation
  # of 0 and read as a clean row. Exit 2, because that is a broken harness
  # and not a drifted audit, and the remedy below would be wrong advice.
  if [[ ! "$got" =~ ^[0-9]+$ ]]; then
    echo "fsguard-sites: the licensed-site scan of $dir produced no usable count (got '$got') — refused as a harness failure, never read as zero." >&2
    return 2
  fi
  # The EXPECTATION is validated at PARSE time, beside the other row-shape
  # guards in check_all_licensed_sites — not here. Here it would be
  # refused only after two full fsguard-scan.py walks, and the message
  # would name the SRC ROOT while the row the operator must edit is keyed
  # by the crate dir.
  if [[ "$got" -ne "$expected" ]]; then
    echo "fsguard-sites: $dir has $got '#[expect(clippy::disallowed_methods, ...)]' sites, this script expects $expected." >&2
    echo "  Adding or removing one is a deliberate audit change, not a silent drift — update this crate's row in LICENSED_SITE_CRATES with a reason." >&2
    return 1
  fi
  return 0
}

# What a WHOLE-MODULE licence reaches beyond the rows it was written
# for. Reported separately from the bare-allow kill switch because it is
# a different finding: the attribute is a legitimate `#[expect]` with a
# reason, and what is wrong is its SCOPE — it silences the ambient-input
# and runtime-concurrency rows of the same lint for everything under it,
# which no comment or count records.
# On success this function prints the line used in
# the gate's summary. Producing the licence count
# here ties that output to execution of the reach
# check; a count taken directly from the scan
# would not establish that the reach check ran.
report_licensed_reach() { # report_licensed_reach <hits> <licence-count>
  local hits="$1" licences="${2:-?}"
  if [[ -n "$hits" ]]; then
    # No backticks in this string: it is double-quoted, so a backtick
    # would be command substitution and the diagnostic would try to RUN
    # the lint's name.
    echo "fsguard-sites: a whole-module #[expect(clippy::disallowed_methods, ...)] is silencing NON-FILESYSTEM rows of the same lint. disallowed_methods is ONE lint carrying every row, so a licence written for the fs rows equally covers the ambient-input determinism seams and the runtime-concurrency bans for everything under it:" >&2
    echo "$hits" >&2
    echo "  Each call below needs its own #[expect] with a reason, or the seam its row exists to protect. Outside a wholesale licence nothing is reported here — clippy is the check there." >&2
    return 1
  fi
  echo "LICENCE-REACH: 0 findings over $licences whole-module licences"
  return 0
}

# check_licensed_sites <crate-dir> <src-root> <expected-src-count>
#
# ONE crate's half of checks 3 and 4, composed: the whole-crate scan feeds
# the bare-#[allow] kill switch and the licence-REACH report, and a second,
# narrower scan of src/ feeds the count. Two scans on purpose — the
# whole-crate number would fold in the `tests/` file-scoped licences the
# count does not describe.
#
# EXTRACTED AS A FUNCTION SO IT CAN BE CONTROLLED. While
# LICENSED_SITE_CRATES has one row, no control reading the REAL table can
# tell a whole-table loop from a first-row loop — `"${arr[@]}"` and
# `"${arr[0]}"` are the same call. A control can call THIS directly with
# its own planted second crate, which is the escape that works before
# `granary-cli` exists.
#
# Prints `<got>|<reach-line>` on success for the caller's summary; every
# refusal has already said why on stderr.
check_licensed_sites() {
  local dir="$1" src="$2" expected="$3"
  local crate_scan crate_hits crate_reach crate_licences src_scan got reach
  # `|| return 2` ON EVERY scan, and it is load-bearing rather than
  # defensive. `scan_or_die` refuses by calling `exit 2`, which works at
  # the top level because errexit aborts the script — but this function is
  # called from inside a `$(...)` on the left of `||`, and THAT SUPPRESSES
  # ERREXIT FOR ITS WHOLE BODY. The inner `exit` then kills only the
  # innermost substitution, leaving `crate_scan` EMPTY, and every check
  # below reads empty as clean: `report_bare_allow ""` returns 0, so the
  # bare-#[allow] KILL SWITCH becomes vacuous and the gate prints a green
  # summary. The caller must propagate the
  # scanner wrapper's status explicitly; an
  # empty result must never reach the later
  # checks as though scanning succeeded.
  crate_scan="$(scan_or_die "$dir")" || return 2
  crate_hits="$(scanned_allow_hits "$crate_scan")"
  report_bare_allow "$crate_hits" || return 1
  crate_reach="$(scanned_reach_hits "$crate_scan")"
  # `|| true` permits capture followed by an
  # EXPLICIT guard. With pipefail, a missing LICENCES
  # line makes the extractor fail. This function
  # can run in a context where errexit is suppressed,
  # so it must check for an empty count itself
  # instead of letting `report_licensed_reach`
  # substitute its question-mark default.
  #
  # THIS GUARD IS UNCONTROLLED, AND THAT IS STATED RATHER THAN HIDDEN.
  # MEASURED: deleting it leaves the whole battery GREEN, because the
  # scanner always emits a LICENCES line, so the empty case cannot be
  # planted from outside the way D13e plants a crashed scan. It is kept as
  # a cheap assertion on an invariant the scanner owns — not as something
  # the suite proves. If `scan_fs_sites` ever gains a path that omits the
  # field, this is the guard that catches it, and a control becomes
  # possible at that point.
  crate_licences="$(scanned_licence_count "$crate_scan" || true)"
  if [[ ! "$crate_licences" =~ ^[0-9]+$ ]]; then
    echo "fsguard-sites: the scan of $dir produced no usable whole-module licence count (got '$crate_licences') — refused rather than reporting reach over an unknown number of licences." >&2
    return 2
  fi
  reach="$(report_licensed_reach "$crate_reach" "$crate_licences")" || return 1
  src_scan="$(scan_or_die "$src")" || return 2
  got="$(scanned_count "$src_scan")"
  report_count "$got" "$expected" "$src" || return $?
  printf '%s|%s\n' "$got" "$reach"
  return 0
}

# check_all_licensed_sites <row>...
#
# The whole table, one pass per row. Takes the rows as ARGUMENTS rather
# than reading the global, so a control can drive it with its own set —
# including the EMPTY set, which is the one shape the real table can never
# have while the gate is healthy and which no control could otherwise
# reach.
#
# Prints `<counts clause>|<reach clause>` for the summary.
check_all_licensed_sites() {
  # AN EMPTY TABLE IS A REFUSAL, NOT A RUN — the guard
  # collect_audited_closures already carries for its own table, and for the
  # same reason: with no rows the loop body never runs, checks 3 and 4
  # simply vanish, and the gate prints a green summary over no crates at
  # all.
  if [[ "$#" -eq 0 ]]; then
    echo "fsguard-sites: the licensed-site table is EMPTY — refused rather than reporting a clean licensed-site audit over no crates at all." >&2
    return 2
  fi

  # ---- PASS 1: VALIDATE EVERY ROW BEFORE SCANNING ANY OF THEM.
  # Two passes on purpose. Interleaved with the scans, a FINDING on an
  # early row (exit 1) returns before a malformed LATER row is ever
  # examined — so a broken table is reported as a count drift, and the
  # operator is told to edit an audit constant. That is the exact
  # exit-1-vs-2 inversion control D13b asserts against in the other
  # direction. Validation is also cheap and scanning is not: a bad row is
  # refused before two fsguard-scan.py walks of every .rs file.
  local -a v_dirs=() v_srcs=() v_exps=()
  local row seps dir src expected seen i
  for row in "$@"; do
    # `IFS='|' read` + a SEPARATOR COUNT — the idiom
    # collect_audited_closures uses, for the reason its own comment gives:
    # `read` fills missing trailing fields with "" and returns 0, so a
    # two-field row would silently put the src path where the count
    # belongs. A hand-rolled `${x##*|}` is worse still: it takes the LAST
    # field, so a four-field row parses "successfully" while dropping
    # field three with no diagnostic.
    seps="${row//[^|]/}"
    if [[ "${#seps}" -ne 2 ]]; then
      echo "fsguard-sites: licensed-site row '$row' has ${#seps} '|' separator(s), expected exactly 2 (<crate-dir>|<src-root>|<expected-count>) — refused rather than parsing a row whose fields cannot be what they look like." >&2
      return 2
    fi
    IFS='|' read -r dir src expected <<<"$row"
    if [[ -z "$dir" || -z "$src" || -z "$expected" ]]; then
      echo "fsguard-sites: licensed-site row '$row' has an EMPTY field — refused." >&2
      return 2
    fi
    # NORMALISED before every comparison below. `scan_fs_sites` strips a
    # trailing slash itself (`${1%/}`), so `crates/x/` and `crates/x` are
    # ONE directory to the scanner — but they are two distinct strings to
    # a duplicate check, and `"$src" != "$dir"/*` against `crates/x//*`
    # would falsely refuse a legitimate row.
    dir="${dir%/}"
    src="${src%/}"
    # Accept zero or a nonzero digit followed by zero or more digits;
    # refuse other shapes, including hexadecimal notation such as `0x1`.
    # `report_count`, called by `check_licensed_sites`, compares with
    # `[[ "$got" -ne "$expected" ]]`: `064` is octal 52, so it compares
    # against the wrong number without an error. Leading-zero digit strings
    # containing any 8 or 9 cause arithmetic errors: the test is false and
    # drift is not refused.
    # A bare identifier is a variable: expected=`got` makes the test false
    # without an error. Reject these expressions before the comparison.
    if [[ ! "$expected" =~ ^(0|[1-9][0-9]*)$ ]]; then
      echo "fsguard-sites: the expected licensed-site count for '$dir' is not a plain decimal integer (got '$expected') — refused. Only zero or a nonzero decimal digit followed by zero or more decimal digits is allowed. Leading-zero digit strings are octal and can compare against the wrong count; those containing any 8 or 9 cause arithmetic errors that make the drift comparison false. Other shapes, including hexadecimal notation, are refused." >&2
      return 2
    fi
    # NO `..` COMPONENT in either field. The containment test below is a
    # string prefix, and `*` matches `/`, so
    # `crates/granary-cli/../granary-client/src` would satisfy it — the
    # decoy the guard exists to refuse, arriving through the guard itself.
    if [[ "$dir" == *".."* || "$src" == *".."* ]]; then
      echo "fsguard-sites: licensed-site row '$row' contains a '..' path component — refused; the containment check below is a string prefix and '..' walks straight through it." >&2
      return 2
    fi
    # THE SRC ROOT MUST LIE STRICTLY UNDER ITS OWN CRATE DIR — the guard
    # collect_audited_closures carries for its manifest field, and its
    # comment names the trigger: "the copy-paste that adds a second row".
    # This table has the identical decoy shape, because the kill switch
    # and the reach audit walk `$dir` while the COUNT audits `$src`: a cli
    # row written `crates/granary-cli|crates/granary-client/src|64` would
    # re-audit the CLIENT tree, never count granary-cli/src at all, and
    # publish a summary claiming coverage of a tree the count never read.
    #
    # STRICTLY under, so `src == dir` is refused too: that collapses the
    # two scans into one and takes the COUNT over the whole crate,
    # folding in the tests/ and fuzz/ file-scoped licences this
    # function's own header says the count does not describe.
    if [[ "$src" != "$dir"/* ]]; then
      echo "fsguard-sites: licensed-site row '$row' has a src root that is not strictly under its own crate dir ('$src' vs '$dir') — refused; the count would audit a different tree from the one the kill switch walks, or the whole crate instead of src/." >&2
      return 2
    fi
    # AND NO CRATE TWICE. collect_audited_closures refuses a repeated
    # directory for the same reason: with two rows for one crate the scan
    # runs twice, the summary names it twice, and if their counts differ
    # the verdict depends on which row is written first.
    for seen in ${v_dirs+"${v_dirs[@]}"}; do
      if [[ "$seen" == "$dir" ]]; then
        echo "fsguard-sites: licensed-site table has more than one row for '$dir' — refused rather than auditing one crate twice and letting row order decide the verdict." >&2
        return 2
      fi
    done
    v_dirs+=("$dir")
    v_srcs+=("$src")
    v_exps+=("$expected")
  done

  # ---- PASS 2: SCAN. Every row is known well-formed by here, so a
  # nonzero status from check_licensed_sites is about the TREE, not the
  # table, and 1-vs-2 keeps its meaning.
  local counts="" reach="" out rc got r
  for ((i = 0; i < ${#v_dirs[@]}; i++)); do
    rc=0
    out="$(check_licensed_sites "${v_dirs[i]}" "${v_srcs[i]}" "${v_exps[i]}")" || rc=$?
    # Preserve status 1 for a finding and 2 for a
    # broken harness. Collapsing both to 1 would
    # misreport a scanner failure as count drift.
    [[ "$rc" -eq 0 ]] || return "$rc"
    got="${out%%|*}"
    r="${out#*|}"
    counts="${counts:+$counts, }$got licensed sites in ${v_srcs[i]}"
    # LABELLED WITH THE CRATE DIR, NOT THE SRC
    # ROOT: the reach and bare-#[allow] audits
    # walk the WHOLE CRATE — src/, tests/ and
    # fuzz/ — while only the COUNT is narrowed to
    # src/. Joined with `, ` rather than `; ` so
    # the clause does not inject the separator
    # used between top-level summary clauses.
    reach="${reach:+$reach, }${v_dirs[i]} $r"
  done
  printf '%s|%s\n' "$counts" "$reach"
  return 0
}

report_bare_allow() {
  local hits="$1"
  if [[ -n "$hits" ]]; then
    echo "fsguard-sites: a wholesale suppression of the filesystem ban was found — a bare #[allow], or an #[expect] naming a lint GROUP rather than the lint (docs/coding-standards.md MUST-1 requires #[expect(clippy::disallowed_methods, reason = ...)] at every licensed site):" >&2
    echo "$hits" >&2
    return 1
  fi
  return 0
}

# --------------------------------------------------------- check 5, part b
# CONFIG DISCOVERY. Reading the repo-root cargo config is not the same
# as knowing which config cargo will read: cargo walks `.cargo/config*`
# up from the CURRENT DIRECTORY's ancestors, so a
# `crates/granary-client/.cargo/config.toml` governs a developer running
# `cargo clippy -p granary-client` from inside the crate, and is
# invisible to a check that only looks at the repo root. Clippy's own
# config lookup starts at $CLIPPY_CONF_DIR, else $CARGO_MANIFEST_DIR,
# else the cwd, and walks UP — so a `crates/granary-client/src/clippy.toml`
# is not consulted for the lib, but a `crates/granary-client/fuzz/clippy.toml`
# IS the nearest one for the fuzz manifest and would replace the audited
# file wholesale for that crate.
#
# The clippy half is refused ANYWHERE in the tree, not only under
# crates/granary-client/: a nested config REPLACES the root file's rows
# for the crate it is nearest to rather than merging with them, and CI
# now runs `cargo clippy` over the granary-core and granary-store fuzz
# workspaces as well, whose nearest config would be a planted
# `crates/granary-core/fuzz/clippy.toml`. Exactly THREE files are
# allowed: the repo-root `clippy.toml`, the audited
# `crates/granary-client/clippy.toml`, and
# `crates/granary-cli/clippy.toml` — which is not separately audited
# here because check 9 holds it byte-identical to the client's.
#
# Neither shape is a level this gate can evaluate, and neither has a
# legitimate use here — so both are refused by EXISTENCE. Enumerated
# with `find` (pruning real cargo build directories, the ones carrying
# CACHEDIR.TAG, exactly as the source scan does) and, when the tree is a
# git checkout, with `git ls-files` as well, so a tracked file hidden
# inside a pruned directory is still seen.
check_stray_configs() {
  local root="${1%/}"
  local rc=0 f list walk_rc
  local -a candidates=()
  # The walk's own STATUS, not just its output. Reading `find` through a
  # `done < <(…)` process substitution swallows the producer's status
  # entirely — the `while` loop simply ends — so a root that could not
  # be walked at all read as "no stray config found" and this check
  # blessed a tree it had never looked at. That is the same fail-open
  # shape the source closure's symlink half closed one function away,
  # and it is closed the same way: a temp file, whose producer's status
  # IS observable. "Could not run" returns 2 and never 1, so the gate
  # can keep it distinguishable from "found something", exactly as it
  # does for check 6.
  list="$(mktemp)" || return 2
  # A RETURN trap, not a pair of `rm` calls placed where the reader
  # believes every exit passes: the cleanup then holds for a path added
  # later without anyone remembering to add an `rm` to it.
  trap 'rm -f "$list"' RETURN
  # `cmd || walk_rc=$?` and not a `set +e` pair: this function is called
  # both with errexit ON (the gate) and with it OFF (the self-test's
  # controls), and a `set -e` inside it would hand the second caller an
  # errexit it had deliberately suspended — turning this function's own
  # `return 2` into an immediate exit of the whole self-test. A command
  # followed by `||` never trips errexit, so no shell state is touched.
  # `-type l` TERMS, not only `-type f`. `find -type f` does not match a
  # symlink, and neither does it DESCEND through one, so three shapes
  # are invisible to a file-only walk: a symlinked `clippy.toml` (clippy
  # follows it and reads whatever it points at), a symlinked
  # `.cargo/config.toml`, and a symlinked `.cargo` DIRECTORY — the last
  # of which hides an entire config directory from the walk while cargo
  # reads it normally. Untracked, none of them is in `git ls-files`
  # either.
  walk_rc=0
  find_pruned "$root" \
    \( -type f \( -name 'config' -o -name 'config.toml' \) -path '*/.cargo/*' -print0 \) -o \
    \( -type f \( -name 'clippy.toml' -o -name '.clippy.toml' \) -print0 \) -o \
    \( -type l \( -name 'config' -o -name 'config.toml' \) -path '*/.cargo/*' -print0 \) -o \
    \( -type l \( -name 'clippy.toml' -o -name '.clippy.toml' \) -print0 \) -o \
    \( -type l -name '.cargo' -print0 \) > "$list" || walk_rc=$?
  if [[ "$walk_rc" -ne 0 ]]; then
    rm -f "$list"
    echo "fsguard-sites: the stray-config walk of $root failed (find exit $walk_rc) — refused, never treated as clean" >&2
    return 2
  fi
  while IFS= read -r -d '' f; do
    candidates+=("$f")
  done < "$list"
  rm -f "$list"
  if git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    # `-z`: git's default output QUOTES a path containing a newline,
    # a quote or a non-ASCII byte, so a line-oriented read would hand
    # the loop a quoted string that names no file on disk. NUL-separated
    # output is the literal path.
    #
    # Through a FILE with its status checked, never `|| true` into a
    # process substitution. `|| true` turns "git could not list the
    # tracked files" into "git listed no tracked files", and the walk
    # above cannot make up the difference: it is the half that sees
    # UNTRACKED files, so a tracked-but-unwalkable config would pass
    # unseen. The gate says so instead.
    local tracked ls_rc=0
    tracked="$(mktemp)" || return 2
    git -C "$root" ls-files -z -- '*.cargo/config' '*.cargo/config.toml' '*clippy.toml' \
      > "$tracked" 2>/dev/null || ls_rc=$?
    if [[ "$ls_rc" -ne 0 ]]; then
      rm -f "$tracked"
      echo "fsguard-sites: git ls-files could not list the tracked configs under $root (exit $ls_rc) — refused, never treated as clean" >&2
      return 2
    fi
    while IFS= read -r -d '' f; do
      if [[ -n "$f" ]]; then
        candidates+=("$root/$f")
      fi
    done < "$tracked"
    rm -f "$tracked"
  fi
  # The dedup list is an ARRAY, never a `|`-joined string: `|` is a legal
  # byte in a path, and a candidate containing one would make a
  # substring test match a file that was never seen.
  local -a seen=()
  local s dup
  for f in "${candidates[@]}"; do
    dup=0
    for s in ${seen[@]+"${seen[@]}"}; do
      if [[ "$s" == "$f" ]]; then
        dup=1
        break
      fi
    done
    if [[ "$dup" -eq 1 ]]; then
      continue
    fi
    seen+=("$f")
    # THE SYMLINK TEST COMES FIRST, before allowing `.cargo/config`,
    # `.cargo/config.toml`, `clippy.toml`, `crates/granary-client/clippy.toml`,
    # or `crates/granary-cli/clippy.toml`, all relative to the repo root. A
    # symlink at an allowed name is not the audited file: clippy and
    # cargo follow it and read whatever it points at, which may be
    # outside the repo and is certainly not what this gate compared. A
    # linked `.cargo` DIRECTORY is the same answer one level up — the
    # walk cannot descend it, so its contents are unaudited by
    # construction.
    if [[ -L "$f" ]]; then
      echo "DISCOVERY: $f is a SYMLINK. cargo and clippy follow it and read the target; this gate reads — and \`find -type f\` walks — only real files, so what the tools load and what was audited are two different things. Refused wherever it points, including at .cargo/config, .cargo/config.toml, clippy.toml, crates/granary-client/clippy.toml, and crates/granary-cli/clippy.toml (relative to the repo root)." >&2
      rc=1
      continue
    fi
    case "$f" in
      "$root/.cargo/config"|"$root/.cargo/config.toml")
        continue ;;
      # ADDING `"$root/crates/granary-cli/clippy.toml"` TO THIS ARM IS NOT
      # THE WHOLE EDIT, and this note is the tripwire for the half that is
      # easy to forget. This arm makes a config acceptable BY NAME; nothing
      # here reads its BYTES. The cli copy's resolution verdict is INHERITED
      # from the client's (see the ruling at CLIENT_RESOLUTION_CRATE), and
      # that inheritance is only real if check_config_identity and
      # check_closure_premise are CALLED on it at the gate's call sites.
      # BOTH CALLS ARE ALREADY WIRED, at check 9 below, gated on the file's
      # EXISTENCE — so widening this arm is the ONLY edit needed here, and
      # adding a second call pair would duplicate them. They run the moment
      # the file appears.
      "$root/clippy.toml"|"$root/crates/granary-client/clippy.toml"|"$root/crates/granary-cli/clippy.toml")
        continue ;;
      */.cargo/config|*/.cargo/config.toml)
        echo "DISCOVERY: $f is a cargo config outside the repo root's .cargo/. Cargo reads .cargo/config* from the ancestors of the directory it is RUN IN, so this file sets rustflags — and the lint level with them — for anyone whose cwd is under it, and this gate does not read it." >&2
        rc=1 ;;
      */clippy.toml|*/.clippy.toml)
        echo "DISCOVERY: $f is a clippy config outside the three allowed paths: clippy.toml at the repo root, crates/granary-client/clippy.toml, and crates/granary-cli/clippy.toml. Clippy takes the NEAREST clippy.toml at or above the compiled crate's manifest dir and uses only that file — it REPLACES the root file's rows wholesale for that crate rather than merging with them — so this one decides the lint configuration for whatever crate it is nearest to." >&2
        rc=1 ;;
    esac
  done
  return "$rc"
}

# ------------------------------------------------- check 6: source closure
# THE SCANNER'S PREMISE, MADE TRUE BY A GATE INSTEAD OF A COMMENT.
# Checks 3 and 4 read "every `.rs` file under the crate directory, as
# surface syntax". Four constructions break that premise from inside the
# crate, and each was measured on the pinned toolchain to COMPILE while
# scanning clean:
#
#   - `macro_rules!` that takes the lint PATH as an argument —
#       macro_rules! licensed { ($p:path) => { #[allow($p)] … } }
#       licensed!(clippy::all);
#     scans `COUNT 0` with no `ALLOW` line. The call site carries no
#     `allow(`/`expect(` tokens at all, so the outside-an-attribute loop
#     (which closes the `licensed!(expect(clippy::all, …))` spelling)
#     never sees it. Every scanner patch of this class has been followed
#     by a sibling spelling; this is the rule that ends the sequence.
#   - `#[path = "../../outside.rs"] mod evasion;` — rustc compiles a
#     file the walk never visits, and `#![expect(clippy::all, reason =
#     "…")]` at the top of THAT file licenses everything in it.
#   - `include!("…")` — the same, spliced inline. `include_str!` and
#     `include_bytes!` are DATA, not source, and are deliberately not
#     matched.
#   - A SYMLINKED `.rs` file under the crate: `find -type f` skips it,
#     rustc follows it. Not a text pattern, so `find -type l` is what
#     matches it.
#
# The three text shapes are matched by `fsguard-scan.py --source-closure`,
# which reuses the SAME comment/string blanking the count and kill switch
# use — load-bearing, not tidiness: this crate's own module docs contain
# four sentences mentioning `#[path = "…"]` and `include!`, and a raw
# grep refuses the real tree on them.
#
# THE DEPENDENCY HALF is the same premise from the other side: a
# PROC-MACRO dependency can emit an attribute that exists only after
# expansion, which no surface scanner can ever see. Nothing in the
# manifest distinguishes a proc-macro crate from an ordinary one — that
# needs a full resolve (`cargo metadata`), and this gate runs in CI
# BEFORE any cargo command, on a possibly cold registry, so it cannot
# ask. What it can do is pin the set: granary-client's direct
# `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]` and
# their `[target.<cfg>.…]` twins are enumerated below, and NONE of them
# is a proc-macro crate today — measured with `cargo metadata --offline
# --locked` against this lockfile, which reports zero proc-macro
# packages among the crate's direct dependencies. So the allowed
# proc-macro set is EMPTY, and any change to the dependency set is an
# audit change that has to answer the proc-macro question by hand. That
# over-refuses an ordinary new dependency too; adding one to this crate
# already goes through docs/dependency-policy.md, and a gate row to
# update is the cheaper half of that checklist.
#
# THE `fuzz/` MANIFEST IS PINNED THE SAME WAY. It sits inside the walked
# tree, is governed by the same nested clippy.toml, and is its own
# workspace with its own lockfile — so a proc-macro arriving there
# arrives in code this gate's scans cover and its dependency set does
# not otherwise constrain.
# `granary-fuse` joined the set because the mount session implements its
# `GrainFetch` seam, so granary-client gained the path edge. Not a
# proc-macro crate — it has no `[lib] proc-macro = true` and emits no
# attributes — so it cannot hide a lint path from this scanner.
# `fuser` joined the set because the daemon itself constructs
# a `fuser::Session`, takes its `SessionUnmounter` and runs the shutdown
# coordinator — `granary-fuse` must not depend on `granary-client`, so
# this crate is the only one left to do it. Already pinned at the
# workspace line with `default-features = false, features =
# ["macos-no-mount"]` and already in Cargo.lock (granary-fuse's own
# edge); this is a new EDGE, not a new package. Not a proc-macro crate
# either — its own `[lib]` table carries no `proc-macro = true`.
# `granary-vfs` belongs in the audited dependency set because the client
# names the engine through `granary_vfs::` directly.
# `granary-fuse` re-exports NO engine item — every naming of one inside it
# is a private per-file `use granary_vfs::…` — so `granary_fuse::` cannot
# supply one and every consumer must name `granary_vfs::` itself.
# `mount.rs` implements `granary_vfs::GrainFetch` and names `AttrPolicy`,
# `GrainUnavailable`, `Snapshot`, `SnapshotError`; `main.rs` names the
# same plus constructs `granary_vfs::AttrPolicy` directly. Not a
# proc-macro crate — its own `[lib]` table carries no
# `proc-macro = true` and it emits no attributes — so, like the two
# entries above it, it cannot hide a lint path from this scanner.
# rustix is the safe Linux descriptor mount/ACL seam for offline discard.
CLIENT_DEPS_AUDITED="granary-core granary-fuse granary-net granary-store granary-vfs h2 http-body-util hyper hyper-rustls hyper-util libc nix object_store rcgen rustix rustls tokio tokio-rustls tracing tracing-subscriber"
CLIENT_FUZZ_MANIFEST="crates/granary-client/fuzz/Cargo.toml"
CLIENT_FUZZ_DEPS_AUDITED="granary-client libfuzzer-sys"

# The four fuzz workspaces CI clippys by manifest path. Each is its own
# workspace with its own lockfile, so none of them inherits the
# workspace [lints] table this gate audits, and the client's is governed
# by the same nested clippy.toml as the crate itself. A [lints.clippy]
# table added to any of them therefore decides the ban's level for code
# that really gets compiled, so these manifests are audited too.
# Their `.cargo/config*` files are read the same way when present —
# check 5b refuses a nested cargo config outright, and reading it is the
# fail-closed half of that: two answers, not one.
FUZZ_MANIFESTS=(
  "crates/granary-core/fuzz/Cargo.toml"
  "crates/granary-store/fuzz/Cargo.toml"
  "crates/granary-client/fuzz/Cargo.toml"
  "crates/granary-fuse/fuzz/Cargo.toml"
)

# The cargo-config arguments for a fuzz workspace: its own `.cargo/`
# spellings when they exist, and the literal "none" when they do not —
# the same distinction the repo-root arguments draw, so "absent" and
# "unreadable" stay different answers.
fuzz_config_args() { # fuzz_config_args <manifest-path>
  local dir args=()
  dir="$(dirname "$1")"
  [[ -f "$dir/.cargo/config.toml" ]] && args+=("$dir/.cargo/config.toml")
  [[ -f "$dir/.cargo/config" ]] && args+=("$dir/.cargo/config")
  # A TRAILING NEWLINE on every line, "none" included: the caller reads
  # this with `read`, which returns nonzero on a final line without one
  # and drops it — leaving the caller an EMPTY argument list, which is
  # not the same request as "no config file here".
  if [[ "${#args[@]}" -eq 0 ]]; then
    printf 'none\n'
  else
    printf '%s\n' "${args[@]}"
  fi
}

# THE TARGET-PATH HALF is `#[path]`'s manifest spelling. `path = "…"`
# under `[lib]`, `[[bin]]`, `[[test]]`, `[[bench]]` or `[[example]]`
# moves a target's source ROOT, so `[lib] path = "../shared/x.rs"`
# compiles a file outside the walked tree while every `.rs` under the
# crate scans clean.
#
# It cannot be "no path key at all": all three manifests legitimately
# carry some — the client names `src/lib.rs`, the cli `src/main.rs`, the
# fuzz crate its one target — and every one of those values is INSIDE
# the walked tree. So it is the dependency half's shape, an audited SET
# compared in both directions: an added or changed target path is
# refused by name, and a removed one is refused too, so the list cannot
# quietly stop describing the manifests.
# `src/main.rs` LEFT THIS LIST AT THE EXTRACTION. The client's manifest
# declares `[lib] path = "src/lib.rs"` and no `[[bin]]` any more, and the
# comment above is exact that a REMOVED target path is refused too — so
# this audit is what noticed, and the edit is the answer rather than the
# suppression.
CLIENT_TARGET_PATHS_AUDITED="src/lib.rs"
# The cli's audited dependency set, in the same sorted, deduplicated,
# normal-AND-dev form as the client's above (the client's own list
# carries `rcgen`, which is dev-only, so dev-dependencies are in scope
# for both). `granary-client` heads it: the whole point of the split is
# that the binary reaches the library's world through that one edge.
CLI_DEPS_AUDITED="fuser granary-client granary-core granary-fuse granary-net granary-store granary-vfs libc object_store tokio tracing tracing-subscriber"
CLI_TARGET_PATHS_AUDITED="src/main.rs"
CLIENT_FUZZ_TARGET_PATHS_AUDITED="fuzz_targets/anchor_decode.rs fuzz_targets/authority_validate.rs"

# THE SOURCE-CLOSURE AUDIT, AS A TABLE — one row per crate, `|`-separated:
#
#   <crate-dir>|<manifest>|<deps audited>|<target paths audited>|<fuzz manifest>|<fuzz deps>|<fuzz target paths>
#
# The last three fields are EMPTY for a crate with no nested fuzz
# workspace, and the closure collector skips the fuzz half when they are.
#
# Keep a separate row for each crate, including `granary-cli`, using
# that crate's own manifest and audited lists.
# `collect_source_closure` must receive the audited LISTS as parameters
# alongside the manifests. Reading the client's lists as globals would
# audit a second crate against granary-client's dependency set,
# reporting dependencies absent from that set as unlisted even when
# they belong to the second crate's own audit.
# The lists have no defaults, so a caller must supply every audited set
# explicitly instead of silently inheriting another crate's coverage.
AUDITED_CLOSURE_CRATES=(
  "$CRATE_DIR|$CLIENT_MANIFEST|$CLIENT_DEPS_AUDITED|$CLIENT_TARGET_PATHS_AUDITED|$CLIENT_FUZZ_MANIFEST|$CLIENT_FUZZ_DEPS_AUDITED|$CLIENT_FUZZ_TARGET_PATHS_AUDITED"
  "$CLI_CRATE_DIR|$CLI_MANIFEST|$CLI_DEPS_AUDITED|$CLI_TARGET_PATHS_AUDITED|||"
)

scan_source_closure() {
  local list rc=0
  list="$(mktemp)" || return 2
  walk_or_die "$list" "source-closure" "$1" \( -name '*.rs' -print0 \) || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    rm -f "$list"
    return "$rc"
  fi
  python3 "$(dirname "${BASH_SOURCE[0]}")/fsguard-scan.py" --source-closure < "$list"
  rc=$?
  rm -f "$list"
  return "$rc"
}

# Same errexit discipline as scan_or_die, and for the same measured
# reason: a nested failing command substitution does not trip `set -e`,
# so a scanner that crashed would read as "no hits found". The `exit 2`
# below ends THIS SUBSHELL — every caller reads it through `$(...)` —
# so the status is what propagates, and `collect_source_closure` is
# where it becomes the gate's refusal.
source_closure_or_die() {
  local dir="$1"
  local out rc
  set +e
  out="$(scan_source_closure "$dir")"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "fsguard-sites: the source-closure scan failed on $dir (exit $rc) — refused, never treated as clean:" >&2
    echo "$out" >&2
    exit 2
  fi
  printf '%s' "$out"
}

report_source_closure() {
  local hits="$1"
  if [[ -n "$hits" ]]; then
    echo "fsguard-sites: a source-input construction was found that takes rustc outside the files this gate reads — a macro_rules! (whose arm can assemble a lint path from tokens no scanner sees), an #[path] module, the include macro under any name, a symlinked source file or directory, a directory named \`target\` that is not a cargo build root, a Cargo.toml that is neither the crate's nor the fuzz workspace's, or a manifest entry (a dependency, or a target's path) outside the audited set:" >&2
    echo "$hits" >&2
    echo "  The licensed-site count and the bare-allow kill switch are both surface-syntax scans of the walked tree; each of these makes that tree the wrong tree." >&2
    return 1
  fi
  return 0
}

# The symlink half. Prints one finding per line on stdout, and returns
# NONZERO if `find` itself could not complete — the enumeration goes
# through a temp file rather than a process substitution, because a
# process substitution swallows the producer's status entirely: the
# `while` loop simply ends, and an unreadable tree reads as "no
# symlinks".
#
# WHAT IS REFUSED is what rustc could read AS SOURCE through the link:
#   - any symlink whose NAME ends in `.rs` — `find -type f` skips it and
#     rustc follows it (this is the K14 shape);
#   - a symlinked DIRECTORY at, or anywhere under, a root that CARGO
#     TURNS INTO COMPILED SOURCE by itself. Cargo auto-discovers
#     `src/`, `tests/`, `examples/` and `benches/` for the client
#     package, the same four plus `fuzz_targets/` for the nested fuzz
#     package, and CI compiles every one of them because it builds with
#     `--all-targets`. MEASURED on the pinned toolchain, in a scratch
#     package: with `examples`, `tests` and `benches` each a SYMLINK to
#     a directory outside the package, `cargo metadata` lists an
#     example, an integration test and a bench whose `src_path` runs
#     through the link, and `cargo build --all-targets` compiles all
#     three. `fuzz/` ITSELF is in the list for the same reason: linking
#     it moves the whole nested package.
#     The `<root>/*` halves are the module tree hanging off a
#     discovered target, not a second auto-discovery claim — a linked
#     subdirectory INSIDE a real `examples/` is NOT itself discovered
#     (measured), but a `mod`/`#[path]` in a discovered target reaches
#     it, which is exactly K14b's shape one directory up.
# Anything else linked under the crate is not source and is not refused:
# a `fuzz/target` link, a corpus directory, a non-`.rs` asset. That is
# why the rule NAMES the roots instead of refusing everything under
# `fuzz/` — refusing ordinary trees would prove nothing about what rustc
# reads, and `fuzz/target` is the shape K21 pins as allowed.
find_source_symlinks() {
  local root="${1%/}" rel sub rc=0 list
  list="$(mktemp)" || return 1
  set +e
  walk_or_die "$list" "symlink" "$root" \( -type l -print0 \)
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    rm -f "$list"
    return "$rc"
  fi
  while IFS= read -r -d '' rel; do
    case "$rel" in
      *.rs)
        printf '%s: a SYMLINKED .rs file — find -type f skips it and rustc follows it\n' "$rel"
        continue ;;
    esac
    # `-d` FOLLOWS the link, which is the question being asked: does
    # this name bring a directory of source into the build.
    if [[ -d "$rel" ]]; then
      sub="${rel#"$root"/}"
      case "$sub" in
        src|src/*|tests|tests/*|examples|examples/*|benches|benches/*|fuzz|\
        fuzz/src|fuzz/src/*|fuzz/tests|fuzz/tests/*|\
        fuzz/examples|fuzz/examples/*|fuzz/benches|fuzz/benches/*|\
        fuzz/fuzz_targets|fuzz/fuzz_targets/*)
          printf '%s: a SYMLINKED DIRECTORY at or under a cargo target root — rustc follows it into a subtree this gate never walked\n' "$rel" ;;
      esac
    fi
  done < "$list"
  rm -f "$list"
  return 0
}

# A `target` DIRECTORY the prune did not take. `find_pruned` prunes a
# cargo target ROOT — `CACHEDIR.TAG` plus a sibling `Cargo.toml` — so
# anything named `target` that survives the walk is not one: either a
# build directory missing half its identity, or a source directory that
# borrowed cargo's name. Both are refused, and the second is the one
# that matters: `crates/granary-client/src/target/` with a
# `CACHEDIR.TAG` dropped in it and a `mod target;` in lib.rs is a real
# module tree that rustc compiles, and under a tag-only prune every
# `.rs` in it is invisible to the licensed-site count, the bare-allow
# kill switch and the source-closure scan at once.
#
# Same temp-file discipline as every other walk here: a `find` that
# could not complete returns 2 and is never read as "no such directory".
# THE PRUNE'S OWN PREMISE, and a foreign manifest.
#
# The prune skips a directory named `target` only when it carries
# `CACHEDIR.TAG` AND has a sibling `Cargo.toml` — so anything named
# `target` that survives the walk is not a cargo build root, and is
# refused (a `src/target/` with a tag dropped in it is a module tree
# rustc compiles).
#
# But the sibling test is only as good as the manifests under the crate.
# `crates/granary-client/src/Cargo.toml` next to `src/target/CACHEDIR.TAG`
# satisfies BOTH conditions and prunes a source tree again — the same
# hole one level up. So the audited manifest set is pinned the way every
# other set here is: exactly two files, `<crate>/Cargo.toml` and
# `<crate>/fuzz/Cargo.toml`, and any other `Cargo.toml` under the crate
# is foreign. It is a finding on its own terms too — cargo treats a
# nested manifest as a package, so one under `src/` changes what is
# compiled and what config is nearest, neither of which this gate reads.
#
# ONE WALK for both questions, so a `find` that fails cannot answer one
# and silently skip the other.
find_foreign_tree_entries() {
  local root="${1%/}" rel sub rc=0 list
  list="$(mktemp)" || return 1
  # `-type l` TERMS beside the `-type f` one. A SYMLINK named
  # `Cargo.toml` or `CACHEDIR.TAG` is what defeats the build-root prune
  # from inside the crate, and `find -type f` matches neither — so
  # before these terms the plant was invisible to the walk that exists
  # to refuse it. Refused wherever it points and whether or not it is
  # tracked: a manifest reached through a link is not the manifest this
  # gate read, and a tag reached through one is not evidence that cargo
  # wrote the directory.
  set +e
  walk_or_die "$list" "target-directory and manifest" "$root" \
    \( -type d -name target -print0 \) -o \
    \( -type f -name Cargo.toml -print0 \) -o \
    \( -type l \( -name Cargo.toml -o -name CACHEDIR.TAG \) -print0 \)
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    rm -f "$list"
    return "$rc"
  fi
  while IFS= read -r -d '' rel; do
    sub="${rel#"$root"/}"
    # THE LINK TEST COMES FIRST, before the two allowed manifest paths:
    # a symlink AT an allowed name is not the audited manifest either,
    # and it is exactly what a plant would choose.
    if [[ -L "$rel" ]]; then
      printf '%s: a SYMLINK named `%s`. The build-root prune tests these two names to decide whether a directory belongs to cargo, and `test -e`/`-f` follow a link — so a link here answers for a file this gate never read, and prunes the tree beneath it out of every scan\n' \
        "$rel" "${rel##*/}"
      continue
    fi
    case "$sub" in
      Cargo.toml|fuzz/Cargo.toml)
        continue ;;
      */Cargo.toml|Cargo.toml*)
        printf '%s: a Cargo.toml that is neither the crate manifest nor the fuzz workspace one — cargo reads a nested manifest as its own package, and beside a CACHEDIR.TAG it also satisfies the build-root prune, hiding the tree under it from every scan here\n' "$rel"
        continue ;;
    esac
    printf '%s: a directory named `target` that is NOT a cargo build root (no CACHEDIR.TAG beside a sibling Cargo.toml) — rustc compiles what is under it, and a tag-only prune would hide every .rs in it from all three scans\n' "$rel"
  done < "$list"
  rm -f "$list"
  return 0
}

# THE ONE assembly of check 6's halves, called by the real gate and by
# every control — a control that reassembles them separately proves
# nothing about what the gate actually runs.
#
# Capture and return each component's status. A
# failing command substitution exits its own
# subshell, and callers using conditional invocation
# cannot rely on errexit to stop the whole check.
# An empty result after failure must not become
# a clean summary; the wrapper propagates a
# nonzero status for the caller to reject.
collect_source_closure() {
  local dir="$1" manifest="$2" fuzz_manifest="$3"
  # Require audited dependencies and target paths
  # as arguments alongside the manifest. Defaulting
  # those sets to one crate's globals could
  # audit another manifest against the wrong
  # expectations. An omitted required argument
  # fails at the call site under `set -u`.
  local deps="$4" targets="$5"
  local fuzz_deps="${6:-}" fuzz_targets="${7:-}"
  local text hits="" rc

  set +e
  text="$(source_closure_or_die "$dir")"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "fsguard-sites: the source-closure text scan could not complete (exit $rc) — refused, never treated as clean" >&2
    return 1
  fi
  if [[ -n "$text" ]]; then
    hits+="$text"$'\n'
  fi

  set +e
  text="$(find_source_symlinks "$dir")"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "fsguard-sites: the symlink half of the source closure could not complete (exit $rc) — refused, never treated as clean" >&2
    return 1
  fi
  if [[ -n "$text" ]]; then
    hits+="$text"$'\n'
  fi

  set +e
  text="$(find_foreign_tree_entries "$dir")"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "fsguard-sites: the target-directory/manifest half of the source closure could not complete (exit $rc) — refused, never treated as clean" >&2
    return 1
  fi
  if [[ -n "$text" ]]; then
    hits+="$text"$'\n'
  fi

  set +e
  text="$(check_manifest_closure "$manifest" "$deps" "$targets")"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "fsguard-sites: the manifest half of the source closure could not complete on $manifest (exit $rc) — refused, never treated as clean" >&2
    return 1
  fi
  if [[ -n "$text" ]]; then
    hits+="$text"$'\n'
  fi

  # A crate with no nested fuzz workspace passes an EMPTY fuzz manifest and
  # the half is skipped. `granary-cli` is that case. Skipping is stated
  # here rather than left to `check_manifest_closure` returning nothing,
  # because a missing manifest is one of the conditions that function
  # exits 2 on, and "this crate has no fuzz workspace" must not read as
  # "this crate's fuzz manifest could not be parsed".
  #
  # AND THE EMPTINESS IS VERIFIED AGAINST THE TREE, NEVER TRUSTED. A row
  # that declares no fuzz manifest while the crate HAS one would skip that
  # workspace's audit entirely — and `find_foreign_tree_entries` would not
  # catch it either, because its `case` arm whitelists `fuzz/Cargo.toml`
  # unconditionally. The two halves would then agree the file is fine, one
  # because it was told to skip it and the other because it is always
  # allowed. EXECUTED before this guard existed: a crate whose
  # `fuzz/Cargo.toml` declared an unaudited proc-macro dependency AND a
  # `[[bin]] path = "../../../outside.rs"` returned rc 0 and EMPTY hits.
  if [[ -z "$fuzz_manifest" && -f "$dir/fuzz/Cargo.toml" ]]; then
    echo "fsguard-sites: $dir declares NO fuzz manifest in its audited-closure row, but $dir/fuzz/Cargo.toml exists — refused. An empty fuzz field means 'this crate has no fuzz workspace', and nothing else audits one that is there." >&2
    return 1
  fi
  if [[ -n "$fuzz_manifest" ]]; then
    set +e
    text="$(check_manifest_closure "$fuzz_manifest" "$fuzz_deps" "$fuzz_targets")"
    rc=$?
    set -e
    if [[ "$rc" -ne 0 ]]; then
      echo "fsguard-sites: the manifest half of the source closure could not complete on $fuzz_manifest (exit $rc) — refused, never treated as clean" >&2
      return 1
    fi
    if [[ -n "$text" ]]; then
      hits+="$text"$'\n'
    fi
  fi

  printf '%s' "$hits"
}

# The LOOP must visit every crate row, including granary-cli's.
# It is a FUNCTION rather than a loop inlined at the gate for the
# reason control P5 checks elsewhere in this file: a control that drove
# its own inline loop would stay green if the gate stopped calling it.
# Control W2 drives this function and plants a SECOND row.
# **A loop that never reaches row two is indistinguishable from one
# that does when tested with only one row**, so the fixture must exercise
# the second row regardless of the checked tree's current table contents.
collect_audited_closures() {
  local row hits="" row_hits row_pipes seen_dirs=""
  # THE VISITED ROWS ARE RECORDED TO A FILE, NOT A VARIABLE, and the file is
  # why this works at all: every caller invokes this in a COMMAND
  # SUBSTITUTION, which is a SUBSHELL, so a global assigned here never
  # reaches the gate. EXECUTED before the file existed: the summary printed
  # `CLOSURE-AUDITED: (none)` on a run that had audited the crate correctly
  # — a clause that publishes nothing is worse than no clause, because it
  # reads as coverage.
  #
  # Appended INSIDE the loop, AFTER the row's collection succeeds, never
  # built from the table — for the reason control P5 states about itself:
  # a name appended from the loop variable is bookkeeping the work never
  # touched, and publishing it leaves a truncated call site green.
  [[ -n "${CLOSURE_AUDIT_LOG:-}" ]] && : > "$CLOSURE_AUDIT_LOG"
  local c_dir c_manifest c_deps c_targets c_fmanifest c_fdeps c_ftargets
  if [[ $# -eq 0 ]]; then
    echo "fsguard-sites: the audited-closure table is EMPTY — refused rather than reporting a clean closure over no crates at all." >&2
    return 2
  fi
  for row in "$@"; do
    IFS='|' read -r c_dir c_manifest c_deps c_targets c_fmanifest c_fdeps c_ftargets <<<"$row"
    # THE FIELD COUNT, not just the first two. `IFS='|' read` fills missing
    # trailing fields with "" and returns 0 (EXECUTED: four fields into seven
    # variables gives rc 0 and three empty), so a row written with its
    # trailing pipes omitted would silently drop the whole fuzz half —
    # including granary-client's, which control K16c exists to prove runs.
    # A row is SEVEN fields: six separators, no more and no fewer.
    row_pipes="${row//[^|]/}"
    if [[ "${#row_pipes}" -ne 6 ]]; then
      echo "fsguard-sites: an audited-closure row has ${#row_pipes} '|' separators, want exactly 6 (seven fields, the last three empty for a crate with no fuzz workspace): '$row'" >&2
      return 2
    fi
    if [[ -z "$c_dir" || -z "$c_manifest" ]]; then
      echo "fsguard-sites: an audited-closure row names no crate directory or no manifest: '$row'" >&2
      return 2
    fi
    # THE MANIFESTS MUST BELONG TO THE ROW'S CRATE DIRECTORY. Without this a
    # row can point at a DECOY: the walk covers `$c_dir` while the manifest
    # half audits some other file, so the crate's real `Cargo.toml` —
    # declaring whatever it likes — is audited by nothing.
    # `find_foreign_tree_entries` does not object either, because its `case`
    # arm whitelists both `Cargo.toml` and `fuzz/Cargo.toml` unconditionally.
    # This is the SAME fail-open the empty-fuzz guard below closes, in the
    # non-empty case, and its trigger is the copy-paste that adds a second
    # row. (`closure_case`'s planted fixtures pass loose paths deliberately;
    # they call `collect_source_closure` DIRECTLY and never come through
    # here.)
    if [[ "$c_manifest" != "$c_dir/Cargo.toml" ]]; then
      echo "fsguard-sites: audited-closure row manifest '$c_manifest' is not '$c_dir/Cargo.toml' — refused. A row whose manifest does not belong to its own directory audits a file the walk never covers." >&2
      return 2
    fi
    if [[ -n "$c_fmanifest" && "$c_fmanifest" != "$c_dir/fuzz/Cargo.toml" ]]; then
      echo "fsguard-sites: audited-closure row fuzz manifest '$c_fmanifest' is not '$c_dir/fuzz/Cargo.toml' — refused, same reason." >&2
      return 2
    fi
    case " $seen_dirs " in
      *" $c_dir "*)
        echo "fsguard-sites: crate directory '$c_dir' appears in more than one audited-closure row — refused. A duplicate is either a copy-paste that forgot to change the directory, or two rows disagreeing about one crate's audited sets." >&2
        return 2 ;;
    esac
    seen_dirs="$seen_dirs $c_dir"
    if ! row_hits="$(collect_source_closure "$c_dir" "$c_manifest" "$c_fmanifest" "$c_deps" "$c_targets" "$c_fdeps" "$c_ftargets")"; then
      return 2
    fi
    if [[ -n "$row_hits" ]]; then
      hits+="$row_hits"$'\n'
    fi
    [[ -n "${CLOSURE_AUDIT_LOG:-}" ]] && printf '%s\n' "$c_dir" >> "$CLOSURE_AUDIT_LOG"
  done
  printf '%s' "$hits"
}

# Prints one finding per line on stdout and EXITS 0 when it completed —
# findings are the caller's to report. A failure to complete (a missing
# or unparsable manifest, a python too old for `tomllib`) exits 2 with
# one line, never an empty stdout the caller would read as "clean": a
# python traceback exits 1, which is indistinguishable from "found
# nothing" if 1 meant findings.
check_manifest_closure() {
  local manifest="$1" audited_deps="$2" audited_paths="$3"
  python3 - "$manifest" "$audited_deps" "$audited_paths" <<'PYEOF'
import sys

# Same prerequisite, same refusal, as check_config's program: `tomllib`
# is stdlib only from PYTHON 3.11, and a missing prerequisite must read
# as a refusal rather than surface as a ModuleNotFoundError traceback.
if sys.version_info < (3, 11):
    print(
        "HARNESS: this gate parses TOML with `tomllib`, which needs python 3.11 or newer "
        f"(found {sys.version_info.major}.{sys.version_info.minor}). Install a newer python3, "
        "or run this gate under one — REFUSED, never treated as clean.",
        file=sys.stderr,
    )
    sys.exit(2)

import tomllib  # noqa: E402 — deliberately after the version guard above

try:
    manifest = sys.argv[1]
    audited_deps = set(sys.argv[2].split())
    audited_paths = set(sys.argv[3].split())
    with open(manifest, "rb") as f:
        m = tomllib.load(f)
    declared = set()
    for table in ("dependencies", "dev-dependencies", "build-dependencies"):
        declared |= set(m.get(table, {}))
        # `[target.'cfg(unix)'.dependencies]` and its dev/build twins are
        # ordinary dependency tables that a plain top-level read never
        # sees — a proc-macro can arrive under any cfg.
        for cfg in m.get("target", {}).values():
            if isinstance(cfg, dict):
                declared |= set(cfg.get(table, {}))
    paths = set()
    for key in ("lib", "bin", "test", "bench", "example"):
        entries = m.get(key)
        if isinstance(entries, dict):  # [lib] is a table; the rest are arrays
            entries = [entries]
        if not isinstance(entries, list):
            continue
        for e in entries:
            if isinstance(e, dict) and isinstance(e.get("path"), str):
                paths.add(e["path"])
except Exception as e:  # noqa: BLE001 — any failure here is a refusal, never a clean answer
    print(f"could not read the manifest ({e}) — refused, never treated as clean",
          file=sys.stderr)
    sys.exit(2)

for name in sorted(declared - audited_deps):
    print(
        f"{manifest}: dependency `{name}` is not in the audited set — a PROC-MACRO dependency "
        "emits attributes that exist only after expansion, which no surface scanner can see, "
        "and this gate cannot resolve which kind this one is"
    )
for name in sorted(audited_deps - declared):
    print(
        f"{manifest}: audited dependency `{name}` is gone from the manifest — update the "
        "audited set, so that it keeps describing what the crate really pulls in"
    )
for target_path in sorted(paths - audited_paths):
    print(
        f"{manifest}: target path `{target_path}` is not in the audited set — a target's "
        "`path` key moves its source ROOT, which is #[path]'s manifest spelling and can name "
        "a file outside the tree this gate walks"
    )
for target_path in sorted(audited_paths - paths):
    print(
        f"{manifest}: audited target path `{target_path}` is gone from the manifest — update "
        "the audited set, so that it keeps describing what the crate really compiles"
    )
PYEOF
}

# ------------------------------------------------------------------ self-test
if [[ "${1:-}" == "--self-test" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  fail=0

  # A fixture-mutation step that cannot find its target text means the
  # real clippy.toml changed shape — report THAT distinctly (exit 3) so
  # it never gets misread as "the control passed" or "the control failed
  # as expected". The mutation body's own `assert` is caught INSIDE
  # python and reported as ONE clean line — never a raw traceback — via
  # a wrapper that runs the caller's code inside a try/except.
  mutate_or_die() {
    local label="$1" body="$2"
    if ! python3 -c "
import sys
def _mutation():
$(printf '%s\n' "$body" | sed 's/^/    /')
try:
    _mutation()
except AssertionError as e:
    print(f'fixture assumption failed: {e}', file=sys.stderr)
    sys.exit(1)
except Exception as e:  # noqa: BLE001 — this IS the self-test's own error boundary
    print(f'unexpected error while mutating the fixture: {e!r}', file=sys.stderr)
    sys.exit(1)
" 2>"$tmp/mutate.err"; then
      echo "self-test BROKEN: control $label's fixture assumption no longer holds:" >&2
      cat "$tmp/mutate.err" >&2
      exit 3
    fi
  }

  # THE ONE PLACE a self-test fixture copies $CRATE_SRC's CONTENTS into
  # an already-created directory. Stated precisely because it is NOT
  # the one place $CRATE_SRC is
  # copied at all: many other sites still do
  # `cp -R "$CRATE_SRC" "$dir"` into a NON-EXISTENT dir, which is
  # recursive and correct, and which the flat-glob trap never reached.
  # Count fixture-copy call sites from code
  # if needed, excluding prose matches. A
  # hand-maintained count would not establish
  # that a particular caller copies
  # subdirectories; the behavioral control
  # exercises the shared helper instead.
  # The contents-into-existing-directory
  # form uses `/.` so subdirectories are
  # copied too. The helper centralizes that
  # operation. T6 plants a licence under
  # a subdirectory in a fixture built by
  # this helper and requires it to be
  # counted. A flat `*.rs` copy would omit
  # that plant. Keeping the fixture
  # construction on the same helper used
  # by the callers lets this control exercise
  # their copy mechanism rather than an
  # independently reconstructed copy.
  copy_crate_src_fixture() {
    local dir="$1"
    mkdir -p "$dir"
    cp -R "$CRATE_SRC"/. "$dir/"
  }

  # ---- control A: superset drift, ISOLATED to disallowed-macros/
  # disallowed-types — a disallowed-methods row would ALSO trip the
  # anchoring check (check 2), so it cannot prove check 1 alone can
  # fail. Removing a disallowed-types row cannot: anchoring never looks
  # at that key at all.
  cp "$CLIENT_CLIPPY" "$tmp/client_missing_type_row.toml"
  mutate_or_die "A" '
import pathlib
p = pathlib.Path("'"$tmp"'/client_missing_type_row.toml")
text = p.read_text()
needle = "{ path = \"std::collections::HashMap\", reason = \"BTreeMap or seeded hasher in core\" },\n"
assert needle in text, "fixture row not found verbatim — clippy.toml text changed"
p.write_text(text.replace(needle, "", 1))
'
  if out="$(check_config "$ROOT_CLIPPY" "$tmp/client_missing_type_row.toml" 2>&1)"; then
    echo "self-test FAILED: control A (removed disallowed-types row) did not fail" >&2
    fail=1
  elif ! grep -q "std::collections::HashMap" <<<"$out" || grep -q "^ANCHOR" <<<"$out"; then
    echo "self-test FAILED: control A failed but not the way expected (superset only, naming the row):" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control A (removed disallowed-types row) — FAILED the superset check ONLY, naming the row, as expected"
  fi

  # ---- control A2: a DUPLICATED disallowed-types row in a COPY must
  # fail the superset check too — a set-based comparison would not have
  # noticed — duplicate rows pass a set comparison silently.
  cp "$CLIENT_CLIPPY" "$tmp/client_dup_type_row.toml"
  mutate_or_die "A2" '
import pathlib
p = pathlib.Path("'"$tmp"'/client_dup_type_row.toml")
text = p.read_text()
needle = "{ path = \"std::collections::HashMap\", reason = \"BTreeMap or seeded hasher in core\" },\n"
assert needle in text, "fixture row not found verbatim — clippy.toml text changed"
p.write_text(text.replace(needle, needle + needle, 1))
'
  if out="$(check_config "$ROOT_CLIPPY" "$tmp/client_dup_type_row.toml" 2>&1)"; then
    echo "self-test FAILED: control A2 (duplicated disallowed-types row) did not fail" >&2
    fail=1
  elif ! grep -q "std::collections::HashMap" <<<"$out"; then
    echo "self-test FAILED: control A2 failed but did not name the row:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control A2 (duplicated disallowed-types row) — FAILED naming the row, as expected"
  fi

  # ---- control A3: a ROOT `disallowed-methods` row removed from the
  # client copy must be named by the SUPERSET check — not only by the
  # ANCHOR one. Without it, nothing exercises the `disallowed-methods`
  # arm of check 1 at all (control A deliberately targets
  # `disallowed-types`, which goes through the EXACT_LIST_KEYS/Counter
  # arm and its `(xN)` message), and a mutation of that arm survives.
  # It is genuinely reachable — this control is the proof.
  cp "$CLIENT_CLIPPY" "$tmp/client_missing_root_method.toml"
  mutate_or_die "A3" '
import pathlib
p = pathlib.Path("'"$tmp"'/client_missing_root_method.toml")
text = p.read_text()
needle = "{ path = \"std::time::Instant::now\", reason = \"use the Clock seam\" },\n"
assert needle in text, "fixture row not found verbatim — clippy.toml text changed"
p.write_text(text.replace(needle, "", 1))
'
  if out="$(check_config "$ROOT_CLIPPY" "$tmp/client_missing_root_method.toml" 2>&1)"; then
    echo "self-test FAILED: control A3 (removed a root disallowed-methods row) did not fail" >&2
    fail=1
  elif ! grep -q "^SUPERSET: disallowed-methods row from root missing in client: 'std::time::Instant::now'" <<<"$out"; then
    echo "self-test FAILED: control A3 failed but the SUPERSET check did not name the row (only ANCHOR did?):" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control A3 (removed a ROOT disallowed-methods row) — the SUPERSET check named it, as expected"
  fi

  # ---- control A4: the OTHER surviving branch — a list-valued root
  # top-level key that is NOT one of the three row keys. No such key
  # exists in clippy.toml today, so the branch is unreachable with the
  # real files and no mutation of it could ever be killed; it is
  # reachable the moment someone adds one, which is exactly when it
  # matters. Both configs are copied and given the key, with a row
  # missing from the client side.
  cp "$ROOT_CLIPPY" "$tmp/root_extra_list_key.toml"
  cp "$CLIENT_CLIPPY" "$tmp/client_extra_list_key.toml"
  printf '\nprobe-list-key = ["alpha", "beta"]\n' >> "$tmp/root_extra_list_key.toml"
  printf '\nprobe-list-key = ["alpha"]\n' >> "$tmp/client_extra_list_key.toml"
  if out="$(check_config "$tmp/root_extra_list_key.toml" "$tmp/client_extra_list_key.toml" 2>&1)"; then
    echo "self-test FAILED: control A4 (non-row list key with a missing entry) did not fail" >&2
    fail=1
  elif ! grep -q "^SUPERSET: probe-list-key row from root missing in client: 'beta'" <<<"$out"; then
    echo "self-test FAILED: control A4 failed but did not name the missing list entry:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control A4 (a non-row list-valued root key with an entry missing from the client) — named the entry, as expected"
  fi

  # ---- control B: a flipped scalar in a COPY must fail the superset
  # check, naming the key.
  cp "$CLIENT_CLIPPY" "$tmp/client_flipped_scalar.toml"
  mutate_or_die "B" '
import pathlib
p = pathlib.Path("'"$tmp"'/client_flipped_scalar.toml")
text = p.read_text()
needle = "allow-unwrap-in-tests = true"
assert needle in text, "fixture scalar not found verbatim — clippy.toml text changed"
p.write_text(text.replace(needle, "allow-unwrap-in-tests = false", 1))
'
  if out="$(check_config "$ROOT_CLIPPY" "$tmp/client_flipped_scalar.toml" 2>&1)"; then
    echo "self-test FAILED: control B (flipped scalar) did not fail" >&2
    fail=1
  elif ! grep -q "allow-unwrap-in-tests" <<<"$out"; then
    echo "self-test FAILED: control B failed but did not name the key:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control B (flipped allow-unwrap-in-tests) — FAILED naming the key, as expected"
  fi

  # ---- control C: a removed fs row in a COPY must fail the anchoring
  # check specifically (the superset check alone would stay green, since
  # fs rows are not in the root file).
  cp "$CLIENT_CLIPPY" "$tmp/client_missing_fs_row.toml"
  mutate_or_die "C" '
import pathlib
p = pathlib.Path("'"$tmp"'/client_missing_fs_row.toml")
text = p.read_text()
needle = "{ path = \"std::fs::write\", reason = \"route filesystem access through fsguard, or license the site with #[expect] and a written reason\" },\n"
assert needle in text, "fixture fs row not found verbatim — clippy.toml text changed"
p.write_text(text.replace(needle, "", 1))
'
  if out="$(check_config "$ROOT_CLIPPY" "$tmp/client_missing_fs_row.toml" 2>&1)"; then
    echo "self-test FAILED: control C (removed fs row) did not fail" >&2
    fail=1
  elif ! grep -q "ANCHOR.*std::fs::write" <<<"$out"; then
    echo "self-test FAILED: control C failed but did not name the fs row via ANCHOR:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control C (removed fs row) — FAILED the anchoring check, as expected"
  fi

  # ---- control C2: an fs row present by PATH but with an EDITED reason
  # must also fail the anchoring check — a paths-only comparison would
  # miss it.
  cp "$CLIENT_CLIPPY" "$tmp/client_edited_fs_reason.toml"
  mutate_or_die "C2" '
import pathlib
p = pathlib.Path("'"$tmp"'/client_edited_fs_reason.toml")
text = p.read_text()
needle = "{ path = \"std::fs::write\", reason = \"route filesystem access through fsguard, or license the site with #[expect] and a written reason\" }"
assert needle in text, "fixture fs row not found verbatim — clippy.toml text changed"
p.write_text(text.replace(needle, "{ path = \"std::fs::write\", reason = \"edited\" }", 1))
'
  if out="$(check_config "$ROOT_CLIPPY" "$tmp/client_edited_fs_reason.toml" 2>&1)"; then
    echo "self-test FAILED: control C2 (edited fs-row reason, same path) did not fail" >&2
    fail=1
  elif ! grep -q "^ANCHOR.*std::fs::write" <<<"$out"; then
    echo "self-test FAILED: control C2 failed but did not name the row via ANCHOR:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control C2 (edited fs-row reason, path unchanged) — FAILED the anchoring check, as expected"
  fi

  # ---- control C3: a DUPLICATED fs row in a COPY must fail the
  # anchoring check (multiset, not set).
  cp "$CLIENT_CLIPPY" "$tmp/client_dup_fs_row.toml"
  mutate_or_die "C3" '
import pathlib
p = pathlib.Path("'"$tmp"'/client_dup_fs_row.toml")
text = p.read_text()
needle = "{ path = \"std::fs::write\", reason = \"route filesystem access through fsguard, or license the site with #[expect] and a written reason\" },\n"
assert needle in text, "fixture fs row not found verbatim — clippy.toml text changed"
p.write_text(text.replace(needle, needle + needle, 1))
'
  if out="$(check_config "$ROOT_CLIPPY" "$tmp/client_dup_fs_row.toml" 2>&1)"; then
    echo "self-test FAILED: control C3 (duplicated fs row) did not fail" >&2
    fail=1
  elif ! grep -q "^ANCHOR.*std::fs::write" <<<"$out"; then
    echo "self-test FAILED: control C3 failed but did not name the row via ANCHOR:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control C3 (duplicated fs row) — FAILED the anchoring check, as expected"
  fi

  # ---- control C6: a row duplicated on the EXPECTED side. The
  # normative list is the gate's own data, and it was compared as a SET
  # — so a path written twice in FS_ROWS collapsed to one and still
  # matched a client config holding it once. Duplicate detection ran in
  # one direction only. Both sides are multisets now, and this control
  # is the half that was never covered.
  printf '%s\n' "${FS_ROWS[@]}" > "$tmp/fs_rows_dup.txt"
  printf '%s\n' "${FS_ROWS[0]}" >> "$tmp/fs_rows_dup.txt"
  if out="$(check_config "$ROOT_CLIPPY" "$CLIENT_CLIPPY" "$tmp/fs_rows_dup.txt" 2>&1)"; then
    echo "self-test FAILED: control C6 (fs row duplicated in the EXPECTED list) did not fail" >&2
    fail=1
  elif ! grep -q "^ANCHOR.*${FS_ROWS[0]}" <<<"$out"; then
    echo "self-test FAILED: control C6 failed but did not name the duplicated row via ANCHOR:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control C6 (a row duplicated on the EXPECTED side, not the client one) — FAILED the anchoring check, as expected"
  fi

  # ---- control C7: the same override path with the REAL list must
  # still pass. Without it, control C6 would also pass if the override
  # simply broke check_config.
  printf '%s\n' "${FS_ROWS[@]}" > "$tmp/fs_rows_real.txt"
  if ! out="$(check_config "$ROOT_CLIPPY" "$CLIENT_CLIPPY" "$tmp/fs_rows_real.txt" 2>&1)"; then
    echo "self-test FAILED: control C7 (override with the REAL row list) did not pass:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control C7 (the same override mechanism carrying the REAL list) — passes, as expected"
  fi

  # ---- control C8: a shared top-level key whose TYPE differs between
  # the two files. A client `disallowed-types = "x"` where the root has
  # a list turns the superset loop's `row not in client_list` into a
  # SUBSTRING test, and an integer raises a bare `TypeError` out of the
  # Counter — a pass and a crash, neither of them a refusal. Graceful
  # exit 2, MALFORMED, naming the key and the type found.
  cp "$CLIENT_CLIPPY" "$tmp/client_type_mismatch.toml"
  mutate_or_die "C8" '
import pathlib
p = pathlib.Path("'"$tmp"'/client_type_mismatch.toml")
text = p.read_text()
start_needle = "disallowed-types = ["
assert start_needle in text, "fixture disallowed-types list not found — clippy.toml text changed"
start = text.index(start_needle)
end_needle = "\n]\n"
assert end_needle in text[start:], "fixture disallowed-types list is not terminated as expected"
end = start + text[start:].index(end_needle) + len(end_needle)
p.write_text(text[:start] + "disallowed-types = \"x\"\n" + text[end:])
'
  set +e
  out="$(check_config "$ROOT_CLIPPY" "$tmp/client_type_mismatch.toml" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 2 ]]; then
    echo "self-test FAILED: control C8 (disallowed-types is a string in the client) exited $rc, wanted 2 (graceful, not a crash and not a pass):" >&2
    echo "$out" >&2
    fail=1
  elif ! grep -q "MALFORMED" <<<"$out" || ! grep -q "disallowed-types" <<<"$out" || ! grep -q "str" <<<"$out"; then
    echo "self-test FAILED: control C8 exited 2 but did not report MALFORMED naming the key and the type found:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control C8 (client disallowed-types = \"x\", a string where root has a list) — graceful exit 2, MALFORMED naming the key and the type, as expected"
  fi

  # ---- control C4: a disallowed-methods row missing its `reason` key
  # in a COPY must be a graceful exit(2), never a raw KeyError.
  cp "$CLIENT_CLIPPY" "$tmp/client_malformed_row.toml"
  mutate_or_die "C4" '
import pathlib
p = pathlib.Path("'"$tmp"'/client_malformed_row.toml")
text = p.read_text()
needle = "{ path = \"std::fs::write\", reason = \"route filesystem access through fsguard, or license the site with #[expect] and a written reason\" }"
assert needle in text, "fixture fs row not found verbatim — clippy.toml text changed"
p.write_text(text.replace(needle, "{ path = \"std::fs::write\" }", 1))
'
  set +e
  out="$(check_config "$ROOT_CLIPPY" "$tmp/client_malformed_row.toml" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 2 ]]; then
    echo "self-test FAILED: control C4 (row missing 'reason') exited $rc, wanted 2 (graceful, not a crash):" >&2
    echo "$out" >&2
    fail=1
  elif ! grep -q "MALFORMED" <<<"$out"; then
    echo "self-test FAILED: control C4 exited 2 but did not report MALFORMED:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control C4 (row missing 'reason') — graceful exit 2, no traceback, as expected"
  fi

  # ---- control C5: a row with a NON-SCALAR field value (a TOML array)
  # must also be a graceful exit(2), never a raw
  # `TypeError: unhashable type: 'list'` traceback out of the Counter
  # construction — `row_key`'s `tuple(sorted(row.items()))` is only
  # hashable if every field is, and the missing-key path is not the only
  # malformed shape that has to reach a clean refusal.
  cp "$CLIENT_CLIPPY" "$tmp/client_nonscalar_row.toml"
  mutate_or_die "C5" '
import pathlib
p = pathlib.Path("'"$tmp"'/client_nonscalar_row.toml")
text = p.read_text()
needle = "{ path = \"std::fs::write\", reason = \"route filesystem access through fsguard, or license the site with #[expect] and a written reason\" }"
assert needle in text, "fixture fs row not found verbatim — clippy.toml text changed"
p.write_text(text.replace(needle, "{ path = \"std::fs::write\", reason = \"r\", allow-invalid = [1, 2] }", 1))
'
  set +e
  out="$(check_config "$ROOT_CLIPPY" "$tmp/client_nonscalar_row.toml" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 2 ]]; then
    echo "self-test FAILED: control C5 (row with a non-scalar field) exited $rc, wanted 2 (graceful, not a TypeError traceback):" >&2
    echo "$out" >&2
    fail=1
  elif ! grep -q "MALFORMED" <<<"$out" || grep -q "Traceback" <<<"$out"; then
    echo "self-test FAILED: control C5 exited 2 but did not report MALFORMED cleanly:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control C5 (row with a non-scalar field value) — graceful exit 2, no traceback, as expected"
  fi

  # ---- control D: a planted extra licensed-looking site in a COPIED
  # tree must fail the SAME comparison (report_count) the real gate
  # calls, not a hand-rolled restatement of it.
  cp -R "$CRATE_SRC" "$tmp/src_planted"
  cat >> "$tmp/src_planted/planted.rs" <<'RS'
#[expect(
    clippy::disallowed_methods,
    reason = "self-test plant"
)]
fn planted() {}
RS
  planted_scan="$(scan_or_die "$tmp/src_planted")"
  planted_count="$(scanned_count "$planted_scan")"
  if out="$(report_count "$planted_count" "$EXPECTED_LICENSED_SITES" "$tmp/src_planted" 2>&1)"; then
    echo "self-test FAILED: control D (planted extra site) — report_count did not refuse it" >&2
    fail=1
  elif ! grep -q "has $planted_count" <<<"$out" || ! grep -q "expects $EXPECTED_LICENSED_SITES" <<<"$out"; then
    echo "self-test FAILED: control D refused but the message did not name the counts:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control D (planted extra licensed site) — report_count refused it, as expected ($planted_count vs $EXPECTED_LICENSED_SITES)"
  fi

  # ---- control D13e: A SCANNER FAILURE MUST REFUSE *THROUGH* THE
  # FUNCTION, exit 2, not be read as a clean crate. Control I proves
  # `scan_or_die` refuses a non-UTF-8 file when called DIRECTLY; nothing
  # exercised it through `check_licensed_sites`, and that is exactly where
  # the refusal was lost — the function is called inside a `$(...)` on the
  # left of `||`, which suppresses errexit for its whole body, so
  # `scan_or_die`'s `exit 2` killed only the innermost substitution and
  # left the scan EMPTY. Every check downstream read empty as clean and the
  # gate printed a GREEN summary. The plant is in the crate dir but NOT
  # under src/, so it is the whole-crate scan that crashes — the one whose
  # result feeds the bare-#[allow] kill switch.
  mkdir -p "$tmp/d13e/src" "$tmp/d13e/tests"
  printf 'fn ok() {}\n' > "$tmp/d13e/src/lib.rs"
  printf 'fn f() {}\n\xff\xfe not valid utf-8\n' > "$tmp/d13e/tests/bad.rs"
  d13e_rc=0
  d13e_out="$(check_licensed_sites "$tmp/d13e" "$tmp/d13e/src" 0 2>&1)" || d13e_rc=$?
  if [[ "$d13e_rc" -eq 0 ]]; then
    echo "self-test FAILED: control D13e — a crate whose whole-crate scan CRASHED was accepted. The kill switch ran against an empty scan and reported clean:" >&2
    echo "$d13e_out" >&2
    fail=1
  elif [[ "$d13e_rc" -ne 2 ]]; then
    echo "self-test FAILED: control D13e — the crashed scan exited $d13e_rc, wanted 2. A scanner failure is a broken harness, not a finding, and exit 1 tells the operator to edit the audit constant:" >&2
    echo "$d13e_out" >&2
    fail=1
  else
    echo "self-test: control D13e (a non-UTF-8 file under a crate's tests/, through check_licensed_sites) — refused with exit 2, never read as a clean crate, as expected"
  fi

  # ---- control D13f: AN EMPTY COUNT IS NOT ZERO. `[[ -ne ]]` evaluates
  # an empty string as 0, so a scan that produced no COUNT line at all
  # satisfied an expectation of 0 and read as a clean row — and the D13d
  # fixture's expected count IS 0, so that row was satisfiable by a scan
  # that never ran. Driven straight at report_count, because a scan that
  # succeeds while emitting no COUNT cannot be planted from outside.
  d13f_rc=0
  d13f_out="$(report_count "" 0 "$tmp/d13f-nonexistent" 2>&1)" || d13f_rc=$?
  if [[ "$d13f_rc" -eq 0 ]]; then
    echo "self-test FAILED: control D13f — report_count ACCEPTED an empty count against an expectation of 0; an unrun scan reads as a clean crate" >&2
    fail=1
  elif [[ "$d13f_rc" -ne 2 ]]; then
    echo "self-test FAILED: control D13f — an empty count exited $d13f_rc, wanted 2 (a broken harness, not a drifted audit):" >&2
    echo "$d13f_out" >&2
    fail=1
  elif ! grep -q 'no usable count' <<<"$d13f_out"; then
    echo "self-test FAILED: control D13f refused but not for the empty count — may be failing for the wrong reason:" >&2
    echo "$d13f_out" >&2
    fail=1
  else
    echo "self-test: control D13f (an empty count against an expectation of 0) — refused as a harness failure, never read as zero, as expected"
  fi

  # ---- control D13g: AN EMPTY TABLE MUST REFUSE. With no rows the loop
  # body never runs, checks 3 and 4 vanish, and the gate prints a green
  # summary over no crates at all. check_all_licensed_sites takes its rows
  # as ARGUMENTS precisely so this shape is reachable — the real table can
  # never be empty while the gate is healthy, so nothing else could get
  # here.
  d13g_rc=0
  d13g_out="$(check_all_licensed_sites 2>&1)" || d13g_rc=$?
  if [[ "$d13g_rc" -ne 2 ]]; then
    echo "self-test FAILED: control D13g (no rows at all) — expected exit 2, got $d13g_rc; an empty table must not read as a clean audit" >&2
    echo "$d13g_out" >&2
    fail=1
  elif ! grep -q 'is EMPTY' <<<"$d13g_out"; then
    echo "self-test FAILED: control D13g refused but did not name the empty table:" >&2
    echo "$d13g_out" >&2
    fail=1
  else
    echo "self-test: control D13g (an empty licensed-site table) — refused, never a clean audit over no crates, as expected"
  fi

  # ---- control D13h: A MALFORMED ROW MUST REFUSE, both shapes. A
  # two-field row would put the src path where the count belongs; a
  # four-field row parses "successfully" under a `${x##*|}` split while
  # silently dropping a field.
  # AND IT ASSERTS THE DIAGNOSTIC, NOT ONLY THE EXIT CODE, because the
  # separator count is a diagnostic refinement rather than a safety
  # property and an exit code cannot tell them apart. MEASURED: with the
  # separator check deleted all three rows STILL exit 2 —
  # `IFS='|' read -r a b c` puts the remainder in the LAST variable, so a
  # four-field row arrives as expected="c|d" and is caught further down the
  # SAME validation pass (today by the containment guard; before that guard
  # existed, by the numeric one). What the separator check buys is a
  # message naming the ROW SHAPE rather than one blaming a path or a count,
  # so that is what is asserted — and the two short rows are asserted on
  # their own EMPTY-field message for the same reason.
  d13h_fail=0
  # EACH ROW ASSERTS ITS OWN MESSAGE, because they are refused by
  # DIFFERENT guards and an alternation either one satisfies would stay
  # green under the deletion of either: `a|b` has ONE separator and is
  # caught by the separator count; `a||3` has two and an empty field.
  d13h_check() {
    local row="$1" want="$2" rc=0 out
    out="$(check_all_licensed_sites "$row" 2>&1)" || rc=$?
    if [[ "$rc" -ne 2 ]]; then
      echo "self-test FAILED: control D13h — the malformed row '$row' exited $rc, wanted 2" >&2
      d13h_fail=1
    elif ! grep -qF "$want" <<<"$out"; then
      echo "self-test FAILED: control D13h — '$row' was refused, but not for '$want'; an exit code alone cannot tell one row guard from another:" >&2
      echo "$out" >&2
      d13h_fail=1
    fi
  }
  d13h_check "a|b"  "separator(s), expected exactly 2"
  d13h_check "a||3" "has an EMPTY field"
  d13h_rc=0
  d13h_out="$(check_all_licensed_sites "a|b|c|d" 2>&1)" || d13h_rc=$?
  if [[ "$d13h_rc" -ne 2 ]]; then
    echo "self-test FAILED: control D13h — the four-field row exited $d13h_rc, wanted 2" >&2
    d13h_fail=1
  elif ! grep -q "separator(s), expected exactly 2" <<<"$d13h_out"; then
    echo "self-test FAILED: control D13h — the four-field row was refused, but NOT for its shape. Without the separator count it dies downstream on the numeric guard and blames the count instead:" >&2
    echo "$d13h_out" >&2
    d13h_fail=1
  fi
  if [[ "$d13h_fail" -ne 0 ]]; then
    fail=1
  else
    echo "self-test: control D13h (rows with too few, too many and empty fields) — all refused, and the four-field one named its SHAPE rather than a count, as expected"
  fi

  # THE TWO PLANTED CRATES D13i-D13k AND D13a-D13b
  # ALL USE. Create them above the first control
  # that reads them, so those controls have
  # their fixture directories available.
  mkdir -p "$tmp/d13/alpha/src" "$tmp/d13/beta/src"
  cat > "$tmp/d13/alpha/src/lib.rs" <<'RS'
#[expect(clippy::disallowed_methods, reason = "self-test plant")]
fn a1() {}
RS
  cat > "$tmp/d13/beta/src/lib.rs" <<'RS'
#[expect(clippy::disallowed_methods, reason = "self-test plant")]
fn b1() {}
#[expect(clippy::disallowed_methods, reason = "self-test plant")]
fn b2() {}
RS

  # ---- control D13i: A NON-INTEGER EXPECTATION. The count field is
  # hand-edited free text, and an arithmetic SYNTAX ERROR inside
  # `[[ -ne ]]` evaluates FALSE — so a row written `18 # split from 64`,
  # or quoted, or with a trailing comma, would make the comparison pass
  # UNCONDITIONALLY. The shapes below are the ones a real edit produces.
  d13i_fail=0
  for d13i_exp in "1 # split from 64" '"1"' "1," "0x1" "01" "064"; do
    d13i_rc=0
    d13i_out="$(check_all_licensed_sites "$tmp/d13/alpha|$tmp/d13/alpha/src|$d13i_exp" 2>&1)" || d13i_rc=$?
    if [[ "$d13i_rc" -ne 2 ]]; then
      echo "self-test FAILED: control D13i — the expectation '$d13i_exp' exited $d13i_rc, wanted 2; an arithmetic error in the comparison evaluates FALSE and the count check passes unconditionally" >&2
      d13i_fail=1
    elif ! grep -q 'not a plain decimal integer' <<<"$d13i_out"; then
      echo "self-test FAILED: control D13i — '$d13i_exp' was refused but not as a non-integer expectation:" >&2
      echo "$d13i_out" >&2
      d13i_fail=1
    fi
  done
  if [[ "$d13i_fail" -ne 0 ]]; then
    fail=1
  else
    echo "self-test: control D13i (commented, quoted, comma'd, hex AND leading-zero expectations) — all six refused; a leading zero matters because [[ -ne ]] re-bases it as OCTAL, so '064' would pin 52 while the table reads 64"
  fi

  # ---- control D13j: THE SRC ROOT MUST LIE UNDER ITS OWN CRATE DIR. The
  # kill switch and the reach audit walk `$dir` while the COUNT audits
  # `$src`, so a copy-pasted src field lets a row re-audit the WRONG tree
  # and still pass — the decoy shape collect_audited_closures guards its
  # own manifest field against, naming the same trigger.
  d13j_rc=0
  d13j_out="$(check_all_licensed_sites "$tmp/d13/beta|$tmp/d13/alpha/src|1" 2>&1)" || d13j_rc=$?
  if [[ "$d13j_rc" -ne 2 ]]; then
    echo "self-test FAILED: control D13j — a row whose src root is another crate's exited $d13j_rc, wanted 2. It would have counted alpha's sites and reported them as beta's." >&2
    echo "$d13j_out" >&2
    fail=1
  elif ! grep -q 'not strictly under its own crate dir' <<<"$d13j_out"; then
    echo "self-test FAILED: control D13j — refused, but not for the mismatched src root:" >&2
    echo "$d13j_out" >&2
    fail=1
  else
    echo "self-test: control D13j (a src root belonging to a different crate) — refused, as expected"
  fi

  # ---- control D13l: the two OTHER ways a src root escapes its crate.
  # `src == dir` collapses the two scans into one and takes the COUNT over
  # the WHOLE crate, folding in the tests/ and fuzz/ file-scoped licences
  # the count does not describe — a mis-scoping with no outward symptom.
  # And a `..` component walks straight through a string-prefix
  # containment test, because `*` matches `/`.
  d13l_fail=0
  for d13l_row in "$tmp/d13/alpha|$tmp/d13/alpha|1" "$tmp/d13/alpha|$tmp/d13/alpha/../beta/src|1"; do
    d13l_rc=0
    d13l_out="$(check_all_licensed_sites "$d13l_row" 2>&1)" || d13l_rc=$?
    if [[ "$d13l_rc" -ne 2 ]]; then
      echo "self-test FAILED: control D13l — the row '$d13l_row' exited $d13l_rc, wanted 2" >&2
      d13l_fail=1
    elif ! grep -qE "not strictly under its own crate dir|'\.\.' path component" <<<"$d13l_out"; then
      echo "self-test FAILED: control D13l — '$d13l_row' was refused, but not for its src root:" >&2
      echo "$d13l_out" >&2
      d13l_fail=1
    fi
  done
  if [[ "$d13l_fail" -ne 0 ]]; then
    fail=1
  else
    echo "self-test: control D13l (src == dir, and a '..' component) — both refused, as expected"
  fi

  # ---- control D13k: NO CRATE TWICE. Two rows for one crate scan it
  # twice, name it twice in the summary, and if their counts differ the
  # verdict depends on which row is written first.
  d13k_rc=0
  d13k_out="$(check_all_licensed_sites "$tmp/d13/alpha|$tmp/d13/alpha/src|1" "$tmp/d13/alpha|$tmp/d13/alpha/src|2" 2>&1)" || d13k_rc=$?
  if [[ "$d13k_rc" -ne 2 ]]; then
    echo "self-test FAILED: control D13k — a table with two rows for one crate exited $d13k_rc, wanted 2; with differing counts the first row would decide the verdict" >&2
    echo "$d13k_out" >&2
    fail=1
  elif ! grep -q 'more than one row' <<<"$d13k_out"; then
    echo "self-test FAILED: control D13k — refused, but not for the duplicate row:" >&2
    echo "$d13k_out" >&2
    fail=1
  else
    echo "self-test: control D13k (two rows for the same crate dir) — refused, as expected"
  fi

  # ---- controls D13a-D13c: LICENSED_SITE_CRATES IS A TABLE, AND THE COUNT
  # IS PER-CRATE. While that table has ONE row, nothing that reads it can
  # tell a whole-table loop from a first-row loop — `"${arr[@]}"` and
  # `"${arr[0]}"` are the same call — so these call check_licensed_sites
  # DIRECTLY with their own planted crates. That is the escape that works
  # before `granary-cli` exists.
  #
  # THE FIXTURE IS CHOSEN SO A SUM CANNOT PASS IT. alpha has ONE licensed
  # site and is told to expect TWO; beta has TWO and is told to expect
  # ONE. The totals are three either way, so an implementation that
  # compared the SUM of the table against the sum of the actuals would
  # accept both rows. A per-crate comparison refuses BOTH, and D6b
  # requires exactly that.
  # D13a — the POSITIVE control. Without it, D13b's refusals prove only that
  # the function refuses, not that it can ever accept.
  d13a_rc=0
  d13a_out="$(check_licensed_sites "$tmp/d13/alpha" "$tmp/d13/alpha/src" 1 2>&1)" || d13a_rc=$?
  if [[ "$d13a_rc" -ne 0 ]]; then
    echo "self-test FAILED: control D13a (a one-site crate told to expect 1) — check_licensed_sites refused a correct row:" >&2
    echo "$d13a_out" >&2
    fail=1
  elif [[ "${d13a_out%%|*}" != "1" ]]; then
    echo "self-test FAILED: control D13a — check_licensed_sites reported count '${d13a_out%%|*}', wanted 1" >&2
    fail=1
  else
    echo "self-test: control D13a (a planted one-site crate expecting 1) — accepted and reported its own count, as expected"
  fi
  # D13b — BOTH swapped rows must refuse, each naming ITS OWN numbers.
  d13b_fail=0
  d13b_a_rc=0
  d13b_a_out="$(check_licensed_sites "$tmp/d13/alpha" "$tmp/d13/alpha/src" 2 2>&1)" || d13b_a_rc=$?
  if [[ "$d13b_a_rc" -eq 0 ]]; then
    echo "self-test FAILED: control D13b — a crate with 1 site was accepted against an expectation of 2" >&2
    d13b_fail=1
  elif [[ "$d13b_a_rc" -ne 1 ]]; then
    echo "self-test FAILED: control D13b — a count drift exited $d13b_a_rc, wanted 1. A drift is a FINDING; 2 tells the operator the harness is broken and NOT to edit the audit constant, which is the opposite advice." >&2
    d13b_fail=1
  elif ! grep -q "has 1 " <<<"$d13b_a_out" || ! grep -q "expects 2" <<<"$d13b_a_out"; then
    echo "self-test FAILED: control D13b — the alpha refusal did not name 1 against 2:" >&2
    echo "$d13b_a_out" >&2
    d13b_fail=1
  fi
  d13b_b_rc=0
  d13b_b_out="$(check_licensed_sites "$tmp/d13/beta" "$tmp/d13/beta/src" 1 2>&1)" || d13b_b_rc=$?
  if [[ "$d13b_b_rc" -eq 0 ]]; then
    echo "self-test FAILED: control D13b — a crate with 2 sites was accepted against an expectation of 1" >&2
    d13b_fail=1
  elif [[ "$d13b_b_rc" -ne 1 ]]; then
    echo "self-test FAILED: control D13b — a count drift exited $d13b_b_rc, wanted 1 (a finding, not a harness fault)" >&2
    d13b_fail=1
  elif ! grep -q "has 2 " <<<"$d13b_b_out" || ! grep -q "expects 1" <<<"$d13b_b_out"; then
    echo "self-test FAILED: control D13b — the beta refusal did not name 2 against 1:" >&2
    echo "$d13b_b_out" >&2
    d13b_fail=1
  fi
  if [[ "$d13b_fail" -ne 0 ]]; then
    fail=1
  else
    echo "self-test: control D13b (counts 1 and 2 against expectations 2 and 1 — the SAME total either way) — both refused per-crate, so the comparison is not a sum, as expected"
  fi
  # D13c — THE TABLE AND ITS SOURCE SCALARS MUST AGREE. 31 of CRATE_SRC's
  # references build self-test fixtures from the scalar, so a drift would
  # leave every one of those controls exercising a crate the gate's loop
  # does not scan — green on both sides, covering different trees.
  # SEARCHES the table; does NOT pin an index. The client's row need not
  # occupy `LICENSED_SITE_CRATES[0]`: granary-cli's row may be written
  # above or below it. Row order is a formatting choice, not a drift
  # between the table and the scalars used to construct the fixtures.
  # W2f's own awk injects a row at index 0, so the check must find the
  # client's matching row wherever it appears.
  d13c_want="$CRATE_DIR|$CRATE_SRC|$EXPECTED_LICENSED_SITES"
  d13c_found=no
  for d13c_row in "${LICENSED_SITE_CRATES[@]}"; do
    [[ "$d13c_row" == "$d13c_want" ]] && { d13c_found=yes; break; }
  done
  if [[ "$d13c_found" != yes ]]; then
    echo "self-test FAILED: control D13c — no row of LICENSED_SITE_CRATES equals '$d13c_want', the scalars the self-test builds its fixtures from. The gate's loop and 31 of the controls are looking at different trees." >&2
    fail=1
  else
    echo "self-test: control D13c (the scalars the fixtures are built from appear as a row) — present, as expected"
  fi

  # ---- control D2: a MULTI-LINT #[expect(...)] site (a second lint
  # sharing the attribute with disallowed_methods) must ALSO bump the
  # count by exactly one — a matcher anchored to the first token after
  # `expect(` misses this shape entirely.
  cp -R "$CRATE_SRC" "$tmp/src_multilint_expect"
  cat >> "$tmp/src_multilint_expect/planted.rs" <<'RS'
#[expect(clippy::too_many_lines, clippy::disallowed_methods, reason = "self-test plant")]
fn planted() {}
RS
  multilint_expect_scan="$(scan_or_die "$tmp/src_multilint_expect")"
  multilint_count="$(scanned_count "$multilint_expect_scan")"
  if [[ "$multilint_count" -ne $((EXPECTED_LICENSED_SITES + 1)) ]]; then
    echo "self-test FAILED: control D2 (multi-lint expect) counted $multilint_count, wanted $((EXPECTED_LICENSED_SITES + 1))" >&2
    fail=1
  else
    echo "self-test: control D2 (multi-lint #[expect(other, clippy::disallowed_methods, ...)]) — counted $multilint_count, as expected"
  fi

  # ---- control D3: a commented-out `#[expect(...)]` must NOT bump the
  # count, and neither must the same text sitting inside a string
  # literal — a raw-source scanner counts both.
  cp -R "$CRATE_SRC" "$tmp/src_commented"
  cat >> "$tmp/src_commented/planted.rs" <<'RS'
// #[expect(clippy::disallowed_methods, reason = "commented out, must not count")]
#[expect(clippy::too_many_lines, reason = "mentions #[expect(clippy::disallowed_methods, reason = \"x\")] as prose, must not count")]
fn planted() {
    let _s = "#[expect(clippy::disallowed_methods, reason = \"x\")]";
}
RS
  commented_scan="$(scan_or_die "$tmp/src_commented")"
  commented_count="$(scanned_count "$commented_scan")"
  if [[ "$commented_count" -ne "$EXPECTED_LICENSED_SITES" ]]; then
    echo "self-test FAILED: control D3 (commented-out / in-string expect) counted $commented_count, wanted $EXPECTED_LICENSED_SITES unchanged" >&2
    fail=1
  else
    echo "self-test: control D3 (commented-out and in-string expect text) — count unchanged at $commented_count, as expected"
  fi

  # ---- control F: a planted bare #[allow(clippy::disallowed_methods)]
  # (both the outer and the inner `#!` forms) in a COPIED tree must be
  # refused by the kill switch, independent of the count check.
  cp -R "$CRATE_SRC" "$tmp/src_bare_allow"
  cat >> "$tmp/src_bare_allow/planted_allow.rs" <<'RS'
#[allow(clippy::disallowed_methods)]
mod planted_mod {
    fn f() {
        let _ = std::fs::create_dir_all("/nowhere");
    }
}
RS
  mkdir -p "$tmp/tests_bare_allow"
  cat > "$tmp/tests_bare_allow/planted.rs" <<'RS'
#![allow(clippy::disallowed_methods)]
fn f() {
    let _ = std::fs::create_dir_all("/nowhere");
}
RS
  src_bare_scan="$(scan_or_die "$tmp/src_bare_allow")"
  src_bare_hits="$(scanned_allow_hits "$src_bare_scan")"
  if report_bare_allow "$src_bare_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control F (outer #[allow] plant) — kill switch did not refuse it" >&2
    fail=1
  else
    echo "self-test: control F (outer #[allow(clippy::disallowed_methods)] plant) — kill switch refused it, as expected"
  fi
  tests_bare_scan="$(scan_or_die "$tmp/tests_bare_allow")"
  tests_bare_hits="$(scanned_allow_hits "$tests_bare_scan")"
  if report_bare_allow "$tests_bare_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control F (inner #![allow] plant) — kill switch did not refuse it" >&2
    fail=1
  else
    echo "self-test: control F (inner #![allow(clippy::disallowed_methods)] plant) — kill switch refused it, as expected"
  fi

  # ---- control F2: a rustfmt-shaped MULTI-LINE #[allow(...)] must also
  # be refused — a line-scoped regex never sees it, because the lint
  # name sits on its own line, never on the `#[allow(` line.
  cp -R "$CRATE_SRC" "$tmp/src_multiline_allow"
  cat >> "$tmp/src_multiline_allow/planted.rs" <<'RS'
#[allow(
    clippy::disallowed_methods
)]
fn planted() {
    let _ = std::fs::create_dir_all("/nowhere");
}
RS
  multiline_allow_scan="$(scan_or_die "$tmp/src_multiline_allow")"
  multiline_hits="$(scanned_allow_hits "$multiline_allow_scan")"
  if report_bare_allow "$multiline_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control F2 (multi-line #[allow] plant) — kill switch did not refuse it" >&2
    fail=1
  else
    echo "self-test: control F2 (multi-line #[allow(\\n    clippy::disallowed_methods\\n)]) — kill switch refused it, as expected"
  fi

  # ---- control F3: a MULTI-LINT #[allow(...)] (a second lint sharing
  # the attribute) must also be refused.
  cp -R "$CRATE_SRC" "$tmp/src_multilint_allow"
  cat >> "$tmp/src_multilint_allow/planted.rs" <<'RS'
#[allow(unused_variables, clippy::disallowed_methods)]
fn planted() {
    let _ = std::fs::create_dir_all("/nowhere");
}
RS
  multilint_allow_scan="$(scan_or_die "$tmp/src_multilint_allow")"
  multilint_allow_hits="$(scanned_allow_hits "$multilint_allow_scan")"
  if report_bare_allow "$multilint_allow_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control F3 (multi-lint #[allow(other, clippy::disallowed_methods)] plant) — kill switch did not refuse it" >&2
    fail=1
  else
    echo "self-test: control F3 (multi-lint #[allow(other, clippy::disallowed_methods)]) — kill switch refused it, as expected"
  fi

  # ---- control G: a CHAR LITERAL holding a double quote (`'"'`) right
  # before a bare allow must not blind the scanner to it.
  # `seam_drivable.rs` has this exact shape (`trim_matches('"')`), and a
  # string handler that treats the `"` inside the char literal as
  # opening a real string blanks everything up to the NEXT literal `"`
  # in the file, hiding a bare allow placed between the two quotes.
  cp -R "$CRATE_SRC" "$tmp/src_char_literal"
  cat >> "$tmp/src_char_literal/planted.rs" <<'RS'
fn f(s: &str) -> &str {
    s.trim_matches('"')
}
#[allow(clippy::disallowed_methods)]
fn planted() {
    let _ = std::fs::create_dir_all("/nowhere");
}
RS
  char_lit_scan="$(scan_or_die "$tmp/src_char_literal")"
  char_lit_hits="$(scanned_allow_hits "$char_lit_scan")"
  if report_bare_allow "$char_lit_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control G (allow right after a '\"' char literal) — kill switch did not refuse it" >&2
    fail=1
  else
    echo "self-test: control G (allow right after a '\"' char literal) — kill switch refused it, as expected"
  fi

  # ---- control G2: a LIFETIME (`'a`), which looks like the start of a
  # char literal but never closes with a quote, must not blind the
  # scanner to a real expect right after it either.
  cp -R "$CRATE_SRC" "$tmp/src_lifetime"
  cat >> "$tmp/src_lifetime/planted.rs" <<'RS'
fn f<'a>(s: &'a str) -> &'a str { s }
#[expect(clippy::disallowed_methods, reason = "self-test plant")]
fn planted() {
    let _ = std::fs::create_dir_all("/nowhere");
}
RS
  # Two plain assignments, never `scanned_count "$(scan_or_die ...)"` —
  # the nesting this same script bans at scan_or_die's own header: a
  # scanner failure inside an argument-position `$(...)`
  # does not trip errexit, and scan_or_die's `exit 2` would only tear
  # down that innermost subshell, leaving the control to compare an
  # EMPTY count and report on a scan that never happened.
  lifetime_scan="$(scan_or_die "$tmp/src_lifetime")"
  lifetime_count="$(scanned_count "$lifetime_scan")"
  if [[ "$lifetime_count" -ne $((EXPECTED_LICENSED_SITES + 1)) ]]; then
    echo "self-test FAILED: control G2 (expect right after a lifetime) counted $lifetime_count, wanted $((EXPECTED_LICENSED_SITES + 1))" >&2
    fail=1
  else
    echo "self-test: control G2 (expect right after a lifetime, not a char literal) — counted $lifetime_count, as expected"
  fi

  # ---- control H: `#[cfg_attr(cond, allow(clippy::disallowed_methods))]`
  # — already a real idiom in this crate (cache.rs, for dead_code) —
  # must be refused the same as a bare top-level allow.
  cp -R "$CRATE_SRC" "$tmp/src_cfg_attr_allow"
  cat >> "$tmp/src_cfg_attr_allow/planted.rs" <<'RS'
#[cfg_attr(not(test), allow(clippy::disallowed_methods))]
fn planted() {
    let _ = std::fs::create_dir_all("/nowhere");
}
RS
  cfg_attr_allow_scan="$(scan_or_die "$tmp/src_cfg_attr_allow")"
  cfg_attr_allow_hits="$(scanned_allow_hits "$cfg_attr_allow_scan")"
  if report_bare_allow "$cfg_attr_allow_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control H (cfg_attr-wrapped allow) — kill switch did not refuse it" >&2
    fail=1
  else
    echo "self-test: control H (#[cfg_attr(cond, allow(clippy::disallowed_methods))]) — kill switch refused it, as expected"
  fi

  # ---- control H2: the cfg_attr-wrapped EXPECT form must count as a
  # licence the same as a bare top-level expect.
  cp -R "$CRATE_SRC" "$tmp/src_cfg_attr_expect"
  cat >> "$tmp/src_cfg_attr_expect/planted.rs" <<'RS'
#[cfg_attr(not(test), expect(clippy::disallowed_methods, reason = "self-test plant"))]
fn planted() {
    let _ = std::fs::create_dir_all("/nowhere");
}
RS
  cfg_attr_expect_scan="$(scan_or_die "$tmp/src_cfg_attr_expect")"
  cfg_attr_expect_count="$(scanned_count "$cfg_attr_expect_scan")"
  if [[ "$cfg_attr_expect_count" -ne $((EXPECTED_LICENSED_SITES + 1)) ]]; then
    echo "self-test FAILED: control H2 (cfg_attr-wrapped expect) counted $cfg_attr_expect_count, wanted $((EXPECTED_LICENSED_SITES + 1))" >&2
    fail=1
  else
    echo "self-test: control H2 (#[cfg_attr(cond, expect(clippy::disallowed_methods, ...))]) — counted $cfg_attr_expect_count, as expected"
  fi

  # ---- control H3: whitespace around `::` in the lint path
  # (`clippy :: disallowed_methods`) is syntactically valid Rust
  # (verified directly with rustc) and must still count as a licence.
  cp -R "$CRATE_SRC" "$tmp/src_whitespace_path"
  cat >> "$tmp/src_whitespace_path/planted.rs" <<'RS'
#[expect(clippy :: disallowed_methods, reason = "self-test plant")]
fn planted() {
    let _ = std::fs::create_dir_all("/nowhere");
}
RS
  whitespace_path_scan="$(scan_or_die "$tmp/src_whitespace_path")"
  whitespace_path_count="$(scanned_count "$whitespace_path_scan")"
  if [[ "$whitespace_path_count" -ne $((EXPECTED_LICENSED_SITES + 1)) ]]; then
    echo "self-test FAILED: control H3 (whitespace around :: in the lint path) counted $whitespace_path_count, wanted $((EXPECTED_LICENSED_SITES + 1))" >&2
    fail=1
  else
    echo "self-test: control H3 (clippy :: disallowed_methods, whitespace around ::) — counted $whitespace_path_count, as expected"
  fi

  # ---- control H4: a comment INSIDE the
  # lint path (`clippy::/* gap */disallowed_methods`)
  # must still be refused by the kill
  # switch after comment stripping.
  cp -R "$CRATE_SRC" "$tmp/src_comment_in_path"
  cat >> "$tmp/src_comment_in_path/planted.rs" <<'RS'
#[allow(clippy::/* gap */disallowed_methods)]
fn planted() {
    let _ = std::fs::create_dir_all("/nowhere");
}
RS
  comment_in_path_scan="$(scan_or_die "$tmp/src_comment_in_path")"
  comment_in_path_hits="$(scanned_allow_hits "$comment_in_path_scan")"
  if report_bare_allow "$comment_in_path_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control H4 (comment inside the lint path) — kill switch did not refuse it" >&2
    fail=1
  else
    echo "self-test: control H4 (clippy::/* gap */disallowed_methods) — kill switch refused it, as expected"
  fi

  # ---- control H5: an attribute-shaped needle sitting inside a NESTED
  # block comment (Rust nests `/* /* */ */`) must be ignored entirely —
  # a stripper that stops at the FIRST `*/` leaves text inside a nested
  # comment unblanked, and it then matches.
  #
  # The needle's POSITION is the whole control, and it is
  # mutation-proven: it must sit AFTER the inner `*/` and before the
  # outer one. With the needle inside the INNER comment a NON-nesting
  # stripper blanks it too (it blanks from `/* outer` to the first `*/`,
  # which is past the needle), so the control would pass for a reason
  # that has nothing to do with nesting. Placed here, a non-nesting
  # stripper stops at the inner
  # `*/` and EXPOSES the needle, which is the failure this control
  # exists to see. Verified by mutating the nested-open branch out of
  # `fsguard-scan.py`: H5 then FAILS.
  cp -R "$CRATE_SRC" "$tmp/src_nested_comment"
  cat >> "$tmp/src_nested_comment/planted.rs" <<'RS'
/* outer /* inner */ #[allow(clippy::disallowed_methods)] still-in-outer */
#[expect(clippy::disallowed_methods, reason = "self-test plant")]
fn planted() {
    let _ = std::fs::create_dir_all("/nowhere");
}
RS
  nested_comment_scan="$(scan_or_die "$tmp/src_nested_comment")"
  nested_comment_count="$(scanned_count "$nested_comment_scan")"
  nested_comment_hits="$(scanned_allow_hits "$nested_comment_scan")"
  if [[ "$nested_comment_count" -ne $((EXPECTED_LICENSED_SITES + 1)) ]] || [[ -n "$nested_comment_hits" ]]; then
    echo "self-test FAILED: control H5 (needle inside a nested block comment) — counted $nested_comment_count (wanted $((EXPECTED_LICENSED_SITES + 1))), hits=[$nested_comment_hits] (wanted none)" >&2
    fail=1
  else
    echo "self-test: control H5 (attribute-shaped text inside a NESTED /* /* */ */ comment) — ignored, real expect still counted at $nested_comment_count, as expected"
  fi

  # ---- control H6: a `\`-newline line continuation inside a plain
  # string, followed by a planted allow further down, must report the
  # PLANT'S OWN line number. A stripper that eats the continuation's
  # newline instead of preserving it shifts every line number after it
  # (28 lines of drift, measured, in seam_drivable.rs, which uses this
  # idiom repeatedly).
  copy_crate_src_fixture "$tmp/src_continuation"
  printf 'fn f() {\n    let s = "hello \\\n              world";\n}\n\n#[allow(clippy::disallowed_methods)]\nfn planted() {\n    let _ = std::fs::create_dir_all("/nowhere");\n}\n' > "$tmp/src_continuation/planted.rs"
  continuation_scan="$(scan_or_die "$tmp/src_continuation")"
  continuation_hits="$(scanned_allow_hits "$continuation_scan")"
  if ! grep -q "planted.rs:6:" <<<"$continuation_hits"; then
    echo "self-test FAILED: control H6 (line-continuation line-number drift) reported [$continuation_hits], wanted a hit naming planted.rs:6" >&2
    fail=1
  else
    echo "self-test: control H6 (a \\-newline continuation earlier in the file does not shift the plant's own reported line number) — as expected"
  fi

  # ---- control H7: a QUOTED SHEBANG on line 1 must not blind the
  # scanner to a bare allow on line 2. rustc DISCARDS a first line
  # starting with `#!` that is not an inner attribute (`#![`), so
  # `#!/usr/bin/env -S rust-script "` compiles fine while leaving an
  # unterminated `"` — which puts a string handler that does not model
  # the shebang into string state, blanking everything up to the next
  # literal `"` in the file. Measured against such a scanner:
  # `COUNT 0`, no `ALLOW` line at all.
  copy_crate_src_fixture "$tmp/src_shebang"
  printf '#!/usr/bin/env -S rust-script "\n#[allow(clippy::disallowed_methods)]\nfn planted() {\n    let _ = std::fs::create_dir_all("/nowhere");\n}\n' > "$tmp/src_shebang/planted.rs"
  shebang_scan="$(scan_or_die "$tmp/src_shebang")"
  shebang_hits="$(scanned_allow_hits "$shebang_scan")"
  if report_bare_allow "$shebang_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control H7 (bare allow on line 2 after a QUOTED shebang) — kill switch did not refuse it" >&2
    fail=1
  elif ! grep -q "planted.rs:2:" <<<"$shebang_hits"; then
    echo "self-test FAILED: control H7 refused but at the wrong line — reported [$shebang_hits], wanted planted.rs:2" >&2
    fail=1
  else
    echo "self-test: control H7 (bare allow on line 2 behind a quoted '#!/usr/bin/env -S rust-script \"' shebang) — kill switch refused it at the right line, as expected"
  fi

  # ---- control H8: WHITESPACE between the `#` and the `[` —
  # `# [allow(clippy::disallowed_methods)]` — is accepted by rustc
  # (verified directly with `rustc --edition 2024`) and evades a
  # `#!?\[` matcher, which requires them adjacent. rustfmt
  # would rewrite the shape, so the fmt gate compensates — but this
  # gate must not depend on another gate having run first.
  cp -R "$CRATE_SRC" "$tmp/src_ws_attr"
  cat >> "$tmp/src_ws_attr/planted.rs" <<'RS'
# [allow(clippy::disallowed_methods)]
fn planted() {
    let _ = std::fs::create_dir_all("/nowhere");
}
RS
  ws_attr_scan="$(scan_or_die "$tmp/src_ws_attr")"
  ws_attr_hits="$(scanned_allow_hits "$ws_attr_scan")"
  if report_bare_allow "$ws_attr_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control H8 (# [allow(...)], whitespace between # and [) — kill switch did not refuse it" >&2
    fail=1
  else
    echo "self-test: control H8 (# [allow(...)] — whitespace between the # and the [) — kill switch refused it, as expected"
  fi

  # ---- controls H9a–H9c: rustc's ACTUAL shebang rule is "after `#!`,
  # skip whitespace AND comments — if the next token is `[`, this is an
  # inner attribute, not a shebang". Recognizing only the adjacent
  # `#![` BLANKS all three spellings below as shebangs while rustc
  # honours them as file-wide lint suppressions: the gate then prints
  # "no bare #[allow]" and exits 0 on a file whose first line switched
  # the lint off entirely. Proved by execution —
  # each of these first lines wrapping `allow(dead_code)` over an
  # unused fn emits ZERO `never used` warnings from rustc.
  #
  # Each plant is LINE 1 of a file written with `>`, not appended: the
  # whole class only exists at line 1, so a control that cannot land
  # there cannot see it.
  h9_case() {
    local label="$1" dir="$2" first_line="$3"
    copy_crate_src_fixture "$dir"
    { printf '%s\n' "$first_line"; printf 'fn planted() {\n    let _ = std::fs::create_dir_all("/nowhere");\n}\n'; } > "$dir/planted.rs"
    local scan hits
    scan="$(scan_or_die "$dir")"
    hits="$(scanned_allow_hits "$scan")"
    if report_bare_allow "$hits" >/dev/null 2>&1; then
      echo "self-test FAILED: control $label — kill switch did not refuse it" >&2
      fail=1
    else
      echo "self-test: control $label — kill switch refused it, as expected"
    fi
  }
  h9_case "H9a (#! [allow(...)] — space after #!, an INNER ATTRIBUTE rustc honours)" \
    "$tmp/src_shebang_space" '#! [allow(clippy::disallowed_methods)]'
  h9_case "H9c (#!/* c */[allow(...)] — a comment between #! and [)" \
    "$tmp/src_shebang_comment" '#!/* c */[allow(clippy::disallowed_methods)]'

  # H9b needs the `[` on the NEXT line, so it cannot go through the
  # one-line helper above.
  copy_crate_src_fixture "$tmp/src_shebang_newline"
  printf '#!\n[allow(clippy::disallowed_methods)]\nfn planted() {\n    let _ = std::fs::create_dir_all("/nowhere");\n}\n' > "$tmp/src_shebang_newline/planted.rs"
  shebang_nl_scan="$(scan_or_die "$tmp/src_shebang_newline")"
  shebang_nl_hits="$(scanned_allow_hits "$shebang_nl_scan")"
  if report_bare_allow "$shebang_nl_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control H9b (#! then a NEWLINE then [allow(...)]) — kill switch did not refuse it" >&2
    fail=1
  else
    echo "self-test: control H9b (#! then a NEWLINE then [allow(...)]) — kill switch refused it, as expected"
  fi

  # ---- control H10: a leading UTF-8 BOM in front of a quoted shebang.
  # A plain `startswith("#!")` is false with a BOM there, so no shebang
  # is recognized and the unterminated quote blinds the scanner exactly
  # as an unquoted one would. rustc strips the BOM before looking for a
  # shebang; so does this scanner.
  copy_crate_src_fixture "$tmp/src_bom_shebang"
  printf '\xef\xbb\xbf#!/usr/bin/env -S rust-script "\n#[allow(clippy::disallowed_methods)]\nfn planted() {\n    let _ = std::fs::create_dir_all("/nowhere");\n}\n' > "$tmp/src_bom_shebang/planted.rs"
  bom_scan="$(scan_or_die "$tmp/src_bom_shebang")"
  bom_hits="$(scanned_allow_hits "$bom_scan")"
  if report_bare_allow "$bom_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control H10 (BOM + quoted shebang + line-2 bare allow) — kill switch did not refuse it" >&2
    fail=1
  elif ! grep -q "planted.rs:2:" <<<"$bom_hits"; then
    echo "self-test FAILED: control H10 refused but at the wrong line — reported [$bom_hits], wanted planted.rs:2" >&2
    fail=1
  else
    echo "self-test: control H10 (a UTF-8 BOM in front of a quoted shebang) — kill switch refused the line-2 allow, as expected"
  fi

  # ---- control H11: discard a genuine
  # shebang without swallowing the next
  # line. A real `#!/bin/sh` first line
  # followed by a real `#[expect]` on
  # line 2 must still count that licence.
  copy_crate_src_fixture "$tmp/src_real_shebang"
  printf '#!/bin/sh is a real shebang, discarded by rustc\n#[expect(clippy::disallowed_methods, reason = "self-test plant")]\nfn planted() {\n    let _ = std::fs::create_dir_all("/nowhere");\n}\n' > "$tmp/src_real_shebang/planted.rs"
  real_shebang_scan="$(scan_or_die "$tmp/src_real_shebang")"
  real_shebang_count="$(scanned_count "$real_shebang_scan")"
  if [[ "$real_shebang_count" -ne $((EXPECTED_LICENSED_SITES + 1)) ]]; then
    echo "self-test FAILED: control H11 (genuine shebang, real expect on line 2) counted $real_shebang_count, wanted $((EXPECTED_LICENSED_SITES + 1))" >&2
    fail=1
  else
    echo "self-test: control H11 (a GENUINE shebang is still discarded, and the line-2 #[expect] below it still counts) — counted $real_shebang_count, as expected"
  fi

  # ---- control H12: whitespace between the `#` and the `!` —
  # `# ![allow(...)]`. Accepted by rustc (verified directly), and
  # missed by a `#!?\s*\[` matcher, which allows a gap only AFTER the
  # `!`.
  cp -R "$CRATE_SRC" "$tmp/src_hash_gap_bang"
  cat > "$tmp/src_hash_gap_bang/planted.rs" <<'RS'
# ![allow(clippy::disallowed_methods)]
fn planted() {
    let _ = std::fs::create_dir_all("/nowhere");
}
RS
  hash_gap_scan="$(scan_or_die "$tmp/src_hash_gap_bang")"
  hash_gap_hits="$(scanned_allow_hits "$hash_gap_scan")"
  if report_bare_allow "$hash_gap_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control H12 (# ![allow(...)], whitespace between # and !) — kill switch did not refuse it" >&2
    fail=1
  else
    echo "self-test: control H12 (# ![allow(...)] — whitespace between the # and the !) — kill switch refused it, as expected"
  fi

  # ---- control H13: a RAW IDENTIFIER names the same lint —
  # `clippy::r#disallowed_methods` is `clippy::disallowed_methods` to
  # rustc, and the same trick on `r#allow(` hides the attribute kind
  # too. Both spellings are planted; either one unrefused fails this
  # control.
  cp -R "$CRATE_SRC" "$tmp/src_raw_ident"
  cat > "$tmp/src_raw_ident/planted.rs" <<'RS'
#[allow(clippy::r#disallowed_methods)]
fn planted() {
    let _ = std::fs::create_dir_all("/nowhere");
}
#[r#allow(clippy::disallowed_methods)]
fn planted_two() {
    let _ = std::fs::create_dir_all("/nowhere");
}
RS
  raw_ident_scan="$(scan_or_die "$tmp/src_raw_ident")"
  raw_ident_hits="$(scanned_allow_hits "$raw_ident_scan")"
  if report_bare_allow "$raw_ident_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control H13 (raw-identifier lint path / attribute kind) — kill switch did not refuse it" >&2
    fail=1
  elif [[ "$(grep -c . <<<"$raw_ident_hits")" -ne 2 ]]; then
    echo "self-test FAILED: control H13 refused but not both spellings — reported [$raw_ident_hits], wanted 2 hits" >&2
    fail=1
  else
    echo "self-test: control H13 (clippy::r#disallowed_methods AND #[r#allow(...)]) — kill switch refused both spellings, as expected"
  fi

  # ---- control H14: U+200E (LEFT-TO-RIGHT MARK) is WHITESPACE to
  # rustc and NOT whitespace to Python — neither `str.isspace()` nor a
  # regex `\s` matches it. With `isspace()` driving the shebang
  # classification, `#!<LRM>[allow(...)]` — an inner attribute rustc
  # HONOURS (verified: it suppresses dead_code over an unused fn, zero
  # warnings) — is classified as a shebang and BLANKED. Fixing only the
  # classifier is NOT enough either: the attribute regexes then still
  # fail to match the gap. Both halves are pinned here.
  copy_crate_src_fixture "$tmp/src_ltr_mark"
  printf '#!\xe2\x80\x8e[allow(clippy::disallowed_methods)]\nfn planted() {\n    let _ = std::fs::create_dir_all("/nowhere");\n}\n' > "$tmp/src_ltr_mark/planted.rs"
  ltr_scan="$(scan_or_die "$tmp/src_ltr_mark")"
  ltr_hits="$(scanned_allow_hits "$ltr_scan")"
  if report_bare_allow "$ltr_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control H14 (U+200E between #! and [) — kill switch did not refuse it" >&2
    fail=1
  else
    echo "self-test: control H14 (a U+200E LEFT-TO-RIGHT MARK where Rust allows whitespace and Python sees none) — kill switch refused it, as expected"
  fi

  # ---- controls K1-K3: a LINT GROUP NAME suppresses the lint without
  # naming it. `disallowed_methods` is in clippy's `style` group, so
  # `clippy::style` and `clippy::all` both switch the fs ban off —
  # measured on the pinned toolchain against a bare
  # `std::fs::create_dir_all` call: with either group allowed the ban
  # produced ZERO errors. `warnings` did not (this crate denies the
  # lint, and `warnings` covers warn-level lints), and is refused here
  # anyway because it is one Cargo.toml line from being the same hole.
  #
  # These plants use the INNER `#![allow(...)]` form deliberately: the
  # manifest's `[lints.clippy] allow_attributes = "deny"` refuses an
  # OUTER `#[allow]` on an item — in every target of the crate, which is
  # why it lives there and not on the two crate roots — but produces no
  # diagnostic at all for an inner attribute on a module (measured both
  # as a module file and as an inline `mod { ... }`). For this shape the
  # kill switch is not a second opinion — it is the only check there is.
  k_case() {
    local label="$1" dir="$2" lints="$3"
    copy_crate_src_fixture "$dir"
    printf '#![allow(%s, reason = "a planted group-name evasion")]\nfn planted() {\n    let _ = std::fs::create_dir_all("/nowhere");\n}\n' \
      "$lints" > "$dir/planted.rs"
    local scan hits
    scan="$(scan_or_die "$dir")"
    hits="$(scanned_allow_hits "$scan")"
    if report_bare_allow "$hits" >/dev/null 2>&1; then
      echo "self-test FAILED: control $label — kill switch did not refuse it" >&2
      fail=1
    else
      echo "self-test: control $label — kill switch refused it, as expected"
    fi
  }
  k_case "K1 (#![allow(clippy::all, reason = ...)] — a group that CONTAINS the lint)" \
    "$tmp/src_group_all" "clippy::all"
  k_case "K2 (#![allow(clippy::style, ...)] — the lint's own group)" \
    "$tmp/src_group_style" "clippy::style"
  k_case "K3 (#![allow(warnings, ...)] — the rustc catch-all)" \
    "$tmp/src_group_warnings" "warnings"

  # ---- control K4: the NEGATIVE half. A group that does NOT contain
  # the lint must not be refused — measured: with `clippy::restriction`
  # allowed, the ban still produced its error. Without this control the
  # group matching could widen to "any clippy group" and look correct.
  copy_crate_src_fixture "$tmp/src_group_unrelated"
  printf '#![allow(clippy::restriction, reason = "unrelated group")]\nfn planted() {}\n' \
    > "$tmp/src_group_unrelated/planted.rs"
  unrelated_scan="$(scan_or_die "$tmp/src_group_unrelated")"
  unrelated_hits="$(scanned_allow_hits "$unrelated_scan")"
  if ! report_bare_allow "$unrelated_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control K4 (clippy::restriction, a group that does NOT contain the lint) was refused, but must not be — reported [$unrelated_hits]" >&2
    fail=1
  else
    echo "self-test: control K4 (clippy::restriction — a group that does NOT contain the lint) — not refused, as expected"
  fi

  # ---- controls K5-K6: a GROUP-WIDE `expect` is
  # not a narrow licence. `clippy::all` suppresses
  # the whole group, and hidden calls can fulfill
  # that expectation rather than trigger an
  # unfulfilled-expectation warning. Counting it as
  # one site could replace a narrow licence without
  # moving the total. The scanner reports group-wide
  # expects like bare allows, including outside src/.
  k_expect_case() {
    local label="$1" dir="$2" attr="$3"
    copy_crate_src_fixture "$dir"
    printf '%s\nfn planted() {\n    let _ = std::fs::create_dir_all("/nowhere");\n}\n' \
      "$attr" > "$dir/planted.rs"
    local scan hits count
    scan="$(scan_or_die "$dir")"
    hits="$(scanned_allow_hits "$scan")"
    count="$(scanned_count "$scan")"
    if report_bare_allow "$hits" >/dev/null 2>&1; then
      echo "self-test FAILED: control $label — a group-wide expect was not refused" >&2
      fail=1
    elif [[ "$count" -ne "$EXPECTED_LICENSED_SITES" ]]; then
      echo "self-test FAILED: control $label — the group expect moved the COUNT to $count (wanted $EXPECTED_LICENSED_SITES); it must be refused, never counted as a licence" >&2
      fail=1
    else
      echo "self-test: control $label — refused, and the licensed-site count did not move, as expected"
    fi
  }
  k_expect_case "K5 (inner #![expect(clippy::all, reason = ...)] on a module file)" \
    "$tmp/src_expect_group_all" '#![expect(clippy::all, reason = "x")]'
  k_expect_case "K6 (outer #[expect(clippy::style, reason = ...)] on an item)" \
    "$tmp/src_expect_group_style" '#[expect(clippy::style, reason = "x")]'

  # ---- controls K7-K8: the MIXED list. Naming the exact lint AND a
  # group in one `expect` is the shape that reads as a licence to a
  # matcher looking for the exact spelling — the count does not move
  # when one narrow site is replaced by it — while `clippy::all` is what
  # actually governs every bare filesystem call in the file. A group
  # name ANYWHERE in the list therefore disqualifies the whole
  # attribute, whether or not the lint is named beside it. This does not
  # touch the multi-LINT `#[expect]`s the crate really has (control D2
  # pins one): they name other lints, never a group.
  k_expect_case "K7 (inner #![expect(clippy::disallowed_methods, clippy::all, reason = ...)] — the exact lint AND a group)" \
    "$tmp/src_expect_mixed_inner" '#![expect(clippy::disallowed_methods, clippy::all, reason = "x")]'
  k_expect_case "K8 (outer #[expect(clippy::disallowed_methods, clippy::style, reason = ...)] on an item)" \
    "$tmp/src_expect_mixed_outer" '#[expect(clippy::disallowed_methods, clippy::style, reason = "x")]'

  # ---- control K9: macro arguments can carry
  # `expect(...)` tokens that a macro splices
  # into a real attribute. The compiler
  # observation for this fixture is that the
  # group-wide licence suppresses the
  # disallowed-method diagnostic. The source
  # has no `#[` immediately before those
  # call-site tokens, so the attribute loop
  # alone cannot recognise the suppression.
  # The outside-attribute scan must report it.
  copy_crate_src_fixture "$tmp/src_macro_route"
  cat > "$tmp/src_macro_route/planted.rs" <<'RS'
macro_rules! licensed { ($m:meta) => { #[$m] pub fn planted() { let _ = std::fs::create_dir_all("/x"); } }; }
licensed!(expect(clippy::all, reason = "constructed group expect"));
RS
  macro_scan="$(scan_or_die "$tmp/src_macro_route")"
  macro_hits="$(scanned_allow_hits "$macro_scan")"
  macro_count="$(scanned_count "$macro_scan")"
  if report_bare_allow "$macro_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control K9 (a macro-constructed group expect) was not refused" >&2
    fail=1
  elif ! grep -q "planted.rs:2" <<<"$macro_hits"; then
    echo "self-test FAILED: control K9 refused but did not name the call-site LINE:" >&2
    echo "$macro_hits" >&2
    fail=1
  elif [[ "$macro_count" -ne "$EXPECTED_LICENSED_SITES" ]]; then
    echo "self-test FAILED: control K9 moved the COUNT to $macro_count (wanted $EXPECTED_LICENSED_SITES)" >&2
    fail=1
  else
    echo "self-test: control K9 (licensed!(expect(clippy::all, ...)) — the macro-argument route) — refused naming the line, as expected"
  fi

  # ---- control K10: the NEGATIVE half of K9. A `.expect("…")` method
  # call is `expect(` followed by an argument, and the crate's test
  # modules are full of them; only an argument that literally names the
  # lint or one of its groups may be reported. String literals are
  # blanked before the match runs, which is what makes the distinction
  # structural rather than a heuristic — but the control is what proves
  # it, since a matcher that reported every `expect(` would refuse the
  # real tree too.
  copy_crate_src_fixture "$tmp/src_expect_call"
  cat > "$tmp/src_expect_call/planted.rs" <<'RS'
fn planted() -> u32 {
    let v: Result<u32, ()> = Ok(1);
    v.expect("clippy::all is only a string here, and warnings is only a word")
}
RS
  expect_call_scan="$(scan_or_die "$tmp/src_expect_call")"
  expect_call_hits="$(scanned_allow_hits "$expect_call_scan")"
  if ! report_bare_allow "$expect_call_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control K10 (a .expect(\"…\") method call naming the lint inside its STRING) was refused, but must not be — reported [$expect_call_hits]" >&2
    fail=1
  else
    echo "self-test: control K10 (a .expect(\"…\") whose message names the group — a blanked string) — not refused, as expected"
  fi

  # ---- controls K11-K21: CHECK 6, the SOURCE CLOSURE. Each plants ONE
  # construction that makes rustc read source the scanner did not, and
  # asserts the gate refuses it BY NAME. A source control runs against
  # the real (clean) manifests and a manifest control against a clean
  # source tree, so the only thing that can be reported is the plant.
  closure_case() {
    local label="$1" dir="$2" needle="$3"
    local manifest="${4:-$CLIENT_MANIFEST}" fuzz="${5:-$CLIENT_FUZZ_MANIFEST}"
    # INDEPENDENT defaults: changing only the
    # manifest arguments leaves the audited dependency
    # and target sets at their real-crate defaults.
    # K19 and K16c use this to audit a planted
    # manifest against granary-client's sets.
    local deps="${6:-$CLIENT_DEPS_AUDITED}" targets="${7:-$CLIENT_TARGET_PATHS_AUDITED}"
    local fdeps="${8:-$CLIENT_FUZZ_DEPS_AUDITED}" ftargets="${9:-$CLIENT_FUZZ_TARGET_PATHS_AUDITED}"
    local hits rc
    set +e
    hits="$(collect_source_closure "$dir" "$manifest" "$fuzz" "$deps" "$targets" "$fdeps" "$ftargets")"
    rc=$?
    set -e
    if [[ "$rc" -ne 0 ]]; then
      echo "self-test FAILED: control $label — the closure collector could not complete" >&2
      fail=1
    elif report_source_closure "$hits" >/dev/null 2>&1; then
      echo "self-test FAILED: control $label — the planted construction was not refused" >&2
      fail=1
    elif ! grep -q "$needle" <<<"$hits"; then
      echo "self-test FAILED: control $label — refused but did not name $needle:" >&2
      echo "$hits" >&2
      fail=1
    else
      echo "self-test: control $label — refused naming it, as expected"
    fi
  }

  mkdir -p "$tmp/k11/src"
  echo "fn ordinary() {}" > "$tmp/k11/src/ordinary.rs"
  cat > "$tmp/k11/src/planted.rs" <<'RS'
macro_rules! wrapper { () => { pub fn planted() {} } }
wrapper!();
RS
  closure_case "K11 (a macro_rules! planted under src/)" "$tmp/k11" "planted.rs:1"

  # ---- control K12: the construction the SCANNER cannot see, and the
  # reason check 6 exists. A `macro_rules!` taking the lint PATH as an
  # argument carries no `allow(`/`expect(` tokens at the call site at
  # all, so neither the attribute loop nor the outside-an-attribute loop
  # (which closes the `licensed!(expect(clippy::all, …))` spelling) has
  # anything to match. Measured on the pinned toolchain: it compiles,
  # the ban does not fire inside it, and it scans COUNT with no ALLOW
  # line. So this control asserts BOTH halves — check 6 refuses it, and
  # the scanner does not, which is exactly why the refusal had to become
  # a rule about the construction rather than another spelling patch.
  copy_crate_src_fixture "$tmp/k12/src"
  cat > "$tmp/k12/src/planted.rs" <<'RS'
macro_rules! licensed { ($p:path) => { #[allow($p)] pub fn planted() { let _ = std::fs::create_dir_all("/x"); } } }
licensed!(clippy::all);
RS
  k12_scan="$(scan_or_die "$tmp/k12/src")"
  k12_hits="$(scanned_allow_hits "$k12_scan")"
  k12_count="$(scanned_count "$k12_scan")"
  if ! report_bare_allow "$k12_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control K12 — the scanner reported the lint-PATH macro route, so this control no longer isolates what check 6 is for: [$k12_hits]" >&2
    fail=1
  elif [[ "$k12_count" -ne "$EXPECTED_LICENSED_SITES" ]]; then
    echo "self-test FAILED: control K12 moved the COUNT to $k12_count (wanted $EXPECTED_LICENSED_SITES)" >&2
    fail=1
  else
    closure_case "K12 (macro_rules! licensed { (\$p:path) => { #[allow(\$p)] … } } — the lint-PATH route the scanner cannot see)" \
      "$tmp/k12" "planted.rs:1"
  fi

  mkdir -p "$tmp/k13/src"
  cat > "$tmp/k13/src/planted.rs" <<'RS'
#[path = "../../outside.rs"]
mod evasion;
RS
  closure_case "K13 (#[path = \"../../outside.rs\"] mod — rustc compiles a file the walk never visits)" \
    "$tmp/k13" "planted.rs:1"

  # ---- control K17: the include! arm. Its own control, not a second
  # plant inside K13's tree: a shared tree would stay green on a
  # mutation that removed either arm, since the other still reports.
  mkdir -p "$tmp/k17/src"
  cat > "$tmp/k17/src/planted.rs" <<'RS'
include!("../../shared.rs");
fn data() -> &'static str { include_str!("k.txt") }
RS
  closure_case "K17 (include! — rustc splices in source the walk never read, while include_str! beside it stays allowed)" \
    "$tmp/k17" "planted.rs:1"

  mkdir -p "$tmp/k14/src"
  echo "fn ordinary() {}" > "$tmp/k14/src/ordinary.rs"
  echo "fn outside() {}" > "$tmp/k14/outside_target.rs"
  ln -s "../outside_target.rs" "$tmp/k14/src/linked.rs"
  closure_case "K14 (a SYMLINKED .rs under src/ — find -type f skips it, rustc follows it)" \
    "$tmp/k14" "linked.rs"

  # ---- control K14b: the OTHER half of the symlink rule. A linked
  # DIRECTORY under a source root brings a whole subtree rustc compiles
  # and this gate never walked, and its name says nothing about `.rs`.
  # Without this control the directory arm is a blind mutation away from
  # doing nothing — measured: disabling it leaves every other control
  # green.
  mkdir -p "$tmp/k14b/src" "$tmp/k14b/outside_mod"
  echo "fn ordinary() {}" > "$tmp/k14b/src/ordinary.rs"
  echo "#![expect(clippy::all, reason = \"licensed from outside the walk\")]" > "$tmp/k14b/outside_mod/mod.rs"
  ln -s "../outside_mod" "$tmp/k14b/src/linked_mod"
  closure_case "K14b (a SYMLINKED DIRECTORY under src/ — rustc follows it into a subtree the walk never enters)" \
    "$tmp/k14b" "linked_mod"

  # ---- control K16: the DEPENDENCY half. A proc-macro dependency emits
  # attributes that exist only after expansion; this gate cannot resolve
  # which kind a new entry is, so the audited set is the mechanism and
  # any change to it must be refused.
  mkdir -p "$tmp/k16/src"
  echo "fn ordinary() {}" > "$tmp/k16/src/ordinary.rs"
  cp "$CLIENT_MANIFEST" "$tmp/k16/Cargo.toml"
  printf '\n[dependencies.planted_derive]\nversion = "1"\n' >> "$tmp/k16/Cargo.toml"
  closure_case "K16 (a dependency entry outside the audited set — the proc-macro route)" \
    "$tmp/k16" "planted_derive" "$tmp/k16/Cargo.toml"

  # ---- control K16b: the same dependency under a TARGET table. A plain
  # top-level read of [dependencies] never sees
  # `[target.'cfg(unix)'.dependencies]`, and a proc-macro can arrive
  # under any cfg — including one that is true on every platform this
  # crate builds for.
  mkdir -p "$tmp/k16b/src"
  echo "fn ordinary() {}" > "$tmp/k16b/src/ordinary.rs"
  cp "$CLIENT_MANIFEST" "$tmp/k16b/Cargo.toml"
  printf "\n[target.'cfg(unix)'.dependencies]\nplanted_derive = \"1\"\n" >> "$tmp/k16b/Cargo.toml"
  closure_case "K16b ([target.'cfg(unix)'.dependencies] planted_derive — the cfg-gated proc-macro route)" \
    "$tmp/k16b" "planted_derive" "$tmp/k16b/Cargo.toml"

  # ---- control K16c: the FUZZ manifest. It is a separate workspace with
  # its own lockfile, inside the walked tree and under the same nested
  # clippy config, so its dependency set is pinned separately — and a
  # control planting into the CLIENT manifest says nothing about
  # whether that second half runs at all (measured: it did not).
  mkdir -p "$tmp/k16c/src"
  echo "fn ordinary() {}" > "$tmp/k16c/src/ordinary.rs"
  cp "$CLIENT_FUZZ_MANIFEST" "$tmp/k16c/fuzz-Cargo.toml"
  printf '\n[dependencies.planted_derive]\nversion = "1"\n' >> "$tmp/k16c/fuzz-Cargo.toml"
  closure_case "K16c (a dependency entry outside the audited set in the fuzz workspace's own manifest)" \
    "$tmp/k16c" "planted_derive" "$CLIENT_MANIFEST" "$tmp/k16c/fuzz-Cargo.toml"

  # ---- control K19: the TARGET-PATH half — `#[path]`'s manifest
  # spelling. A target's `path` key moves its source ROOT, so a `[lib]`
  # pointing outside the crate compiles a file this gate never walks
  # while every `.rs` under the crate scans clean.
  mkdir -p "$tmp/k19/src"
  echo "fn ordinary() {}" > "$tmp/k19/src/ordinary.rs"
  cp "$CLIENT_MANIFEST" "$tmp/k19/Cargo.toml"
  mutate_or_die "K19" '
import pathlib
p = pathlib.Path("'"$tmp"'/k19/Cargo.toml")
text = p.read_text()
needle = "[lib]\nname = \"granary_client\"\npath = \"src/lib.rs\"\n"
assert needle in text, "the client manifest [lib] table changed shape"
p.write_text(text.replace(needle, "[lib]\nname = \"granary_client\"\npath = \"../shared/x.rs\"\n", 1))
'
  closure_case "K19 ([lib] path = \"../shared/x.rs\" — a target source root outside the walked tree)" \
    "$tmp/k19" "shared/x.rs" "$tmp/k19/Cargo.toml"

  # ---- control K20: the include macro reached by ANOTHER NAME. An
  # aliased import carries no `include` token at the call site at all,
  # so a pattern anchored on `include!` sees nothing — measured: the
  # scanner's literal arm does not report this file.
  mkdir -p "$tmp/k20/src"
  cat > "$tmp/k20/src/planted.rs" <<'RS'
use std::include as splice;
splice!("../../shared.rs");
RS
  k20_literal="$(printf '%s\0' "$tmp/k20/src/planted.rs" | python3 "$(dirname "${BASH_SOURCE[0]}")/fsguard-scan.py" --source-closure | grep -c 'include! —' || true)"
  if [[ "$k20_literal" -ne 0 ]]; then
    echo "self-test FAILED: control K20 — the literal include! arm reported the aliased import, so this control no longer isolates the aliased route" >&2
    fail=1
  else
    closure_case "K20 (use std::include as splice — the include macro under another name, which the include! pattern cannot see)" \
      "$tmp/k20" "planted.rs:1"
  fi

  # ---- control K21: the NEGATIVE half of the symlink rule. Not every
  # symlink under the crate is source rustc can read: a linked build
  # directory and a linked non-source asset are ordinary, and refusing
  # them would refuse real trees while proving nothing about what the
  # compiler reads.
  mkdir -p "$tmp/k21/src" "$tmp/k21/fuzz" "$tmp/k21/outside_dir"
  echo "fn ordinary() {}" > "$tmp/k21/src/ordinary.rs"
  echo "asset bytes" > "$tmp/k21/outside_asset.txt"
  ln -s "../outside_dir" "$tmp/k21/fuzz/target"
  ln -s "../outside_asset.txt" "$tmp/k21/src/data.txt"
  set +e
  k21_hits="$(collect_source_closure "$tmp/k21" "$CLIENT_MANIFEST" "$CLIENT_FUZZ_MANIFEST" "$CLIENT_DEPS_AUDITED" "$CLIENT_TARGET_PATHS_AUDITED" "$CLIENT_FUZZ_DEPS_AUDITED" "$CLIENT_FUZZ_TARGET_PATHS_AUDITED")"
  k21_rc=$?
  set -e
  if [[ "$k21_rc" -ne 0 ]]; then
    echo "self-test FAILED: control K21 — the closure collector could not complete" >&2
    fail=1
  elif ! report_source_closure "$k21_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control K21 (a symlinked fuzz/target and a symlinked non-source asset) was refused, but must not be: [$k21_hits]" >&2
    fail=1
  else
    echo "self-test: control K21 (a symlinked fuzz/target directory and a symlinked non-source asset — neither is source rustc reads) — not refused, as expected"
  fi

  # ---- controls K22-K23: the roots cargo discovers WITHOUT being told.
  # K14b covers `src/`; these two cover the roots a manifest never
  # mentions and CI still compiles, because `--all-targets` builds
  # examples and benches as well as lib/bin/tests. Cargo auto-discovers
  # `examples/` and `benches/` for the client package and the same
  # names, plus `fuzz_targets/`, inside the nested fuzz package — so a
  # link at any of them is a subtree rustc reads and this walk never
  # enters, exactly like a linked `src/`.
  mkdir -p "$tmp/k22/src" "$tmp/k22/outside_examples"
  echo "fn ordinary() {}" > "$tmp/k22/src/ordinary.rs"
  echo "fn main() {}" > "$tmp/k22/outside_examples/main.rs"
  ln -s "outside_examples" "$tmp/k22/examples"
  closure_case "K22 (a SYMLINKED examples/ — cargo auto-discovers it and --all-targets compiles what is behind the link)" \
    "$tmp/k22" "k22/examples"

  mkdir -p "$tmp/k23/src" "$tmp/k23/fuzz" "$tmp/k23/outside_fuzz_tests"
  echo "fn ordinary() {}" > "$tmp/k23/src/ordinary.rs"
  echo "#[test] fn planted() {}" > "$tmp/k23/outside_fuzz_tests/it.rs"
  ln -s "../outside_fuzz_tests" "$tmp/k23/fuzz/tests"
  closure_case "K23 (a SYMLINKED fuzz/tests/ — the nested fuzz package's own auto-discovered test root)" \
    "$tmp/k23" "k23/fuzz/tests"

  # ---- control K18: CHECK 6 MUST FAIL CLOSED. Every caller of
  # collect_source_closure invokes it with errexit suspended (under
  # `if !`, or an explicit `set +e`), and a command substitution is a
  # subshell — so a half that could not run yielded an empty result and
  # the gate printed its green summary. This control injects a failure
  # into the closure scanner: a COPY of fsguard-scan.py whose
  # scan_source_inputs raises, beside a COPY of this gate, run against
  # the real tree. Nothing in the real tree is touched.
  #
  # The refusal it greps for is the CLOSURE HALF'S OWN — the line
  # `source_closure_or_die` prints, naming the source-closure scan and
  # the directory it failed on. A generic "refused, never treated as
  # clean" would be satisfied by ANY earlier exit-2 path in the copied
  # gate (the python-version guard, a manifest half that could not run),
  # so the control would pass without the injected failure ever being
  # the reason.
  mkdir -p "$tmp/k18"
  cp "${BASH_SOURCE[0]}" "$tmp/k18/check-fsguard-sites.sh"
  cp "$(dirname "${BASH_SOURCE[0]}")/fsguard-scan.py" "$tmp/k18/fsguard-scan.py"
  mutate_or_die "K18" '
import pathlib
p = pathlib.Path("'"$tmp"'/k18/fsguard-scan.py")
text = p.read_text()
needle = "def scan_source_inputs(path: str):\n"
assert needle in text, "the closure scanner entry point changed shape"
p.write_text(text.replace(needle, needle + "    raise RuntimeError(\"injected closure-scanner failure\")\n", 1))
'
  set +e
  k18_out="$(bash "$tmp/k18/check-fsguard-sites.sh" 2>&1)"
  k18_rc=$?
  set -e
  if [[ "$k18_rc" -ne 2 ]]; then
    echo "self-test FAILED: control K18 — a closure scanner that CRASHED left the gate at exit $k18_rc (wanted 2):" >&2
    echo "$k18_out" >&2
    fail=1
  elif ! grep -q "the source-closure scan failed on $CRATE_DIR" <<<"$k18_out"; then
    echo "self-test FAILED: control K18 — the gate exited 2, but not by the source-closure scan's own refusal, so something else refused it:" >&2
    echo "$k18_out" >&2
    fail=1
  elif grep -q "licensed sites" <<<"$k18_out"; then
    echo "self-test FAILED: control K18 — the gate printed its green summary after a scanner failure:" >&2
    echo "$k18_out" >&2
    fail=1
  else
    echo "self-test: control K18 (an injected failure in the closure scanner) — the gate exited 2 with no green summary, as expected"
  fi

  # ---- control L: the SCAN ROOT. The nested clippy.toml governs the
  # whole crate directory (clippy resolves its config from the compiled
  # crate's manifest dir upward, so the `fuzz/` crate nested inside
  # granary-client gets this same config), and a bare allow there
  # switches the fs ban off for real code. A scan rooted at src/ and
  # tests/ would never look at it.
  # The copy EXCLUDES cargo build directories — a directory holding
  # cargo's own CACHEDIR.TAG. `cp -R` of the crate directory pulled in
  # crates/granary-client/fuzz/target/ whenever one existed: gigabytes
  # copied on every self-test run, and exactly the tree the scanner
  # prunes, so nothing was gained by copying it. Same predicate as the
  # scan's prune, so the two cannot drift.
  copy_crate_tree() {
    local src="${1%/}" dest="$2" rel
    mkdir -p "$dest"
    while IFS= read -r -d '' rel; do
      rel="${rel#./}"
      if [[ -d "$src/$rel" ]]; then
        mkdir -p "$dest/$rel"
      else
        mkdir -p "$dest/$(dirname "$rel")"
        cp "$src/$rel" "$dest/$rel"
      fi
    done < <(cd "$src" && find_pruned . -print0)
  }

  # The exclusion, PROVEN, on a SYNTHETIC tree — the real crate is never
  # copied to prove it. Copying the real one to demonstrate that a copy
  # skips build directories walks (and duplicates) whatever
  # crates/granary-client/fuzz/target/ happens to hold, which is the
  # exact cost the prune exists to avoid. Three files are enough to
  # decide it: one source file that must survive, and a build directory
  # (its CACHEDIR.TAG plus one residue) that must not.
  # The build directory is a real cargo target ROOT: `CACHEDIR.TAG`
  # AND a sibling `Cargo.toml`, which is what the prune requires. A tag
  # alone prunes nothing — that is the whole point of control
  # L3 below — so a fixture carrying only the tag would prove the
  # opposite of what it claims.
  mkdir -p "$tmp/l_src/src" "$tmp/l_src/fuzz/target"
  echo "fn x() {}" > "$tmp/l_src/src/x.rs"
  printf '[package]\nname = "l-fixture"\n' > "$tmp/l_src/fuzz/Cargo.toml"
  : > "$tmp/l_src/fuzz/target/CACHEDIR.TAG"
  echo "build residue" > "$tmp/l_src/fuzz/target/residue.rlib"
  copy_crate_tree "$tmp/l_src" "$tmp/l_excluded"
  if [[ -e "$tmp/l_excluded/fuzz/target/residue.rlib" || -e "$tmp/l_excluded/fuzz/target/CACHEDIR.TAG" ]]; then
    echo "self-test FAILED: control L's copy pulled in a cargo build directory (CACHEDIR.TAG present)" >&2
    fail=1
  elif [[ ! -e "$tmp/l_excluded/src/x.rs" ]]; then
    echo "self-test FAILED: control L's copy excluded the build dir but did not copy the source either — the exclusion cannot be proven by an empty copy" >&2
    fail=1
  else
    echo "self-test: control L copy (a cargo build directory is excluded; src/ still copied) — as expected"
  fi

  mkdir -p "$tmp/crate_copy"
  copy_crate_tree "$CRATE_DIR" "$tmp/crate_copy"
  mkdir -p "$tmp/crate_copy/fuzz/fuzz_targets"
  cat >> "$tmp/crate_copy/fuzz/fuzz_targets/planted.rs" <<'RS'
#[allow(clippy::disallowed_methods)]
fn planted() {
    let _ = std::fs::create_dir_all("/nowhere");
}
RS
  crate_copy_scan="$(scan_or_die "$tmp/crate_copy")"
  crate_copy_hits="$(scanned_allow_hits "$crate_copy_scan")"
  if report_bare_allow "$crate_copy_hits" >/dev/null 2>&1; then
    echo "self-test FAILED: control L (bare allow under fuzz/) — kill switch did not refuse it" >&2
    fail=1
  elif ! grep -q "fuzz/fuzz_targets/planted.rs" <<<"$crate_copy_hits"; then
    echo "self-test FAILED: control L refused but did not name the fuzz/ file — reported [$crate_copy_hits]" >&2
    fail=1
  else
    echo "self-test: control L (a bare #[allow] under fuzz/, outside src/ and tests/) — kill switch refused it, naming the file, as expected"
  fi

  # ---- control L2: a cargo BUILD directory inside the crate must be
  # pruned, and only a real one. Generated sources under a build dir are
  # not this crate's source, and without the prune the gate's answer
  # would depend on whether anyone had run `cargo fuzz` lately.
  mkdir -p "$tmp/crate_copy/fuzz/target" "$tmp/crate_copy/src/target"
  : > "$tmp/crate_copy/fuzz/target/CACHEDIR.TAG"
  printf '#[allow(clippy::disallowed_methods)]\nfn generated() {}\n' \
    > "$tmp/crate_copy/fuzz/target/generated.rs"
  printf '#[allow(clippy::disallowed_methods)]\nfn not_a_build_dir() {}\n' \
    > "$tmp/crate_copy/src/target/hidden.rs"
  l2_scan="$(scan_or_die "$tmp/crate_copy")"
  l2_hits="$(scanned_allow_hits "$l2_scan")"
  if grep -q "fuzz/target/generated.rs" <<<"$l2_hits"; then
    echo "self-test FAILED: control L2 — a cargo build directory (CACHEDIR.TAG present) was scanned" >&2
    fail=1
  elif ! grep -q "src/target/hidden.rs" <<<"$l2_hits"; then
    echo "self-test FAILED: control L2 — a directory merely NAMED target, with no CACHEDIR.TAG, must still be scanned; reported [$l2_hits]" >&2
    fail=1
  else
    echo "self-test: control L2 (a cargo build dir is pruned by its CACHEDIR.TAG; a directory merely named 'target' is not) — as expected"
  fi

  # ---- control O1: the DORMANT-BAN ORACLE's own entry guard. The
  # oracle is the lint lane's positive control — it plants a bare
  # filesystem call, runs clippy and requires the ban's diagnostic on
  # that exact span — so where it plants matters as much as what it
  # checks. Its `cd "$(git rev-parse --show-toplevel)" || exit 2` was
  # inert: when the substitution fails the shell runs `cd ""`, a no-op
  # returning 0 on bash 3.2 (the /bin/bash a stock macOS resolves), so
  # the guard could not fire and the oracle went on to plant into
  # whatever directory the caller happened to be in.
  #
  # GIT_DIR pointing at a non-repository makes `rev-parse` fail
  # deterministically. The MESSAGE is pinned, not just the exit code: on
  # bash 5 the no-op `cd` errors on its own and an unguarded oracle also
  # exits 2 — via `git diff` refusing a few lines later, which is a different
  # refusal for a different reason and would have read as "ok".
  mkdir -p "$tmp/o1-not-a-repo"
  o1_rc=0
  o1_out="$(GIT_DIR="$tmp/o1-not-a-repo" bash scripts/probes/fsguard-dormant-ban-oracle.sh 2>&1)" || o1_rc=$?
  if [[ "$o1_rc" -ne 2 ]]; then
    echo "self-test FAILED: control O1 — the oracle run outside a worktree exited $o1_rc, wanted 2:" >&2
    echo "$o1_out" >&2
    fail=1
  elif ! grep -q "not inside a git worktree" <<<"$o1_out"; then
    echo "self-test FAILED: control O1 — the oracle exited 2 but not by its own worktree guard:" >&2
    echo "$o1_out" >&2
    fail=1
  else
    echo "self-test: control O1 (the dormant-ban oracle refuses to plant when it cannot find the worktree root) — refused at status 2, naming the guard, as expected"
  fi

  # ---- control O2: the oracle's dirty guard covers the STAGED half.
  # `git diff --quiet` compares the working tree against the INDEX, so
  # a `git add`ed change reads as clean to it — and the restore is
  # `git checkout -- <file>`, which rewrites from the index. A scratch
  # repo carrying the path the oracle plants into is enough to decide
  # it: the guard runs before any cargo command, so this costs nothing.
  # An ABSOLUTE path, resolved before the subshell cds away: the oracle
  # is reached through this script's own directory, and a relative one
  # would resolve against the scratch repo.
  ORACLE_ABS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/probes/fsguard-dormant-ban-oracle.sh"
  mkdir -p "$tmp/o2/crates/granary-client/src"
  ( cd "$tmp/o2" || exit 9
    git init -q -b main .
    printf 'pub fn x() {}\n' > crates/granary-client/src/lib.rs
    git add -A
    git -c user.email=t@t -c user.name=t -c commit.gpgsign=false -c core.hooksPath=/dev/null \
      commit -qm base
    printf 'pub fn y() {}\n' >> crates/granary-client/src/lib.rs
    git add crates/granary-client/src/lib.rs
  ) >/dev/null 2>&1 || { echo "self-test FAILED: control O2 scratch repo could not be built" >&2; fail=1; }
  o2_rc=0
  o2_out="$( cd "$tmp/o2" && bash "$ORACLE_ABS" 2>&1 )" || o2_rc=$?
  if [[ "$o2_rc" -ne 2 ]]; then
    echo "self-test FAILED: control O2 — a STAGED change to the planted file did not stop the oracle (exit $o2_rc):" >&2
    echo "$o2_out" >&2
    fail=1
  elif ! grep -q "staged, unstaged or both" <<<"$o2_out"; then
    echo "self-test FAILED: control O2 — the oracle refused, but not by its dirty guard:" >&2
    echo "$o2_out" >&2
    fail=1
  else
    echo "self-test: control O2 (a STAGED edit to the file the oracle plants into — which git diff alone reads as clean) — refused at status 2, as expected"
  fi

  # ---- controls D4-D5: WHERE a wholesale licence is legitimate. An
  # inner `#![expect(clippy::disallowed_methods, …)]` licenses its whole
  # module, which is the sanctioned form under tests/ and fuzz/ (the
  # integration crates license their fixtures once at the top; the fuzz
  # target's banned call is inside a macro expansion where rustc
  # discards a narrower attribute) and is neither sanctioned nor
  # necessary under src/, where one line would silence the ban for a
  # module of production code while moving the count by exactly one.
  # Three fixtures, one refusal: the same attribute under src/, under a
  # module INSIDE src/ that happens to be named `tests`, and under the
  # crate's real tests/ tree. The middle one is why the rule is not
  # "any path with a tests component" — `src/tests/mod.rs` is an
  # ordinary library module, and naming it `tests` must not buy it a
  # module-wide licence.
  mkdir -p "$tmp/d4/src/tests" "$tmp/d4/tests"
  printf '#![expect(clippy::disallowed_methods, reason = "planted file-scoped licence")]\nfn x() {}\n' \
    > "$tmp/d4/src/planted.rs"
  printf '#![expect(clippy::disallowed_methods, reason = "planted inside a src module named tests")]\nfn z() {}\n' \
    > "$tmp/d4/src/tests/mod.rs"
  printf '#![expect(clippy::disallowed_methods, reason = "the sanctioned form under tests/")]\nfn y() {}\n' \
    > "$tmp/d4/tests/fixture.rs"
  d4_scan="$(scan_or_die "$tmp/d4")"
  d4_hits="$(scanned_allow_hits "$d4_scan")"
  d4_count="$(scanned_count "$d4_scan")"
  if ! grep -q "src/planted.rs" <<<"$d4_hits"; then
    echo "self-test FAILED: control D4 — a file-scoped #![expect] under src/ was not refused. Reported [$d4_hits]" >&2
    fail=1
  elif ! grep -q "src/tests/mod.rs" <<<"$d4_hits"; then
    echo "self-test FAILED: control D4b — a file-scoped #![expect] in a src/ module NAMED tests was not refused. Reported [$d4_hits]" >&2
    fail=1
  elif grep -q "d4/tests/fixture.rs" <<<"$d4_hits"; then
    echo "self-test FAILED: control D5 — the same attribute under the crate's tests/ tree was refused, and it is the sanctioned form there. Reported [$d4_hits]" >&2
    fail=1
  elif [[ "$d4_count" != "1" ]]; then
    echo "self-test FAILED: control D4 — the refused licences must not also be COUNTED; counted $d4_count, wanted 1 (the tests/ one alone)" >&2
    fail=1
  else
    echo "self-test: control D4/D4b/D5 (a file-scoped #![expect] is refused under src/ and under a src module named tests, accepted under the crate's tests/, and the refused ones are not counted) — as expected"
  fi

  # ---- controls R1-R5: WHAT A WHOLE-MODULE LICENCE ALSO LICENSES.
  # `disallowed_methods` is ONE lint carrying every row of
  # `disallowed-methods`, so a `#[expect]` on a `mod tests` item — or a
  # `#![expect]` at the top of an integration test — written for "bare
  # fs calls on their own scratch directories" equally silences the
  # ambient-input determinism seams and runtime-concurrency bans for
  # everything under it. Calling those methods "clippy-banned here"
  # does not preserve their ban: the whole-module licence suppresses it,
  # and the scanner must check their reach separately.
  #
  # The fixtures are one tree, scanned once, so the accept and refuse
  # halves cannot come from two different runs:
  #   licensed.rs    a file-scoped licence: a bare tokio::spawn and a
  #                  bare SystemTime::now (REFUSED), plus one call under
  #                  its own narrow fn #[expect] and one under a narrow
  #                  #[expect] on a `let` — the shape the pid sites use
  #                  (ACCEPTED)
  #   modlicensed.rs the OTHER wholesale shape, an #[expect] on a
  #                  `mod tests` item, with one call inside (REFUSED)
  #                  and one outside the module (left to clippy)
  #   unlicensed.rs  the same two calls with no licence anywhere — left
  #                  to clippy, never double-reported
  mkdir -p "$tmp/r1/tests"
  cat > "$tmp/r1/tests/licensed.rs" <<'RS'
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories"
)]
fn bare_spawn() {
    let _ = tokio::spawn(async {});
}
fn bare_clock() {
    let _ = std::time::SystemTime::now();
}
#[expect(clippy::disallowed_methods, reason = "narrow, per-site, reviewed on its own terms")]
fn narrow_spawn() {
    let _ = tokio::spawn(async {});
}
fn narrow_let() {
    static COUNTER: u64 = 0;
    #[expect(clippy::disallowed_methods, reason = "narrow, on the let — the pid sites' shape")]
    let _dir = format!("scratch-{}-{}", std::process::id(), COUNTER);
}
RS
  cat > "$tmp/r1/tests/modlicensed.rs" <<'RS'
#[expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories"
)]
#[cfg(test)]
mod tests {
    fn inside() {
        let _ = SystemTime::now();
    }
}
fn outside() {
    let _ = tokio::spawn(async {});
}
RS
  cat > "$tmp/r1/tests/unlicensed.rs" <<'RS'
fn no_licence_at_all() {
    let _ = tokio::spawn(async {});
    let _ = std::time::SystemTime::now();
}
RS
  r1_scan="$(scan_or_die "$tmp/r1")"
  r1_reach="$(scanned_reach_hits "$r1_scan")"
  r1_bad=""
  grep -q "licensed.rs:6:" <<<"$r1_reach" || r1_bad="$r1_bad tokio::spawn-under-a-file-licence"
  grep -q "licensed.rs:9:" <<<"$r1_reach" || r1_bad="$r1_bad SystemTime::now-under-a-file-licence"
  grep -q "modlicensed.rs:8:" <<<"$r1_reach" || r1_bad="$r1_bad call-inside-a-mod-tests-licence"
  grep -q "licensed.rs:12:" <<<"$r1_reach" && r1_bad="$r1_bad narrow-fn-expect-was-refused"
  grep -q "licensed.rs:18:" <<<"$r1_reach" && r1_bad="$r1_bad narrow-let-expect-was-refused"
  grep -q "modlicensed.rs:12:" <<<"$r1_reach" && r1_bad="$r1_bad call-outside-the-licensed-module-was-reported"
  grep -q "unlicensed.rs" <<<"$r1_reach" && r1_bad="$r1_bad unlicensed-file-was-double-reported"
  if [[ -n "$r1_bad" ]]; then
    echo "self-test FAILED: controls R1-R5 —$r1_bad. Reported [$r1_reach]" >&2
    fail=1
  else
    echo "self-test: controls R1-R5 (a non-fs row under a whole-file licence and under a mod-tests licence are refused; a narrow fn or let #[expect] excuses one; a call outside the licence, and any call in an unlicensed file, are left to clippy) — as expected"
  fi

  # ---- controls R8-R9: THE IMPORT ROUTE. A call oracle that matches
  # `std::process::id(` sees nothing after
  # `use std::process::id as ambient_pid;` — the call is `ambient_pid()`,
  # a name no text scanner resolves. Nor does it see a bare `now()`
  # after `use std::time::SystemTime::now;`, which needs no alias at
  # all: the two-segment spelling `SystemTime::now` is simply not what
  # the call site writes. Both are closed at the IMPORT, which has to
  # spell the path out.
  mkdir -p "$tmp/r8/tests"
  cat > "$tmp/r8/tests/aliased.rs" <<'RS'
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories"
)]
use std::process::id as ambient_pid;
fn f() {
    let _ = ambient_pid();
}
RS
  cat > "$tmp/r8/tests/onesegment.rs" <<'RS'
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories"
)]
use std::time::SystemTime::now;
fn f() {
    let _ = now();
}
RS
  cat > "$tmp/r8/tests/plainimport.rs" <<'RS'
fn no_licence() {}
RS
  printf 'use std::process::id as ambient_pid;\nfn f() { let _ = ambient_pid(); }\n' \
    >> "$tmp/r8/tests/plainimport.rs"
  r8_scan="$(scan_or_die "$tmp/r8")"
  r8_reach="$(scanned_reach_hits "$r8_scan")"
  r8_bad=""
  grep -q "aliased.rs:5:" <<<"$r8_reach" || r8_bad="$r8_bad aliased-import-not-refused"
  grep -q "onesegment.rs:5:" <<<"$r8_reach" || r8_bad="$r8_bad one-segment-import-not-refused"
  grep -q "plainimport.rs" <<<"$r8_reach" && r8_bad="$r8_bad unlicensed-import-was-reported"
  if [[ -n "$r8_bad" ]]; then
    echo "self-test FAILED: controls R8-R9 —$r8_bad. Reported [$r8_reach]" >&2
    fail=1
  else
    echo "self-test: controls R8-R9 (an aliased import and a one-segment import of a non-fs row are refused at the 'use' under a whole-file licence; the same import with no licence is left to clippy) — as expected"
  fi

  # ---- control R10: THE PARENT RENAME, the one shape the call
  # pattern and the import pattern both miss. After
  # `use std::process as pr;` the call reads `pr::id()`, whose last two
  # segments match no row, on an import line that names no row either.
  # Three spellings, one refusal each, plus the negative half on the
  # same tree: the same renames with no licence anywhere are left to
  # clippy.
  mkdir -p "$tmp/r10/tests"
  cat > "$tmp/r10/tests/rename_plain.rs" <<'RS'
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories"
)]
use std::process as pr;
fn f() {
    let _ = pr::id();
}
RS
  cat > "$tmp/r10/tests/rename_self.rs" <<'RS'
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories"
)]
use std::process::{self as pr};
fn f() {
    let _ = pr::id();
}
RS
  cat > "$tmp/r10/tests/rename_brace.rs" <<'RS'
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories"
)]
use std::{process as pr};
fn f() {
    let _ = pr::id();
}
RS
  cat > "$tmp/r10/tests/rename_glob.rs" <<'RS'
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories"
)]
use std::process::*;
fn f() {
    let _ = id();
}
RS
  cat > "$tmp/r10/tests/rename_globbrace.rs" <<'RS'
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories"
)]
use std::process::{self, *};
fn f() {
    let _ = id();
}
RS
  cat > "$tmp/r10/tests/turbofish.rs" <<'RS'
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories"
)]
fn f() {
    let _ = tokio::spawn::<_>(async {});
}
RS
  cat > "$tmp/r10/tests/rename_unlicensed.rs" <<'RS'
use std::process as pr;
use std::process::*;
fn f() {
    let _ = pr::id();
    let _ = tokio::spawn::<_>(async {});
}
RS
  r10_reach="$(scanned_reach_hits "$(scan_or_die "$tmp/r10")")"
  r10_bad=""
  for spelling in rename_plain rename_self rename_brace rename_glob rename_globbrace; do
    grep -q "$spelling.rs:5:" <<<"$r10_reach" || r10_bad="$r10_bad $spelling-not-refused"
  done
  # The TURBOFISH is a call, not an import: `tokio::spawn::<_>(fut)` is
  # the same call rustc lints, and the `::<…>` between the path and the
  # paren is the whole of the evasion.
  grep -q "turbofish.rs:6:" <<<"$r10_reach" || r10_bad="$r10_bad turbofish-not-refused"
  grep -q "rename_unlicensed.rs" <<<"$r10_reach" && r10_bad="$r10_bad unlicensed-file-was-reported"
  if [[ -n "$r10_bad" ]]; then
    echo "self-test FAILED: control R10 —$r10_bad. Reported [$r10_reach]" >&2
    fail=1
  else
    echo "self-test: control R10 (a rename or GLOB of a banned path's PARENT module — plain, self-in-braces, in-brace-group, bare glob and glob-in-braces — and a TURBOFISH call are all refused under a whole-file licence, while the same lines without one are left to clippy) — as expected"
  fi

  # ---- control D9: A GATE MUST NOT FAIL ON WHERE THE TREE IS. The
  # `src` rule reads the CRATE-RELATIVE components, so a checkout under
  # any directory named `src` — `~/src/granary` is the ordinary case —
  # keeps its crate-level `tests/*.rs` licences. Testing the whole path
  # refused every one of them, on a tree that is correct, because of
  # where someone put it.
  mkdir -p "$tmp/d9/src/proj/tests" "$tmp/d9/src/proj/src/tests"
  printf '#![expect(clippy::disallowed_methods, reason = "the sanctioned crate-level form")]\nfn y() {}\n' \
    > "$tmp/d9/src/proj/tests/fixture.rs"
  printf '#![expect(clippy::disallowed_methods, reason = "planted in a src module named tests")]\nfn z() {}\n' \
    > "$tmp/d9/src/proj/src/tests/mod.rs"
  d9_hits="$(scanned_allow_hits "$(scan_or_die "$tmp/d9/src/proj")")"
  if grep -q "proj/tests/fixture.rs" <<<"$d9_hits"; then
    echo "self-test FAILED: control D9 — a crate-level tests/ licence was refused because the CHECKOUT PATH contains a src component. Reported [$d9_hits]" >&2
    fail=1
  elif ! grep -q "proj/src/tests/mod.rs" <<<"$d9_hits"; then
    echo "self-test FAILED: control D9 — the src/tests/ licence INSIDE the crate stopped being refused. Reported [$d9_hits]" >&2
    fail=1
  else
    echo "self-test: control D9 (a crate checked out under a directory named src keeps its crate-level tests/ licence, while src/tests/ inside the crate is still refused) — as expected"
  fi

  # ---- control D10: A LICENCE COVERS ITS WHOLE STATEMENT. A `let`
  # whose expression contains a brace group — a struct literal, a
  # closure, a block — is one statement ending at its `;`. Reading the
  # first brace group as the item's BODY ends the licence early and
  # reports a correctly licensed call as unlicensed, which is a gate
  # refusing a tree that is right. Both halves on one file: the call
  # inside the licensed statement is accepted, the one after the `;` is
  # still refused.
  mkdir -p "$tmp/d10/tests"
  cat > "$tmp/d10/tests/braced.rs" <<'RS'
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories"
)]
struct Wrapper { n: u32 }
impl Wrapper {
    fn tag(self, _p: u32) -> u32 { self.n }
}
fn f() {
    #[expect(clippy::disallowed_methods, reason = "narrow, on the let, past a brace group")]
    let _x = Wrapper { n: 1 }.tag(std::process::id());
    let _after = std::process::id();
}
RS
  d10_reach="$(scanned_reach_hits "$(scan_or_die "$tmp/d10")")"
  if grep -q "braced.rs:11:" <<<"$d10_reach"; then
    echo "self-test FAILED: control D10 — a call inside its own licensed 'let' was refused because the licence span stopped at a brace group. Reported [$d10_reach]" >&2
    fail=1
  elif ! grep -q "braced.rs:12:" <<<"$d10_reach"; then
    echo "self-test FAILED: control D10 — the call AFTER the licensed statement was not refused, so the span now runs too far. Reported [$d10_reach]" >&2
    fail=1
  else
    echo "self-test: control D10 (a narrow licence on a let whose expression holds a brace group covers its own call, and stops at the semicolon) — as expected"
  fi

  # ---- control D11: recognize a licensed
  # function through its modifiers, including
  # `const`. Misclassifying a function as
  # a statement can extend the licence past
  # its body to a later semicolon and cover
  # the following item. The fixture checks
  # both sides: calls inside the licensed
  # function are accepted, while the
  # next item's call remains refused.
  #
  # Each half on the same file: the call INSIDE each licensed fn is
  # accepted, the call in the NEXT item is still refused.
  mkdir -p "$tmp/d11/tests"
  cat > "$tmp/d11/tests/modifiers.rs" <<'RS'
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories"
)]
#[expect(clippy::disallowed_methods, reason = "narrow, on a const fn")]
const fn a() -> u32 { let _ = std::process::id(); 0 }
fn after_a() { let _ = std::process::id(); }
#[expect(clippy::disallowed_methods, reason = "narrow, on an async unsafe fn")]
async unsafe fn b() { let _ = std::process::id(); }
fn after_b() { let _ = std::process::id(); }
fn outer() {
    #[expect(clippy::disallowed_methods, reason = "narrow, on a NESTED const fn")]
    const fn inner() -> u32 { let _ = std::process::id(); 0 }
    let _after_inner = std::process::id();
}
RS
  d11_reach="$(scanned_reach_hits "$(scan_or_die "$tmp/d11")")"
  d11_bad=""
  grep -q "modifiers.rs:6:" <<<"$d11_reach" && d11_bad="$d11_bad const-fn-body-was-refused"
  grep -q "modifiers.rs:9:" <<<"$d11_reach" && d11_bad="$d11_bad async-unsafe-fn-body-was-refused"
  grep -q "modifiers.rs:7:" <<<"$d11_reach" || d11_bad="$d11_bad the-item-after-the-const-fn-was-covered-by-its-licence"
  grep -q "modifiers.rs:10:" <<<"$d11_reach" || d11_bad="$d11_bad the-item-after-the-async-unsafe-fn-was-covered-by-its-licence"
  # THE NESTED CASE, because a licence on an inner item is the shape a
  # reader is least sure about. It does NOT tell the keyword list apart
  # from the safety net: measured, the net ends the span at the same
  # brace here, and the scanner records that the list is not
  # independently killable. Control D12 is what proves the net.
  grep -q "modifiers.rs:13:" <<<"$d11_reach" && d11_bad="$d11_bad nested-const-fn-body-was-refused"
  grep -q "modifiers.rs:14:" <<<"$d11_reach" || d11_bad="$d11_bad the-statement-after-a-nested-const-fn-was-covered-by-its-licence"
  if [[ -n "$d11_bad" ]]; then
    echo "self-test FAILED: control D11 —$d11_bad. Reported [$d11_reach]" >&2
    fail=1
  else
    echo "self-test: control D11 (a narrow licence on a const fn and on an async unsafe fn covers exactly its own body, and the banned call in the next item is still refused) — as expected"
  fi

  # ---- control D12: THE SAFETY NET, on a form the keyword list does
  # not know. `macro m { … }` (declarative macros 2.0) is real Rust and
  # is deliberately not in the list, so it falls to statement mode —
  # where a fn-shaped body ends with `}` and no `;`, and without the net
  # the span would run to the next `;` at depth 0 and cover the items
  # after it. The net ends it at the brace group that opened and closed
  # at depth 0, because what follows starts a new item.
  mkdir -p "$tmp/d12/tests"
  cat > "$tmp/d12/tests/unlisted.rs" <<'RS'
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories"
)]
#[expect(clippy::disallowed_methods, reason = "narrow, on an item form the list does not know")]
macro m() { let _ = std::process::id(); }
fn after_macro() { let _ = std::process::id(); }
RS
  d12_reach="$(scanned_reach_hits "$(scan_or_die "$tmp/d12")")"
  d12_bad=""
  grep -q "unlisted.rs:6:" <<<"$d12_reach" && d12_bad="$d12_bad the-unlisted-items-own-body-was-refused"
  grep -q "unlisted.rs:7:" <<<"$d12_reach" || d12_bad="$d12_bad the-item-after-an-unlisted-braced-item-was-covered-by-its-licence"
  if [[ -n "$d12_bad" ]]; then
    echo "self-test FAILED: control D12 —$d12_bad. Reported [$d12_reach]" >&2
    fail=1
  else
    echo "self-test: control D12 (a narrow licence on a braced item form the keyword list does not know covers its own body and stops there, rather than running on to the next semicolon) — as expected"
  fi

  # ---- control R11: NESTED `use` TREES. A regex can allow ONE brace
  # group before the segment it wants; Rust puts no limit on the
  # nesting, so the tree is expanded into full paths instead and depth
  # stops mattering. Four spellings, plus the negative on the same tree.
  mkdir -p "$tmp/r11/tests"
  cat > "$tmp/r11/tests/nested_named.rs" <<'RS'
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories"
)]
use std::{process::{id}};
fn f() { let _ = id(); }
RS
  cat > "$tmp/r11/tests/nested_alias.rs" <<'RS'
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories"
)]
use std::{process::{id as my_id}};
fn f() { let _ = my_id(); }
RS
  cat > "$tmp/r11/tests/nested_self.rs" <<'RS'
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories"
)]
use std::{process::{self as pr}};
fn f() { let _ = pr::id(); }
RS
  cat > "$tmp/r11/tests/nested_glob.rs" <<'RS'
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories"
)]
use std::{process::{*}};
fn f() { let _ = id(); }
RS
  cat > "$tmp/r11/tests/nested_clean.rs" <<'RS'
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories"
)]
use std::{sync::{atomic::{AtomicU64, Ordering}}, time::Duration};
use super::*;
fn f() {}
RS
  r11_reach="$(scanned_reach_hits "$(scan_or_die "$tmp/r11")")"
  r11_bad=""
  for spelling in nested_named nested_alias nested_self nested_glob; do
    grep -q "$spelling.rs:5:" <<<"$r11_reach" || r11_bad="$r11_bad $spelling-not-refused"
  done
  grep -q "nested_clean.rs" <<<"$r11_reach" && r11_bad="$r11_bad an-unrelated-nested-tree-was-reported"
  if [[ -n "$r11_bad" ]]; then
    echo "self-test FAILED: control R11 —$r11_bad. Reported [$r11_reach]" >&2
    fail=1
  else
    echo "self-test: control R11 (a nested use tree naming, aliasing, self-renaming or globbing a banned path is refused at any depth, while an unrelated nested tree and a super glob are not) — as expected"
  fi

  # ---- control D8: the licence-scope rule must not depend on WHERE
  # THE WALK STARTED. The licensed-site count is invoked with the
  # crate's `src` as its crate directory, and under that invocation a
  # first-component rule alone reads `src/tests/mod.rs` as the
  # crate-level tests tree — the exact case the rule exists to refuse.
  # Both invocations, one tree, one answer.
  mkdir -p "$tmp/d8/src/tests"
  printf '#![expect(clippy::disallowed_methods, reason = "planted in a src module named tests")]\nfn z() {}\n' \
    > "$tmp/d8/src/tests/mod.rs"
  d8_crate="$(scanned_allow_hits "$(scan_or_die "$tmp/d8")")"
  d8_src="$(scanned_allow_hits "$(scan_or_die "$tmp/d8/src")")"
  if ! grep -q "src/tests/mod.rs" <<<"$d8_crate"; then
    echo "self-test FAILED: control D8 — refused under the crate-root walk it was not. Reported [$d8_crate]" >&2
    fail=1
  elif ! grep -q "src/tests/mod.rs" <<<"$d8_src"; then
    echo "self-test FAILED: control D8 — under the src-only walk (the licensed-site count's own invocation) a src module named tests was ALLOWED a whole-file licence. Reported [$d8_src]" >&2
    fail=1
  else
    echo "self-test: control D8 (a whole-file licence in src/tests/ is refused under the crate-root walk AND under the src-only walk the count uses) — as expected"
  fi

  # ---- control D6: `tests` and `fuzz` are the CRATE'S OWN two roots,
  # not any directory with those names. `examples/tests/main.rs` and
  # `benches/fuzz/main.rs` are ordinary modules of ordinary targets, and
  # a whole-file licence at the top of one covers production-shaped code
  # the per-site count never describes.
  mkdir -p "$tmp/d6/examples/tests" "$tmp/d6/tests"
  printf '#![expect(clippy::disallowed_methods, reason = "planted under examples/tests")]\nfn x() {}\n' \
    > "$tmp/d6/examples/tests/main.rs"
  printf '#![expect(clippy::disallowed_methods, reason = "the sanctioned crate-level form")]\nfn y() {}\n' \
    > "$tmp/d6/tests/fixture.rs"
  d6_scan="$(scan_or_die "$tmp/d6")"
  d6_hits="$(scanned_allow_hits "$d6_scan")"
  if ! grep -q "examples/tests/main.rs" <<<"$d6_hits"; then
    echo "self-test FAILED: control D6 — a whole-file licence under examples/tests/ was not refused. Reported [$d6_hits]" >&2
    fail=1
  elif grep -q "d6/tests/fixture.rs" <<<"$d6_hits"; then
    echo "self-test FAILED: control D6 — the crate-level tests/ licence was refused, and it is the sanctioned form. Reported [$d6_hits]" >&2
    fail=1
  else
    echo "self-test: control D6 (a whole-file licence under examples/tests/ is refused while the crate-level tests/ one is not — the first component after the crate dir is what decides) — as expected"
  fi

  # ---- control D7: A LICENCE BY PROXY. `#[expect(...)] mod foo;`
  # attaches to the DECLARATION and licenses the whole of `foo.rs`,
  # which is scanned on its own and carries no attribute at all — the
  # count moves by one while the coverage is a file. The INLINE form
  # (`mod tests { … }`) is the wholesale shape this crate really uses
  # and must keep working, so it is the positive half.
  mkdir -p "$tmp/d7/src"
  cat > "$tmp/d7/src/lib.rs" <<'RS'
#[expect(clippy::disallowed_methods, reason = "a licence for a file this attribute is not in")]
mod proxy;

#[expect(clippy::disallowed_methods, reason = "the inline wholesale form, which is legitimate")]
mod inline_tests {
    fn a() {}
}
RS
  printf 'pub fn hidden() { let _ = std::fs::create_dir_all("/nowhere"); }\n' > "$tmp/d7/src/proxy.rs"
  d7_scan="$(scan_or_die "$tmp/d7")"
  d7_hits="$(scanned_allow_hits "$d7_scan")"
  d7_count="$(scanned_count "$d7_scan")"
  if ! grep -q "OUT-OF-LINE" <<<"$d7_hits"; then
    echo "self-test FAILED: control D7 — an #[expect] on a 'mod name;' declaration was not refused. Reported [$d7_hits]" >&2
    fail=1
  elif [[ "$d7_count" != "1" ]]; then
    echo "self-test FAILED: control D7 — the proxy licence must not be COUNTED and the inline one must be; counted $d7_count, wanted 1" >&2
    fail=1
  else
    echo "self-test: control D7 (an #[expect] on an out-of-line 'mod name;' is refused and not counted, while the inline 'mod { }' form still counts) — as expected"
  fi

  # ---- controls T1-T6: a test file must carry its OWN test-only shield.
  # Keep the PARENT declaration bare (`#[cfg(test)] mod tests;`, with
  # no lint attribute): the ban on licensing an out-of-line module
  # declaration remains absolute. The CHILD carries
  # BOTH `#![cfg(test)]` and `#![expect(clippy::disallowed_methods, …)]`
  # at file scope. Every fixture below lives under a `src/` path with no
  # `tests/`/`fuzz/` top-level component, so `wholesale_licence_allowed`'s
  # path-based reading refuses all of them on its own. Only the file's
  # own test-implying shield can make T1/T4's `all(test, unix)` case
  # ACCEPT, isolating content-based acceptance from path-based acceptance.

  # ---- control T1: the sanctioned shape itself. ACCEPTED (not reported
  # in ALLOW), COUNTED as a licence, and its own non-fs banned row still
  # REACHES. Assert all three: accepting the licence and preserving COUNT
  # does not establish that non-filesystem calls remain visible to REACH.
  # A zero REACH result for the planted banned call is a failure even
  # when acceptance and the licensed-site count are both correct.
  mkdir -p "$tmp/t1/src/foo"
  cat > "$tmp/t1/src/foo/tests.rs" <<'RS'
#![cfg(test)]
#![expect(clippy::disallowed_methods, reason = "test module: fixture uses bare fs calls")]

#[test]
fn t() {
    let _ = std::fs::create_dir_all("/nowhere");
    let _ = std::process::id();
}
RS
  t1_scan="$(scan_or_die "$tmp/t1")"
  t1_count="$(scanned_count "$t1_scan")"
  t1_hits="$(scanned_allow_hits "$t1_scan")"
  t1_reach="$(scanned_reach_hits "$t1_scan")"
  t1_licences="$(scanned_licence_count "$t1_scan")"
  if [[ "$t1_count" != "1" ]]; then
    echo "self-test FAILED: control T1 — a file-scoped #![cfg(test)] + #![expect] was not COUNTED; counted $t1_count, wanted 1" >&2
    fail=1
  elif [[ -n "$t1_hits" ]]; then
    echo "self-test FAILED: control T1 — the sanctioned shape was refused. Reported [$t1_hits]" >&2
    fail=1
  elif ! grep -q "tests.rs:7:" <<<"$t1_reach"; then
    echo "self-test FAILED: control T1 — the accepted licence's own non-fs row (std::process::id) did not REACH; the reach half is the reason this shape was chosen. Reported [$t1_reach]" >&2
    fail=1
  elif [[ "$t1_licences" != "1" ]]; then
    echo "self-test FAILED: control T1 — LICENCES did not register the wholesale span; got $t1_licences, wanted 1" >&2
    fail=1
  else
    echo "self-test: control T1 (a file-scoped #![cfg(test)] + #![expect(clippy::disallowed_methods, …)] is ACCEPTED, COUNTED, and its own non-fs row still REACHES) — as expected"
  fi

  # ---- control T2: the identical file WITHOUT #![cfg(test)] stays
  # REFUSED — a bare file-scoped #![expect] under src/ buys nothing on
  # its own; the compiler's own enforcement is what the whole repair
  # rests on, and it is the `#![cfg(test)]` that invokes it.
  mkdir -p "$tmp/t2/src/foo"
  cat > "$tmp/t2/src/foo/tests.rs" <<'RS'
#![expect(clippy::disallowed_methods, reason = "test module: fixture uses bare fs calls")]

#[test]
fn t() {
    let _ = std::fs::create_dir_all("/nowhere");
    let _ = std::process::id();
}
RS
  t2_scan="$(scan_or_die "$tmp/t2")"
  t2_count="$(scanned_count "$t2_scan")"
  t2_hits="$(scanned_allow_hits "$t2_scan")"
  if [[ "$t2_count" != "0" ]]; then
    echo "self-test FAILED: control T2 — a file-scoped #![expect] with NO #![cfg(test)] was COUNTED; counted $t2_count, wanted 0" >&2
    fail=1
  elif ! grep -q "tests.rs:1:" <<<"$t2_hits"; then
    echo "self-test FAILED: control T2 — the same file with no #![cfg(test)] was not refused. Reported [$t2_hits]" >&2
    fail=1
  else
    echo "self-test: control T2 (the identical file WITHOUT #![cfg(test)] stays REFUSED) — as expected"
  fi

  # ---- controls T3a-T3c: condition 1, FILE-SCOPED MEANS DEPTH 0 OVER
  # ALL THREE DELIMITER KINDS. Same lint attribute as T1, at the same
  # file scope; the only difference across the three is which delimiter
  # kind the only `#![cfg(test)]` is nested inside — `{}` (T3a, an
  # inline `mod { … }`), `()` (T3b, `nop!(#![cfg(test)]);`) and `[]`
  # (T3c, `nop![#![cfg(test)]]`). T3b and T3c are the two shapes that
  # demonstrated the fail-open this rule had: `block_spans` tracks only
  # `{`…`}`, so an inner attribute sitting inside a paren- or
  # bracket-delimited macro call read as depth 0 — file-scoped — and
  # wholesale-licensed the whole file, with `nop!` never itself gating
  # anything (a macro's argument list is not a module; rustc compiles
  # `prod()` normally either way). Reproduced against the unfixed scanner:
  # `COUNT 1` with no `ALLOW` line for both T3b's and T3c's shape; deleting
  # the `nop!`/`nop![...]` line, or fixing `file_scoped_cfg_test` to read
  # depth over `{}`, `()` AND `[]` together, both correctly refuse it.
  # T3a is unaffected either way (braces were always tracked) and stays
  # here as the ORIGINAL delimiter kind, so all three are pinned in one
  # place rather than only the one that happened to be checked before.
  mkdir -p "$tmp/t3a/src/foo"
  cat > "$tmp/t3a/src/foo/tests.rs" <<'RS'
#![expect(clippy::disallowed_methods, reason = "test module: fixture uses bare fs calls")]

mod nested {
    #![cfg(test)]
}

#[test]
fn t() {
    let _ = std::fs::create_dir_all("/nowhere");
    let _ = std::process::id();
}
RS
  t3a_scan="$(scan_or_die "$tmp/t3a")"
  t3a_count="$(scanned_count "$t3a_scan")"
  t3a_hits="$(scanned_allow_hits "$t3a_scan")"
  if [[ "$t3a_count" != "0" ]]; then
    echo "self-test FAILED: control T3a — a #![cfg(test)] nested inside an inline 'mod { }' licensed the FILE; counted $t3a_count, wanted 0" >&2
    fail=1
  elif ! grep -q "tests.rs:1:" <<<"$t3a_hits"; then
    echo "self-test FAILED: control T3a — the file-scoped #![expect] was not refused when the only #![cfg(test)] is nested inside '{}', not at file scope. Reported [$t3a_hits]" >&2
    fail=1
  else
    echo "self-test: control T3a (#![cfg(test)] inside an inline 'mod { }' does not license the FILE — refused) — as expected"
  fi

  mkdir -p "$tmp/t3b/src/foo"
  cat > "$tmp/t3b/src/foo/tests.rs" <<'RS'
#![expect(clippy::disallowed_methods, reason = "test module: fixture uses bare fs calls")]

nop!(#![cfg(test)]);

pub fn prod() {
    let _ = std::fs::create_dir_all("/nowhere");
    let _ = std::process::id();
}
RS
  t3b_scan="$(scan_or_die "$tmp/t3b")"
  t3b_count="$(scanned_count "$t3b_scan")"
  t3b_hits="$(scanned_allow_hits "$t3b_scan")"
  if [[ "$t3b_count" != "0" ]]; then
    echo "self-test FAILED: control T3b — a #![cfg(test)] nested inside 'nop!( … )' (a PAREN-delimited macro call) licensed the FILE; counted $t3b_count, wanted 0" >&2
    fail=1
  elif ! grep -q "tests.rs:1:" <<<"$t3b_hits"; then
    echo "self-test FAILED: control T3b — the file-scoped #![expect] was not refused when the only #![cfg(test)] is nested inside '()', not at file scope. Reported [$t3b_hits]" >&2
    fail=1
  else
    echo "self-test: control T3b (#![cfg(test)] inside 'nop!(#![cfg(test)]);' — a PAREN-delimited macro call — does not license the FILE — refused) — as expected"
  fi

  mkdir -p "$tmp/t3c/src/foo"
  cat > "$tmp/t3c/src/foo/tests.rs" <<'RS'
#![expect(clippy::disallowed_methods, reason = "test module: fixture uses bare fs calls")]

nop![#![cfg(test)]]

pub fn prod() {
    let _ = std::fs::create_dir_all("/nowhere");
    let _ = std::process::id();
}
RS
  t3c_scan="$(scan_or_die "$tmp/t3c")"
  t3c_count="$(scanned_count "$t3c_scan")"
  t3c_hits="$(scanned_allow_hits "$t3c_scan")"
  if [[ "$t3c_count" != "0" ]]; then
    echo "self-test FAILED: control T3c — a #![cfg(test)] nested inside 'nop![ … ]' (a BRACKET-delimited macro call) licensed the FILE; counted $t3c_count, wanted 0" >&2
    fail=1
  elif ! grep -q "tests.rs:1:" <<<"$t3c_hits"; then
    echo "self-test FAILED: control T3c — the file-scoped #![expect] was not refused when the only #![cfg(test)] is nested inside '[]', not at file scope. Reported [$t3c_hits]" >&2
    fail=1
  else
    echo "self-test: control T3c (#![cfg(test)] inside 'nop![#![cfg(test)]]' — a BRACKET-delimited macro call — does not license the FILE — refused) — as expected"
  fi

  # ---- control T4: the predicate must IMPLY test — condition 2.
  # `any(test, feature = "x")` is a real hole (production code under
  # `--features x`) and `not(test)` is refused by the same substring
  # search; `all(test, unix)` names test as a direct conjunct and is
  # ACCEPTED. One tree, three fixtures, scanned once — so accept and
  # refuse cannot come from different runs.
  mkdir -p "$tmp/t4/src/any_case" "$tmp/t4/src/not_case" "$tmp/t4/src/all_case"
  cat > "$tmp/t4/src/any_case/tests.rs" <<'RS'
#![cfg(any(test, feature = "x"))]
#![expect(clippy::disallowed_methods, reason = "test module: fixture uses bare fs calls")]

fn t() {
    let _ = std::fs::create_dir_all("/nowhere");
}
RS
  cat > "$tmp/t4/src/not_case/tests.rs" <<'RS'
#![cfg(not(test))]
#![expect(clippy::disallowed_methods, reason = "test module: fixture uses bare fs calls")]

fn t() {
    let _ = std::fs::create_dir_all("/nowhere");
}
RS
  cat > "$tmp/t4/src/all_case/tests.rs" <<'RS'
#![cfg(all(test, unix))]
#![expect(clippy::disallowed_methods, reason = "test module: fixture uses bare fs calls")]

#[test]
fn t() {
    let _ = std::fs::create_dir_all("/nowhere");
    let _ = std::process::id();
}
RS
  t4_scan="$(scan_or_die "$tmp/t4")"
  t4_count="$(scanned_count "$t4_scan")"
  t4_hits="$(scanned_allow_hits "$t4_scan")"
  t4_reach="$(scanned_reach_hits "$t4_scan")"
  t4_bad=""
  [[ "$t4_count" == "1" ]] || t4_bad="$t4_bad count-$t4_count-wanted-1"
  grep -q "any_case/tests.rs:2:" <<<"$t4_hits" || t4_bad="$t4_bad any(test,...)-not-refused"
  grep -q "not_case/tests.rs:2:" <<<"$t4_hits" || t4_bad="$t4_bad not(test)-not-refused"
  grep -q "all_case/tests.rs" <<<"$t4_hits" && t4_bad="$t4_bad all(test,unix)-was-refused"
  grep -q "all_case/tests.rs:7:" <<<"$t4_reach" || t4_bad="$t4_bad all(test,unix)-reach-missing"
  if [[ -n "$t4_bad" ]]; then
    echo "self-test FAILED: control T4 —$t4_bad. hits=[$t4_hits] reach=[$t4_reach]" >&2
    fail=1
  else
    echo "self-test: control T4 (#![cfg(any(test, feature = \"x\"))] and #![cfg(not(test))] are REFUSED; #![cfg(all(test, unix))] naming test as a direct conjunct is ACCEPTED) — as expected"
  fi

  # ---- control T5: the two-level tests.rs -> tests/<concern>.rs chain
  # is a disclosed scanner limit. Only tests.rs carries `#![cfg(test)]` +
  # `#![expect]`; concern.rs is a SEPARATE file this scanner reads on its
  # own, with no attribute of its own — so its own non-fs banned row is
  # NOT reported as reach, and does not move COUNT either. The scanner
  # does not propagate licences between files or resolve module ownership.
  # This control pins that per-file behaviour so any change to inherited
  # licence handling must produce an observable change in the test.
  mkdir -p "$tmp/t5/src/foo/tests"
  cat > "$tmp/t5/src/foo/tests.rs" <<'RS'
#![cfg(test)]
#![expect(clippy::disallowed_methods, reason = "test module: fixture uses bare fs calls")]

#[cfg(test)]
mod concern;
RS
  cat > "$tmp/t5/src/foo/tests/concern.rs" <<'RS'
#[test]
fn t() {
    let _ = std::fs::create_dir_all("/nowhere");
    let _ = std::process::id();
}
RS
  t5_scan="$(scan_or_die "$tmp/t5")"
  t5_count="$(scanned_count "$t5_scan")"
  t5_hits="$(scanned_allow_hits "$t5_scan")"
  t5_reach="$(scanned_reach_hits "$t5_scan")"
  if [[ "$t5_count" != "1" ]]; then
    echo "self-test FAILED: control T5 — tests.rs's own licence was not COUNTED; counted $t5_count, wanted 1" >&2
    fail=1
  elif [[ -n "$t5_hits" ]]; then
    echo "self-test FAILED: control T5 — tests.rs was refused when it should be the sanctioned shape. Reported [$t5_hits]" >&2
    fail=1
  elif grep -q "concern.rs" <<<"$t5_reach"; then
    echo "self-test FAILED: control T5 — concern.rs's own non-fs row was reported as REACH; this scanner has no cross-file machinery and was not expected to see it. Reported [$t5_reach]" >&2
    fail=1
  else
    echo "self-test: control T5 (a two-level tests.rs -> tests/concern.rs chain: tests.rs's own licence is counted; concern.rs's non-fs row is DISCLOSED as invisible to --banned-rows, not reported, since only tests.rs carries the attributes and this scanner reads each file on its own) — as expected"
  fi

  # ---- control T6: fixture copies must include source subdirectories.
  # `cp -R "$CRATE_SRC"/*.rs "$dir/"` uses a FLAT glob: it expands only
  # to files directly inside $CRATE_SRC, silently omitting nested files
  # such as `cache/space.rs`. That file carries zero licences, so its
  # omission alone cannot distinguish flat and recursive copies by COUNT.
  # The `<module>/tests.rs` bodies DO carry licences and DO affect COUNT —
  # re-derive how many rather than trusting a number written here, because
  # every child cut out of the crate root adds another such file.
  # Omitting them makes the copied fixture's count incomplete.
  # The six controls that compare a copy's COUNT to
  # EXPECTED_LICENSED_SITES must therefore receive the complete tree,
  # or they can reject a correct source tree because the copy is wrong.
  # Copy `$CRATE_SRC`'s CONTENTS recursively at every fixture-copy site,
  # through `copy_crate_src_fixture`.
  # See the comments at CRATE_SRC's definition and at the helper for
  # the destination layout and the required trailing `/.` source form.
  #
  # TWO HALVES, because routing every site through one helper closes two
  # DIFFERENT regressions, not one:
  #   STATIC — a call site stops calling the helper at all and inlines
  #   the flat glob directly again, bypassing it. The dynamic half below
  #   cannot see this: it only ever exercises the helper's OWN copy, so
  #   a bypassed call site would leave every other site, and this
  #   dynamic half, silently green — exactly the failure mode this
  #   control exists to close, now that there is one function every site
  #   is SUPPOSED to call. Checked by reading THIS SCRIPT'S OWN SOURCE
  #   (never `find`-walked — the self-test's fixtures all live under
  #   $tmp) for the flat-glob text on a CODE line; never a comment, since
  #   this file's own prose names the flat form three times, verbatim,
  #   to explain the trap, and pinning that prose would be the control
  #   tripping over its own documentation.
  #   DYNAMIC — the helper ITSELF regresses to the flat form. Proved by
  #   planting a licence one level down, under `cache/`, in a copy the
  #   helper built, and requiring the count to see it — a flat copy
  #   would silently drop the whole `cache/` subdirectory instead.
  self_source="${BASH_SOURCE[0]}"
  flat_glob_code_hits="$(python3 - "$self_source" <<'PY'
import sys
path = sys.argv[1]
# ASSEMBLED from two fragments so that THIS line is not itself the
# first occurrence of the needle in the file. Without it the scan
# reports its own definition as a "call site" and the control fails on
# a clean tree — a probe that matches itself. `main.rs`'s
# `production_source()` documents the same trick for the same reason.
needle = 'cp -R "$CRATE_' + 'SRC"/*.rs'
# encoding PINNED: this is a self-test that must not abort with a raw
# UnicodeDecodeError under a non-UTF-8 default locale, and the file it
# reads is ITSELF, which carries 2,462 non-ASCII bytes.
with open(path, encoding="utf-8") as f:
    for lineno, line in enumerate(f, 1):
        if needle in line and not line.lstrip().startswith("#"):
            print(f"{lineno}: {line.rstrip(chr(10))}")
PY
)"
  # THE STATIC HALF PINS ONE EXACT SPELLING and is belt-and-braces only:
  # `cp "$CRATE_SRC"/*.rs` without -R, or an unquoted variant, reintroduces
  # the regression with this half green. The DYNAMIC half below is the real
  # control — it plants under cache/ and counts, so it catches a flat copy
  # whatever spelling reintroduced it. Proved: a `find -maxdepth 1` rewrite
  # of the helper defeats the static half and the dynamic half still fires.
  t6_bad=""
  if [[ -n "$flat_glob_code_hits" ]]; then
    t6_bad="STATIC: a fixture-copy call site bypassed copy_crate_src_fixture and inlined the flat glob directly — [$flat_glob_code_hits]"
  fi
  copy_crate_src_fixture "$tmp/t6"
  if [[ ! -f "$tmp/t6/cache/space.rs" ]]; then
    t6_bad="${t6_bad}${t6_bad:+; }DYNAMIC: this control's own fixture assumption no longer holds — $CRATE_SRC/cache/space.rs is missing from a recursive copy of \$CRATE_SRC. Either the copy silently regressed to a flat glob (which would drop the whole cache/ subdirectory) or the crate's one subdirectory file moved/was renamed — this control has nothing to plant into either way"
  else
    cat >> "$tmp/t6/cache/space.rs" <<'RS'

#[expect(clippy::disallowed_methods, reason = "planted one level down, under cache/, to prove a subdirectory licence is not dropped")]
fn t6_planted() {
    let _ = std::fs::create_dir_all("/nowhere");
}
RS
    t6_scan="$(scan_or_die "$tmp/t6")"
    t6_count="$(scanned_count "$t6_scan")"
    t6_want=$((EXPECTED_LICENSED_SITES + 1))
    if [[ "$t6_count" != "$t6_want" ]]; then
      t6_bad="${t6_bad}${t6_bad:+; }DYNAMIC: a licence planted under cache/ (a subdirectory of \$CRATE_SRC) was not counted; got $t6_count, wanted $t6_want. A flat 'cp -R \"\$CRATE_SRC\"/*.rs' copy drops every file under a subdirectory silently, which is exactly the regression this control exists to catch"
    fi
  fi
  if [[ -n "$t6_bad" ]]; then
    echo "self-test FAILED: control T6 —$t6_bad" >&2
    fail=1
  else
    echo "self-test: control T6 (STATIC: no fixture-copy call site bypasses copy_crate_src_fixture for the flat glob; DYNAMIC: a licence planted one level down, under cache/, is counted at $t6_count — the fixture copy is recursive) — as expected, both halves"
  fi

  # ---- control R6: the row set is the CONFIG'S. A scanner carrying its
  # own copy of the rows would keep refusing after the config stopped
  # naming them, and would keep passing after it started. Same tree,
  # same scanner, a row list with the concurrency and clock rows removed
  # — the refusals must disappear.
  printf 'disallowed-methods = [\n  { path = "std::fs::write", reason = "an fs row and nothing else" },\n]\n' \
    > "$tmp/r6-clippy.toml"
  r6_scan="$(scan_or_die "$tmp/r1" "$tmp/r6-clippy.toml")"
  r6_reach="$(scanned_reach_hits "$r6_scan")"
  if [[ -n "$r6_reach" ]]; then
    echo "self-test FAILED: control R6 — the refusals survived a row set that does not name the calls, so the scanner is not reading the config. Reported [$r6_reach]" >&2
    fail=1
  else
    echo "self-test: control R6 (a row set without the clock and concurrency rows reports nothing on the same tree — the set is the config's, not a second list) — as expected"
  fi

  # ---- control R7: an unreadable or empty row set is a REFUSAL, never
  # an empty set that quietly checks nothing.
  r7_rc=0
  ( printf '' > "$tmp/r7-empty.toml"
    scan_fs_sites "$tmp/r1" "$tmp/r7-empty.toml" ) >/dev/null 2>"$tmp/r7.err" || r7_rc=$?
  if [[ "$r7_rc" -ne 2 ]] || ! grep -q "disallowed-methods" "$tmp/r7.err"; then
    echo "self-test FAILED: control R7 — an empty row-set file returned $r7_rc and said:" >&2
    cat "$tmp/r7.err" >&2
    fail=1
  else
    echo "self-test: control R7 (a row-set file with no disallowed-methods rows) — refused at status 2, as expected"
  fi

  # ---- control L3: the TAG IS NOT ENOUGH. A `CACHEDIR.TAG` dropped
  # into `src/target/` plus a `mod target;` in lib.rs is a real module
  # tree rustc compiles; a prune keyed on the tag alone hides every
  # `.rs` under it from the count, the kill switch and the source
  # closure at once. The prune also requires a SIBLING `Cargo.toml`,
  # which `src/` does not have — so the tree is scanned, and the
  # directory is refused by check 6 on top of that.
  mkdir -p "$tmp/l3/src/target"
  printf 'mod target;\n' > "$tmp/l3/src/lib.rs"
  : > "$tmp/l3/src/target/CACHEDIR.TAG"
  printf '#[allow(clippy::disallowed_methods)]\nfn tagged_but_not_a_build_dir() {}\n' \
    > "$tmp/l3/src/target/tagged.rs"
  l3_scan="$(scan_or_die "$tmp/l3")"
  l3_hits="$(scanned_allow_hits "$l3_scan")"
  set +e
  l3_closure="$(collect_source_closure "$tmp/l3" "$CLIENT_MANIFEST" "$CLIENT_FUZZ_MANIFEST" "$CLIENT_DEPS_AUDITED" "$CLIENT_TARGET_PATHS_AUDITED" "$CLIENT_FUZZ_DEPS_AUDITED" "$CLIENT_FUZZ_TARGET_PATHS_AUDITED")"
  l3_closure_rc=$?
  set -e
  if ! grep -q "src/target/tagged.rs" <<<"$l3_hits"; then
    echo "self-test FAILED: control L3 — a CACHEDIR.TAG in src/target/ pruned a SOURCE tree; the bare allow inside it was never scanned. Reported [$l3_hits]" >&2
    fail=1
  elif [[ "$l3_closure_rc" -ne 0 ]]; then
    echo "self-test FAILED: control L3 — the source closure could not complete on the planted tree" >&2
    fail=1
  elif ! grep -q "src/target: a directory named" <<<"$l3_closure"; then
    echo "self-test FAILED: control L3 — check 6 did not refuse the src/target directory itself. Reported [$l3_closure]" >&2
    fail=1
  else
    echo "self-test: control L3 (src/target/ + CACHEDIR.TAG + mod target; — scanned anyway, and refused by check 6 as a non-build 'target' directory) — as expected"
  fi

  # ---- control L4: THE PRUNE'S PREMISE, one level up. `find_pruned`
  # skips a `target` directory only when a `Cargo.toml` sits beside it,
  # so a manifest planted under `src/` makes `src/target/` a build root
  # again and hides the tree under it from every scan — the same hole
  # L3 closes, reached through the test L3 relies on. The manifest set
  # is pinned instead: exactly the crate's own and the fuzz
  # workspace's, both of which the POSITIVE half below must not refuse.
  mkdir -p "$tmp/l4/src/target" "$tmp/l4/fuzz"
  printf '[package]\nname = "l4"\n' > "$tmp/l4/Cargo.toml"
  printf '[package]\nname = "l4-fuzz"\n' > "$tmp/l4/fuzz/Cargo.toml"
  printf 'mod target;\n' > "$tmp/l4/src/lib.rs"
  set +e
  l4_ok="$(find_foreign_tree_entries "$tmp/l4")"
  l4_ok_rc=$?
  set -e
  printf '[package]\nname = "planted"\n' > "$tmp/l4/src/Cargo.toml"
  : > "$tmp/l4/src/target/CACHEDIR.TAG"
  printf '#[allow(clippy::disallowed_methods)]\nfn hidden() {}\n' > "$tmp/l4/src/target/hidden.rs"
  set +e
  l4_bad="$(find_foreign_tree_entries "$tmp/l4")"
  l4_bad_rc=$?
  set -e
  if [[ "$l4_ok_rc" -ne 0 || "$l4_bad_rc" -ne 0 ]]; then
    echo "self-test FAILED: control L4 — the target-directory/manifest walk could not complete" >&2
    fail=1
  elif grep -q "a Cargo.toml that is neither" <<<"$l4_ok"; then
    echo "self-test FAILED: control L4 positive half — the crate's own manifest or the fuzz workspace's was refused. Reported [$l4_ok]" >&2
    fail=1
  elif ! grep -q "src/Cargo.toml: a Cargo.toml that is neither" <<<"$l4_bad"; then
    echo "self-test FAILED: control L4 — a Cargo.toml planted under src/ was not refused. Reported [$l4_bad]" >&2
    fail=1
  else
    echo "self-test: control L4 (a Cargo.toml under src/ — which would make src/target/ satisfy the build-root prune — is refused, while the crate's own manifest and the fuzz workspace's are not) — as expected"
  fi

  # ---- control L5: THE SYMLINKED MANIFEST.
  # Following `src/Cargo.toml -> ../Cargo.toml`
  # could satisfy the manifest half of a build-root
  # prune. A planted tag could then hide
  # src/target/mod.rs from the scanner even though
  # rustc compiles it. The foreign-manifest walk
  # and build-root predicate must distinguish the
  # symlink from an actual manifest at that path.
  #
  # THREE assertions: refuse the link by name, keep
  # the directory outside the build-root classification,
  # and scan the Rust file inside it. Its whole-file
  # expect under src must then be reported.
  mkdir -p "$tmp/l5/src/target" "$tmp/l5/fuzz"
  printf '[package]\nname = "l5"\n' > "$tmp/l5/Cargo.toml"
  printf '[package]\nname = "l5-fuzz"\n' > "$tmp/l5/fuzz/Cargo.toml"
  ln -s ../Cargo.toml "$tmp/l5/src/Cargo.toml"
  : > "$tmp/l5/src/target/CACHEDIR.TAG"
  cat > "$tmp/l5/src/target/mod.rs" <<'RS'
#![expect(clippy::disallowed_methods, reason = "a whole-file licence nothing counts")]
pub fn hidden() {
    let _ = std::fs::create_dir_all("/nowhere");
}
RS
  printf 'mod target;\n' > "$tmp/l5/src/lib.rs"
  set +e
  l5_closure="$(find_foreign_tree_entries "$tmp/l5")"
  l5_closure_rc=$?
  set -e
  l5_scan="$(scan_or_die "$tmp/l5")"
  l5_hits="$(scanned_allow_hits "$l5_scan")"
  l5_bad=""
  [[ "$l5_closure_rc" -eq 0 ]] || l5_bad="$l5_bad the-walk-could-not-complete"
  grep -q "src/Cargo.toml: a SYMLINK named" <<<"$l5_closure" || l5_bad="$l5_bad symlinked-manifest-not-refused"
  grep -q "src/target: a directory named" <<<"$l5_closure" || l5_bad="$l5_bad src-target-still-reads-as-a-build-root"
  grep -q "src/target/mod.rs" <<<"$l5_hits" || l5_bad="$l5_bad the-hidden-file-was-still-pruned-from-the-scan"
  if [[ -n "$l5_bad" ]]; then
    echo "self-test FAILED: control L5 —$l5_bad. Closure [$l5_closure] Hits [$l5_hits]" >&2
    fail=1
  else
    echo "self-test: control L5 (src/Cargo.toml -> ../Cargo.toml plus src/target/CACHEDIR.TAG — the link is refused by name, src/target is no longer a build root, and src/target/mod.rs is scanned again) — as expected"
  fi

  # ---- control L6: a SYMLINKED CACHEDIR.TAG, the other half of the
  # same pair. A real manifest beside the directory and a linked tag
  # inside it satisfies a prune that follows links, and `-type f` misses
  # the tag for the same reason it missed the manifest.
  mkdir -p "$tmp/l6/src/target" "$tmp/l6/elsewhere"
  printf '[package]\nname = "l6"\n' > "$tmp/l6/Cargo.toml"
  printf '[package]\nname = "l6-src"\n' > "$tmp/l6/src/Cargo.toml"
  : > "$tmp/l6/elsewhere/CACHEDIR.TAG"
  ln -s ../../elsewhere/CACHEDIR.TAG "$tmp/l6/src/target/CACHEDIR.TAG"
  printf 'fn x() {}\n' > "$tmp/l6/src/target/hidden.rs"
  set +e
  l6_closure="$(find_foreign_tree_entries "$tmp/l6")"
  l6_rc=$?
  set -e
  if [[ "$l6_rc" -ne 0 ]] || ! grep -q "src/target/CACHEDIR.TAG: a SYMLINK named" <<<"$l6_closure"; then
    echo "self-test FAILED: control L6 — a symlinked CACHEDIR.TAG was not refused (exit $l6_rc). Reported [$l6_closure]" >&2
    fail=1
  else
    echo "self-test: control L6 (a SYMLINKED CACHEDIR.TAG inside a target directory) — refused by name, as expected"
  fi

  # ---- controls N25-N27: the config walk sees SYMLINKS. `find -type f`
  # matches none of these and descends through none of them, and an
  # UNTRACKED one is in no `git ls-files` output either — so before the
  # `-type l` terms the walk had nothing to report while cargo and
  # clippy read the target normally.
  # The POSITIVE half of this pair is control N10/N11's, on the same
  # minimal shape: a tree carrying only the two allowed clippy configs
  # and the root cargo config passes. Without it a walk that refused
  # every tree would satisfy both negatives below.
  mkdir -p "$tmp/n26/crates/granary-client"
  cp "$ROOT_CLIPPY" "$tmp/n26/clippy.toml"
  ln -s ../../clippy.toml "$tmp/n26/crates/granary-client/clippy.toml"
  if check_stray_configs "$tmp/n26" 2>"$tmp/n26.err"; then
    echo "self-test FAILED: control N26 (an UNTRACKED symlinked clippy.toml) was not refused" >&2
    fail=1
  elif ! grep -q "is a SYMLINK" "$tmp/n26.err"; then
    echo "self-test FAILED: control N26 was refused but not as a symlink:" >&2
    cat "$tmp/n26.err" >&2
    fail=1
  else
    echo "self-test: control N26 (an untracked SYMLINKED clippy.toml, invisible to find -type f and to git ls-files) — refused, naming the link, as expected"
  fi
  mkdir -p "$tmp/n27/crates/granary-client" "$tmp/n27/real-cargo"
  cp "$ROOT_CLIPPY" "$tmp/n27/clippy.toml"
  cp "$CLIENT_CLIPPY" "$tmp/n27/crates/granary-client/clippy.toml"
  cp "$CARGO_CONFIG" "$tmp/n27/real-cargo/config.toml"
  ln -s ../../real-cargo "$tmp/n27/crates/granary-client/.cargo"
  if check_stray_configs "$tmp/n27" 2>"$tmp/n27.err"; then
    echo "self-test FAILED: control N27 (a SYMLINKED .cargo directory) was not refused" >&2
    fail=1
  elif ! grep -q "is a SYMLINK" "$tmp/n27.err"; then
    echo "self-test FAILED: control N27 was refused but not as a symlink:" >&2
    cat "$tmp/n27.err" >&2
    fail=1
  else
    echo "self-test: control N27 (a symlinked .cargo DIRECTORY — find cannot descend it, so its config is unaudited) — refused, naming the link, as expected"
  fi

  # ---- control N28: `git ls-files` FAILING must not read as "no
  # tracked configs". The walk above is the untracked half; this is the
  # tracked half, and `|| true` on it turned "git could not answer" into
  # "git answered nothing".
  mkdir -p "$tmp/gitshim"
  n28_git="$(command -v git)"
  case "$n28_git" in
    /*) ;;
    *)  echo "self-test FAILED: control N28 — 'git' does not resolve to an absolute path (${n28_git:-<none>}); the shim cannot be built" >&2
        fail=1
        n28_git="" ;;
  esac
  cat > "$tmp/gitshim/git" <<SHIM
#!/bin/sh
for a in "\$@"; do
  if [ "\$a" = "ls-files" ]; then exit 3; fi
done
exec "$n28_git" "\$@"
SHIM
  chmod +x "$tmp/gitshim/git"
  n28_rc=0
  ( PATH="$tmp/gitshim:$PATH"; hash -r; check_stray_configs "." ) 2>"$tmp/n28.err" || n28_rc=$?
  if [[ "$n28_rc" -ne 2 ]]; then
    echo "self-test FAILED: control N28 — a failing git ls-files returned $n28_rc, wanted 2 (could not run):" >&2
    cat "$tmp/n28.err" >&2
    fail=1
  elif ! grep -q "could not list the tracked configs" "$tmp/n28.err"; then
    echo "self-test FAILED: control N28 returned 2 but did not name the ls-files failure:" >&2
    cat "$tmp/n28.err" >&2
    fail=1
  else
    echo "self-test: control N28 (git ls-files failing is 'could not run', never 'no tracked configs') — refused at status 2, as expected"
  fi

  # ---- controls N29-N30: the OTHER two walks, through the same
  # walk-or-die helper. N18 covers the config walk; these cover the .rs
  # scan and the source-closure scan, so no consumer of `find` is left
  # reading a failed walk as an empty tree.
  n29_rc=0
  ( scan_fs_sites "$tmp/does-not-exist-at-all" ) >/dev/null 2>"$tmp/n29.err" || n29_rc=$?
  if [[ "$n29_rc" -ne 2 ]] || ! grep -q ".rs source walk" "$tmp/n29.err"; then
    echo "self-test FAILED: control N29 — a .rs walk of a missing root returned $n29_rc and said:" >&2
    cat "$tmp/n29.err" >&2
    fail=1
  else
    echo "self-test: control N29 (the .rs walk of a root that does not exist) — refused at status 2, as expected"
  fi
  n30_rc=0
  ( scan_source_closure "$tmp/does-not-exist-at-all" ) >/dev/null 2>"$tmp/n30.err" || n30_rc=$?
  if [[ "$n30_rc" -ne 2 ]] || ! grep -q "source-closure walk" "$tmp/n30.err"; then
    echo "self-test FAILED: control N30 — a source-closure walk of a missing root returned $n30_rc and said:" >&2
    cat "$tmp/n30.err" >&2
    fail=1
  else
    echo "self-test: control N30 (the source-closure walk of a root that does not exist) — refused at status 2, as expected"
  fi

  # ---- control I: a non-UTF-8 .rs file must REFUSE (exit 2), never be
  # silently skipped or read as clean.
  # Run in a literal subshell so scan_or_die's own `exit 2` (correct
  # behaviour) does not tear down this self-test script too — only the
  # isolated subshell.
  mkdir -p "$tmp/tests_nonutf8"
  printf 'fn f() {}\n\xff\xfe not valid utf-8\n' > "$tmp/tests_nonutf8/bad.rs"
  nonutf8_rc=0
  nonutf8_out="$(scan_or_die "$tmp/tests_nonutf8" 2>&1)" || nonutf8_rc=$?
  if [[ "$nonutf8_rc" -ne 2 ]]; then
    echo "self-test FAILED: control I (non-UTF-8 file under tests/) exited $nonutf8_rc, wanted 2 (refused, not skipped):" >&2
    echo "$nonutf8_out" >&2
    fail=1
  elif ! grep -qi "utf-8" <<<"$nonutf8_out"; then
    echo "self-test FAILED: control I exited 2 but did not name the UTF-8 problem:" >&2
    echo "$nonutf8_out" >&2
    fail=1
  else
    echo "self-test: control I (non-UTF-8 .rs file) — refused with exit 2, naming the problem, as expected"
  fi

  # ---- control I2: a non-UTF-8 PATH. Unix
  # filenames are bytes, and a legal Rust
  # filename can fail UTF-8 decoding. The
  # scanner must issue a named refusal rather
  # than end in an unhandled decode traceback.
  #
  # The path is fed to the scanner DIRECTLY rather than through a
  # planted file, and that is not a shortcut: APFS refuses to create a
  # name that is not valid UTF-8 (EILSEQ, measured on this machine), so
  # the file cannot exist here at all — while on the ext4 CI runners it
  # can, and `find` would then hand exactly these bytes over. The
  # scanner's contract is "NUL-separated paths on stdin", and the decode
  # happens before any file is opened, so stdin IS the interface under
  # test.
  i2_rc=0
  i2_out="$(printf 'bad\xff.rs\0' | python3 "$(dirname "${BASH_SOURCE[0]}")/fsguard-scan.py" 2>&1)" || i2_rc=$?
  if [[ "$i2_rc" -ne 2 ]]; then
    echo "self-test FAILED: control I2 (a non-UTF-8 PATH) exited $i2_rc, wanted 2 (refused, not skipped):" >&2
    echo "$i2_out" >&2
    fail=1
  elif ! grep -qi "not valid utf-8" <<<"$i2_out"; then
    echo "self-test FAILED: control I2 exited 2 but did not name the UTF-8 problem:" >&2
    echo "$i2_out" >&2
    fail=1
  elif grep -q "Traceback" <<<"$i2_out"; then
    echo "self-test FAILED: control I2 refused, but with a raw traceback rather than one line:" >&2
    echo "$i2_out" >&2
    fail=1
  else
    echo "self-test: control I2 (a .rs PATH that is not valid UTF-8) — refused with exit 2, naming the problem, as expected"
  fi

  # ---- control J1: flipping `allow-invalid = true` off a REAL root row
  # (rand::rngs::OsRng, a `disallowed-types` row) in a copy of the
  # client config must fail: a (path, reason)-only comparison silently
  # drops this field and passes the mutated row untouched.
  cp "$CLIENT_CLIPPY" "$tmp/client_dropped_allow_invalid.toml"
  mutate_or_die "J1" '
import pathlib
p = pathlib.Path("'"$tmp"'/client_dropped_allow_invalid.toml")
text = p.read_text()
needle = "{ path = \"rand::rngs::OsRng\", reason = \"ambient entropy; use the Rng seam\", allow-invalid = true },"
assert needle in text, "fixture row not found verbatim — clippy.toml text changed"
p.write_text(text.replace(needle, "{ path = \"rand::rngs::OsRng\", reason = \"ambient entropy; use the Rng seam\" },", 1))
'
  if out="$(check_config "$ROOT_CLIPPY" "$tmp/client_dropped_allow_invalid.toml" 2>&1)"; then
    echo "self-test FAILED: control J1 (dropped allow-invalid on a real disallowed-types row) did not fail" >&2
    fail=1
  elif ! grep -q "rand::rngs::OsRng" <<<"$out"; then
    echo "self-test FAILED: control J1 failed but did not name the row:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control J1 (dropped allow-invalid = true off rand::rngs::OsRng, disallowed-types) — FAILED naming the row, as expected"
  fi

  # ---- control J2: the SAME field-drop on
  # the ANCHOR key (disallowed-methods). This
  # exercises the allow-invalid field on the
  # disallowed-methods comparison path
  # separately from J1's disallowed-types
  # path: check_config's superset check uses
  # different keys for each list. rand::rng
  # is the fixture, with its allow-invalid
  # field removed from a copy of the client
  # config. The mutation checks that the
  # expected row exists before replacing it.
  cp "$CLIENT_CLIPPY" "$tmp/client_dropped_allow_invalid_methods.toml"
  mutate_or_die "J2" '
import pathlib
p = pathlib.Path("'"$tmp"'/client_dropped_allow_invalid_methods.toml")
text = p.read_text()
needle = "{ path = \"rand::rng\", reason = \"ambient entropy; use the Rng seam\", allow-invalid = true },"
assert needle in text, "fixture row not found verbatim — clippy.toml text changed"
p.write_text(text.replace(needle, "{ path = \"rand::rng\", reason = \"ambient entropy; use the Rng seam\" },", 1))
'
  if out="$(check_config "$ROOT_CLIPPY" "$tmp/client_dropped_allow_invalid_methods.toml" 2>&1)"; then
    echo "self-test FAILED: control J2 (dropped allow-invalid on a real disallowed-methods row) did not fail" >&2
    fail=1
  elif ! grep -q "rand::rng" <<<"$out"; then
    echo "self-test FAILED: control J2 failed but did not name the row:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control J2 (dropped allow-invalid = true off rand::rng, disallowed-methods — the ANCHOR key) — FAILED naming the row, as expected"
  fi

  # ---- controls M1-M5: the ban's LEVEL, in COPIES of the crate
  # manifest. Every one of these is a ONE-LINE edit that leaves checks
  # 1-4 green and produces no diagnostic from any compiler, which is
  # why the level needs a check of its own. All five pass the REAL
  # cargo config, so the manifest mutation is the only difference
  # between them and a passing run.
  cp "$CLIENT_MANIFEST" "$tmp/manifest_level_allow.toml"
  mutate_or_die "M1" '
import pathlib
p = pathlib.Path("'"$tmp"'/manifest_level_allow.toml")
text = p.read_text()
needle = "disallowed_methods = \"deny\"\n"
assert needle in text, "fixture lint line not found verbatim — Cargo.toml text changed"
p.write_text(text.replace(needle, "disallowed_methods = \"allow\"\n", 1))
'
  if out="$(check_lint_level primary "$tmp/manifest_level_allow.toml" "$CARGO_CONFIG_ARG" 2>&1)"; then
    echo "self-test FAILED: control M1 (disallowed_methods = \"allow\") did not fail" >&2
    fail=1
  elif ! grep -q "lints.clippy.disallowed_methods" <<<"$out" || ! grep -q "level 'allow'" <<<"$out"; then
    echo "self-test FAILED: control M1 failed but did not name the key AND the value found:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control M1 (lints.clippy.disallowed_methods = \"allow\") — FAILED naming the key and the value found, as expected"
  fi

  # M2: the key DELETED. clippy's default for it is `warn`, so this is
  # not "no opinion" — it is a ban that only warns.
  cp "$CLIENT_MANIFEST" "$tmp/manifest_level_absent.toml"
  mutate_or_die "M2" '
import pathlib
p = pathlib.Path("'"$tmp"'/manifest_level_absent.toml")
text = p.read_text()
needle = "disallowed_methods = \"deny\"\n"
assert needle in text, "fixture lint line not found verbatim — Cargo.toml text changed"
p.write_text(text.replace(needle, "", 1))
'
  if out="$(check_lint_level primary "$tmp/manifest_level_absent.toml" "$CARGO_CONFIG_ARG" 2>&1)"; then
    echo "self-test FAILED: control M2 (disallowed_methods deleted) did not fail" >&2
    fail=1
  elif ! grep -q "lints.clippy.disallowed_methods is ABSENT" <<<"$out"; then
    echo "self-test FAILED: control M2 failed but did not name the key as absent:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control M2 (lints.clippy.disallowed_methods DELETED) — FAILED naming the key as absent, as expected"
  fi

  # M3: a lint GROUP that contains the lint. This exact spelling does
  # not itself silence the ban on the pinned toolchain (`priority = -1`
  # puts it BEFORE the specific `deny`) — `all = "allow"` at the
  # default priority does. The key is refused for being present at all,
  # which is the property this control pins; see the check's comment
  # for the four measured spellings.
  cp "$CLIENT_MANIFEST" "$tmp/manifest_group_all.toml"
  mutate_or_die "M3" '
import pathlib
p = pathlib.Path("'"$tmp"'/manifest_group_all.toml")
text = p.read_text()
needle = "[lints.clippy]\n"
assert needle in text, "fixture table header not found verbatim — Cargo.toml text changed"
p.write_text(text.replace(needle, needle + "all = { level = \"allow\", priority = -1 }\n", 1))
'
  if out="$(check_lint_level primary "$tmp/manifest_group_all.toml" "$CARGO_CONFIG_ARG" 2>&1)"; then
    echo "self-test FAILED: control M3 (lints.clippy.all added) did not fail" >&2
    fail=1
  elif ! grep -q "lints.clippy.all is set to" <<<"$out"; then
    echo "self-test FAILED: control M3 failed but did not name the group key:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control M3 (lints.clippy.all = { level = \"allow\", ... }, a GROUP containing the lint) — FAILED naming the group, as expected"
  fi

  # M4: the whole table replaced by the inherited `workspace = true`
  # form. Every level this check reads then lives in the workspace
  # manifest instead, which this gate does not read — and the crate
  # would not compile under the workspace's `unsafe_code = "forbid"`
  # anyway, so the shape is wrong for this crate on its own terms.
  cp "$CLIENT_MANIFEST" "$tmp/manifest_workspace_lints.toml"
  mutate_or_die "M4" '
import pathlib
p = pathlib.Path("'"$tmp"'/manifest_workspace_lints.toml")
text = p.read_text()
assert "[lints.rust]" in text, "fixture [lints.rust] table not found — Cargo.toml text changed"
assert "[lints.clippy]" in text, "fixture [lints.clippy] table not found — Cargo.toml text changed"
assert text.index("[lints.rust]") < text.index("[lints.clippy]"), "the lint tables are no longer last, in that order — this mutation truncates from [lints.rust]"
p.write_text(text[: text.index("[lints.rust]")] + "[lints]\nworkspace = true\n")
'
  if out="$(check_lint_level primary "$tmp/manifest_workspace_lints.toml" "$CARGO_CONFIG_ARG" 2>&1)"; then
    echo "self-test FAILED: control M4 ([lints] workspace = true) did not fail" >&2
    fail=1
  elif ! grep -q "\[lints\] is the inherited form (workspace = true)" <<<"$out"; then
    echo "self-test FAILED: control M4 failed but did not name the inherited form:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control M4 ([lints] replaced by the inherited workspace = true form) — FAILED naming the form, as expected"
  fi

  # M5: the POSITIVE control for the accept path. The table spelling of
  # the same level is what cargo writes when a priority is needed, and
  # it must pass — without this, M1-M4 could all pass on a check that
  # refuses everything it is handed.
  cp "$CLIENT_MANIFEST" "$tmp/manifest_level_table_form.toml"
  mutate_or_die "M5" '
import pathlib
p = pathlib.Path("'"$tmp"'/manifest_level_table_form.toml")
text = p.read_text()
needle = "disallowed_methods = \"deny\"\n"
assert needle in text, "fixture lint line not found verbatim — Cargo.toml text changed"
p.write_text(text.replace(needle, "disallowed_methods = { level = \"deny\", priority = 0 }\n", 1))
'
  if ! out="$(check_lint_level primary "$tmp/manifest_level_table_form.toml" "$CARGO_CONFIG_ARG" 2>&1)"; then
    echo "self-test FAILED: control M5 (the table form of the SAME level) did not pass:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control M5 (disallowed_methods = { level = \"deny\", priority = 0 }) — passes, as expected"
  fi

  # ---- controls M6-M7: the two MUST-1 denies, now in the manifest
  # rather than on the two crate roots. The move is what extends them to
  # the seven tests/*.rs crates; one line puts it back the way it was,
  # in a file this check already reads.
  cp "$CLIENT_MANIFEST" "$tmp/manifest_must1_allow.toml"
  mutate_or_die "M6" '
import pathlib
p = pathlib.Path("'"$tmp"'/manifest_must1_allow.toml")
text = p.read_text()
needle = "allow_attributes_without_reason = \"deny\"\n"
assert needle in text, "fixture MUST-1 line not found verbatim — Cargo.toml text changed"
p.write_text(text.replace(needle, "allow_attributes_without_reason = \"allow\"\n", 1))
'
  if out="$(check_lint_level primary "$tmp/manifest_must1_allow.toml" "$CARGO_CONFIG_ARG" 2>&1)"; then
    echo "self-test FAILED: control M6 (allow_attributes_without_reason = \"allow\") did not fail" >&2
    fail=1
  elif ! grep -q "lints.clippy.allow_attributes_without_reason" <<<"$out"; then
    echo "self-test FAILED: control M6 failed but did not name the key:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control M6 (lints.clippy.allow_attributes_without_reason = \"allow\") — FAILED naming the key, as expected"
  fi

  cp "$CLIENT_MANIFEST" "$tmp/manifest_must1_absent.toml"
  mutate_or_die "M7" '
import pathlib
p = pathlib.Path("'"$tmp"'/manifest_must1_absent.toml")
text = p.read_text()
needle = "allow_attributes = \"deny\"\n"
assert needle in text, "fixture MUST-1 line not found verbatim — Cargo.toml text changed"
p.write_text(text.replace(needle, "", 1))
'
  if out="$(check_lint_level primary "$tmp/manifest_must1_absent.toml" "$CARGO_CONFIG_ARG" 2>&1)"; then
    echo "self-test FAILED: control M7 (allow_attributes deleted) did not fail" >&2
    fail=1
  elif ! grep -q "lints.clippy.allow_attributes is ABSENT" <<<"$out"; then
    echo "self-test FAILED: control M7 failed but did not name the key as absent:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control M7 (lints.clippy.allow_attributes DELETED) — FAILED naming the key as absent, as expected"
  fi

  # ---- control M8: the `restriction` GROUP, which reaches the two
  # MUST-1 keys the same way `all`/`style` reach the fs ban.
  # `allow_attributes` and `allow_attributes_without_reason` are both
  # `clippy::restriction` lints, so one line under [lints.clippy]
  # overrides both denies while they still read "deny" two lines above.
  cp "$CLIENT_MANIFEST" "$tmp/manifest_restriction_group.toml"
  mutate_or_die "M8" '
import pathlib
p = pathlib.Path("'"$tmp"'/manifest_restriction_group.toml")
text = p.read_text()
needle = "allow_attributes = \"deny\"\n"
assert needle in text, "fixture MUST-1 line not found verbatim — Cargo.toml text changed"
p.write_text(text.replace(needle, needle + "restriction = { level = \"allow\", priority = 1 }\n", 1))
'
  if out="$(check_lint_level primary "$tmp/manifest_restriction_group.toml" "$CARGO_CONFIG_ARG" 2>&1)"; then
    echo "self-test FAILED: control M8 (lints.clippy.restriction = { level = \"allow\", priority = 1 }) did not fail" >&2
    fail=1
  elif ! grep -q "lints.clippy.restriction" <<<"$out"; then
    echo "self-test FAILED: control M8 failed but did not name the group:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control M8 (lints.clippy.restriction = { level = \"allow\", priority = 1 }) — FAILED naming the group, as expected"
  fi

  # ---- control M9: the POSITIVE half of the MUST-1 level check.
  # `forbid` is STRICTLY STRONGER for these two keys — nothing in this
  # crate legitimately `#[expect]`s either of them — so it must PASS,
  # where the same level on `disallowed_methods` is refused (it would
  # break every licensed site). Without this control, M6/M7 could pass
  # on a check that only ever accepted the literal string "deny".
  cp "$CLIENT_MANIFEST" "$tmp/manifest_must1_forbid.toml"
  mutate_or_die "M9" '
import pathlib
p = pathlib.Path("'"$tmp"'/manifest_must1_forbid.toml")
text = p.read_text()
needle = "allow_attributes = \"deny\"\n"
assert needle in text, "fixture MUST-1 line not found verbatim — Cargo.toml text changed"
p.write_text(text.replace(needle, "allow_attributes = \"forbid\"\n", 1))
'
  if ! out="$(check_lint_level primary "$tmp/manifest_must1_forbid.toml" "$CARGO_CONFIG_ARG" 2>&1)"; then
    echo "self-test FAILED: control M9 (allow_attributes = \"forbid\", strictly stronger) did not pass:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control M9 (lints.clippy.allow_attributes = \"forbid\") — passes, as expected"
  fi

  # ---- controls N1-N2: `cap-lints` in a COPY of the repo-root cargo
  # config. It caps every lint in the build whatever the manifests say,
  # in both the spelling cargo documents and the packed `-C` one, and
  # under `build` or a `target.*` table alike. The copy is taken from
  # the REAL file: if it ever stops existing, `cp` fails under errexit
  # and this self-test dies loudly rather than silently testing nothing.
  cp "$CARGO_CONFIG" "$tmp/cargo_config_cap_lints_build.toml"
  cat >> "$tmp/cargo_config_cap_lints_build.toml" <<'TOML'

[build]
rustflags = ["--cap-lints", "allow"]
TOML
  if out="$(check_lint_level primary "$CLIENT_MANIFEST" "$tmp/cargo_config_cap_lints_build.toml" 2>&1)"; then
    echo "self-test FAILED: control N1 (build.rustflags --cap-lints) did not fail" >&2
    fail=1
  elif ! grep -q "build.rustflags" <<<"$out" || ! grep -q "cap-lints" <<<"$out"; then
    echo "self-test FAILED: control N1 failed but did not name build.rustflags and cap-lints:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control N1 ([build] rustflags = [\"--cap-lints\", \"allow\"]) — FAILED naming the flag, as expected"
  fi

  cp "$CARGO_CONFIG" "$tmp/cargo_config_cap_lints_target.toml"
  cat >> "$tmp/cargo_config_cap_lints_target.toml" <<'TOML'

[target.'cfg(all())']
rustflags = ["-Ccap-lints=allow"]
TOML
  if out="$(check_lint_level primary "$CLIENT_MANIFEST" "$tmp/cargo_config_cap_lints_target.toml" 2>&1)"; then
    echo "self-test FAILED: control N2 (target.* rustflags -Ccap-lints=allow) did not fail" >&2
    fail=1
  elif ! grep -q "target.cfg(all()).rustflags" <<<"$out" || ! grep -q "cap-lints" <<<"$out"; then
    echo "self-test FAILED: control N2 failed but did not name the target table and cap-lints:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control N2 ([target.'cfg(all())'] rustflags = [\"-Ccap-lints=allow\"]) — FAILED naming the flag, as expected"
  fi

  # ---- controls N3-N8: every OTHER lint-level rustflag. `cap-lints`
  # was never the only way through — rustc takes the LAST level given
  # for a lint and a config's rustflags come after the manifest's, so
  # `-A`, `-W` and `--force-warn` all demote or silence the ban from a
  # checked-in file, in the joined and the split spellings and in the
  # whitespace-STRING form of the key. N8 is the positive half.
  n_flag_case() {
    local label="$1" body="$2" needle="$3"
    local file="$tmp/cargo_config_${label%% *}.toml"
    cp "$CARGO_CONFIG" "$file"
    printf '\n%s\n' "$body" >> "$file"
    if out="$(check_lint_level primary "$CLIENT_MANIFEST" "$file" 2>&1)"; then
      echo "self-test FAILED: control $label did not fail" >&2
      fail=1
    elif ! grep -q -- "$needle" <<<"$out"; then
      echo "self-test FAILED: control $label failed but did not name [$needle]:" >&2
      echo "$out" >&2
      fail=1
    else
      echo "self-test: control $label — FAILED naming the flag, as expected"
    fi
  }
  n_flag_case "N3 ([build] rustflags = [\"-A\", \"clippy::disallowed_methods\"], the SPLIT spelling)" \
    '[build]
rustflags = ["-A", "clippy::disallowed_methods"]' \
    'the lint-level flag `-A`'
  n_flag_case "N4 ([build] rustflags = \"-Aclippy::all\", the whitespace-STRING form of the key)" \
    '[build]
rustflags = "-Aclippy::all"' \
    'the lint-level flag `-A`'
  n_flag_case "N5 ([build] rustflags = [\"--force-warn=clippy::disallowed-methods\"])" \
    '[build]
rustflags = ["--force-warn=clippy::disallowed-methods"]' \
    'the lint-level flag `--force-warn`'
  n_flag_case "N6 ([env] RUSTFLAGS = \"--cap-lints=allow\")" \
    '[env]
RUSTFLAGS = "--cap-lints=allow"' \
    'env.RUSTFLAGS'
  n_flag_case "N7 ([env] CLIPPY_CONF_DIR = \"/tmp\", redirecting clippy's config lookup away from the audited file)" \
    '[env]
CLIPPY_CONF_DIR = "/tmp"' \
    'env.CLIPPY_CONF_DIR'

  # N8: the POSITIVE half. `-D`/`-F` cannot weaken anything and a
  # non-lint `-C` flag is not a level at all — without this, N3-N7 could
  # every one of them pass on a check that refused any rustflag it saw,
  # which would also refuse the real file.
  cp "$CARGO_CONFIG" "$tmp/cargo_config_deny_flags.toml"
  cat >> "$tmp/cargo_config_deny_flags.toml" <<'TOML'

[build]
rustflags = ["-D", "warnings", "-C", "target-feature=+crt-static"]
TOML
  if ! out="$(check_lint_level primary "$CLIENT_MANIFEST" "$tmp/cargo_config_deny_flags.toml" 2>&1)"; then
    echo "self-test FAILED: control N8 ([build] rustflags = [\"-D\", \"warnings\", \"-C\", \"target-feature=+crt-static\"]) did not pass:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control N8 (a -D/-C rustflags array that weakens nothing) — passes, as expected"
  fi

  # ---- controls N12-N16: the repo-visible switches that are not lint
  # flags at all. Each is a checked-in line that decides what the clippy
  # lane does, and none of them LOOKS like a lint level.
  n_flag_case "N12 ([alias] clippy = \"check\" — cargo resolves aliases before external subcommands)" \
    '[alias]
clippy = "check"' \
    'alias] clippy = '
  n_flag_case "N13 ([build] rustc-wrapper = \"x\" — the compiler selector)" \
    '[build]
rustc-wrapper = "x"' \
    'build.rustc-wrapper'
  n_flag_case "N14 ([env] RUSTC_WORKSPACE_WRAPPER = \"x\" — the exact variable cargo clippy uses to inject clippy-driver)" \
    '[env]
RUSTC_WORKSPACE_WRAPPER = "x"' \
    'env.RUSTC_WORKSPACE_WRAPPER'
  n_flag_case "N15 ([build] rustflags = [\"@lints.rsp\"] — a rustc RESPONSE FILE, list form)" \
    '[build]
rustflags = ["@lints.rsp"]' \
    'the lint-level flag `@ (a rustc response file)`'
  n_flag_case "N16 ([build] rustflags = \"-C opt-level=1 @lints.rsp\" — the same indirection in the whitespace-STRING form)" \
    '[build]
rustflags = "-C opt-level=1 @lints.rsp"' \
    'the lint-level flag `@ (a rustc response file)`'

  n_flag_case "N31 ([build] rustflags = [\"--allow\", \"clippy::disallowed_methods\"], the SPLIT LONG spelling)" \
    '[build]
rustflags = ["--allow", "clippy::disallowed_methods"]' \
    'the lint-level flag `-A`'
  n_flag_case "N32 ([build] rustflags = [\"--warn\", \"clippy::all\"], the same for the demoting head)" \
    '[build]
rustflags = ["--warn", "clippy::all"]' \
    'the lint-level flag `-W`'
  n_flag_case "N33 ([env] RUSTFLAGS = \"--allow clippy::disallowed_methods\", the long form through the environment)" \
    '[env]
RUSTFLAGS = "--allow clippy::disallowed_methods"' \
    'env.RUSTFLAGS'

  # ---- controls N19-N23: the UNDERSCORE spellings. Cargo treats `-`
  # and `_` in a config key as the same key, so every dash-form key the
  # gate refuses has an underscore twin that is honoured exactly the
  # same way and matched by nothing until the normalisation above. Each
  # of these is the N-series control it mirrors, respelled.
  n_flag_case "N19 ([build] rustc_wrapper = \"x\" — the UNDERSCORE spelling cargo honours identically)" \
    '[build]
rustc_wrapper = "x"' \
    'build.rustc_wrapper'
  n_flag_case "N20 ([build] rustc_workspace_wrapper = \"x\" — the wrapper cargo clippy itself uses)" \
    '[build]
rustc_workspace_wrapper = "x"' \
    'build.rustc_workspace_wrapper'
  n_flag_case "N21 ([build] warnings = \"allow\" reached through the normalised [build] table)" \
    '[build]
warnings = "allow"' \
    'build.warnings is set to'

  # ---- controls N22-N23: the nightly door. `-Zcrate-attr` injects an
  # inner attribute into every crate root it reaches — a file-scoped
  # suppression that appears in no source file the scanner walks and in
  # no lint table check 5 reads — and RUSTC_BOOTSTRAP is what lets a
  # stable toolchain accept it.
  n_flag_case "N22 ([build] rustflags = [\"-Zcrate-attr=allow(clippy::all)\"] — a crate-root attribute from a config file)" \
    '[build]
rustflags = ["-Zcrate-attr=allow(clippy::all)"]' \
    'the lint-level flag `-Z'
  n_flag_case "N23 ([build] rustflags = [\"-Z\", \"crate-attr=allow(clippy::all)\"] — the SPLIT spelling)" \
    '[build]
rustflags = ["-Z", "crate-attr=allow(clippy::all)"]' \
    'the lint-level flag `-Z'
  n_flag_case "N24 ([env] RUSTC_BOOTSTRAP = \"1\" — what makes -Z reachable on a stable toolchain)" \
    '[env]
RUSTC_BOOTSTRAP = "1"' \
    'env.RUSTC_BOOTSTRAP'

  # ---- control M10: the manifest's own underscore/dash twin. rustc
  # normalises lint names, so `disallowed-methods = "allow"` is a real
  # `-A clippy::disallowed-methods` emitted BESIDE the
  # `disallowed_methods = "deny"` the gate reads and approves — two keys
  # to a dict, one lint to the compiler, and the last level wins.
  cp "$CLIENT_MANIFEST" "$tmp/manifest_dash_twin.toml"
  mutate_or_die "M10" '
import pathlib
p = pathlib.Path("'"$tmp"'/manifest_dash_twin.toml")
text = p.read_text()
needle = "disallowed_methods = \"deny\""
assert needle in text, "the manifest no longer spells disallowed_methods = \"deny\""
p.write_text(text.replace(needle, needle + "\ndisallowed-methods = \"allow\"", 1))
'
  if out="$(check_lint_level primary "$tmp/manifest_dash_twin.toml" "$CARGO_CONFIG_ARG" 2>&1)"; then
    echo "self-test FAILED: control M10 (disallowed-methods = \"allow\" beside disallowed_methods = \"deny\") did not fail" >&2
    fail=1
  elif ! grep -q 'lints.clippy.disallowed-methods' <<<"$out"; then
    echo "self-test FAILED: control M10 failed but did not name the DASH spelling:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control M10 (lints.clippy.disallowed-methods = \"allow\" beside the deny) — FAILED naming the dash spelling, as expected"
  fi

  # ---- controls P1-P3: the four fuzz WORKSPACES. Each is its own
  # workspace with its own lockfile, so none inherits the [lints] table
  # check 5 audits, and the client's is governed by the same nested
  # clippy.toml as the crate. Absence of a [lints] table there is the
  # sanctioned state — clippy's default warn plus the lanes'
  # CARGO_BUILD_WARNINGS=deny is what makes the ban bite — so the
  # POSITIVE control runs first, on the real manifests.
  for fuzz_manifest in "${FUZZ_MANIFESTS[@]}"; do
    if ! out="$(check_lint_level secondary "$fuzz_manifest" "$(fuzz_config_args "$fuzz_manifest")" 2>&1)"; then
      echo "self-test FAILED: control P1 (the REAL $fuzz_manifest, no [lints] table) did not pass:" >&2
      echo "$out" >&2
      fail=1
    fi
  done
  echo "self-test: control P1 (the four REAL fuzz manifests, no [lints] table at all) — pass, as expected"

  cp "crates/granary-client/fuzz/Cargo.toml" "$tmp/fuzz_lints_allow.toml"
  printf '\n[lints.clippy]\ndisallowed_methods = "allow"\n' >> "$tmp/fuzz_lints_allow.toml"
  if out="$(check_lint_level secondary "$tmp/fuzz_lints_allow.toml" none 2>&1)"; then
    echo "self-test FAILED: control P2 (a fuzz workspace's [lints.clippy] disallowed_methods = \"allow\") did not fail" >&2
    fail=1
  elif ! grep -q 'lints.clippy.disallowed_methods' <<<"$out"; then
    echo "self-test FAILED: control P2 failed but did not name the key:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control P2 (a fuzz workspace switching the ban off in its own [lints.clippy]) — FAILED naming the key, as expected"
  fi

  cp "crates/granary-client/fuzz/Cargo.toml" "$tmp/fuzz_group_all.toml"
  printf '\n[lints.clippy]\nall = "allow"\n' >> "$tmp/fuzz_group_all.toml"
  if out="$(check_lint_level secondary "$tmp/fuzz_group_all.toml" none 2>&1)"; then
    echo "self-test FAILED: control P3 (a fuzz workspace's lints.clippy.all = \"allow\") did not fail" >&2
    fail=1
  elif ! grep -q 'lints.clippy.all' <<<"$out"; then
    echo "self-test FAILED: control P3 failed but did not name the group:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control P3 (a fuzz workspace silencing the ban through the group that contains it) — FAILED naming the group, as expected"
  fi

  mkdir -p "$tmp/p4/.cargo"
  cp "crates/granary-client/fuzz/Cargo.toml" "$tmp/p4/Cargo.toml"
  cat > "$tmp/p4/.cargo/config.toml" <<'TOML'
[build]
rustflags = ["--cap-lints", "allow"]
TOML
  if out="$(check_lint_level secondary "$tmp/p4/Cargo.toml" "$tmp/p4/.cargo/config.toml" 2>&1)"; then
    echo "self-test FAILED: control P4 (a fuzz workspace's own .cargo/config.toml capping lints) did not fail" >&2
    fail=1
  elif ! grep -q 'cap-lints' <<<"$out"; then
    echo "self-test FAILED: control P4 failed but did not name the flag:" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control P4 (a fuzz workspace's own .cargo/config.toml capping every lint) — FAILED naming the flag, as expected"
  fi

  # ---- control N9: the LEGACY extensionless `.cargo/config`. Cargo
  # reads it too (it warns when both spellings exist and prefers the
  # `.toml`), so a check that read only the `.toml` sibling would call
  # the pair clean while the legacy file capped every lint in the build.
  mkdir -p "$tmp/n9/.cargo"
  cp "$CARGO_CONFIG" "$tmp/n9/.cargo/config.toml"
  cat > "$tmp/n9/.cargo/config" <<'TOML'
[build]
rustflags = ["--cap-lints", "allow"]
TOML
  if out="$(check_lint_level primary "$CLIENT_MANIFEST" "$tmp/n9/.cargo/config.toml" "$tmp/n9/.cargo/config" 2>&1)"; then
    echo "self-test FAILED: control N9 (a legacy .cargo/config beside an innocent config.toml) did not fail" >&2
    fail=1
  elif ! grep -q "n9/.cargo/config carries" <<<"$out"; then
    echo "self-test FAILED: control N9 failed but did not name the LEGACY file (as opposed to its .toml sibling):" >&2
    echo "$out" >&2
    fail=1
  else
    echo "self-test: control N9 (a legacy .cargo/config carrying --cap-lints beside an innocent config.toml) — FAILED naming the legacy file, as expected"
  fi

  # ---- controls N10-N11: CONFIG DISCOVERY, in a minimal COPIED tree.
  # The positive half runs FIRST and on the same tree, so a check that
  # refused any tree at all could not satisfy the two negatives.
  mkdir -p "$tmp/tree/crates/granary-client/src" "$tmp/tree/.cargo"
  : > "$tmp/tree/.cargo/config.toml"
  : > "$tmp/tree/crates/granary-client/clippy.toml"
  : > "$tmp/tree/clippy.toml"
  if ! check_stray_configs "$tmp/tree" 2>"$tmp/discovery.err"; then
    echo "self-test FAILED: control N10/N11 positive half — a tree with only the repo-root .cargo/config.toml and the crate-root clippy.toml was refused:" >&2
    cat "$tmp/discovery.err" >&2
    fail=1
  else
    echo "self-test: control N10/N11 positive half (root .cargo/config.toml + the crate-root clippy.toml only) — passes, as expected"
  fi

  : > "$tmp/tree/crates/granary-client/src/clippy.toml"
  if check_stray_configs "$tmp/tree" 2>"$tmp/discovery.err"; then
    echo "self-test FAILED: control N10 (a planted crates/granary-client/src/clippy.toml) was not refused" >&2
    fail=1
  elif ! grep -q "granary-client/src/clippy.toml" "$tmp/discovery.err"; then
    echo "self-test FAILED: control N10 refused but did not name the planted path:" >&2
    cat "$tmp/discovery.err" >&2
    fail=1
  else
    echo "self-test: control N10 (a nested crates/granary-client/src/clippy.toml) — refused, naming the path, as expected"
  fi
  rm -f "$tmp/tree/crates/granary-client/src/clippy.toml"

  mkdir -p "$tmp/tree/crates/granary-client/.cargo"
  : > "$tmp/tree/crates/granary-client/.cargo/config.toml"
  if check_stray_configs "$tmp/tree" 2>"$tmp/discovery.err"; then
    echo "self-test FAILED: control N11 (a planted crates/granary-client/.cargo/config.toml) was not refused" >&2
    fail=1
  elif ! grep -q "granary-client/.cargo/config.toml" "$tmp/discovery.err"; then
    echo "self-test FAILED: control N11 refused but did not name the planted path:" >&2
    cat "$tmp/discovery.err" >&2
    fail=1
  else
    echo "self-test: control N11 (a nested crates/granary-client/.cargo/config.toml, which governs a cargo run made from inside the crate) — refused, naming the path, as expected"
  fi
  rm -rf "$tmp/tree/crates/granary-client/.cargo"

  # ---- control N17: a clippy.toml OUTSIDE granary-client. CI clippys
  # the granary-core and granary-store fuzz workspaces too, and the
  # nearest config for `crates/granary-core/fuzz/Cargo.toml` would be a
  # planted `crates/granary-core/fuzz/clippy.toml` — which REPLACES the
  # root file's rows for that crate rather than merging with them.
  mkdir -p "$tmp/tree/crates/granary-core/fuzz"
  : > "$tmp/tree/crates/granary-core/fuzz/clippy.toml"
  if check_stray_configs "$tmp/tree" 2>"$tmp/discovery.err"; then
    echo "self-test FAILED: control N17 (a planted crates/granary-core/fuzz/clippy.toml) was not refused" >&2
    fail=1
  elif ! grep -q "granary-core/fuzz/clippy.toml" "$tmp/discovery.err"; then
    echo "self-test FAILED: control N17 refused but did not name the planted path:" >&2
    cat "$tmp/discovery.err" >&2
    fail=1
  else
    echo "self-test: control N17 (a clippy.toml in another crate's fuzz workspace, which CI now clippys) — refused, naming the path, as expected"
  fi
  rm -rf "$tmp/tree/crates/granary-core"

  # ---- control W2: THE TABLE'S SECOND ROW IS ACTUALLY VISITED, and this
  # is the control that checks that property directly.
  # **A loop that stops after row one is indistinguishable from a
  # correct loop when tested with a one-row AUDITED_CLOSURE_CRATES.**
  # The fixture must therefore exercise a second row independently of
  # the checked tree's table contents. It plants a SECOND row whose manifest
  # declares a dependency its own audited set does not name, and requires
  # the refusal to name THAT crate.
  #
  # The negative half matters as much: row one must NOT be reported, or a
  # control that refuses everything passes this too.
  # THE TWO ROWS AUDIT DIFFERENT SETS, and that is what makes this control
  # more than a reachability check. Giving both rows the SAME
  # audited dependency and target path would catch a loop that stops at row
  # one but NOT a loop that reaches row two while reusing row ONE's sets — the
  # two are indistinguishable when the sets are equal. Row one audits `libc` /
  # `src/lib.rs`, row two audits `serde` / `src/main.rs`, so reusing row one's
  # selection reports `serde` and `src/main.rs` and the assertions below say
  # so by name.
  mkdir -p "$tmp/w2a/src" "$tmp/w2b/src"
  printf 'fn a() {}\n' > "$tmp/w2a/src/lib.rs"
  printf 'fn b() {}\n' > "$tmp/w2b/src/main.rs"
  printf '[package]\nname = "w2a"\nversion = "0.0.1"\n\n[lib]\npath = "src/lib.rs"\n\n[dependencies]\nlibc = "0.2"\n' > "$tmp/w2a/Cargo.toml"
  printf '[package]\nname = "w2b"\nversion = "0.0.1"\n\n[lib]\npath = "src/main.rs"\n\n[dependencies]\nserde = "1"\nUNAUDITED_DEP = "1"\n' > "$tmp/w2b/Cargo.toml"
  w2_one="$tmp/w2a|$tmp/w2a/Cargo.toml|libc|src/lib.rs|||"
  w2_two="$tmp/w2b|$tmp/w2b/Cargo.toml|serde|src/main.rs|||"
  set +e
  w2_hits="$(collect_audited_closures "$w2_one")"
  w2_rc=$?
  set -e
  if [[ "$w2_rc" -ne 0 ]]; then
    echo "self-test FAILED: control W2 — a one-row table whose crate is clean could not complete (exit $w2_rc)" >&2
    fail=1
  elif [[ -n "$w2_hits" ]]; then
    echo "self-test FAILED: control W2 negative half — a clean single row was reported: [$w2_hits]" >&2
    fail=1
  else
    set +e
    w2_hits="$(collect_audited_closures "$w2_one" "$w2_two")"
    w2_rc=$?
    set -e
    if [[ "$w2_rc" -ne 0 ]]; then
      echo "self-test FAILED: control W2 — a two-row table could not complete (exit $w2_rc)" >&2
      fail=1
    elif [[ -z "$w2_hits" ]]; then
      echo "self-test FAILED: control W2 — the SECOND row's unaudited dependency was not reported. The loop is not reaching row two, and with one real row in the table nothing else would ever say so." >&2
      fail=1
    elif ! grep -q 'UNAUDITED_DEP' <<<"$w2_hits"; then
      echo "self-test FAILED: control W2 — row two was reported but not by the offending name: [$w2_hits]" >&2
      fail=1
    elif grep -q 'w2a' <<<"$w2_hits"; then
      echo "self-test FAILED: control W2 — the CLEAN first row was reported alongside the dirty second: [$w2_hits]" >&2
      fail=1
    elif grep -qE 'serde|src/main\.rs' <<<"$w2_hits"; then
      echo "self-test FAILED: control W2 — row two's OWN audited dependency (serde) or target path (src/main.rs) was reported as unaudited. The loop reached row two but audited it against row ONE's sets: [$w2_hits]" >&2
      fail=1
    else
      echo "self-test: control W2 (a SECOND table row is visited, audited against ITS OWN sets and not row one's, its unaudited dependency refused by name, and the clean first row not reported) — the loop reaches row two"
    fi
  fi
  # CONTROL W2b — A DECLARED-ABSENT FUZZ WORKSPACE THAT IS PRESENT. The
  # empty fuzz field means "this crate has no fuzz workspace"; if the crate
  # HAS one, skipping it audits nothing and `find_foreign_tree_entries`
  # whitelists `fuzz/Cargo.toml` unconditionally, so neither half objects.
  mkdir -p "$tmp/w2c/src" "$tmp/w2c/fuzz"
  printf 'fn c() {}
' > "$tmp/w2c/src/lib.rs"
  printf '[package]
name = "w2c"
version = "0.0.1"

[lib]
path = "src/lib.rs"

[dependencies]
libc = "0.2"
' > "$tmp/w2c/Cargo.toml"
  printf '[package]
name = "w2cfuzz"
version = "0.0.1"

[dependencies]
EVIL_PROC_MACRO = "1"
' > "$tmp/w2c/fuzz/Cargo.toml"
  set +e
  collect_audited_closures "$tmp/w2c|$tmp/w2c/Cargo.toml|libc|src/lib.rs|||" >/dev/null 2>"$tmp/w2b.err"
  w2b_rc=$?
  set -e
  if [[ "$w2b_rc" -eq 0 ]]; then
    echo "self-test FAILED: control W2b — a row declaring NO fuzz manifest was accepted while the crate HAS fuzz/Cargo.toml. That workspace is then audited by nothing, and the foreign-tree walk whitelists the file unconditionally." >&2
    fail=1
  elif ! grep -q 'fuzz/Cargo.toml exists' "$tmp/w2b.err"; then
    echo "self-test FAILED: control W2b refused, but not for the declared-absent-fuzz reason: $(cat "$tmp/w2b.err")" >&2
    fail=1
  else
    echo "self-test: control W2b — a row declaring no fuzz workspace is refused when one is present"
  fi

  # CONTROL W2c — A ROW WITH THE WRONG FIELD COUNT. `read` pads missing
  # trailing fields with "" and returns 0, so a row written without its
  # trailing pipes silently drops the fuzz half rather than failing.
  set +e
  collect_audited_closures "$tmp/w2a|$tmp/w2a/Cargo.toml|libc|src/lib.rs" >/dev/null 2>"$tmp/w2c.err"
  w2c_rc=$?
  set -e
  if [[ "$w2c_rc" -eq 0 ]]; then
    echo "self-test FAILED: control W2c — a FOUR-field row was accepted; its fuzz half was dropped silently" >&2
    fail=1
  elif ! grep -q "separators, want exactly 6" "$tmp/w2c.err"; then
    echo "self-test FAILED: control W2c refused, but not on the field count: $(cat "$tmp/w2c.err")" >&2
    fail=1
  else
    echo "self-test: control W2c — a row with the wrong field count is refused, never padded"
  fi

  # CONTROL W2e — A DECOY MANIFEST, and a DUPLICATE ROW. A row whose
  # manifest does not live in its own crate directory audits a file the walk
  # never covers, and the crate's real Cargo.toml is then audited by nothing
  # — `find_foreign_tree_entries` whitelists both `Cargo.toml` and
  # `fuzz/Cargo.toml` unconditionally, so neither half objects. Same class as
  # W2b, in the NON-empty case. A duplicate crate directory is the other
  # copy-paste failure: two rows disagreeing about one crate's audited sets.
  printf '[package]\nname = "decoy"\nversion = "0.0.1"\n\n[lib]\npath = "src/lib.rs"\n\n[dependencies]\nlibc = "0.2"\n' > "$tmp/decoy-Cargo.toml"
  set +e
  collect_audited_closures "$tmp/w2a|$tmp/decoy-Cargo.toml|libc|src/lib.rs|||" >/dev/null 2>"$tmp/w2e.err"
  w2e_rc=$?
  set -e
  if [[ "$w2e_rc" -eq 0 ]]; then
    echo "self-test FAILED: control W2e — a row whose manifest is NOT \$c_dir/Cargo.toml was accepted; the crate's real manifest is then audited by nothing" >&2
    fail=1
  elif ! grep -q 'audited-closure row manifest' "$tmp/w2e.err"; then
    echo "self-test FAILED: control W2e refused, but not on the manifest's location: $(cat "$tmp/w2e.err")" >&2
    fail=1
  else
    echo "self-test: control W2e — a decoy manifest outside the row's crate directory is refused"
  fi
  set +e
  collect_audited_closures \
    "$tmp/w2a|$tmp/w2a/Cargo.toml|libc|src/lib.rs|||" \
    "$tmp/w2a|$tmp/w2a/Cargo.toml|serde|src/main.rs|||" >/dev/null 2>"$tmp/w2e2.err"
  w2e2_rc=$?
  set -e
  if [[ "$w2e2_rc" -eq 0 ]]; then
    echo "self-test FAILED: control W2e — the SAME crate directory in two rows was accepted, with two different audited sets" >&2
    fail=1
  elif ! grep -q 'more than one audited-closure row' "$tmp/w2e2.err"; then
    echo "self-test FAILED: control W2e refused a duplicate, but not by naming it: $(cat "$tmp/w2e2.err")" >&2
    fail=1
  else
    echo "self-test: control W2e — a duplicate crate directory is refused"
  fi

  # CONTROL W2d — THE WIRING: the REAL table still covers the incumbent.
  # W2/W2b/W2c all drive synthetic rows, and K15 calls
  # `collect_source_closure` directly with the scalars, so overwriting the
  # client row instead of appending to it would leave check 6 covering
  # nothing real while every one of them stayed green. This is the same
  # wiring discipline control P5 states for `check_lint_level`.
  w2d_found=no
  for row in "${AUDITED_CLOSURE_CRATES[@]}"; do
    IFS='|' read -r w2d_dir w2d_manifest _ _ _ _ _ <<<"$row"
    if [[ "$w2d_dir" == "$CRATE_DIR" && "$w2d_manifest" == "$CLIENT_MANIFEST" ]]; then
      w2d_found=yes; break
    fi
  done
  if [[ "$w2d_found" != yes ]]; then
    echo "self-test FAILED: control W2d — AUDITED_CLOSURE_CRATES has no row for \$CRATE_DIR ($CRATE_DIR) with \$CLIENT_MANIFEST. Check 6 is no longer covering the incumbent crate, and every synthetic-row control above would still pass." >&2
    fail=1
  else
    echo "self-test: control W2d — the real table still carries the incumbent's row; check 6 covers it"
  fi

  # CONTROL W2f — THE CALL SITE, which no other control can reach, and it
  # runs a COPY carrying a SECOND ROW because the real table has one.
  #
  # W2d inspects the TABLE; W2/W2b/W2c/W2e drive the
  # FUNCTION with synthetic rows. None sees the
  # gate's own call. A control that runs only a
  # one-row table cannot distinguish
  # `"${AUDITED_CLOSURE_CRATES[@]}"` from
  # `"${AUDITED_CLOSURE_CRATES[0]}"`: they pass the same row.
  # The fixture must supply another row to expose truncation.
  #
  # So this copies the gate (K18's pattern — the copy inherits any mutation
  # to the original), injects a SECOND row naming a clean scratch crate, and
  # requires CLOSURE-AUDITED to name BOTH. Truncating the call to row zero
  # names one, and this goes red. The injection is VERIFIED to have landed:
  # a mutation that applies nothing reads as a pass.
  mkdir -p "$tmp/w2f" "$tmp/w2g"
  cp "$(dirname "${BASH_SOURCE[0]}")/fsguard-scan.py" "$tmp/w2f/fsguard-scan.py"
  # P5b's injected primary-lint row needs a manifest that PASSES
  # `check_lint_level primary`, so it is a COPY OF THE REAL ONE rather
  # than a hand-written table: a fixture spelling the lint keys itself
  # would go stale the day the real requirements move, and would do it
  # silently, by passing.
  cp "$CLIENT_MANIFEST" "$tmp/w2g/Cargo.toml"
  awk -v row="  \"$tmp/w2a|$tmp/w2a/Cargo.toml|libc|src/lib.rs|||\"" \
      -v lrow="  \"$tmp/w2a|$tmp/w2a/src|0\"" \
      -v prow="  \"$tmp/w2g/Cargo.toml\"" \
    '{ print }
     /^AUDITED_CLOSURE_CRATES=\(/  { print row }
     /^LICENSED_SITE_CRATES=\(/    { print lrow }
     /^PRIMARY_LINT_MANIFESTS=\(/  { print prow }' \
    "${BASH_SOURCE[0]}" > "$tmp/w2f/check-fsguard-sites.sh"
  chmod +x "$tmp/w2f/check-fsguard-sites.sh"
  if ! grep -q "^  \"$tmp/w2a|$tmp/w2a/Cargo.toml|" "$tmp/w2f/check-fsguard-sites.sh" \
     || ! grep -q "^  \"$tmp/w2a|$tmp/w2a/src|0\"" "$tmp/w2f/check-fsguard-sites.sh" \
     || ! grep -q "^  \"$tmp/w2g/Cargo.toml\"" "$tmp/w2f/check-fsguard-sites.sh"; then
    echo "self-test FAILED: control W2f/D13d/P5b — one or more of the three second rows were NOT injected into the copy; the controls would have proved nothing" >&2
    fail=1
  else
    set +e
    w2f_out="$(bash "$tmp/w2f/check-fsguard-sites.sh" 2>&1)"
    w2f_rc=$?
    set -e
    if [[ "$w2f_rc" -ne 0 ]]; then
      echo "self-test FAILED: control W2f — the copied gate with a second audited row did not pass, so the wiring could not be read:" >&2
      printf '%s\n' "$w2f_out" | tail -5 >&2
      fail=1
    else
      w2f_missing=""
      grep -q "CLOSURE-AUDITED: [^;]*$CRATE_DIR" <<<"$w2f_out" || w2f_missing="$w2f_missing $CRATE_DIR"
      grep -q "CLOSURE-AUDITED: [^;]*$tmp/w2a" <<<"$w2f_out" || w2f_missing="$w2f_missing $tmp/w2a"
      if [[ -n "$w2f_missing" ]]; then
        echo "self-test FAILED: control W2f — the gate ran with a TWO-row table but CLOSURE-AUDITED does not name:$w2f_missing. Check 6 is not passing the whole table." >&2
        fail=1
      else
        echo "self-test: control W2f (a copied gate with a SECOND audited row names BOTH directories) — check 6 passes the WHOLE table, not row zero"
      fi
      # ---- control D13d: THE LICENSED-SITE LOOP'S CALL
      # SITE. D13a-D13c drive check_licensed_sites DIRECTLY
      # and prove the function; none sees the gate's
      # own `for` over LICENSED_SITE_CRATES. With ONE
      # row, `"${arr[@]}"` and `"${arr[0]}"` pass the
      # same row, so a control must supply another row
      # to distinguish full traversal from truncation.
      #
      # Reuse W2f's copied gate run: each full
      # run temporarily edits both real clippy.toml
      # files during check 8. The additional
      # row names the clean scratch crate with
      # expected count zero, and the successful
      # summary must name both source roots.
      d13d_missing=""
      grep -q "licensed sites [^;]*$CRATE_SRC" <<<"$w2f_out" || d13d_missing="$d13d_missing $CRATE_SRC"
      grep -q "licensed sites [^;]*$tmp/w2a/src" <<<"$w2f_out" || d13d_missing="$d13d_missing $tmp/w2a/src"
      if [[ -n "$d13d_missing" ]]; then
        echo "self-test FAILED: control D13d — the gate ran with a TWO-row LICENSED_SITE_CRATES but the summary's licensed-sites clause does not name:$d13d_missing. The loop is not covering the whole table." >&2
        fail=1
      else
        echo "self-test: control D13d (a copied gate with a SECOND licensed-site row names BOTH src roots) — the loop covers the WHOLE table, not row zero"
      fi
      # ---- control P5b: THE PRIMARY-LINT LOOP'S CALL SITE. The M
      # controls drive `check_lint_level` DIRECTLY and prove the
      # validator; none of them sees the gate's own `for` over
      # PRIMARY_LINT_MANIFESTS. W2f/D13d inject into the OTHER two
      # tables and cannot detect a truncation of this one.
      #
      # The real table has TWO rows, so `"${arr[@]}"` and `"${arr[0]}"`
      # are different calls on the real gate — but they are the same
      # call on a one-row table, and a table that ever falls back to one
      # row would quietly make a real-gate control vacuous. So this
      # rides W2f's copy with a THIRD row, and requires the summary to
      # name it. The row is a copy of the client's own manifest, so the
      # copy still passes and the clause must name all three.
      p5b_missing=""
      grep -q "PRIMARY-LINTS-READ: [^;]*$CLIENT_MANIFEST" <<<"$w2f_out" || p5b_missing="$p5b_missing $CLIENT_MANIFEST"
      grep -q "PRIMARY-LINTS-READ: [^;]*$CLI_MANIFEST" <<<"$w2f_out" || p5b_missing="$p5b_missing $CLI_MANIFEST"
      grep -q "PRIMARY-LINTS-READ: [^;]*$tmp/w2g/Cargo.toml" <<<"$w2f_out" || p5b_missing="$p5b_missing $tmp/w2g/Cargo.toml"
      if [[ -n "$p5b_missing" ]]; then
        echo "self-test FAILED: control P5b — the gate ran with a THREE-row PRIMARY_LINT_MANIFESTS but PRIMARY-LINTS-READ does not name:$p5b_missing. Check 5 is not covering the whole table, and a crate it misses has the whole fs ban switched off for it in one manifest line." >&2
        fail=1
      else
        echo "self-test: control P5b (a copied gate with a THIRD primary-lint row names ALL THREE manifests) — check 5 covers the WHOLE table, not row zero"
      fi

      # Publish the copied gate output for
      # P5 so these controls share one full
      # run. Check 8 temporarily edits both
      # real clippy.toml files, and reusing
      # the output avoids another such
      # interval. W2f checks that its
      # additional table row is present; the
      # copy still emits the FUZZ-LINTS-READ
      # clause that P5 needs to inspect.
      W2F_GATE_OUT="$w2f_out"
    fi
  fi

  # ---- control Q9d: AN ABSENT CLI CONFIG MUST TAKE THE GATE DOWN, and
  # this is the only control that can see it. Q7*/Q8* drive
  # check_config_identity and check_closure_premise directly; Q9c proves
  # the gate CALLS them. None of the three would notice an existence gate
  # being put back around the call — on the real tree the file is there,
  # so every one of them stays green.
  #
  # An existence condition around the identity check
  # could silently skip a missing CLI config. This
  # control changes the copied gate's CLI path to a
  # nonexistent file and requires the missing-file
  # refusal. The absence must stop the gate rather than
  # being treated as a state where checking is optional.
  #
  # Use a separate copy because this control
  # requires refusal, while W2f's copy must pass.
  # The premises run before check 8, so a missing
  # config is rejected before the compiler or
  # configuration mutations. Verify the
  # rewritten path before trusting the result.
  mkdir -p "$tmp/q9d"
  cp "$(dirname "${BASH_SOURCE[0]}")/fsguard-scan.py" "$tmp/q9d/fsguard-scan.py"
  q9d_absent="$tmp/q9d/no-such-dir/clippy.toml"
  awk -v repl="CLI_CLIPPY=\"$q9d_absent\"" \
    '/^CLI_CLIPPY=/ { print repl; next } { print }' \
    "${BASH_SOURCE[0]}" > "$tmp/q9d/check-fsguard-sites.sh"
  chmod +x "$tmp/q9d/check-fsguard-sites.sh"
  if ! grep -q "^CLI_CLIPPY=\"$q9d_absent\"$" "$tmp/q9d/check-fsguard-sites.sh" \
     || grep -q "^CLI_CLIPPY=\"crates/granary-cli/clippy.toml\"$" "$tmp/q9d/check-fsguard-sites.sh"; then
    echo "self-test FAILED: control Q9d — CLI_CLIPPY was NOT rewritten in the copy (or the original spelling survived); the control would have proved nothing" >&2
    fail=1
  else
    set +e
    q9d_out="$(bash "$tmp/q9d/check-fsguard-sites.sh" 2>&1)"
    q9d_rc=$?
    set -e
    # THE EXIT CODE, never the printed line. A gate that prints a refusal
    # and exits 0 is the exact shape this suite has shipped twice.
    if [[ "$q9d_rc" -ne 2 ]]; then
      echo "self-test FAILED: control Q9d — a gate whose cli clippy.toml does not exist exited $q9d_rc, wanted 2. An absent nested config is being read as nothing to check." >&2
      printf '%s\n' "$q9d_out" | tail -5 >&2
      fail=1
    elif ! grep -q 'is MISSING' <<<"$q9d_out"; then
      echo "self-test FAILED: control Q9d — the gate refused at exit 2 but not by naming the missing file:" >&2
      printf '%s\n' "$q9d_out" | tail -5 >&2
      fail=1
    else
      echo "self-test: control Q9d (a gate whose cli clippy.toml is absent) — refused at exit 2 naming the missing file, never 'nothing to inherit'"
    fi
  fi

  # An EMPTY table is a refusal, not a clean closure over no crates.
  set +e
  collect_audited_closures >/dev/null 2>"$tmp/w2.err"
  w2_empty_rc=$?
  set -e
  if [[ "$w2_empty_rc" -eq 0 ]]; then
    echo "self-test FAILED: control W2 — an EMPTY audited-closure table reported a clean closure instead of refusing" >&2
    fail=1
  else
    echo "self-test: control W2 (an empty table) — refused, never a clean closure over no crates"
  fi

  # ---- control W1: A NESTED CHECKOUT, and THE PRUNE'S PREMISE beside
  # it. `find_pruned` skips any directory other than the walk root that
  # carries a `.git` entry, because a linked worktree (a `.git` FILE) or
  # a nested clone (a `.git` DIRECTORY) is a different checkout whose
  # configs are that checkout's own copies of the files audited here.
  # Before the prune existed, the harness's own subagent worktrees under
  # `.claude/worktrees/` turned this gate red on a clean tree.
  #
  # TWO halves, and the SECOND is the one that matters: pruning by
  # "separate checkout" must not become pruning by "somewhere under a
  # directory called worktrees". A stray config beside the checkout is
  # still a stray config, and the tempting repair — allow-listing the
  # worktree's `clippy.toml` by name — would have made a second nested
  # config acceptable forever.
  mkdir -p "$tmp/tree/.claude/worktrees/agent-x/crates/granary-client" \
           "$tmp/tree/.claude/worktrees/agent-x/.cargo"
  printf 'gitdir: /elsewhere/.git/worktrees/agent-x\n' \
    > "$tmp/tree/.claude/worktrees/agent-x/.git"
  : > "$tmp/tree/.claude/worktrees/agent-x/clippy.toml"
  : > "$tmp/tree/.claude/worktrees/agent-x/.cargo/config.toml"
  : > "$tmp/tree/.claude/worktrees/agent-x/crates/granary-client/clippy.toml"
  if ! check_stray_configs "$tmp/tree" 2>"$tmp/discovery.err"; then
    echo "self-test FAILED: control W1 negative half — a nested checkout's own clippy.toml/.cargo/config.toml were reported as stray configs of this tree:" >&2
    cat "$tmp/discovery.err" >&2
    fail=1
  else
    echo "self-test: control W1 negative half (a linked worktree carrying its own root clippy.toml, .cargo/config.toml and crate-root clippy.toml) — pruned as a separate checkout, as expected"
  fi

  # THE PREMISE: not inside the checkout, one level up, in a directory
  # that carries no `.git` of its own.
  : > "$tmp/tree/.claude/worktrees/clippy.toml"
  if check_stray_configs "$tmp/tree" 2>"$tmp/discovery.err"; then
    echo "self-test FAILED: control W1 positive half — a stray clippy.toml BESIDE the nested checkout was pruned too, so the prune is blinding the check" >&2
    fail=1
  elif ! grep -q "worktrees/clippy.toml" "$tmp/discovery.err"; then
    echo "self-test FAILED: control W1 positive half refused but did not name the planted path:" >&2
    cat "$tmp/discovery.err" >&2
    fail=1
  else
    echo "self-test: control W1 positive half (a stray clippy.toml beside the checkout, under no .git of its own) — refused, naming the path, as expected"
  fi
  rm -rf "$tmp/tree/.claude"

  # ---- control N18: the discovery WALK's status.
  # File-plant controls do not establish behavior
  # when find itself fails. A missing root
  # provides that failure; a process substitution
  # could hide the producer's exit status and
  # leave an empty list looking clean. This
  # control requires status 2 and the walk-failure
  # diagnostic, not merely a nonzero exit.
  n18_rc=0
  check_stray_configs "$tmp/no-such-tree" 2>"$tmp/discovery.err" || n18_rc=$?
  if [[ "$n18_rc" -ne 2 ]]; then
    echo "self-test FAILED: control N18 — a walk root that does not exist left config discovery at status $n18_rc (wanted 2, the status the gate turns into exit 2):" >&2
    cat "$tmp/discovery.err" >&2
    fail=1
  elif ! grep -q "the stray-config walk of .* failed" "$tmp/discovery.err"; then
    echo "self-test FAILED: control N18 — refused, but not by saying the walk could not run:" >&2
    cat "$tmp/discovery.err" >&2
    fail=1
  else
    echo "self-test: control N18 (a walk root that does not exist — find cannot complete) — refused at status 2, the gate's exit 2, as expected"
  fi

  # ---- control E: the real, unmodified tree passes every check.
  if ! out="$(check_config "$ROOT_CLIPPY" "$CLIENT_CLIPPY" 2>&1)"; then
    echo "self-test FAILED: control E (real tree) did not pass check_config:" >&2
    echo "$out" >&2
    fail=1
  fi
  # The real cargo config carries real `rustflags` arrays (the musl
  # crt-static rows), so this is also the NEGATIVE control for the
  # cap-lints matcher: a check that refused any rustflag at all would
  # fail here rather than pass N1/N2 for the wrong reason.
  # EVERY ROW, not just the client's: the real tree's positive control
  # has to cover the same manifests the gate does, or a real cli manifest
  # that the validator refuses would be found first by CI rather than here.
  for e_manifest in "${PRIMARY_LINT_MANIFESTS[@]}"; do
    if ! out="$(check_lint_level primary "$e_manifest" "${CARGO_CONFIG_ARGS[@]}" 2>&1)"; then
      echo "self-test FAILED: control E (real tree) did not pass the lint-level check for $e_manifest:" >&2
      echo "$out" >&2
      fail=1
    fi
  done
  # The real tree carries exactly two of the files discovery refuses
  # elsewhere — the repo-root .cargo/config.toml and the crate-root
  # clippy.toml — so it is also the positive control for that check on a
  # REAL tree, not just the minimal one N10/N11 build.
  if ! check_stray_configs "." 2>"$tmp/e.err"; then
    echo "self-test FAILED: control E (real tree) did not pass config discovery:" >&2
    cat "$tmp/e.err" >&2
    fail=1
  fi
  real_src_scan="$(scan_or_die "$CRATE_SRC")"
  real_count="$(scanned_count "$real_src_scan")"
  if ! report_count "$real_count" "$EXPECTED_LICENSED_SITES" "$CRATE_SRC" 2>"$tmp/e.err"; then
    echo "self-test FAILED: control E (real tree) count check did not pass:" >&2
    cat "$tmp/e.err" >&2
    fail=1
  fi
  real_src_hits="$(scanned_allow_hits "$real_src_scan")"
  real_crate_scan="$(scan_or_die "$CRATE_DIR")"
  real_crate_hits="$(scanned_allow_hits "$real_crate_scan")"
  if ! report_bare_allow "$real_src_hits" 2>"$tmp/e.err" || ! report_bare_allow "$real_crate_hits" 2>>"$tmp/e.err"; then
    echo "self-test FAILED: control E (real tree) kill switch did not pass:" >&2
    cat "$tmp/e.err" >&2
    fail=1
  fi
  # ---- control K15: the NEGATIVE half of K11-K14 and K16, on the REAL
  # tree. Without it, a check 6 that refused everything would still show
  # five green controls. It is not decoration: this crate's own module
  # docs contain four sentences mentioning `#[path = "…"]` and
  # `include!`, and a matcher reading raw source instead of the blanked
  # text refuses the real tree on them.
  set +e
  real_closure="$(collect_source_closure "$CRATE_DIR" "$CLIENT_MANIFEST" "$CLIENT_FUZZ_MANIFEST" "$CLIENT_DEPS_AUDITED" "$CLIENT_TARGET_PATHS_AUDITED" "$CLIENT_FUZZ_DEPS_AUDITED" "$CLIENT_FUZZ_TARGET_PATHS_AUDITED")"
  real_closure_rc=$?
  set -e
  if [[ "$real_closure_rc" -ne 0 ]]; then
    echo "self-test FAILED: control K15 (real tree) — the closure collector could not complete" >&2
    fail=1
  elif ! report_source_closure "$real_closure" 2>"$tmp/e.err"; then
    echo "self-test FAILED: control K15 (real tree) — check 6 refused the real tree:" >&2
    cat "$tmp/e.err" >&2
    fail=1
  else
    echo "self-test: control K15 (the REAL tree under check 6 — four module docs mention #[path] and include! in prose) — not refused, as expected"
  fi
  # ---- control P5: the WIRING, not the check. P1-P4 call
  # check_lint_level directly, so they stay green if the gate stops
  # calling it at all. The gate names every fuzz manifest it read in its
  # summary line; this runs the whole gate and requires all four names
  # to be there.
  # REUSES W2f's run rather than opening a second check-8 mutation window
  # (see W2f). If W2f could not produce one, P5 runs its own rather than
  # silently asserting over an empty string — a control whose input went
  # missing must refuse, not pass.
  p5_out="${W2F_GATE_OUT:-}"
  p5_rc=0
  if [[ -z "$p5_out" ]]; then
    p5_out="$(bash "${BASH_SOURCE[0]}" 2>&1)" || p5_rc=$?
  fi
  if [[ "$p5_rc" -eq 0 ]]; then
    # CI is an independent inventory: reading only FUZZ_MANIFESTS would
    # miss a workspace omitted from that same array.
    if ! out="$(python3 - "${FUZZ_MANIFESTS[@]}" 2>&1 <<'PYTHON'
import pathlib
import shlex
import sys

manifests = set()
for line in pathlib.Path(".github/workflows/ci.yml").read_text().splitlines():
    if line.strip().startswith("- run: cargo clippy "):
        args = shlex.split(line.strip().removeprefix("- run: "))
        if "--manifest-path" in args:
            manifests.add(args[args.index("--manifest-path") + 1])
if not manifests:
    sys.exit("no CI clippy --manifest-path commands found; coverage is unverified")
missing = manifests - set(sys.argv[1:])
if missing:
    sys.exit("FUZZ_MANIFESTS omits CI clippy manifests: " + " ".join(sorted(missing)))
PYTHON
)"; then
      echo "self-test FAILED: control P5 — $out" >&2
      fail=1
    else
      echo "self-test: control P5 (CI clippy manifests are all in FUZZ_MANIFESTS) — as expected"
    fi
    p5_missing=""
    for fuzz_manifest in "${FUZZ_MANIFESTS[@]}"; do
      grep -q "FUZZ-LINTS-READ: .*$fuzz_manifest" <<<"$p5_out" || p5_missing="$p5_missing $fuzz_manifest"
    done
    # WHAT P5 PROVES. The manifest names in the summary come from
    # each `check_lint_level` run's OWN output — the program prints
    # `MANIFEST-VALIDATED:` and the loop refuses any answer that does
    # not name the manifest it asked about — so a loop that stopped
    # calling the validator has no name to publish and this goes red.
    # Sourcing the names from the loop variable instead would not prove
    # this: that variable is bookkeeping the validator never touches, so
    # a loop that stopped calling the validator would still publish a
    # name and this would stay green.

    # ---- control P6: the REACH half's WIRING — proven by a refusal,
    # not by a number in a passing summary. Reading the licence count
    # out of the success line proved only that the SCANNER ran: the
    # count is computed beside the refusal, so deleting
    # `report_licensed_reach` left the number in place and P6 green.
    # What has to be observed is the gate REFUSING, so this plants a
    # reach finding in a COPY of the crate, points the gate's own crate
    # scan at the copy, and requires a nonzero exit naming the plant.
    # The plant is a bare `tokio::spawn(` added to a file that already
    # carries a wholesale test-module licence, which is exactly the
    # shape the check exists for.
    p6_dir="$tmp/p6-crate"
    copy_crate_tree "$CRATE_DIR" "$p6_dir"
    printf '\n#[cfg(test)]\nmod planted_reach {\n    #[expect(clippy::disallowed_methods, reason = "test module: fixtures use bare fs calls on their own scratch directories")]\n    mod inner {\n        pub fn f() { let _ = tokio::spawn(async {}); }\n    }\n}\n' \
      >> "$p6_dir/src/lib.rs"
    p6_rc=0
    p6_reach="$(scanned_reach_hits "$(scan_or_die "$p6_dir")")"
    p6_out="$(report_licensed_reach "$p6_reach" 2>&1)" || p6_rc=$?
    if [[ "$p6_rc" -eq 0 ]]; then
      echo "self-test FAILED: control P6 — a bare tokio::spawn under a whole-module licence did not make the gate refuse. Reach [$p6_reach]" >&2
      fail=1
    elif ! grep -q "p6-crate/src/lib.rs" <<<"$p6_reach" || ! grep -q "tokio::spawn" <<<"$p6_reach"; then
      echo "self-test FAILED: control P6 — the gate refused, but not for the plant. Reach [$p6_reach]" >&2
      fail=1
    elif ! grep -q "NON-FILESYSTEM rows of the same lint" <<<"$p6_out"; then
      echo "self-test FAILED: control P6 — the refusal did not say what it refuses:" >&2
      echo "$p6_out" >&2
      fail=1
    else
      echo "self-test: control P6 (a bare tokio::spawn planted under a whole-module licence in a copy of the crate — the gate REFUSES, naming the plant) — as expected"
    fi

    # ---- control P7: the other half of P6 — that the GATE calls the
    # refusal at all. P6 proves the refusal works when it is called;
    # nothing in it would notice the gate no longer calling it. The
    # licence count in the summary is printed BY the pass path of
    # `report_licensed_reach`, so it exists only when the gate ran it —
    # delete the call and the clause reads "(never run)" and this goes
    # red. Digits only in the capture, for the reason control P5's
    # sibling records: a non-numeric token reaching `-lt` is silently 0.
    # ANCHORED TO THE CLIENT'S OWN CLAUSE. The summary carries one
    # `<crate-dir> LICENCE-REACH: ...` clause PER ROW — the CRATE DIR, not
    # the src root, because the reach audit walks the whole crate — and the
    # leading `.*` here is greedy, so without an anchor it captured
    # whichever clause came LAST and went red on a healthy gate purely on
    # the order the rows were written.
    # `#` as the sed delimiter, because the anchor is a PATH and `/` in
    # `$CRATE_SRC` closes the substitution early — EXECUTED, it failed with
    # "bad flag in substitute command" and took the self-test to exit 1
    # with no FAILED line, which is not a shape anything reports well.
    p7_n="$(sed -n "s#.*$CRATE_DIR LICENCE-REACH: 0 findings over \([0-9][0-9]*\) whole-module licences.*#\1#p" <<<"$p5_out" | head -n1)"
    if [[ -z "$p7_n" ]] || [[ "$p7_n" -lt 1 ]]; then
      echo "self-test FAILED: control P7 — the gate's summary carries no LICENCE-REACH count above zero (got [${p7_n:-<none>}]), so nothing proves the gate called the refusal:" >&2
      echo "$p5_out" >&2
      fail=1
    else
      echo "self-test: control P7 (the gate itself calls the whole-module reach refusal — its summary quotes the line that refusal prints, over $p7_n licences) — as expected"
    fi

    # ---- control P5c: THE REAL table still carries BOTH primary
    # manifests. P5b drives a copy with synthetic rows; M1-M10 drive the
    # validator directly. Replacing a real row instead of appending to it
    # would leave check 5 covering one crate while every one of them
    # stayed green. Same wiring discipline as W2d for the closure table.
    p5c_missing=""
    for p5c_want in "$CLIENT_MANIFEST" "$CLI_MANIFEST"; do
      p5c_found=no
      for p5c_row in "${PRIMARY_LINT_MANIFESTS[@]}"; do
        [[ "$p5c_row" == "$p5c_want" ]] && { p5c_found=yes; break; }
      done
      [[ "$p5c_found" == yes ]] || p5c_missing="$p5c_missing $p5c_want"
    done
    if [[ -n "$p5c_missing" ]]; then
      echo "self-test FAILED: control P5c — PRIMARY_LINT_MANIFESTS has no row for:$p5c_missing. Check 5 is no longer covering that crate's own lint level, and every synthetic-row control above would still pass." >&2
      fail=1
    else
      echo "self-test: control P5c (the real table carries both primary manifests) — check 5 covers both crates"
    fi

    # ---- control Q9c: THE GATE CALLS CHECK 9 AT ALL. Q7*/Q8* drive
    # check_config_identity and check_closure_premise directly and prove
    # the FUNCTIONS; nothing in them would notice the gate no longer
    # calling either. The INHERITED line is printed BY the pass path, and
    # it carries the byte count the identity check itself produced — so a
    # deleted call, or one made `|| true`, leaves no line to match.
    # Anchored on the byte count rather than the prose, because the prose
    # is this file's and the count is the CHECK's.
    if ! grep -qE "^INHERITED: $CLI_CLIPPY carries $CLIENT_CLIPPY's resolution verdict\. IDENTITY: .* \([0-9][0-9]* bytes\)" <<<"$p5_out"; then
      echo "self-test FAILED: control Q9c — the gate's output carries no INHERITED line quoting the identity check's own byte count, so nothing proves the gate ran check 9:" >&2
      echo "$p5_out" >&2
      fail=1
    else
      echo "self-test: control Q9c (the gate itself runs check 9 — its output quotes the byte count the identity check printed) — as expected"
    fi

    if [[ -n "$p5_missing" ]]; then
      echo "self-test FAILED: control P5 — the gate's summary does not name the fuzz manifests it must read:$p5_missing" >&2
      fail=1
    else
      echo "self-test: control P5 (the gate itself reads all registered fuzz manifests, named in its summary) — as expected"
    fi
  else
    echo "self-test FAILED: control P5 — the gate did not pass on the real tree:" >&2
    echo "$p5_out" >&2
    fail=1
  fi

  if [[ "$fail" -eq 0 ]]; then
    echo "self-test: control E (real tree) — passes every check, as expected"
  fi

  # ---- controls Q1-Q5 exercise resolution at
  # the real clippy-discovered config paths.
  # They mutate the client and root clippy.toml
  # files in place, saving byte backups first.
  # Cleanup restores those backups instead of
  # checking files out of Git, which could
  # discard uncommitted contents. The self-test
  # extends its EXIT trap so the scratch cleanup
  # remains registered, and normal-path
  # restoration is checked with `cmp`. Signal
  # handling and the pre-run cleanliness guard
  # address interrupted mutations separately.
  # PRE-RUN CLEANLINESS GUARD. Traps cannot restore
  # configuration after SIGKILL. A stopped mutation
  # can leave a typo or stripped flag in a real
  # clippy.toml, changing which bans apply to subsequent
  # runs. Before saving backups and starting these
  # controls, ask Git whether each target is clean.
  # A failed status query or a dirty file refuses
  # the self-test, so an interrupted mutation is
  # not silently adopted as the next run's baseline.
  # This also protects unrelated uncommitted edits
  # from being overwritten by fixture cleanup.
  #
  # The cleanliness check makes interrupted
  # edits detectable on the next run. It cannot
  # make a trap run after SIGKILL; it refuses
  # to begin another mutation while either
  # target differs from its committed state.
  for _q_target in "$CLIENT_CLIPPY" "$ROOT_CLIPPY"; do
    set +e
    _q_dirty="$(git status --porcelain -- "$_q_target" 2>/dev/null)"
    _q_rc=$?
    set -e
    if [[ "$_q_rc" -ne 0 ]]; then
      echo "self-test BROKEN: could not ask git whether $_q_target is clean before mutating it in place (exit $_q_rc) — refused rather than risking an unrestorable edit" >&2
      exit 3
    fi
    if [[ -n "$_q_dirty" ]]; then
      echo "self-test REFUSED: $_q_target already differs from its committed bytes before the Q controls run." >&2
      echo "  These controls mutate that file IN PLACE and restore it afterwards. A dirty file here means either" >&2
      echo "  (a) a previous self-test was killed before its restore ran — check for a planted typo such as" >&2
      echo "      'std::fs::reed', which silently disables a ban because clippy reports an unresolvable path" >&2
      echo "      as a config-loader diagnostic and still exits 0 — or (b) you have real uncommitted work here," >&2
      echo "  which these controls would overwrite. Resolve it first; this gate will not mutate a dirty file." >&2
      git --no-pager diff -- "$_q_target" >&2 || true
      exit 3
    fi
  done
  q_client_backup="$tmp/q_client_clippy.toml.orig"
  q_root_backup="$tmp/q_root_clippy.toml.orig"
  cp "$CLIENT_CLIPPY" "$q_client_backup"
  cp "$ROOT_CLIPPY" "$q_root_backup"
  trap 'cp "$q_client_backup" "$CLIENT_CLIPPY" 2>/dev/null; cp "$q_root_backup" "$ROOT_CLIPPY" 2>/dev/null; rm -rf "$tmp"' EXIT
  q_restore() {
    cp "$q_client_backup" "$CLIENT_CLIPPY"
    cp "$q_root_backup" "$ROOT_CLIPPY"
    if ! cmp -s "$q_client_backup" "$CLIENT_CLIPPY" || ! cmp -s "$q_root_backup" "$ROOT_CLIPPY"; then
      echo "self-test BROKEN: could not restore a real clippy.toml to its pre-Q-control bytes" >&2
      exit 3
    fi
  }

  # ---- Q1: DORMANCY — a planted typo in a known-good client fs row
  # that carries no allow-invalid marker of its own.
  python3 - "$CLIENT_CLIPPY" "std::fs::read" "std::fs::reed" <<'PYEOF'
import pathlib, sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
p = pathlib.Path(path)
text = p.read_text()
needle = f'{{ path = "{old}", reason = "route filesystem access through fsguard, or license the site with #[expect] and a written reason" }},'
assert text.count(needle) == 1, f"fixture row not found verbatim (count={text.count(needle)}) — clippy.toml text changed"
mutated = needle.replace(f'"{old}"', f'"{new}"', 1)
p.write_text(text.replace(needle, mutated, 1))
PYEOF
  q1_out="$(check_resolution "$CLIENT_CLIPPY" "$CLIENT_RESOLUTION_CRATE" "$ROOT_CLIPPY" 2>&1)" && q1_rc=0 || q1_rc=$?
  if [[ "$q1_rc" -eq 0 ]]; then
    echo "self-test FAILED: control Q1 (planted typo std::fs::reed) — check_resolution did not refuse it" >&2
    fail=1
  elif ! grep -q "DORMANT" <<<"$q1_out" || ! grep -q "std::fs::reed" <<<"$q1_out"; then
    echo "self-test FAILED: control Q1 refused but did not name DORMANT / the typo'd path — may be failing for the wrong reason:" >&2
    echo "$q1_out" >&2
    fail=1
  else
    echo "self-test: control Q1 (planted typo std::fs::read -> std::fs::reed, a client fs row with no allow-invalid of its own) — check_resolution refused it as DORMANT, naming the path, as expected"
  fi
  q_restore

  # ---- Q2: RE-ARM FALLING DUE — `allow-invalid = true` planted on a
  # row that is genuinely resolvable (a plain std fs row; nothing calls
  # it, so no build break either way).
  python3 - "$CLIENT_CLIPPY" "std::fs::create_dir" <<'PYEOF'
import pathlib, sys
path, target = sys.argv[1], sys.argv[2]
p = pathlib.Path(path)
text = p.read_text()
needle = f'{{ path = "{target}", reason = "route filesystem access through fsguard, or license the site with #[expect] and a written reason" }},'
assert text.count(needle) == 1, f"fixture row not found verbatim (count={text.count(needle)}) — clippy.toml text changed"
mutated = needle.replace(' },', ', allow-invalid = true },', 1)
assert mutated != needle
p.write_text(text.replace(needle, mutated, 1))
PYEOF
  q2_out="$(check_resolution "$CLIENT_CLIPPY" "$CLIENT_RESOLUTION_CRATE" "$ROOT_CLIPPY" 2>&1)" && q2_rc=0 || q2_rc=$?
  if [[ "$q2_rc" -eq 0 ]]; then
    echo "self-test FAILED: control Q2 (planted allow-invalid on a resolvable row) — check_resolution did not refuse it" >&2
    fail=1
  elif ! grep -q "REARM" <<<"$q2_out" || ! grep -q "std::fs::create_dir'" <<<"$q2_out"; then
    echo "self-test FAILED: control Q2 refused but did not name REARM / the planted path — may be failing for the wrong reason:" >&2
    echo "$q2_out" >&2
    fail=1
  else
    echo "self-test: control Q2 (allow-invalid = true planted on std::fs::create_dir, which resolves) — check_resolution refused it as a RE-ARM falling due, naming the path, as expected"
  fi
  q_restore

  # ---- Q3: the UNMUTATED real tree, on BOTH configs — must pass, so
  # an obsolete matcher (or a drifted `rand::*` row) cannot make check 8
  # permanently red. Q3b is also the
  # only control that exercises the ROOT config's crate PAIR and must
  # show real (non-zero) re-arm coverage, not merely a clean rc.
  if q3a_out="$(check_resolution "$CLIENT_CLIPPY" "$CLIENT_RESOLUTION_CRATE" "$ROOT_CLIPPY" 2>&1)"; then
    echo "self-test: control Q3a (unmutated $CLIENT_CLIPPY, via $CLIENT_RESOLUTION_CRATE) — check_resolution passes, as expected"
  else
    echo "self-test FAILED: control Q3a (unmutated client config) — check_resolution did not pass:" >&2
    echo "$q3a_out" >&2
    fail=1
  fi
  if q3b_out="$(check_resolution "$ROOT_CLIPPY" "$ROOT_RESOLUTION_CRATE" "" "$ROOT_RESOLUTION_CRATE_SECONDARY" 2>&1)"; then
    if ! grep -q "^COVERAGE .* re-arm [1-9][0-9]*/[1-9]" <<<"$q3b_out"; then
      echo "self-test FAILED: control Q3b (unmutated root config) passed but reported ZERO re-arm coverage — the exact fail-open this control exists to refuse:" >&2
      echo "$q3b_out" >&2
      fail=1
    else
      echo "self-test: control Q3b (unmutated $ROOT_CLIPPY, via $ROOT_RESOLUTION_CRATE + $ROOT_RESOLUTION_CRATE_SECONDARY) — check_resolution passes WITH non-zero re-arm coverage, as expected"
    fi
  else
    echo "self-test FAILED: control Q3b (unmutated root config) — check_resolution did not pass:" >&2
    echo "$q3b_out" >&2
    fail=1
  fi

  # ---- Q4: the FORCING proof — a SECOND CONSECUTIVE check_resolution
  # call, on the SAME mutated config with nothing changed in between,
  # must refuse identically, never read as a vacuous pass because
  # nothing looked "new" to cargo's cache. A DIFFERENT row from Q1's
  # (Q1 already restored its own), so this is its own fixture.
  python3 - "$CLIENT_CLIPPY" "std::fs::write" "std::fs::writ3" <<'PYEOF'
import pathlib, sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
p = pathlib.Path(path)
text = p.read_text()
needle = f'{{ path = "{old}", reason = "route filesystem access through fsguard, or license the site with #[expect] and a written reason" }},'
assert text.count(needle) == 1, f"fixture row not found verbatim (count={text.count(needle)}) — clippy.toml text changed"
mutated = needle.replace(f'"{old}"', f'"{new}"', 1)
p.write_text(text.replace(needle, mutated, 1))
PYEOF
  q4a_out="$(check_resolution "$CLIENT_CLIPPY" "$CLIENT_RESOLUTION_CRATE" "$ROOT_CLIPPY" 2>&1)" && q4a_rc=0 || q4a_rc=$?
  q4b_out="$(check_resolution "$CLIENT_CLIPPY" "$CLIENT_RESOLUTION_CRATE" "$ROOT_CLIPPY" 2>&1)" && q4b_rc=0 || q4b_rc=$?
  if [[ "$q4a_rc" -eq 0 ]] || [[ "$q4b_rc" -eq 0 ]]; then
    echo "self-test FAILED: control Q4 (second consecutive run) — a run passed vacuously (rc $q4a_rc then rc $q4b_rc)" >&2
    fail=1
  elif ! grep -q "DORMANT" <<<"$q4a_out" || ! grep -q "std::fs::writ3" <<<"$q4a_out" \
    || ! grep -q "DORMANT" <<<"$q4b_out" || ! grep -q "std::fs::writ3" <<<"$q4b_out"; then
    echo "self-test FAILED: control Q4 — the two consecutive runs did not both name the same DORMANT row:" >&2
    echo "RUN1: $q4a_out" >&2
    echo "RUN2: $q4b_out" >&2
    fail=1
  else
    echo "self-test: control Q4 (two consecutive check_resolution calls on the SAME unchanged, mutated config) — both refused identically as DORMANT naming std::fs::writ3, no caching fail-open, as expected"
  fi
  q_restore

  # ---- Q5: META-CONTROL — neuter what the check's verdict depends on
  # (point it at a package name that does not exist) and prove it
  # refuses distinctly rather than reading empty clippy output as a
  # pass. `check-server-log-path.sh`'s control S0 (a required source
  # goes invisible to the gate; refuse, never read as clean) is the
  # model this copies. No mutation: the real, unmutated client config.
  q5_out="$(check_resolution "$CLIENT_CLIPPY" "granary-client-self-test-bogus-crate" "$ROOT_CLIPPY" 2>&1)" && q5_rc=0 || q5_rc=$?
  if [[ "$q5_rc" -eq 0 ]]; then
    echo "self-test FAILED: control Q5 (bogus crate name) — check_resolution silently passed instead of refusing" >&2
    fail=1
  elif ! grep -q "HARNESS" <<<"$q5_out"; then
    echo "self-test FAILED: control Q5 refused but did not say HARNESS — may be failing for the wrong reason:" >&2
    echo "$q5_out" >&2
    fail=1
  else
    echo "self-test: control Q5 (a package name check_resolution cannot possibly clippy) — refused as HARNESS, never a silent pass, as expected"
  fi

  # ---- Q6: ZERO-COVERAGE must refuse. The
  # control runs resolution against granary-core
  # with the real root config and no fallback
  # crate, then requires a nonzero status
  # naming ZERO-COVERAGE in the re-arm
  # direction. It tests that considering
  # rows without evaluating any cannot count
  # as a clean check; a refusal for another
  # reason does not satisfy the control.
  q6_out="$(check_resolution "$ROOT_CLIPPY" "granary-core" 2>&1)" && q6_rc=0 || q6_rc=$?
  if [[ "$q6_rc" -eq 0 ]]; then
    echo "self-test FAILED: control Q6 (granary-core, zero rand coverage) — check_resolution silently passed instead of refusing" >&2
    fail=1
  elif ! grep -q "ZERO-COVERAGE.*re-arm" <<<"$q6_out"; then
    echo "self-test FAILED: control Q6 refused but did not name ZERO-COVERAGE on the re-arm direction — may be failing for the wrong reason:" >&2
    echo "$q6_out" >&2
    fail=1
  else
    echo "self-test: control Q6 (granary-core reaches neither rand version, no second crate given) — refused as ZERO-COVERAGE on the re-arm direction, never a silent \"ok\", as expected"
  fi

  # ---- control R: SIGNAL SURVIVAL — restore on
  # SIGINT/SIGTERM as well as clean return. A RETURN trap
  # alone does not run on signals. Launch check_resolution
  # against the real root config in the background, poll for
  # $ROOT_CLIPPY to actually sit in its STRIPPED state (every
  # `allow-invalid = true` marker gone — a window this call leaves open
  # across two real `cargo clippy` invocations, wide enough to catch),
  # send SIGTERM, then assert the tracked file is back to clean bytes
  # rather than left with all seven rows silently re-armed.
  (
    check_resolution "$ROOT_CLIPPY" "$ROOT_RESOLUTION_CRATE" "" "$ROOT_RESOLUTION_CRATE_SECONDARY" >/dev/null 2>&1
  ) &
  r_pid=$!
  r_hit=0
  r_tries=0
  while [[ "$r_tries" -lt 800 ]]; do
    if ! kill -0 "$r_pid" 2>/dev/null; then
      break
    fi
    if [[ "$(grep -c ', allow-invalid = true' "$ROOT_CLIPPY" 2>/dev/null || true)" -eq 0 ]]; then
      r_hit=1
      break
    fi
    r_tries=$((r_tries + 1))
    sleep 0.05
  done
  if [[ "$r_hit" -eq 1 ]]; then
    kill -TERM "$r_pid" 2>/dev/null || true
  fi
  wait "$r_pid" 2>/dev/null || true
  if [[ "$r_hit" -ne 1 ]]; then
    echo "self-test FAILED: control R — never observed $ROOT_CLIPPY in its stripped state inside the poll window; cannot exercise the signal-restore path" >&2
    fail=1
  elif ! cmp -s "$q_root_backup" "$ROOT_CLIPPY"; then
    echo "self-test FAILED: control R (SIGTERM sent mid-strip) — $ROOT_CLIPPY did not restore to clean bytes" >&2
    fail=1
  else
    echo "self-test: control R (SIGTERM sent while $ROOT_CLIPPY sat in its stripped state) — the EXIT/TERM trap restored it to clean bytes, as expected"
  fi

  # FAIL FAST if either tracked configuration file did
  # not restore. Later controls copy `CLIENT_CLIPPY` as
  # their reference, so continuing would propagate a
  # planted mutation into their oracle. The byte comparisons
  # therefore guard the transition to those controls
  # independently of the accumulated failure count. A
  # mismatch exits immediately; the cleanup trap gets
  # its restoration attempt instead of allowing the
  # remaining battery to operate on a changed working tree.
  if ! cmp -s "$q_client_backup" "$CLIENT_CLIPPY" || ! cmp -s "$q_root_backup" "$ROOT_CLIPPY"; then
    echo "self-test BROKEN: after controls Q1-Q6/R, a real clippy.toml did not restore to clean bytes" >&2
    echo "fsguard-sites self-test: STOPPING HERE rather than running the remaining controls against a corrupted working tree. The EXIT trap installed with the Q backups restores both files as this exit runs, so the tree should be clean by the time you see this — CHECK \`git diff\` FIRST and do NOT reach for \`git checkout --\`, which can overwrite uncommitted work." >&2
    exit 3
  else
    echo "self-test: controls Q1-Q6/R — both real clippy.toml files restored to clean bytes after every mutation"
  fi

  # ---- controls Q7a-Q7f: check_config_identity CAN FAIL. Driven wholly
  # from FIXTURES, never the real files: `cmp` takes paths (unlike
  # check_resolution, which needs its config at clippy's own discovered
  # location), so copies suffice and nothing tracked is touched. That is
  # also what lets these controls run BEFORE crates/granary-cli/clippy.toml
  # exists — the mechanism is proven now, the call sites arrive with the
  # crate.
  mkdir -p "$tmp/q7"
  cp "$CLIENT_CLIPPY" "$tmp/q7/original.toml"
  cp "$CLIENT_CLIPPY" "$tmp/q7/copy.toml"

  # Q7a — the identical pair must PASS, or Q7b proves nothing.
  if ! check_config_identity "$tmp/q7/copy.toml" "$tmp/q7/original.toml" 2>"$tmp/q7/a.err"; then
    echo "self-test FAILED: control Q7a — two byte-identical copies were not accepted; Q7b cannot be read:" >&2
    cat "$tmp/q7/a.err" >&2
    fail=1
  else
    echo "self-test: control Q7a (two byte-identical copies) — check_config_identity accepts, as expected"
  fi

  # Q7b — strip ONE `allow-invalid` marker from the copy. This is the
  # residue a SIGKILL-interrupted strip window leaves behind, and it is a
  # change CI would NOT catch: `rand` resolves under this config's
  # consumers, so no diagnostic is emitted and the config-loader's own
  # warning is `code: null` and never promoted by deny-warnings. The
  # Verify that the mutation changed the marker count; an unchanged
  # fixture cannot establish that the refusal detects this edit.
  # grep -o, not grep -c: the mutation strips ONE OCCURRENCE and a line
  # carrying two markers would make a line count read as "did not land".
  # `|| true` on the grep: under `set -euo pipefail` a ZERO-match grep exits
  # 1 and kills the self-test mid-battery with no diagnostic, before
  # mutate_or_die's own "fixture carries no marker to strip" assertion can
  # report it. `grep -o` rather than `-c` because the mutation strips one
  # OCCURRENCE and a line carrying two markers would read as "did not land".
  q7_before="$( { grep -o ', allow-invalid = true' "$tmp/q7/copy.toml" || true; } | wc -l | tr -d '[:space:]')"
  mutate_or_die "Q7b" "
import pathlib
p = pathlib.Path('$tmp/q7/copy.toml')
t = p.read_text()
assert ', allow-invalid = true' in t, 'fixture carries no allow-invalid marker to strip'
p.write_text(t.replace(', allow-invalid = true', '', 1))
"
  q7_after="$( { grep -o ', allow-invalid = true' "$tmp/q7/copy.toml" || true; } | wc -l | tr -d '[:space:]')"
  if [[ "$q7_after" -ne $((q7_before - 1)) ]]; then
    echo "self-test FAILED: control Q7b — the mutation did NOT land ($q7_before -> $q7_after); the control would have proved nothing" >&2
    fail=1
  elif check_config_identity "$tmp/q7/copy.toml" "$tmp/q7/original.toml" 2>"$tmp/q7/b.err"; then
    echo "self-test FAILED: control Q7b (one allow-invalid marker stripped from the copy) — check_config_identity did not refuse" >&2
    fail=1
  elif ! grep -q '^IDENTITY: ' "$tmp/q7/b.err"; then
    echo "self-test FAILED: control Q7b refused but not as IDENTITY — may be failing for the wrong reason:" >&2
    cat "$tmp/q7/b.err" >&2
    fail=1
  else
    echo "self-test: control Q7b (one allow-invalid marker stripped from the copy) — refused as IDENTITY, as expected"
  fi

  # Q7c — THE INSTRUMENT. A row-canonical comparison would pass this and
  # `cmp` must not: append ONE SPACE to a comment line. No row changes, so
  # anything comparing parsed rows sees two identical configs — and anchor
  # 5 says byte-identical. This is the control that pins WHICH comparison
  # is in use, not merely that some comparison exists.
  cp "$CLIENT_CLIPPY" "$tmp/q7/copy.toml"
  mutate_or_die "Q7c" "
import pathlib
p = pathlib.Path('$tmp/q7/copy.toml')
lines = p.read_text().split(chr(10))
for i, ln in enumerate(lines):
    if ln.startswith('# '):
        lines[i] = ln + ' '
        break
else:
    raise AssertionError('fixture carries no comment line to pad')
p.write_text(chr(10).join(lines))
"
  if ! cmp -s "$tmp/q7/copy.toml" "$tmp/q7/original.toml"; then
    if check_config_identity "$tmp/q7/copy.toml" "$tmp/q7/original.toml" 2>"$tmp/q7/c.err"; then
      echo "self-test FAILED: control Q7c (one trailing space on a comment line — no row changes) — check_config_identity did not refuse, so it is NOT comparing bytes" >&2
      fail=1
    elif ! grep -q '^IDENTITY: ' "$tmp/q7/c.err"; then
      echo "self-test FAILED: control Q7c refused but not as IDENTITY — this is the control that pins WHICH comparison is in use, so a refusal for any other reason proves nothing:" >&2
      cat "$tmp/q7/c.err" >&2
      fail=1
    else
      echo "self-test: control Q7c (a whitespace-only divergence that changes no row) — refused as IDENTITY, which is what pins the comparison to bytes, as expected"
    fi
  else
    echo "self-test FAILED: control Q7c — the padding mutation did not change the bytes; the control would have proved nothing" >&2
    fail=1
  fi

  # Q7d — the two refusals that are NOT cmp's, in BOTH seats: a SYMLINK
  # (cmp follows it and compares the target, which is not the file the gate
  # audited) and an ABSENT file (which must
  # never read as identical to nothing). FOUR
  # INDEPENDENT CHECKS: an elif chain could skip
  # later cases after the first failure while
  # the success line still claimed all four.
  #
  # EVERY case greps the REASON. `cmp -s present /nonexistent`
  # fails on its own, so a nonzero status alone cannot
  # establish that the absent-file guard ran. Requiring
  # the diagnostic distinguishes that guard from an
  # unrelated refusal caused by comparing a missing file.
  ln -s "$tmp/q7/original.toml" "$tmp/q7/link.toml"
  q7d_pass=0
  q7d_case() {
    local label="$1" copy="$2" original="$3" want="$4" errf="$tmp/q7/d-$1.err"
    if check_config_identity "$copy" "$original" 2>"$errf"; then
      echo "self-test FAILED: control Q7d/$label — check_config_identity ACCEPTED it; the guard term for this seat is uncontrolled or gone" >&2
      fail=1
    elif ! grep -q "$want" "$errf"; then
      echo "self-test FAILED: control Q7d/$label — refused, but not as $want, so it may be refusing for an unrelated reason (cmp alone refuses a missing file, which is exactly how this control goes vacuous):" >&2
      cat "$errf" >&2
      fail=1
    else
      q7d_pass=$((q7d_pass + 1))
    fi
  }
  q7d_case "symlink-in-copy"     "$tmp/q7/link.toml"           "$tmp/q7/original.toml"        SYMLINK
  q7d_case "symlink-in-original" "$tmp/q7/original.toml"       "$tmp/q7/link.toml"            SYMLINK
  q7d_case "absent-in-copy"      "$tmp/q7/does-not-exist.toml" "$tmp/q7/original.toml"        MISSING
  q7d_case "absent-in-original"  "$tmp/q7/original.toml"       "$tmp/q7/does-not-exist.toml"  MISSING
  if [[ "$q7d_pass" -eq 4 ]]; then
    echo "self-test: control Q7d (a symlink and an absent file, in BOTH seats — 4/4) — each refused, and each for its own stated reason, as expected"
  else
    echo "self-test FAILED: control Q7d — only $q7d_pass of 4 cases behaved; the other(s) are reported above" >&2
    fail=1
  fi

  # Q7e — the DEGENERATE identity call must be refused, not accepted.
  # `cmp -s X X` exits 0, so passing the same file in both argument seats
  # would report the two configs' byte-identity premise verified having
  # compared a file to itself. check_closure_premise refuses the same
  # shape and has Q8e for it. This control must fail if the identity
  # function's same-file guard is removed; ordinary equal-file fixtures
  # alone cannot establish that the two arguments identify distinct files.
  q7e_rc=0
  q7e_out="$(check_config_identity "$tmp/q7/original.toml" "$tmp/q7/original.toml" 2>&1)" || q7e_rc=$?
  if [[ "$q7e_rc" -eq 0 ]]; then
    echo "self-test FAILED: control Q7e (the same path in both seats) — check_config_identity ACCEPTED it; a file is identical to itself and this must not read as the premise verified" >&2
    fail=1
  elif ! grep -q '^IDENTITY: ' <<<"$q7e_out"; then
    echo "self-test FAILED: control Q7e refused but not as IDENTITY — may be failing for the wrong reason:" >&2
    echo "$q7e_out" >&2
    fail=1
  else
    echo "self-test: control Q7e (the same path in both seats) — refused as IDENTITY, never as the premise verified, as expected"
  fi

  # Q7f — the SAME FILE under two DIFFERENT PATHS. Q7e passes the same
  # STRING twice, so it is satisfied by the string comparison alone and
  # cannot see `-ef` deleted: MEASURED, dropping `-ef` left the whole
  # battery green. A hard link is the cleanest plant — neither path is a
  # symlink, so the symlink guard passes through, and `cmp` on two links to
  # one inode compares a file to itself and exits 0. `./x` vs `x` and
  # `a/../a/x` are the same class.
  ln "$tmp/q7/original.toml" "$tmp/q7/hard.toml"
  q7f_rc=0
  q7f_out="$(check_config_identity "$tmp/q7/hard.toml" "$tmp/q7/original.toml" 2>&1)" || q7f_rc=$?
  if [[ "$q7f_rc" -eq 0 ]]; then
    echo "self-test FAILED: control Q7f (a HARD LINK to the original — two paths, one inode) — check_config_identity ACCEPTED it; cmp compared a file to itself and the -ef guard is gone" >&2
    fail=1
  elif ! grep -q 'same file in both seats' <<<"$q7f_out"; then
    echo "self-test FAILED: control Q7f refused but not as the same-file case — may be failing for the wrong reason:" >&2
    echo "$q7f_out" >&2
    fail=1
  else
    echo "self-test: control Q7f (a hard link — two paths naming one inode) — refused as the same file, as expected"
  fi

  # ---- controls Q8a-Q8i (EIGHT; they run a, b, e, c, d, f, h, i): check_closure_premise
  # CAN FAIL, and its
  # DIRECTION is pinned. `granary-core` is Q6's own crate and reaches
  # neither tokio nor rand, so putting it in the INHERITOR seat must refuse
  # and must NAME a package it cannot reach. A `comm -13` transposition
  # would make this pass, which is exactly what the direction assertion
  # below catches.
  q8a_rc=0
  check_closure_premise granary-core "$CLIENT_RESOLUTION_CRATE" 2>"$tmp/q8a.err" || q8a_rc=$?
  if [[ "$q8a_rc" -eq 0 ]]; then
    echo "self-test FAILED: control Q8a (granary-core in the inheritor seat) — check_closure_premise did not refuse" >&2
    fail=1
  elif [[ "$q8a_rc" -ne 1 ]]; then
    echo "self-test FAILED: control Q8a refused with exit $q8a_rc, not 1 — that is a HARNESS refusal (a cargo/registry problem), NOT the SUPERSET verdict this control exists to prove:" >&2
    cat "$tmp/q8a.err" >&2
    fail=1
  elif ! grep -q '^PREMISE: granary-core' "$tmp/q8a.err" || ! grep -qE '^  tokio v' "$tmp/q8a.err"; then
    echo "self-test FAILED: control Q8a refused but did not name tokio as source-only — may be failing for the wrong reason (a transposed comm would refuse for the other direction's reason):" >&2
    cat "$tmp/q8a.err" >&2
    fail=1
  else
    echo "self-test: control Q8a (a crate reaching none of the client's deps, in the inheritor seat) — refused as PREMISE/source-only naming tokio, as expected"
  fi

  # Q8b — the POSITIVE half. A crate must contain ITSELF, so this is the
  # one superset assertion available while granary-cli does not exist. It
  # is what proves a refusal is not unconditional.
  # The inheritor-only side here is NOT empty — granary-client reaches
  # everything granary-core does PLUS its own dependency tree — so this
  # control passes that whole set as expected. That is the point: the
  # expected list is how a legitimate extra is declared, and Q8h proves an
  # UNdeclared one is refused.
  q8b_extra=()
  while IFS= read -r q8b_l; do [[ -n "$q8b_l" ]] && q8b_extra+=("${q8b_l%% *}"); done < <(
    LC_ALL=C comm -13 \
      <(cargo tree --locked -p granary-core -e normal,build --prefix none 2>/dev/null | sed 's/ (\*)$//' | LC_ALL=C sort -u) \
      <(cargo tree --locked -p "$CLIENT_RESOLUTION_CRATE" -e normal,build --prefix none 2>/dev/null | sed 's/ (\*)$//' | LC_ALL=C sort -u))
  if ! q8b_out="$(check_closure_premise "$CLIENT_RESOLUTION_CRATE" granary-core ${q8b_extra+"${q8b_extra[@]}"} 2>&1)"; then
    echo "self-test FAILED: control Q8b ($CLIENT_RESOLUTION_CRATE over granary-core, a real non-degenerate containment) — check_closure_premise refused it:" >&2
    echo "$q8b_out" >&2
    fail=1
  elif ! grep -q '0 source-only, 0 unexpected inheritor-only' <<<"$q8b_out"; then
    echo "self-test FAILED: control Q8b passed but did not report 0 source-only — the coverage clause is not being produced:" >&2
    echo "$q8b_out" >&2
    fail=1
  else
    echo "self-test: control Q8b ($CLIENT_RESOLUTION_CRATE over granary-core, with the client's own extras declared) — accepted, reporting 0 source-only and 0 unexpected, as expected"
  fi

  # Q8e — the DEGENERATE call must be refused, not accepted. A crate
  # contains itself, so the same package in both seats reports full
  # coverage having checked nothing: one copy-pasted call site
  # (`check_closure_premise granary-cli granary-cli`) and the premise is
  # silently unverified. Q8b's positive pairs two DIFFERENT packages
  # instead, so it cannot pass by that shape.
  q8e_rc=0
  q8e_out="$(check_closure_premise "$CLIENT_RESOLUTION_CRATE" "$CLIENT_RESOLUTION_CRATE" 2>&1)" || q8e_rc=$?
  if [[ "$q8e_rc" -ne 2 ]]; then
    echo "self-test FAILED: control Q8e (the same package in both seats) — expected exit 2 (HARNESS), got $q8e_rc; a crate trivially contains itself and this must not read as coverage" >&2
    echo "$q8e_out" >&2
    fail=1
  elif ! grep -q '^HARNESS: ' <<<"$q8e_out"; then
    echo "self-test FAILED: control Q8e exited 2 but did not report HARNESS — may be failing for the wrong reason:" >&2
    echo "$q8e_out" >&2
    fail=1
  else
    echo "self-test: control Q8e (the same package in both seats) — refused as HARNESS, never as full coverage, as expected"
  fi

  # Q8c — THE HARNESS half, the Q5 shape. A `cargo tree` that cannot run
  # must exit 2 and say HARNESS, never fold into "nothing is missing".
  # Dropping the rc checks leaves Q8a still refusing on a real diff, so
  # without this control that fail-open is invisible.
  q8c_rc=0
  q8c_out="$(check_closure_premise "granary-cli-self-test-bogus-crate" "$CLIENT_RESOLUTION_CRATE" 2>&1)" || q8c_rc=$?
  if [[ "$q8c_rc" -ne 2 ]]; then
    echo "self-test FAILED: control Q8c (a package name cargo tree cannot resolve) — expected exit 2 (HARNESS), got $q8c_rc" >&2
    echo "$q8c_out" >&2
    fail=1
  elif ! grep -q '^HARNESS: ' <<<"$q8c_out"; then
    echo "self-test FAILED: control Q8c exited 2 but did not report HARNESS — may be failing for the wrong reason:" >&2
    echo "$q8c_out" >&2
    fail=1
  else
    echo "self-test: control Q8c (a package cargo tree cannot resolve) — refused as HARNESS with exit 2, never as \"nothing is missing\", as expected"
  fi

  # Q8d exercises the source crate's query
  # failure. Q8c puts the bogus crate in the
  # inheritor position and reaches a different
  # `cargo tree` call. Each call needs a
  # control requiring status 2 and the
  # HARNESS diagnostic for its own failure.
  q8d_rc=0
  q8d_out="$(check_closure_premise "$CLIENT_RESOLUTION_CRATE" "granary-cli-self-test-bogus-source" 2>&1)" || q8d_rc=$?
  if [[ "$q8d_rc" -ne 2 ]]; then
    echo "self-test FAILED: control Q8d (a bogus crate in the SOURCE seat) — expected exit 2 (HARNESS), got $q8d_rc" >&2
    echo "$q8d_out" >&2
    fail=1
  elif ! grep -q '^HARNESS: ' <<<"$q8d_out"; then
    echo "self-test FAILED: control Q8d exited 2 but did not report HARNESS — may be failing for the wrong reason:" >&2
    echo "$q8d_out" >&2
    fail=1
  else
    echo "self-test: control Q8d (a package cargo tree cannot resolve, in the SOURCE seat) — refused as HARNESS with exit 2, as expected"
  fi

  # Q8f — the `comm` refusal branch. Mutating `|| comm_rc=$?` to
  # `|| comm_rc=0` must make this control fail. A real `comm` failure cannot be
  # provoked from outside, so the control SHADOWS
  # `comm` with a failing shell function for the duration of one call — a
  # function takes precedence over the PATH lookup — and restores it after.
  # The shadow is VERIFIED to be in effect before the result is trusted.
  comm() { return 3; }
  if [[ "$(comm -23 /dev/null /dev/null 2>/dev/null; echo $?)" != "3" ]]; then
    echo "self-test FAILED: control Q8f — the comm shadow is NOT in effect, so the control would have proved nothing" >&2
    fail=1
  else
    q8f_rc=0
    q8f_out="$(check_closure_premise "$CLIENT_RESOLUTION_CRATE" granary-core 2>&1)" || q8f_rc=$?
    if [[ "$q8f_rc" -ne 2 ]]; then
      echo "self-test FAILED: control Q8f (comm forced to fail) — expected exit 2 (HARNESS), got $q8f_rc; an empty difference was read as \"nothing is missing\"" >&2
      echo "$q8f_out" >&2
      fail=1
    elif ! grep -q '^HARNESS: .*comm' <<<"$q8f_out"; then
      echo "self-test FAILED: control Q8f exited 2 but did not name comm — may be failing for the wrong reason:" >&2
      echo "$q8f_out" >&2
      fail=1
    else
      echo "self-test: control Q8f (comm forced to fail) — refused as HARNESS, never as \"0 source-only\", as expected"
    fi
  fi

  unset -f comm
  # The shadow must be GONE, or every later control silently runs against it.
  if [[ "$(comm -23 /dev/null /dev/null >/dev/null 2>&1; echo $?)" == "3" ]]; then
    echo "self-test FAILED: control Q8f — the comm shadow survived \`unset -f\`; later controls would run against it" >&2
    fail=1
  fi

  # Q8h checks the RE-ARM containment direction.
  # The client reaches packages absent from
  # granary-core; without an expected-extra
  # list those inheritor-only packages must
  # cause refusal. This fixture observes the
  # `comm -13` comparison separately from
  # the checks of the opposite containment.
  q8h_rc=0
  q8h_out="$(check_closure_premise "$CLIENT_RESOLUTION_CRATE" granary-core 2>&1)" || q8h_rc=$?
  if [[ "$q8h_rc" -eq 0 ]]; then
    echo "self-test FAILED: control Q8h (inheritor-only packages, none declared) — check_closure_premise did not refuse; the RE-ARM half of the premise is unchecked" >&2
    fail=1
  elif [[ "$q8h_rc" -ne 1 ]]; then
    echo "self-test FAILED: control Q8h refused with exit $q8h_rc, not 1 — that is a HARNESS refusal, not the PREMISE verdict this control exists to prove:" >&2
    echo "$q8h_out" >&2
    fail=1
  elif ! grep -q 'RE-ARM half' <<<"$q8h_out"; then
    echo "self-test FAILED: control Q8h refused, but not for the inheritor-only direction — it may be failing for the source-only reason instead:" >&2
    echo "$q8h_out" >&2
    fail=1
  else
    echo "self-test: control Q8h (undeclared inheritor-only packages) — refused as PREMISE/RE-ARM, as expected"
  fi

  # Q8i — THE PREFIX TRAP, INSIDE THE EXPECTED LIST. `granary-cli` is a
  # proper string prefix of `granary-client`, so a SUBSTRING membership
  # test would silently absorb the client as if it were the cli — and the
  # mis-acceptance runs in ONE DIRECTION ONLY, so the plant has to be that
  # direction. MEASURED: with an exact test this refuses; with `== *"$e"*`
  # the whole battery stayed green, so nothing else covers it.
  #
  # The expected list is the REAL inheritor-only set with `granary-client`
  # swapped for `granary-cli`. Every other package is declared, so the ONLY
  # thing that can make this pass is the substring mis-match — which is
  # what makes it discriminating rather than merely red.
  q8i_expected=()
  while IFS= read -r q8i_l; do
    [[ -n "$q8i_l" ]] || continue
    q8i_n="${q8i_l%% *}"
    [[ "$q8i_n" == "granary-client" ]] && q8i_n="granary-cli"
    q8i_expected+=("$q8i_n")
  done < <(
    LC_ALL=C comm -13 \
      <(cargo tree --locked -p granary-core -e normal,build --prefix none 2>/dev/null | sed 's/ (\*)$//' | LC_ALL=C sort -u) \
      <(cargo tree --locked -p "$CLIENT_RESOLUTION_CRATE" -e normal,build --prefix none 2>/dev/null | sed 's/ (\*)$//' | LC_ALL=C sort -u))
  if [[ "${#q8i_expected[@]}" -eq 0 ]]; then
    echo "self-test FAILED: control Q8i — could not build its expected list, so it would have asserted over nothing" >&2
    fail=1
  else
    q8i_rc=0
    q8i_out="$(check_closure_premise "$CLIENT_RESOLUTION_CRATE" granary-core "${q8i_expected[@]}" 2>&1)" || q8i_rc=$?
    if [[ "$q8i_rc" -eq 0 ]]; then
      echo "self-test FAILED: control Q8i (granary-client declared only as 'granary-cli') — check_closure_premise ACCEPTED it, so its expected-list membership is a SUBSTRING test and granary-client is being absorbed as granary-cli" >&2
      fail=1
    elif ! grep -qE '^  granary-client v' <<<"$q8i_out"; then
      echo "self-test FAILED: control Q8i refused but did not name granary-client as the unexpected package — may be failing for the wrong reason:" >&2
      echo "$q8i_out" >&2
      fail=1
    else
      echo "self-test: control Q8i (the prefix trap: granary-client declared only as granary-cli) — refused naming granary-client, so the membership test is exact, as expected"
    fi
  fi

  # THE FAIL GATE belongs after every control and
  # immediately before the success message. A control
  # placed after this gate could set `fail=1` without
  # affecting the exit code; removing the gate would
  # likewise let printed failures end in success. Check
  # the accumulated result only after the whole battery,
  # then print success only on the zero-failure path.
  #
  # If you move, delete or re-anchor anything in this region, re-run one
  # mutation afterwards and assert the EXIT CODE, not the output: a printed
  # "self-test FAILED" line with rc 0 is exactly what this shape produces.
  if [[ "$fail" -ne 0 ]]; then
    echo "fsguard-sites self-test: at least one control did not behave as expected" >&2
    exit 2
  fi
  echo "fsguard-sites self-test: all controls behaved as expected — the gate can fail"
  exit 0
fi

# ------------------------------------------------------------------- the gate
if ! out="$(check_config "$ROOT_CLIPPY" "$CLIENT_CLIPPY" 2>&1)"; then
  echo "fsguard-sites: $CLIENT_CLIPPY failed the whole-config/fs-row check:" >&2
  echo "$out" >&2
  exit 1
fi

# Anchored rows apply nothing on their own. The level the crate's own
# manifest gives the lint, and any rustflag or environment key in a
# checked-in cargo config that overrides it, are what decide whether the
# rows above are errors or decoration — so check 5 reads both.
#
# ONE PASS PER ROW of PRIMARY_LINT_MANIFESTS — `"${arr[@]}"`, never
# `"${arr[0]}"`. The table has two rows from birth, so a truncation to row
# zero drops `granary-cli` from PRIMARY-LINTS-READ; control P5b proves it
# on a COPIED gate carrying a third, injected row, because a table that
# ever falls back to one row would make a real-gate control vacuous again.
if [[ "${#PRIMARY_LINT_MANIFESTS[@]}" -eq 0 ]]; then
  echo "fsguard-sites: the primary lint-manifest table is EMPTY — refused rather than reporting a clean lint-level audit over no manifests at all." >&2
  exit 2
fi
primary_read=()
configs_read=""
configs_read_from=""
for primary_manifest in "${PRIMARY_LINT_MANIFESTS[@]}"; do
  [[ -f "$primary_manifest" ]] || { echo "fsguard-sites: $primary_manifest is missing — the audited primary lint-manifest set no longer describes the tree" >&2; exit 1; }
  if ! out="$(check_lint_level primary "$primary_manifest" "${CARGO_CONFIG_ARGS[@]}" 2>&1)"; then
    echo "fsguard-sites: $primary_manifest / ${CARGO_CONFIG_ARGS[*]} failed the lint-level check:" >&2
    echo "$out" >&2
    exit 1
  fi
  # From the CHECK's own output, never from the loop variable: the name
  # is evidence that check_lint_level ran on this manifest. Same
  # discipline, same sentence, as the fuzz loop below.
  primary_validated="$(grep -m1 '^MANIFEST-VALIDATED: ' <<<"$out" | sed 's/^MANIFEST-VALIDATED: //')"
  if [[ "$primary_validated" != "$primary_manifest" ]]; then
    echo "fsguard-sites: the lint-level check did not report validating $primary_manifest (said '${primary_validated:-<nothing>}') — refused, never treated as checked" >&2
    exit 2
  fi
  primary_read+=("$primary_validated")
  # CONFIGS-READ IS ASSERTED TO AGREE, NOT OVERWRITTEN. Every row is
  # handed the SAME $CARGO_CONFIG_ARGS, so every row must report the same
  # set. Letting the last row simply win would leave the summary's clause
  # describing one row's answer while reading as the check's — and the
  # day the two disagree is the day something is passing a different set,
  # which is a finding rather than a formatting question.
  this_configs_read="$(grep -m1 '^CONFIGS-READ: ' <<<"$out" || true)"
  if [[ -z "$configs_read_from" ]]; then
    configs_read="$this_configs_read"
    configs_read_from="$primary_validated"
  elif [[ "$this_configs_read" != "$configs_read" ]]; then
    echo "fsguard-sites: the lint-level check reported different cargo configs for $configs_read_from ('${configs_read:-<nothing>}') and $primary_validated ('${this_configs_read:-<nothing>}') — refused; they are handed the same set and cannot legitimately disagree." >&2
    exit 2
  fi
done
primary_lints_read="PRIMARY-LINTS-READ: $(IFS=', '; echo "${primary_read[*]}")"

# The same level question for the four fuzz workspaces CI clippys by
# manifest path. `secondary`: absence of a [lints] table is the
# sanctioned state there (clippy's default warn plus the lanes'
# CARGO_BUILD_WARNINGS=deny is what makes the ban bite), so only a table
# that WEAKENS it is refused.
# The manifests actually read are NAMED in the summary line, and control
# P5 asserts all four appear there. Without that, deleting this loop
# leaves every P control green — they call check_lint_level directly, so
# they prove the CHECK works and say nothing about whether the gate runs
# it.
fuzz_lint_args=()
fuzz_read=()
for fuzz_manifest in "${FUZZ_MANIFESTS[@]}"; do
  [[ -f "$fuzz_manifest" ]] || { echo "fsguard-sites: $fuzz_manifest is missing — the audited fuzz workspace set no longer describes the tree" >&2; exit 1; }
  # A `read` loop, not `mapfile`: mapfile is bash 4, and the bash a
  # stock macOS resolves through /usr/bin/env is 3.2.
  fuzz_lint_args=()
  while IFS= read -r fuzz_lint_arg; do
    fuzz_lint_args+=("$fuzz_lint_arg")
  done < <(fuzz_config_args "$fuzz_manifest")
  if ! out="$(check_lint_level secondary "$fuzz_manifest" ${fuzz_lint_args[@]+"${fuzz_lint_args[@]}"} 2>&1)"; then
    echo "fsguard-sites: $fuzz_manifest failed the lint-level check:" >&2
    echo "$out" >&2
    exit 1
  fi
  # From the CHECK's own output, never from the loop variable: the name
  # is evidence that check_lint_level ran on this manifest.
  fuzz_validated="$(grep -m1 '^MANIFEST-VALIDATED: ' <<<"$out" | sed 's/^MANIFEST-VALIDATED: //')"
  if [[ "$fuzz_validated" != "$fuzz_manifest" ]]; then
    echo "fsguard-sites: the lint-level check did not report validating $fuzz_manifest (said '${fuzz_validated:-<nothing>}') — refused, never treated as checked" >&2
    exit 2
  fi
  fuzz_read+=("$fuzz_validated")
done
fuzz_lints_read="FUZZ-LINTS-READ: $(IFS=', '; echo "${fuzz_read[*]}")"

# And which config files exist at all is part of the same question: a
# nested cargo config or a nested clippy.toml changes the answer for
# anyone whose cwd or manifest sits under it.
# Status 2 is "the walk could not run" and status 1 is "the walk found
# something" — the same split check 6 makes, and the reason
# check_stray_configs returns them separately.
stray_rc=0
check_stray_configs "." || stray_rc=$?
if [[ "$stray_rc" -eq 2 ]]; then
  echo "fsguard-sites: config discovery could not walk the tree (see above) — refused, never treated as clean" >&2
  exit 2
elif [[ "$stray_rc" -ne 0 ]]; then
  echo "fsguard-sites: config discovery refused the tree (see above)" >&2
  exit 1
fi

# The kill switch runs over the WHOLE crate directory (src/, tests/,
# fuzz/, and anything added later), because that is the scope the nested
# clippy.toml governs.
# ONE PASS PER ROW of LICENSED_SITE_CRATES. `"${arr[@]}"`, not `"${arr[0]}"`
# — and while the table has one row those are the same call, which is why
# the proof that this iterates lives in control D13d, which runs a COPIED
# gate carrying an injected second row. D13a-D13c call check_licensed_sites
# DIRECTLY and prove the FUNCTION; none of them can see this loop at all,
# and citing one of them here would send a maintainer to a control that
# stays green under the truncation.
_ls_all_rc=0
# `${#arr[@]}` FIRST, the shape check-unsafe-sites.sh uses at its own
# table and for the same reason: on a shell where `"${arr[@]}"` under
# nounset is an unbound-variable error, an empty table would die with
# status 1 and no diagnostic instead of reaching the named refusal inside
# the function. Both venues refuse, and both say why.
if [[ "${#LICENSED_SITE_CRATES[@]}" -eq 0 ]]; then
  echo "fsguard-sites: LICENSED_SITE_CRATES is EMPTY — refused rather than reporting a clean licensed-site audit over no crates at all." >&2
  exit 2
fi
_ls_all="$(check_all_licensed_sites "${LICENSED_SITE_CRATES[@]}")" || _ls_all_rc=$?
[[ "$_ls_all_rc" -eq 0 ]] || exit "$_ls_all_rc"
licensed_counts="${_ls_all%%|*}"
reach_line="${_ls_all#*|}"

# Check 6 — the SOURCE CLOSURE. Everything above reads the files this
# gate walks; these are the constructions that make rustc read others.
# Whole-crate scope, the same scope the kill switch uses.
CLOSURE_AUDIT_LOG="$(mktemp)" || exit 2
trap 'rm -f "$CLOSURE_AUDIT_LOG"' EXIT
if ! closure_hits="$(collect_audited_closures "${AUDITED_CLOSURE_CRATES[@]}")"; then
  exit 2
fi
CLOSURE_AUDITED_DIRS="$(paste -sd, - < "$CLOSURE_AUDIT_LOG")"
if ! report_source_closure "$closure_hits"; then
  exit 1
fi

# ---- check 9's TWO PREMISES run before
# check 8 invokes the compiler. The
# inheritance verdict follows check 8 because
# it depends on the client's resolution
# verdict. Checking these premises first
# also lets an absent-config refusal happen
# before another full gate run temporarily
# edits the real configuration files.
#
# The identity check is UNCONDITIONAL. The
# cli config must exist and match the client
# config: skipping the check when it is
# absent would let clippy inherit the root
# config, whose rows do not provide the
# filesystem ban. `check_config_identity`
# distinguishes a missing file with a
# harness refusal. There is no absent-config
# success arm, so removal of the config
# cannot silently disable both its ban
# and the gate meant to verify it.
cli_ident_rc=0
cli_ident_out="$(check_config_identity "$CLI_CLIPPY" "$CLIENT_CLIPPY" 2>&1)" || cli_ident_rc=$?
if [[ "$cli_ident_rc" -ne 0 ]]; then
  echo "fsguard-sites: $CLI_CLIPPY failed the byte-identity check:" >&2
  echo "$cli_ident_out" >&2
  exit "$cli_ident_rc"
fi
cli_prem_rc=0
cli_prem_out="$(check_closure_premise "$CLI_RESOLUTION_CRATE" "$CLIENT_RESOLUTION_CRATE" "${CLI_ONLY_PACKAGES_EXPECTED[@]}" 2>&1)" || cli_prem_rc=$?
if [[ "$cli_prem_rc" -ne 0 ]]; then
  echo "fsguard-sites: the INHERITED-resolution premise for $CLI_CLIPPY failed:" >&2
  echo "$cli_prem_out" >&2
  exit "$cli_prem_rc"
fi

# Check 8 — RESOLUTION, on both configs against a real `cargo clippy`.
# Real compiler invocations, so this runs last: every check above is
# static-analysis-cheap and should refuse before this gate pays for one.
# Each call's COVERAGE line (evaluated rows out
# of considered rows) is captured here on success:
# a verdict without coverage cannot be distinguished
# from a check that evaluated zero rows.
client_res_out=""
if ! client_res_out="$(check_resolution "$CLIENT_CLIPPY" "$CLIENT_RESOLUTION_CRATE" "$ROOT_CLIPPY" 2>&1)"; then
  echo "fsguard-sites: $CLIENT_CLIPPY failed the resolution check:" >&2
  echo "$client_res_out" >&2
  exit 1
fi
root_res_out=""
if ! root_res_out="$(check_resolution "$ROOT_CLIPPY" "$ROOT_RESOLUTION_CRATE" "" "$ROOT_RESOLUTION_CRATE_SECONDARY" 2>&1)"; then
  echo "fsguard-sites: $ROOT_CLIPPY failed the resolution check:" >&2
  echo "$root_res_out" >&2
  exit 1
fi

# ---- check 9: the cli config's INHERITED VERDICT -------------------------
# The two premises ran above, before check 8 paid for a compiler; what is
# left here is the VERDICT they license, and it is printed AFTER check 8
# because the inheritance is inherited FROM the client's resolution
# verdict. Stating it before check 8 could refuse would assert an
# inheritance of something not yet established.
#
# The identity check's OWN success line is carried through rather than
# discarded, so this verdict states its coverage instead of asserting it.
#
# >>> WHY `CLIENT_CLIPPY` IS NOT A PER-CRATE TABLE. <<<
# The cli's config must satisfy the same SUPERSET CHECK as the client's;
# allow-listing its path is insufficient. Byte identity establishes that
# transitively and imposes a stronger comparison. `check_config`'s verdict is a
# function of the two files' bytes and of this script's own FS_ROWS /
# FS_ROW_REASON constants; nothing in it is selected by WHICH crate path
# it was handed. So a file byte-identical to one that passed it passes it
# too, and identity additionally refuses the comment-and-whitespace
# divergence a re-run of check_config would wave through. A second
# check_config row would be implied by this check while identity stands,
# and weaker than it if identity were ever dropped.
#
# The divergence that will one day force this open — a bin-only crate
# wanting a row the library must not have — is refused by check_config
# itself (an extra key, an extra row), so it is check_config's CONTRACT
# that such a day edits, and THAT is where a table earns its rows, with
# the divergence as its driver and its own still-can-fail control.
echo "INHERITED: $CLI_CLIPPY carries $CLIENT_CLIPPY's resolution verdict. $cli_ident_out; $cli_prem_out"
client_res_coverage="$(grep '^COVERAGE ' <<<"$client_res_out")"
root_res_coverage="$(grep '^COVERAGE ' <<<"$root_res_out")"
res_advisories="$(grep '^ADVISORY ' <<<"$client_res_out"$'\n'"$root_res_out" || true)"

echo "fsguard-sites: $CLIENT_CLIPPY is a verified superset of $ROOT_CLIPPY with exactly the audited fs rows, and $CLI_CLIPPY carries that verdict by byte-identity ($cli_ident_out); $licensed_counts; no bare #[allow], no group-wide #[expect] and ${reach_line:-LICENCE-REACH: (never run)}; no macro_rules!, #[path], include under any name or symlinked source, and the audited dependency and target-path sets; CLOSURE-AUDITED: ${CLOSURE_AUDITED_DIRS:-(none)}; no stray cargo/clippy config; ${primary_lints_read:-PRIMARY-LINTS-READ: (never run)}; ${configs_read:-CONFIGS-READ: (none)}; ${fuzz_lints_read:-FUZZ-LINTS-READ: (none)}; RESOLUTION: ok — ${client_res_coverage}; ${root_res_coverage}${res_advisories:+; $res_advisories}"
