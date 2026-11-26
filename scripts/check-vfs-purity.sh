#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# The source-axis rule: `crates/granary-vfs`'s `#![cfg_attr(not(test), no_std)]`
# is the crate's WHOLE enforcement of "the engine's own production source
# cannot introduce a direct dependency on the std crate" — and the
# attribute's own deletion is unguarded. The compiler enforces the
# attribute; this gate enforces that the attribute (and the two other
# preconditions its guarantee rests on) are actually THERE, in the exact
# shape that guarantee needs. The compiler and this gate are ONE mechanism,
# not two independent opinions.
#
# THREE ITEMS, each with its own planted red in `--self-test`:
#
#   1. An ACTIVE crate-level inner attribute, structurally
#      `#![cfg_attr(not(test), no_std)]` — parsed on comment/string-stripped
#      text (scripts/vfs-purity-scan.py, reusing scripts/fsguard-scan.py's
#      stripper and block-depth machinery rather than a third lexer), never
#      as a literal grep: a literal match is satisfied by the same text in
#      a comment, a string, or a decoy. The PREDICATE is asserted exactly —
#      `not(any(test, feature = "x"))` would hand a feature build `std` and
#      is refused, not accepted as "close enough".
#   2. No `extern crate std` item survives macro expansion of the crate's
#      NON-TEST `--lib` build. Structural source scanning cannot see this:
#      a `macro_rules!` arm can assemble the item from a token the
#      INVOCATION supplies (`macro_rules! escape { ($c:ident) => { extern
#      crate $c as host; }; } escape!(std);` — the literal text
#      "extern crate std" never appears anywhere in that source), and only
#      rustc's own expansion renders what the macro actually produces.
#      Instrument (EXECUTED on this repo's pinned 1.97.1 stable toolchain,
#      `crates/granary-vfs` at the tracked HEAD):
#
#          RUSTC_BOOTSTRAP=granary_vfs CARGO_TARGET_DIR=<scratch> \
#            cargo rustc -p granary-vfs --lib --locked -- -Zunpretty=expanded
#
#      **RUSTC_BOOTSTRAP=granary_vfs, not =1** — the CRATE-scoped bootstrap
#      form, which `-Z`-gates ONLY the build of the crate named. Measured:
#      the scoped form exits 0; the same command with NO bootstrap exits 1
#      (`error: the option 'Z' is only accepted on the nightly compiler`);
#      an intentionally WRONG scope name (`RUSTC_BOOTSTRAP=some_other_name`)
#      also exits 1 — proving the scoping is real, not decorative.
#
#      **Expands the NON-TEST `--lib` ONLY.** `cargo rustc -p granary-vfs
#      --lib --profile test -- -Zunpretty=expanded` was ALSO executed, and
#      its output carries the compiler's OWN injected `extern crate std;`
#      near the top of the file (rustc's test harness always links std) —
#      expanding that build is a GUARANTEED false red. The non-test
#      expansion carries only `extern crate core;` / `extern crate alloc;`,
#      which is the green control.
#
#      **THE MATCH IS `^[ \t]*extern crate std\b`, NOT anchored to column
#      0** — file-based production modules are rendered indented:
#      `-Zunpretty=expanded` renders every
#      FILE-BASED module's body (the crate's production modules —
#      `snapshot.rs`, `read.rs`, `attr.rs`, `inode.rs`, `handle.rs`,
#      `listing.rs`, `source.rs`) indented one level inside a
#      `mod name { ... }` block. That list is the crate's PRODUCTION
#      source, not its whole `src/` tree: since the crate's own tests live
#      in separate files rather than inline, the tree also holds nine
#      `#[cfg(test)]` files, which this item deliberately never sees
#      because it expands the NON-test lib. Read item 3's own scanned-file
#      count for the tree total. An
#      escape planted in ANY of those files — which is every realistic
#      production location — appears as `    extern crate std as
#      whatever;`, not at column 0. An anchor requiring column 0 would
#      silently pass an escape planted anywhere a real one would actually
#      live. Verified directly: a macro-assembled escape placed in a
#      `mod`-declared file renders indented; `^extern crate std\b` (column
#      0) misses it, `^[ \t]*extern crate std\b` (any leading whitespace)
#      catches it, and neither form matches the clean crate's own
#      expansion.
#
#      **Why the bootstrap variable is permissible here, said in these
#      words because two families read `check-fsguard-sites.sh` and agreed
#      the quote should travel with this gate:** that script's own header
#      says
#
#        "RUSTC_BOOTSTRAP is the last of them, and the one that makes -Z
#        reachable at all: a stable toolchain refuses unstable options,
#        and RUSTC_BOOTSTRAP=1 turns them on. A checked-in value for it is
#        the other half of the -Z refusal above"
#
#      and its refusal names a FILE: `env.{raw_key} is set to {value!r} in
#      {cargo_config_path}`. That scanner's subject is `.cargo/config.toml`
#      / `.cargo/config`, TOML-loaded — a variable exported for ONE
#      invocation, by this gate, never enters that file and never reaches
#      that scanner's subject. This gate writes RUSTC_BOOTSTRAP into no
#      checked-in file, ever.
#
#      A raw-source lexer stays useful as a fast diagnostic (item 3, below,
#      already runs one for a related question) but is not authoritative
#      here — there is no lint-level substitute (`clippy-driver -W help`
#      has nothing that forbids a USED `extern crate std`) and no
#      stable-only instrument answers the same question short of
#      expansion (`--emit=metadata`, rlibs, `cargo tree`, `rustc --print`
#      all expose artifacts or edges, never expanded items).
#
#   3. No `#[path]` and no `include!` (under any spelling — aliased,
#      renamed, qualified) anywhere in the crate's source. This is the
#      closure premise items 1 and 2 both rest on: a `#[path = "../x.rs"]`
#      or an `include!("../x.rs")` makes rustc compile source this gate,
#      and item 2's own `find`-driven expansion, never walked or read at
#      all. DELIBERATELY NARROWER than `scripts/check-fsguard-sites.sh`'s
#      own `--source-closure` mode, which ALSO refuses every
#      `macro_rules!` definition on sight — copying that wholesale would
#      contradict item 2's own required control, "a macro that EMITS the
#      escape, BESIDE a legitimate macro that must stay green": if item 3
#      banned macro_rules! outright, the legitimate macro in item 2's own
#      fixture would itself be a finding. `scripts/vfs-purity-scan.py
#      --closure` calls the SAME underlying function
#      (`fsguard_scan.scan_source_inputs` — no re-derived regex) and
#      filters its `macro_rules!` findings out before printing.
#
#      Two premises, kept separate here:
#      the ABSENCE of `include_str!`/`include_bytes!` self-readers answers
#      the self-reader condition (a reader whose subject leaves the file
#      must be re-rooted to the child and have its own positive control
#      re-run in that same commit, and a self-reader with no positive
#      control must not be split past); it says nothing about item 3, which
#      bans including
#      EXECUTABLE Rust. Both happen to hold at this crate's HEAD
#      (`grep -c` for either is 0), but they are two different facts, and
#      this gate asserts only the second.
#
# PLUS an END-TO-END CONTROL, in `--self-test` only, that the attribute
# BITES rather than merely being spelled correctly: a scratch copy with
# `std::fs::read` planted in a production fn fails `cargo check` with
# E0433 while the attribute is active, and the IDENTICAL source compiles
# at rc=0 once the attribute is removed — the unguarded case this whole
# gate exists for.
#
# COVERAGE, NARROWED IN WRITING (the source-axis rule's own demand: which
# configurations are expanded is part of the guarantee, not an implementation
# detail, so this gate either expands every supported target and feature
# configuration or names the narrowing in writing — and a narrowing left
# unstated is indistinguishable from a gate that thinks it covers more
# than it does):
#
#   FEATURE DIMENSION — item 2 runs TWICE: once against the crate's default
#   feature set, once against `--all-features`. There is no standing ban on
#   `granary-vfs` declaring a feature. The source-axis rule names the
#   `not(test)` attribute, no post-expansion `extern crate std`, and no
#   `#[path]`/`include!`; it does not prohibit features. The two runs
#   currently expand the identical configuration because the crate declares
#   no features. This covers the default set and `--all-features`, and
#   nothing else. A feature-gated escape in a
#   configuration NOBODY expands (a named feature deliberately excluded
#   from both the default set and turned off by a `default = []` some
#   other feature still gates around) is not detected by this gate. The
#   self-test's `item2-feature-escape` control plants exactly that shape
#   — `#[cfg(feature = "extra")] extern crate std as ...;` — and proves
#   it is an EXPECTED SURVIVOR under default features (cfg selection
#   drops it before expansion ever sees it) and a KILL under
#   `--all-features` (which turns the feature on).
#
#   TARGET DIMENSION — NOT one, and this gate does not close it. It runs
#   wherever it is invoked: locally, whatever the host triple is; in CI,
#   only inside ci.yml's `gates` job, on a full x86_64-unknown-linux-gnu
#   runner. Expansion happens AFTER `cfg`
#   selection, so an item gated on a target this run is not building for
#   is simply ABSENT from the output. The musl build in lint does not run
#   this gate, and aarch64 Linux and Windows are outside its coverage too.
#   Each target needs its own invocation for this gate to cover it.
#
#   THE SOURCE-AXIS RULE'S OWN REQUESTED `cfg(windows)` PLANTED RED IS THE
#   DEMONSTRATION OF THAT NARROWING, not a fourth item: `--self-test`
#   plants `#[cfg(windows)] extern crate std as ...;` in a scratch copy
#   and expands it on THIS run's host target. It is not detected — cfg
#   selection already dropped the item before expansion ever saw it — and
#   the self-test reports that outcome as a SURVIVOR, explicitly, not as
#   a passing control. A survivor logged as a pass is the exact fail-open
#   this gate exists against. It becomes a KILL only once a Windows-target
#   expansion lane exists; until then it stays a survivor by design, and
#   every run says so.
#
# WHICH COMMANDS FIRE THE ATTRIBUTE'S OWN REFUSAL AND WHICH ARE BLIND TO
# IT — a fact about the ATTRIBUTE (which cfg it reads), not about this
# gate, but the two are easy to conflate and worth separating explicitly:
# `cargo check`, `cargo clippy --all-targets` and an UNSCOPED
# `cargo nextest run` (the lint, breakage and test jobs in
# `.github/workflows/ci.yml`) all build the crate under `cfg(not(test))` and so
# would themselves refuse a bare `std::` NAME with no `extern crate`
# reintroduction (ordinary `no_std` behaviour, no gate needed for that
# case). `cargo test --lib`, `nextest -p granary-vfs` and the BODY
# `cargo doc` compiles to check intra-doc links all build under
# `cfg(test)`, where `no_std` is OFF by this crate's own predicate — they
# are BLIND to a production `std::` use by design, because under test cfg
# naming `std` is legitimate. This gate's item 2 is independent of both:
# it expands the non-test build itself, on demand, rather than relying on
# any of the above having run.
#
# House gate idiom: exit 0 pass / 1 fail / 2 the check could not run —
# and an unreadable input, or an expansion that fails to run at all, is
# ALWAYS a refusal, never read as clean.
#
#   scripts/check-vfs-purity.sh              run the gate
#   scripts/check-vfs-purity.sh --self-test  prove it can fail
set -euo pipefail

# ARGUMENT VALIDATION. An argv that is not exactly
# `--self-test` must not fall through to the real gate and
# exit 0 — if it did, `check-vfs-purity.sh self-test` (dashes
# dropped) would print a GREEN verdict having run ZERO
# self-test controls, which is indistinguishable in a log from
# the self-test passing. Refused here rather than silently
# running: an unreadable INPUT is already always a refusal in
# these gates, and an unreadable INSTRUCTION must be too. This
# guard sits immediately after `set -euo pipefail`
# deliberately — before any top-level setup — so the
# diagnostic names the argument rather than whatever the setup
# fails on first.
#
# KNOWINGLY DUPLICATED across the `--self-test` gates rather than extracted
# into a shared sourced helper: most of them source nothing, and
# adding a new shared file would be riskier than keeping a tripwired
# copy. The red that
# guards it is `selftest_argv_guard` in the three vfs gates.
if [[ $# -gt 1 || ( $# -eq 1 && "${1:-}" != "--self-test" ) ]]; then
  echo "vfs-purity: unrecognised argument(s): $* — the only accepted form is '--self-test' (or no argument, to run the gate). Refused rather than silently running the gate and reporting green." >&2
  exit 2
fi

# Self-locate like every sibling gate (check-inventory-fresh.sh,
# check-licence-boundary.sh) rather than requiring the caller's cwd to be
# the repo root: the refusal this gate gives when it cannot read a path
# should be about the CRATE, not about where the invoker happened to be
# standing.
cd "$(dirname "$0")/.."

# STANDING PROTECTION: CI (ci.yml:17) sets
# CARGO_BUILD_WARNINGS=deny at the WORKFLOW env: level, which applies to
# EVERY job — including this gate's own --self-test inside the `gates`
# job (ci.yml:311). The local lane only sets that variable per-clippy-
# command, so a scratch fixture this gate compiles (every cargo
# invocation below, self-test or real run) could pass locally on an
# unexported shell and still redden CI on the first push — exactly what
# happened with the bite-absent control's zz_bite_probe (dead code, clean
# under a bare `cargo check`, but rejected because warnings are denied under CI's actual
# setting). Forcing it here, unconditionally, means this gate's local
# behaviour can never diverge from CI's regardless of the caller's shell —
# it is exported, not merely read, so it overrides any ambient value too.
export CARGO_BUILD_WARNINGS=deny

CRATE_DIR=crates/granary-vfs
CRATE_SRC="$CRATE_DIR/src"
LIB_RS="$CRATE_SRC/lib.rs"
SCAN_PY="$(pwd)/scripts/vfs-purity-scan.py"
# RUSTC_BOOTSTRAP's scoped form takes the CRATE name (`--crate-name`, i.e.
# the package name with `-` -> `_`), not the package name itself. Every
# scratch fixture below is ALSO packaged as `granary-vfs`, so this one
# value scopes both the real crate and every fixture.
VFS_CRATE_NAME=granary_vfs

# shellcheck source=vfs-scratch-fixture.sh
source "$(pwd)/scripts/vfs-scratch-fixture.sh"
vfs_ws_edition_and_rust_version

# A floor, not a pin (see item3_report's own comment on VFS_SRC_FILE_FLOOR,
# below): DERIVED from the tracked crate's own file list rather than a
# hand-maintained constant, so removing a legitimate file lowers this
# floor along with it instead of needing a matching edit here every time
# — a hand-maintained constant floor would refuse a genuine,
# intentional file removal until someone remembered to lower it
# too. `git ls-files` (not `find`) so this reads the tracked source list
# the same way every other count-shaped gate in this repo does, and a
# git failure (not a repo, git missing) is refused rather than read as
# zero files.
#
# Factored into a function and computed under `set +e` /
# an explicit rc capture, NOT a bare `VAR="$(pipeline)"` under this
# script's own `set -euo pipefail` — a bare assignment form is subject
# to errexit ITSELF: EXECUTED, `bash -c 'set -euo pipefail;
# V="$(git --no-such-flag ls-files | wc -l | tr -d " ")"; echo reached'`
# never prints "reached" and exits 129, so the diagnostic below could
# never have fired on a git failure at all — the process would already
# be dead with a bare 127/128/129 and no message, which is exactly the
# silent-as-clean failure the function form exists to refuse. Factoring
# into a function also makes this its own self-testable unit, the same
# technique check-vfs-deps.sh's selftest_arm3_empty_tree uses for a
# fake-command PATH override.
#
# Root-shape-gate duplication note: scripts/check-vfs-root-shape.sh's
# macro_export_git_floor is a near-verbatim copy of this same idiom
# (parameterized by directory instead of the hardcoded path above).
# Left duplicated rather than extracted into a shared helper: changing
# this already-shipped, separately self-tested gate while changing the
# root-shape gate was judged riskier than leaving a KNOWN, tripwired
# duplicate (check-vfs-root-shape.sh's own --self-test asserts BOTH
# copies still guard their `git ls-files` pipeline with set +e/set -e —
# the exact hazard that same round found missing from one of the two). If
# you touch the `set +e`/`rc=$?`/`set -e` shape here, mirror it there.
vfs_src_file_floor() {
  local rc floor
  set +e
  floor="$(git ls-files 'crates/granary-vfs/src/*.rs' | wc -l | tr -d ' ')"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 || -z "$floor" || "$floor" -lt 1 ]]; then
    echo "vfs-purity: could not derive the source-file floor from 'git ls-files crates/granary-vfs/src/*.rs' (exit $rc) — refused, never treated as clean" >&2
    return 2
  fi
  echo "$floor"
  return 0
}

if ! VFS_SRC_FILE_FLOOR="$(vfs_src_file_floor)"; then
  exit 2
fi

# CLEANUP TRAP: every self-test control below builds a
# scratch fixture (a copied or empty crate, a cargo target directory) in
# $TMPDIR, and several of them exit 2 or hit `set -e` partway through —
# before their own `rm -rf` runs. check-core-purity.sh's own
# `trap '…' EXIT` for a smaller version of the identical class (two temp
# files, one script). One shared registry and one trap here instead, so
# no failure path — planted or genuine — can skip cleanup: every
# `mktemp`/`mktemp -d` call in this file registers itself with
# `_vfs_purity_track` right after creation, and this trap sweeps
# whatever is still registered when the process exits, by ANY path.
_VFS_PURITY_CLEANUP=()
_vfs_purity_track() { _VFS_PURITY_CLEANUP+=("$1"); }
_vfs_purity_cleanup() {
  local d
  for d in "${_VFS_PURITY_CLEANUP[@]+"${_VFS_PURITY_CLEANUP[@]}"}"; do
    rm -rf "$d"
  done
}
trap _vfs_purity_cleanup EXIT

# VFS_PURITY_SHARED_TARGET_DIR — ONE scratch CARGO_TARGET_DIR, created ONCE
# here and reused by every item-2 expansion and every selftest_bites `cargo
# check` for the rest of this process. MEASURED: each expansion cold-builds
# granary-core's whole closure (shlex, find-msvc-tools, constant_time_eq,
# cfg-if, arrayref, arrayvec, fastcdc, cc, blake3, granary-core,
# granary-vfs) — 44 MB, 1.65s on this host — and a target dir per caller
# would pay that cost on EVERY one of item2-escape, item2-cfg-windows,
# item2-feature-escape (x2) and selftest_bites' own target dir, plus the
# real gate's two item-2 runs, each deleting its target dir immediately
# after. The isolation every caller's own comment requires is from the
# TRACKED crate's shared `target/` directory every other gate and lane uses
# — NOT from the previous scratch fixture within this same run, which is a
# different fixture at a different mktemp path every time regardless of
# which CARGO_TARGET_DIR it builds into.
#
# Created EAGERLY, at this top-level scope, rather than lazily inside a
# function memoizing a global on first call: `item2_report` and
# `selftest_bites` are invoked as `out="$(fn ...)"` — a COMMAND
# SUBSTITUTION, which runs in a SUBSHELL. A lazy getter's own
# assignment to a "memoized" global happens INSIDE that subshell and is
# discarded the instant it exits; the parent shell's variable is never
# updated, so the very next call sees it still empty and mints ANOTHER
# fresh directory — silently defeating the whole point while still
# LOOKING like sharing (same function, same variable name). EXECUTED:
# a lazy-getter version of this measured a DIFFERENT mktemp path printed
# on every one of four item-2 self-test calls, each one cold. Reading an
# already-set variable works fine from inside a subshell — only the
# WRITE was the hazard — so this is set once, here, in the main shell,
# and every caller below only ever READS it.
VFS_PURITY_SHARED_TARGET_DIR="$(mktemp -d)" || { echo "vfs-purity: mktemp failed" >&2; exit 2; }
_vfs_purity_track "${VFS_PURITY_SHARED_TARGET_DIR}"

# ------------------------------------------------------------------ item 1
item1_scan() {
  python3 "$SCAN_PY" --attr "$1"
}

# item1_report <file> — the ONE comparison the real gate and every
# self-test control below call, so a self-test that reimplements the
# comparison separately proves nothing about the gate's ACTUAL logic.
item1_report() {
  local file="$1" out rc attr_lines near_lines
  set +e
  out="$(item1_scan "$file")"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "vfs-purity: item 1 scanner failed reading $file (exit $rc) — refused, never treated as clean:" >&2
    echo "$out" >&2
    exit 2
  fi
  attr_lines="$(grep '^ATTR ' <<<"$out" || true)"
  near_lines="$(grep '^NEAR-MISS ' <<<"$out" || true)"
  if [[ -z "$attr_lines" ]]; then
    echo "vfs-purity: item 1 FAILED — no ACTIVE crate-level \`#![cfg_attr(not(test), no_std)]\` in $file (parsed structurally on comment/string-stripped text; a commented-out or string-quoted spelling does not count, however exact)." >&2
    if [[ -n "$near_lines" ]]; then
      echo "  a cfg_attr(not(...), no_std) DOES exist, but its predicate is not exactly not(test) — the predicate is asserted exactly, and this is refused rather than accepted as equivalent:" >&2
      echo "$near_lines" | sed 's/^/  /' >&2
    fi
    return 1
  fi
  echo "vfs-purity: item 1 ok — active, exact, structural: $attr_lines"
  return 0
}

# ------------------------------------------------------------------ item 2
# item2_expand [manifest] <target-dir> [feature-mode]
# With $1 empty, runs against the TRACKED crate from the real workspace —
# sharing its Cargo.lock and dependency resolution, with only the build
# ARTIFACTS isolated in <target-dir> (a -Zunpretty build must never share
# fingerprints with the target/ directory every other gate and lane uses).
# With $1 set to a manifest path, runs against a scratch fixture instead
# (self-test only) — its own single-member workspace, so its resolution
# never touches the tracked Cargo.lock either.
#
# `feature-mode` is "default" (the crate's default
# feature set — the historic behaviour) or "all" (`--all-features`).
# These are the ONLY two configurations item 2 expands; see the header's
# FEATURE DIMENSION note on why that is a narrowing worth stating rather
# than a completeness claim.
item2_expand() {
  local manifest="${1:-}" target_dir="$2" feature_mode="${3:-default}"
  local feature_flag=()
  if [[ "$feature_mode" == "all" ]]; then
    feature_flag=(--all-features)
  fi
  if [[ -n "$manifest" ]]; then
    CARGO_TARGET_DIR="$target_dir" RUSTC_BOOTSTRAP="$VFS_CRATE_NAME" \
      cargo rustc --offline --manifest-path "$manifest" --lib "${feature_flag[@]}" -- -Zunpretty=expanded
  else
    CARGO_TARGET_DIR="$target_dir" RUSTC_BOOTSTRAP="$VFS_CRATE_NAME" \
      cargo rustc -p granary-vfs --lib --locked "${feature_flag[@]}" -- -Zunpretty=expanded
  fi
}

# The one pattern-match every caller below uses — see the header note on
# why it is NOT anchored to column 0.
EXTERN_STD_RE='^[[:space:]]*extern crate std\b'

# item2_report <manifest> [save-expansion-to] [feature-mode]
#
# THE ONE comparison the real gate and every self-test control below
# calls — item1_report's own comment above applies here too: a control
# that re-ran `grep -nE "$EXTERN_STD_RE"` on its OWN capture, instead of
# calling this function, would prove nothing about THIS function's
# actual pass/fail branch. `manifest` follows item1_report's/
# item3_report's own shape: empty runs the real tracked crate, set runs
# a scratch fixture (self-test only).
# `save-expansion-to`, when given, also saves the raw expansion text
# there — a self-test needs the RAW text for fixture-specific checks (a
# legitimate macro's own expansion rendering beside the escape) that are
# not part of this function's verdict and so do not belong inside it.
# `feature-mode` ("default" or "all") is forwarded to item2_expand; see
# its own comment.
item2_report() {
  local manifest="$1" save_expansion_to="${2:-}" feature_mode="${3:-default}" target_dir err_file out rc hits
  target_dir="$VFS_PURITY_SHARED_TARGET_DIR"
  err_file="$(mktemp)" || { echo "vfs-purity: mktemp failed" >&2; exit 2; }
  _vfs_purity_track "${err_file}"
  # STDOUT ALONE is captured for matching. cargo's OWN progress output
  # (one "Compiling …" line per fresh scratch build, since every fixture
  # gets its own target dir) goes to stderr; merging it in would make
  # every "post-EXPANSION line:text" number an offset into stdout+stderr
  # rather than into the expansion itself — measured: the self-test
  # reported an escape at a line number thousands past where the same
  # planted item lands in a real-crate mutation. Worse, a cargo
  # diagnostic that happens to quote indented source containing
  # `extern crate std` would misread as a hit that was never emitted by
  # the expansion. stderr is kept ONLY for the rc≠0 diagnostic below.
  set +e
  out="$(item2_expand "$manifest" "$target_dir" "$feature_mode" 2>"$err_file")"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "vfs-purity: item 2 ($feature_mode features) could not expand granary-vfs's non-test --lib (exit $rc) — refused, never treated as clean:" >&2
    tail -40 "$err_file" >&2
    rm -f "$err_file"
    exit 2
  fi
  rm -f "$err_file"
  if [[ -n "$save_expansion_to" ]]; then
    printf '%s\n' "$out" > "$save_expansion_to"
  fi
  hits="$(grep -nE "$EXTERN_STD_RE" <<<"$out" || true)"
  if [[ -n "$hits" ]]; then
    echo "vfs-purity: item 2 ($feature_mode features) FAILED — a bare 'extern crate std' item survives macro expansion of granary-vfs's non-test lib (post-EXPANSION line:text — not the original source, which may spell nothing at all, exactly as the escape control demonstrates):" >&2
    echo "$hits" >&2
    return 1
  fi
  # A POSITIVE control that the expansion actually rendered something —
  # the check above only asks whether a BAD line is absent, which a
  # zero-hit grep over an empty or truncated expansion would answer
  # identically to a genuinely clean crate (the pre-push battery closed the
  # same shape for its rustdoc lane, by adding a positive anchor to a check
  # that only asked whether a bad line was absent; that battery does not ship,
  # so its coordinate is not spelled here). Two anchors, not one: the
  # compiler's own `extern crate core;` (present in every non-test
  # no_std expansion, so alone it would not distinguish this crate's
  # expansion from any other no_std crate's) AND a known item from the
  # crate's OWN source (`dir_and_parent`, pinned on the curated root,
  # crates/granary-vfs/src/lib.rs).
  if ! grep -qE '^extern crate core;$' <<<"$out"; then
    echo "vfs-purity: item 2 ($feature_mode features) could not confirm the expansion actually rendered anything ('extern crate core;' absent from the output) — refused, never treated as clean" >&2
    exit 2
  fi
  if ! grep -q 'fn dir_and_parent' <<<"$out"; then
    echo "vfs-purity: item 2 ($feature_mode features) could not confirm the expansion actually rendered the crate's OWN source (a known item, dir_and_parent, absent from the output) — refused, never treated as clean" >&2
    exit 2
  fi
  echo "vfs-purity: item 2 ok — post-expansion non-test lib ($feature_mode features) carries only 'extern crate core;'/'extern crate alloc;', no 'extern crate std'"
  return 0
}

# ------------------------------------------------------------------ item 3
# A floor, not a pin: item 3 must be able to tell "scanned the crate and
# found nothing" from "scanned nothing" (`find` exits 0 on zero matches),
# because item 3 is the closure premise items 1 and 2 both rest on — the
# house idiom's "an unreadable input is always a refusal" applies just as
# much to an unreadable DIRECTORY. VFS_SRC_FILE_FLOOR itself is set,
# above, from `git ls-files` rather than pinned here as a literal — see
# that assignment's own comment for why.

item3_scan() {
  local dir="$1" list rc symlist rel
  list="$(mktemp)" || { echo "vfs-purity: mktemp failed" >&2; exit 2; }
  _vfs_purity_track "${list}"
  if ! find "$dir" -name '*.rs' -print0 > "$list"; then
    echo "vfs-purity: the .rs walk of $dir failed — refused, never treated as clean" >&2
    rm -f "$list"
    exit 2
  fi
  echo "SCANNED $(tr -cd '\0' < "$list" | wc -c | tr -d ' ')"
  python3 "$SCAN_PY" --closure < "$list"
  rc=$?
  rm -f "$list"
  if [[ "$rc" -ne 0 ]]; then
    return "$rc"
  fi

  # SYMLINKS: `find "$dir" -name '*.rs'` runs in
  # find's default -P (physical) mode, which never DESCENDS into a
  # symlinked directory at all — a module compiled from behind one is
  # invisible to the walk above, and so to item 2's own expansion, which
  # only ever compiles what this crate's source tree actually contains.
  # rustc does not share that caution: it follows the link and compiles
  # whatever is behind it. fsguard-scan.py's own header names symlinked
  # source as exactly this kind of escape, and the sibling gate
  # (check-fsguard-sites.sh's find_source_symlinks) makes the identical
  # choice for the identical reason: prefer REFUSING a symlink under the
  # crate's source over teaching this gate to follow it, which would
  # need real traversal semantics for no benefit item 3 needs. Refuses
  # BOTH shapes fsguard-scan.py's own header names: a symlinked `.rs`
  # file, and a symlinked directory anywhere under $dir.
  symlist="$(mktemp)" || { echo "vfs-purity: mktemp failed" >&2; exit 2; }
  _vfs_purity_track "${symlist}"
  if ! find "$dir" -type l -print0 > "$symlist"; then
    echo "vfs-purity: the symlink walk of $dir failed — refused, never treated as clean" >&2
    rm -f "$symlist"
    exit 2
  fi
  while IFS= read -r -d '' rel; do
    case "$rel" in
      *.rs)
        printf 'SOURCE %s: a SYMLINKED .rs file — rustc follows it into source this walk treats as a plain directory entry\n' "$rel"
        continue ;;
    esac
    if [[ -d "$rel" ]]; then
      printf 'SOURCE %s: a SYMLINKED DIRECTORY under %s — find (default -P mode) never descends it, but rustc compiles the modules behind it\n' "$rel" "$dir"
    fi
  done < "$symlist"
  rm -f "$symlist"
  return 0
}

item3_report() {
  # <dir> <floor> — the floor is a PARAMETER, not a constant baked into
  # this function, because a self-test fixture is deliberately a much
  # smaller directory than the real crate: reusing $VFS_SRC_FILE_FLOOR
  # unconditionally would refuse every self-test control on coverage
  # grounds before it ever reached the behaviour under test. The real
  # gate call below passes $VFS_SRC_FILE_FLOOR; self-test controls that
  # are not testing coverage itself pass a floor sized to their own
  # fixture.
  local dir="$1" floor="$2" out rc hits scanned
  set +e
  out="$(item3_scan "$dir")"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "vfs-purity: item 3 scanner failed scanning $dir (exit $rc) — refused, never treated as clean:" >&2
    echo "$out" >&2
    exit 2
  fi
  scanned="$(grep '^SCANNED ' <<<"$out" | sed 's/^SCANNED //')"
  if [[ -z "$scanned" || "$scanned" -lt "$floor" ]]; then
    echo "vfs-purity: item 3 FAILED — scanned only ${scanned:-0} .rs file(s) under $dir, below the floor of $floor; a scan that walked nothing must not read the same as a scan that walked the crate and found nothing (item 3 is the closure premise items 1 and 2 both rest on)" >&2
    exit 2
  fi
  hits="$(grep '^SOURCE ' <<<"$out" || true)"
  if [[ -n "$hits" ]]; then
    echo "vfs-purity: item 3 FAILED — a #[path] or include! (under any spelling) construction was found under $dir; rustc would compile source this gate (and item 2's expansion) never walked:" >&2
    echo "$hits" | sed 's/^SOURCE /  /' >&2
    return 1
  fi
  echo "vfs-purity: item 3 ok — scanned $scanned .rs file(s) under $dir, no #[path], no include! (any spelling)"
  return 0
}

# ---------------------------------------------------------- scratch fixtures
# populate_scratch_vfs <tmp-root>
# Lays out <tmp-root>/vfscopy as a COPY of the tracked crate, in its own
# single-member workspace — `cargo`'s resolution and target directory for
# it never touch the tracked Cargo.lock or target/, so every control below
# can plant, compile and discard without any inverse edit on real files.
populate_scratch_vfs() {
  local root="$1"
  mkdir -p "$root/vfscopy/src"
  cp -R "$CRATE_SRC"/. "$root/vfscopy/src/"
  vfs_write_scratch_manifests "$root"
}

replace_once_or_die() {
  # replace_once_or_die <file> <needle> <replacement>
  #
  # Matches <needle> only as a WHOLE LINE (its own line, start to end),
  # never as a substring — the crate root's doc now quotes this
  # same attribute's exact text in prose, inside a `//!` paragraph, which
  # a plain `str.count` would count as a second occurrence and refuse on.
  # The genuine, ACTIVE attribute always sits on its own line at column
  # 0; a prose mention never does.
  python3 - "$1" "$2" "$3" <<'PYEOF'
import re
import sys
path, needle, repl = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding="utf-8").read()
pattern = re.compile(r"^" + re.escape(needle) + r"$", re.MULTILINE)
matches = list(pattern.finditer(text))
if len(matches) != 1:
    print(
        f"self-test fixture BROKEN: expected exactly one WHOLE-LINE occurrence of {needle!r} "
        f"in {path}, found {len(matches)}",
        file=sys.stderr,
    )
    sys.exit(2)
m = matches[0]
open(path, "w", encoding="utf-8").write(text[: m.start()] + repl + text[m.end() :])
PYEOF
}

ATTR_NEEDLE='#![cfg_attr(not(test), no_std)]'

# ---------------------------------------------- self-test: source-file floor
# selftest_vfs_src_file_floor proves the diagnostic
# actually FIRES on a git failure, rather than the whole process dying
# silently at 127/128/129 before the guard ever runs. Same fake-command
# PATH-override technique as check-vfs-deps.sh's selftest_arm3_empty_tree.
selftest_vfs_src_file_floor() {
  local real_git fake_bin out rc

  out="$(vfs_src_file_floor)" || {
    echo "self-test FAILED: vfs_src_file_floor did not pass against the real, unmodified repo" >&2
    exit 2
  }
  echo "self-test: control floor-positive — derived a floor of $out"

  real_git="$(command -v git)"
  fake_bin="$(mktemp -d)"
  _vfs_purity_track "${fake_bin}"
  # A `git` stand-in that fails on `ls-files` specifically (the command
  # this function's pipeline runs) and defers everything else to the
  # real binary — confirmed applied below before trusting the refusal.
  cat > "$fake_bin/git" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == "ls-files" ]]; then
  echo "fatal: fake git failure planted by check-vfs-purity.sh --self-test" >&2
  exit 128
fi
exec "$real_git" "\$@"
EOF
  chmod +x "$fake_bin/git"

  # Confirm the mutation actually applies before trusting the refusal —
  # a mutation that fails to apply looks identical to one that passed.
  if PATH="$fake_bin:$PATH" git ls-files >/dev/null 2>&1; then
    echo "self-test BROKEN: control floor-git-failure's fake 'git ls-files' did not fail as intended" >&2
    exit 2
  fi

  set +e
  out="$(PATH="$fake_bin:$PATH" vfs_src_file_floor 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 2 ]]; then
    echo "self-test FAILED: control floor-git-failure — a 'git ls-files' failure was NOT refused with rc=2 (got rc=$rc) — under set -euo pipefail, a bare assignment can die at 127/128/129 before any guard runs, silently, exactly the hazard this control exists to catch" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'could not derive the source-file floor' <<<"$out"; then
    echo "self-test FAILED: control floor-git-failure refused, but did not print the diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control floor-git-failure — a 'git ls-files' failure is refused with rc=2 and its own diagnostic, not a silent bare 127/128/129 with the guard below never reached"
}

# ------------------------------------------------------------- self-test: 1
selftest_item1() {
  local tmp out rc

  out="$(item1_report "$LIB_RS")" || {
    echo "self-test FAILED: item 1 did not pass against the real, unmodified $LIB_RS" >&2
    exit 2
  }
  echo "self-test: control item1-positive — $out"

  tmp="$(mktemp -d)"
  _vfs_purity_track "${tmp}"

  # DECOY: comment out the real attribute, and leave its EXACT spelling
  # elsewhere in the file (inside a comment) — a literal grep would be
  # fooled by this; structural parsing on stripped text must not be.
  cp "$LIB_RS" "$tmp/decoy.rs"
  replace_once_or_die "$tmp/decoy.rs" "$ATTR_NEEDLE" \
    "// $ATTR_NEEDLE
// DECOY — the exact spelling still appears here, in a comment:
// $ATTR_NEEDLE"
  set +e
  out="$(item1_report "$tmp/decoy.rs" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    echo "self-test FAILED: control item1-decoy — a commented-out attribute, with its exact text left as a decoy elsewhere in the file, was NOT refused" >&2
    echo "$out" >&2
    rm -rf "$tmp"
    exit 2
  fi
  echo "self-test: control item1-decoy — the commented-out attribute (exact text left as a decoy elsewhere) IS refused, as expected"

  # PREDICATE: not(test) widened to not(any(test, feature = "x")) — a
  # real cfg_attr(..., no_std) exists, but it is not the guarantee this
  # crate needs, and must be refused rather than accepted as "close".
  cp "$LIB_RS" "$tmp/widened.rs"
  replace_once_or_die "$tmp/widened.rs" "$ATTR_NEEDLE" \
    '#![cfg_attr(not(any(test, feature = "x")), no_std)]'
  set +e
  out="$(item1_report "$tmp/widened.rs" 2>&1)"
  rc=$?
  set -e
  rm -rf "$tmp"
  if [[ "$rc" -eq 0 ]]; then
    echo 'self-test FAILED: control item1-predicate — not(any(test, feature = "x")) was accepted as equivalent to not(test); it is not (it hands a feature build std)' >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'predicate is not exactly not(test)' <<<"$out"; then
    echo "self-test FAILED: control item1-predicate refused, but did not name the widened predicate as a near-miss" >&2
    echo "$out" >&2
    exit 2
  fi
  echo 'self-test: control item1-predicate — the widened predicate not(any(test, feature = "x")) is refused and named as a near-miss, as expected'
}

# ------------------------------------------------------------- self-test: 2
selftest_item2_escape() {
  local tmp expansion_file out rc

  tmp="$(mktemp -d)"
  _vfs_purity_track "${tmp}"
  populate_scratch_vfs "$tmp"
  cat > "$tmp/vfscopy/src/zz_probe.rs" <<'EOF'
// Planted ONLY by check-vfs-purity.sh --self-test, in a throwaway scratch
// copy — never in the tracked crate.
macro_rules! zz_legit_macro {
    () => {
        pub fn zz_legit_probe() -> u32 { 0 }
    };
}
zz_legit_macro!();

// The escape: assembled from the INVOCATION's own argument, so the
// banned item's literal spelling never appears anywhere in this file as
// one run of text — a raw grep for it finds nothing here. Only rustc's
// own macro expansion substitutes $c and renders the item whole.
macro_rules! zz_escape_macro {
    ($c:ident) => {
        extern crate $c as zz_escape_host;
    };
}
zz_escape_macro!(std);
EOF
  printf '\nmod zz_probe;\n' >> "$tmp/vfscopy/src/lib.rs"

  if grep -q 'extern crate std' "$tmp/vfscopy/src/zz_probe.rs"; then
    echo "self-test BROKEN: the escape fixture spells 'extern crate std' literally — it would not exercise the post-expansion case at all" >&2
    rm -rf "$tmp"
    exit 2
  fi

  # Drives item2_report's OWN pass/fail branch on a fixture carrying a
  # live escape — not a re-derived grep over a separately-captured
  # expansion, which is the exact gap G1 found: a control that never
  # calls this function proves nothing about its actual logic.
  expansion_file="$(mktemp)"
  _vfs_purity_track "${expansion_file}"
  set +e
  out="$(item2_report "$tmp/vfscopy/Cargo.toml" "$expansion_file" 2>&1)"
  rc=$?
  set -e
  rm -rf "$tmp"
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control item2-escape — item2_report did not FAIL (rc=$rc, wanted 1) against a macro-assembled 'extern crate std' beside a legitimate macro:" >&2
    echo "$out" >&2
    rm -f "$expansion_file"
    exit 2
  fi
  if ! grep -q 'zz_escape_host' <<<"$out"; then
    echo "self-test FAILED: control item2-escape — item2_report FAILED but its message did not name zz_escape_host:" >&2
    echo "$out" >&2
    rm -f "$expansion_file"
    exit 2
  fi
  if ! grep -q 'zz_legit_probe' "$expansion_file"; then
    echo "self-test FAILED: the legitimate macro's own expansion is missing from the saved expansion — the fixture is broken" >&2
    rm -f "$expansion_file"
    exit 2
  fi
  rm -f "$expansion_file"
  echo "self-test: control item2-escape — item2_report's OWN pass/fail branch (not a re-derived comparison) FAILS on a macro_rules!-emitted 'extern crate std as zz_escape_host;' (assembled from the invocation's own argument, absent as literal text from the source): $out"
  echo "self-test: control item2-legit — the legitimate macro beside it ('zz_legit_probe') expands and stays green (no false match) in the same run"
}

selftest_item2_windows_survivor() {
  local tmp out rc host

  tmp="$(mktemp -d)"
  _vfs_purity_track "${tmp}"
  populate_scratch_vfs "$tmp"
  cat >> "$tmp/vfscopy/src/lib.rs" <<'EOF'

#[cfg(windows)]
extern crate std as zz_windows_only_host;
EOF
  set +e
  out="$(item2_report "$tmp/vfscopy/Cargo.toml" 2>&1)"
  rc=$?
  set -e
  rm -rf "$tmp"
  host="$(rustc -vV | sed -n 's/^host: //p')"
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: a cfg(windows)-gated 'extern crate std' was DETECTED (item2_report rc=$rc) on host target $host — that would mean this run is somehow building for Windows, contradicting the coverage narrowing this control exists to demonstrate:" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control item2-cfg-windows — a cfg(windows)-gated 'extern crate std' is an EXPECTED SURVIVOR on host target $host: item2_report's own pass branch reports ok, because cfg selection runs BEFORE expansion, so the item is simply absent from this run's output. This is the coverage narrowing this script's own header documents under 'COVERAGE, NARROWED IN WRITING', not a kill, and is recorded as a survivor rather than a pass. It becomes a kill only once a Windows-target expansion lane exists."
}

# ------------------------------------------------------------- self-test: 3
selftest_item3() {
  local tmp tmp2 out rc

  out="$(item3_report "$CRATE_SRC" "$VFS_SRC_FILE_FLOOR")" || {
    echo "self-test FAILED: item 3 did not pass against the real, unmodified $CRATE_SRC" >&2
    exit 2
  }
  echo "self-test: control item3-positive — $out"

  tmp="$(mktemp -d)"
  _vfs_purity_track "${tmp}"
  mkdir -p "$tmp/src"
  cat > "$tmp/src/a_path.rs" <<'EOF'
#[path = "../../outside.rs"]
mod evasion;
EOF
  cat > "$tmp/src/b_include.rs" <<'EOF'
fn f() {
    include!("../../outside.rs");
}
EOF
  cat > "$tmp/src/c_legit_macro.rs" <<'EOF'
macro_rules! legit {
    () => {
        pub fn legit_fn() -> u32 { 0 }
    };
}
legit!();
EOF
  # Floor of 1, not $VFS_SRC_FILE_FLOOR: this fixture is deliberately three
  # files, far smaller than the real crate, and this control is testing
  # #[path]/include! detection, not coverage — that is the control below.
  set +e
  out="$(item3_report "$tmp/src" 1 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    echo "self-test FAILED: control item3-path/include — a planted #[path] and include! were NOT refused" >&2
    echo "$out" >&2
    rm -rf "$tmp"
    exit 2
  fi
  if ! grep -q '#\[path\]' <<<"$out" || ! grep -q 'include!' <<<"$out"; then
    echo "self-test FAILED: control item3-path/include refused, but did not name BOTH the #[path] and the include! site" >&2
    echo "$out" >&2
    rm -rf "$tmp"
    exit 2
  fi
  if grep -qi 'legit_fn\|macro_rules' <<<"$out"; then
    echo "self-test FAILED: control item3-legit-macro — the legitimate macro_rules! definition was reported; item 3 must not ban macro_rules! itself (that would contradict item 2's required legitimate-macro green control)" >&2
    rm -rf "$tmp"
    exit 2
  fi
  rm -rf "$tmp"
  echo "self-test: control item3-path/include — both named:"
  echo "$out" | sed 's/^/  /'
  echo "self-test: control item3-legit-macro — the legitimate macro_rules! beside them stays green (not reported), matching item 2's required control"

  # COVERAGE: `find` exits 0 on zero matches, so a directory item 3 never
  # actually walked (wrong path, an empty tree, a mount that vanished)
  # would otherwise print "no #[path], no include!" — indistinguishable
  # from having scanned the crate and found nothing clean. Item 3 is the
  # closure premise items 1 and 2 both rest on, so this is the exact
  # fail-open the house idiom forbids.
  tmp2="$(mktemp -d)"
  _vfs_purity_track "${tmp2}"
  mkdir -p "$tmp2/empty_src"
  set +e
  out="$(item3_report "$tmp2/empty_src" 1 2>&1)"
  rc=$?
  set -e
  rm -rf "$tmp2"
  if [[ "$rc" -eq 0 ]]; then
    echo "self-test FAILED: control item3-coverage — an empty directory (zero .rs files) was NOT refused" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -qi 'floor' <<<"$out"; then
    echo "self-test FAILED: control item3-coverage refused, but did not name the coverage floor" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control item3-coverage — an empty directory (find exits 0 on zero matches) is refused, not read as a clean scan of the crate that simply found nothing"

  # REWORDED REASON: item 3's macro_rules! exemption filters on `h.kind`
  # (fsguard.MACRO_RULES_KIND), not on a substring of fsguard-scan.py's
  # own PROSE such as `" <- macro_rules! " not in h`, which nothing would
  # tie to the exemption. This proves the kind filter survives the attack:
  # reword that prose ENTIRELY (drop the "macro_rules!" substring,
  # change the arrow, the works) on a scratch copy of fsguard-scan.py,
  # and confirm the legitimate macro STILL stays green (kind, not
  # prose, excludes it) and a genuinely real #[path] finding is NOT
  # silently dropped alongside it — the worse of the two directions a
  # prose coupling could fail in.
  tmp="$(mktemp -d)"
  _vfs_purity_track "${tmp}"
  mkdir -p "$tmp/src"
  cp "$SCAN_PY" "$tmp/vfs-purity-scan.py"
  cp "$(dirname "$SCAN_PY")/fsguard-scan.py" "$tmp/fsguard-scan.py"
  python3 - "$tmp/fsguard-scan.py" <<'PYEOF'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
needle = (
    '            "macro_rules! — an arm can assemble a lint path from tokens this scanner never sees",\n'
    '            MACRO_RULES_KIND,\n'
)
replacement = (
    '            "macro definition site, reworded for the self-test — no \'macro_rules!\' substring survives here",\n'
    '            MACRO_RULES_KIND,\n'
)
count = text.count(needle)
if count != 1:
    print(f"self-test fixture BROKEN: expected exactly one occurrence of the macro_rules! report() call, found {count}", file=sys.stderr)
    sys.exit(2)
open(path, "w", encoding="utf-8").write(text.replace(needle, replacement))
PYEOF
  if grep -q 'arm can assemble a lint path' "$tmp/fsguard-scan.py"; then
    echo "self-test BROKEN: control item3-reworded-reason's mutation did not apply — the old reason text is still present" >&2
    rm -rf "$tmp"
    exit 2
  fi
  cat > "$tmp/src/mixed.rs" <<'EOF'
macro_rules! legit {
    () => {
        pub fn legit_fn() -> u32 { 0 }
    };
}
legit!();

#[path = "../../outside.rs"]
mod evasion;
EOF
  set +e
  out="$(find "$tmp/src" -name '*.rs' -print0 | python3 "$tmp/vfs-purity-scan.py" --closure 2>&1)"
  rc=$?
  set -e
  rm -rf "$tmp"
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: control item3-reworded-reason — the closure scan errored (rc=$rc) against a totally reworded macro_rules! reason" >&2
    echo "$out" >&2
    exit 2
  fi
  if grep -qi 'legit_fn\|macro_rules\|macro definition' <<<"$out"; then
    echo "self-test FAILED: control item3-reworded-reason — the legitimate macro_rules! was reported once its reason text no longer said 'macro_rules!' — the filter is still coupled to the prose, not the kind" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q '#\[path\]' <<<"$out"; then
    echo "self-test FAILED: control item3-reworded-reason — a genuinely real #[path] finding was DROPPED once the macro_rules! reason was reworded (the worse direction: silent data loss)" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control item3-reworded-reason — with fsguard-scan.py's macro_rules! reason text reworded entirely (no 'macro_rules!' substring left anywhere in it), the KIND-based filter still excludes the legitimate macro and still reports the real #[path] finding: neither a false item-3 finding on clean code, nor a real finding silently dropped"

  # SYMLINK: `find -name '*.rs'` (default -P mode)
  # never descends a symlinked directory, though rustc compiles the
  # modules behind it — and, separately, a symlinked .rs file. Both must
  # be refused rather than silently followed or silently skipped.
  # The symlinked FILE's target is deliberately CLEAN of #[path]/
  # include! — `find "$dir" -name '*.rs'` still lists
  # the symlink's own name and the closure scan opens it (following the
  # link, reading the TARGET's content), so a #[path] planted in the
  # target would make the closure scan itself emit a finding whose text
  # happens to name "linked_file.rs" — satisfying a substring grep for
  # entirely the wrong reason, with the symlink-detection arm this
  # control exists to exercise never having run at all. With the target
  # clean, the ONLY way "linked_file.rs" can appear in item3_scan's
  # output is the dedicated `*.rs)` arm of the symlink loop.
  tmp="$(mktemp -d)"
  _vfs_purity_track "${tmp}"
  mkdir -p "$tmp/outside"
  cat > "$tmp/outside/clean_target.rs" <<'EOF'
pub fn clean_target() -> u32 { 0 }
EOF
  mkdir -p "$tmp/src"
  cat > "$tmp/src/clean.rs" <<'EOF'
pub fn clean() -> u32 { 0 }
EOF
  ln -s "$tmp/outside" "$tmp/src/linked_dir"
  ln -s "$tmp/outside/clean_target.rs" "$tmp/src/linked_file.rs"
  set +e
  out="$(item3_report "$tmp/src" 1 2>&1)"
  rc=$?
  set -e
  rm -rf "$tmp"
  if [[ "$rc" -eq 0 ]]; then
    echo "self-test FAILED: control item3-symlink — a symlinked directory and a symlinked .rs file under the crate src were NOT refused" >&2
    echo "$out" >&2
    exit 2
  fi
  # The DISTINCTIVE reason text each symlink-loop arm emits, not a bare
  # 'linked_dir'/'linked_file.rs' substring — with
  # the target now clean, a bare substring match would already be
  # tight enough, but the distinctive text is what actually PROVES the
  # dedicated arm ran, rather than merely being consistent with it.
  if ! grep -q 'linked_dir: a SYMLINKED DIRECTORY' <<<"$out" || ! grep -q 'linked_file.rs: a SYMLINKED .rs file' <<<"$out"; then
    echo "self-test FAILED: control item3-symlink refused, but did not name BOTH the symlinked directory and the symlinked .rs file with their distinctive reason text" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control item3-symlink — a symlinked directory (find's default -P mode never descends it, though rustc compiles the modules behind it) and a symlinked .rs file are BOTH refused"
}

# ---------------------------------------------------------- self-test: bites
selftest_bites() {
  local tmp out rc

  tmp="$(mktemp -d)"
  _vfs_purity_track "${tmp}"
  populate_scratch_vfs "$tmp"
  # #[expect(dead_code, …)]: this probe is never called (its only job is
  # to be COMPILED, once with the attribute active and once with it
  # removed), and CI's ci.yml:17 sets CARGO_BUILD_WARNINGS=deny at the
  # workflow env: level for every job — including this gate's own
  # --self-test in the `gates` job. Without this, the bite-absent control
  # below (attribute removed, std genuinely reachable) compiles clean
  # under a bare cargo check but fails under that denial with an unrelated
  # `dead_code` warning-turned-error, which is not what bite-absent is
  # testing and would redden CI on the very first push.
  cat >> "$tmp/vfscopy/src/lib.rs" <<'EOF'

#[expect(dead_code, reason = "compiled only to be checked, never called")]
fn zz_bite_probe() {
    let _ = std::fs::read("/nonexistent");
}
EOF

  set +e
  out="$(CARGO_TARGET_DIR="$VFS_PURITY_SHARED_TARGET_DIR" cargo check --offline --manifest-path "$tmp/vfscopy/Cargo.toml" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    echo "self-test FAILED: control bite-present — with the attribute ACTIVE, std::fs::read in a production fn compiled at rc=0 (wanted a nonzero rc, E0433) — the attribute is not biting" >&2
    echo "$out" | tail -20 >&2
    rm -rf "$tmp"
    exit 2
  fi
  if ! grep -q 'E0433' <<<"$out"; then
    echo "self-test FAILED: control bite-present failed for the WRONG reason (no E0433) — a different error means the attribute is not what stopped the build:" >&2
    echo "$out" | tail -20 >&2
    rm -rf "$tmp"
    exit 2
  fi
  echo "self-test: control bite-present — with the attribute active, std::fs::read in a production fn fails at rc=$rc, E0433, as expected"

  replace_once_or_die "$tmp/vfscopy/src/lib.rs" "$ATTR_NEEDLE" "// $ATTR_NEEDLE"
  set +e
  out="$(CARGO_TARGET_DIR="$VFS_PURITY_SHARED_TARGET_DIR" cargo check --offline --manifest-path "$tmp/vfscopy/Cargo.toml" 2>&1)"
  rc=$?
  set -e
  rm -rf "$tmp"
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: control bite-absent — with the attribute REMOVED, the identical std::fs::read did not compile clean (rc=$rc):" >&2
    echo "$out" | tail -20 >&2
    exit 2
  fi
  echo "self-test: control bite-absent — with the attribute removed, the identical source compiles at rc=0 — the unguarded case this whole gate exists for"
}

# ------------------------------------------------ self-test: item 2, features
# item2-feature-escape proves the FEATURE DIMENSION
# narrowing item 2's header now states, in place of the deleted
# check_no_features standing ban. A feature-gated 'extern crate std' is
# an EXPECTED SURVIVOR under item 2's DEFAULT-feature expansion — cfg
# selection drops it before expansion ever sees it, the same mechanism
# as item2-cfg-windows above — and a KILL once --all-features turns the
# feature on. That pair of outcomes IS the coverage this gate claims:
# the default set and --all-features, nothing gated on a configuration
# neither of those two runs ever builds.
selftest_item2_feature_escape() {
  local tmp out rc

  tmp="$(mktemp -d)"
  _vfs_purity_track "${tmp}"
  populate_scratch_vfs "$tmp"
  cat >> "$tmp/vfscopy/Cargo.toml" <<'MANIFEOF'

[features]
zz_extra = []
MANIFEOF
  cat >> "$tmp/vfscopy/src/lib.rs" <<'LIBEOF'

#[cfg(feature = "zz_extra")]
extern crate std as zz_feature_escape_host;
LIBEOF

  set +e
  out="$(item2_report "$tmp/vfscopy/Cargo.toml" "" default 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: control item2-feature-escape — a feature-gated 'extern crate std' behind an OFF feature was DETECTED under item 2's DEFAULT expansion (rc=$rc) — cfg selection should have dropped it before expansion ever ran:" >&2
    echo "$out" >&2
    rm -rf "$tmp"
    exit 2
  fi
  echo "self-test: control item2-feature-escape-default — a feature-gated 'extern crate std' behind an OFF feature is an EXPECTED SURVIVOR under item 2's default-feature expansion (cfg selection drops it before expansion ever sees it): $out"

  set +e
  out="$(item2_report "$tmp/vfscopy/Cargo.toml" "" all 2>&1)"
  rc=$?
  set -e
  rm -rf "$tmp"
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control item2-feature-escape — the SAME feature-gated 'extern crate std' was NOT caught under --all-features (rc=$rc, wanted 1) — this is exactly the configuration item 2's second expansion exists to cover:" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'zz_feature_escape_host' <<<"$out"; then
    echo "self-test FAILED: control item2-feature-escape — item 2 FAILED under --all-features but did not name zz_feature_escape_host:" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control item2-feature-escape-all — the identical feature-gated 'extern crate std', invisible to the default-feature expansion (cfg excludes it entirely), is caught once --all-features turns the feature on: $out"
}


# selftest_argv_guard — the planted RED for the argument guard at the head
# of this file. Without it the guard is the only check here with no control,
# and a refactor that reintroduced a `*)` fallthrough would leave every other
# control green while the gate silently reported success on a mistyped
# `--self-test`. Runs THIS script with a bogus argv in a subshell: the guard
# sits before all top-level setup, so this costs nothing and cannot recurse.
selftest_argv_guard() {
  local out rc
  set +e
  out="$("$0" __selftest_argv_probe__ 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 2 ]]; then
    echo "self-test FAILED: control argv-guard — a bogus argument was NOT refused with rc=2 (got rc=$rc); the gate would run and report green having executed zero controls" >&2
    exit 1
  fi
  case "$out" in
    *"unrecognised argument(s): __selftest_argv_probe__"*) ;;
    *) echo "self-test FAILED: control argv-guard — refused at rc=2 but without the diagnostic naming the argument: $out" >&2; exit 1 ;;
  esac
  # and the two LEGITIMATE forms must still be accepted, or the guard has
  # traded a fail-open for a fail-closed on every real invocation.
  set +e
  "$0" >/dev/null 2>&1; rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: control argv-guard — the no-argument form (the real gate) no longer runs (rc=$rc)" >&2
    exit 1
  fi
  echo "self-test: control argv-guard — a bogus argv is refused at rc=2 naming the argument, and the no-argument form still runs the real gate at rc=0; a mistyped '--self-test' cannot print a green verdict having run zero controls"
}

# --------------------------------------------------------------------- main
if [[ "${1:-}" == "--self-test" ]]; then
  selftest_vfs_src_file_floor
  selftest_item1
  selftest_item2_escape
  selftest_item2_windows_survivor
  selftest_item2_feature_escape
  selftest_item3
  selftest_bites
  selftest_argv_guard
  echo "vfs-purity self-test: every control behaved as predicted — a git failure in the source-file floor is refused with its own diagnostic rather than dying silently at a bare 127/128/129 (the floor computation), decoy and widened-predicate refused (item 1), macro-assembled escape detected with the legitimate macro staying green (item 2), the cfg(windows) escape recorded as a SURVIVOR (not a kill), a feature-gated escape recorded as a SURVIVOR under default features and a KILL under --all-features (item 2's own feature-dimension coverage, replacing the deleted standing feature ban), #[path]/include! refused without banning macro_rules! (item 3, plus an empty-directory coverage refusal, a symlinked directory and a symlinked .rs file under the crate src both refused, and a reworded macro_rules! reason text neither producing a false finding nor silently dropping a real one), and the end-to-end bite fires E0433 with the attribute active and clears at rc=0 once it is removed"
  exit 0
fi

item1_out="$(item1_report "$LIB_RS")"
item2_default_out="$(item2_report "" "" default)"
item2_all_out="$(item2_report "" "" all)"
item3_out="$(item3_report "$CRATE_SRC" "$VFS_SRC_FILE_FLOOR")"
echo "$item1_out"
echo "$item2_default_out"
echo "$item2_all_out"
echo "$item3_out"
echo "vfs-purity: ok — $CRATE_DIR carries its purity boundary (item 1), no extern crate std survives expansion of its non-test lib under EITHER configuration this gate expands — default features and --all-features (item 2; the crate declares no features today, so the two runs expand the identical build, and that is a narrowing to state, not a completeness claim) — no #[path]/include! escape and no symlinked source under it (item 3). There is no standing ban on granary-vfs ever declaring a feature: the source-axis rule pins three items — this script's own header lists them — and 'no feature may ever exist' is not one of them. The source-axis rule does not require every future public addition to fail CI. The crate's root was verified once, at twenty items, from the compiler's own rustdoc JSON output — see crates/granary-vfs/src/lib.rs's doc near root_surface_probe."
