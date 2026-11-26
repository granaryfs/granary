#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# The granary-vfs DEPENDENCY axis — the counterpart to
# scripts/check-vfs-purity.sh's SOURCE axis. Between them they close the one
# thing this crate's `no_std` attribute promises: no DIRECT DEPENDENCY on the
# std crate, whether the source names it or the manifest pulls it in. It is
# NOT an effect guarantee and not even a guarantee about naming an effect —
# the crate root's own doc says so in terms, and this gate must not be read as
# saying more. All three of that gate's items constrain what
# crates/granary-vfs/src's SOURCE names (its fourth check is an end-to-end
# control that runs under `--self-test` only); none of them
# constrains its MANIFEST. Adding a no_std-compatible dependency that
# reaches the platform through libc, adding a build.rs, or pulling in a
# proc-macro leaves every purity item green.
#
# FIVE ARMS, each with its own planted red in --self-test:
#
#   1. cargo-deny bans + build-script + licence policy, reusing
#      deny.core.toml — granary-core's OWN purity gate's config
#      (scripts/check-core-purity.sh) — scoped to granary-vfs's OWN
#      manifest. `--manifest-path` naming a workspace member makes that
#      crate the SOLE ROOT of the graph cargo-deny evaluates (cargo-deny
#      --help, confirmed live 2026-09-12: "Normally, if you specify a
#      manifest path that is a member of a workspace, that crate will be
#      the sole root of the crate graph" — `--workspace` is what widens
#      it back to every member), so this reuses the SAME exceptions
#      (blake3 pinned, libc via cpufeatures) granary-core already
#      carries, correctly: granary-vfs's whole tree IS granary-core's
#      tree plus itself, so nothing here should ever need an exception
#      granary-core's config does not already have.
#   2. A ONE-DIRECTIONAL set difference of granary-vfs's dependency tree
#      against granary-core's: granary-vfs names ONLY granary-core in its
#      manifest, so its whole tree is granary-core's tree plus itself — a
#      genuinely NEW dependency (one arm 1's ban list does not already
#      know to forbid — an innocuous, unbanned crate reaching the
#      platform through a path arm 1 has no opinion on) shows up as an
#      EXTRA package neither list explains.
#      THE FLAGS ARE LOAD-BEARING: a bare `cargo tree -p X` resolves
#      normal edges only, the HOST target only, and DEFAULT features
#      only — a narrower, different question that would miss a
#      dev-dependency-only addition, one gated on a feature, or one that
#      exists only on a target this host is not. This gate uses
#      `-e normal,dev --target all --all-features`, matching
#      check-core-purity.sh's own mechanism 3 for granary-core exactly.
#   3. No proc-macro anywhere in the tree — the SAME diff trick
#      check-core-purity.sh's mechanism 3 already uses for granary-core:
#      the SAME edges with `no-proc-macro` added must render an IDENTICAL
#      set.
#   4. Isolated resolution with --all-features — check-core-purity.sh's
#      own mechanism 2 for granary-core ("a feature-gated impurity must
#      not hide behind a default-features check"), carried over here
#      after that layer was found dropped entirely on
#      this file's first commit. Currently VACUOUS against the tracked
#      crate specifically: granary-vfs declares no `[features]` table at
#      all today, so `--all-features` and a default build are the
#      identical command against the real crate. There is no standing
#      ban on it ever declaring one (`check-vfs-purity.sh` deleted its
#      `check_no_features` because the source-axis rule
#      pins three items, and "no feature may ever exist" was never one
#      of them), so this arm is not merely parity with
#      check-core-purity.sh but the arm that stops being vacuous the day
#      a feature IS added — its self-test proves the mechanism against a
#      scratch fixture that legitimately carries a feature, since the
#      tracked crate does not today.
#   5. An EXACT direct-manifest-edge check: this
#      header has said "granary-vfs names ONLY granary-core in its
#      manifest" since this file's first commit, and no arm enforced
#      that claim directly until now. Arm 2 is a package-NAME SET
#      difference over the RESOLVED tree, which discards parentage and
#      edge kind — a direct edge to any package already inside
#      granary-core's own closure (normal, dev, OR build) adds nothing
#      to that difference and passes arm 2 clean regardless. SET
#      INCLUSION CANNOT ENFORCE PARENTAGE. This arm instead reads
#      `cargo metadata`'s own `dependencies` array for the `granary-vfs`
#      package — the MANIFEST-level fact `cargo tree` never shows,
#      covering all three edge kinds uniformly — and asserts it names
#      exactly one thing, `granary-core`, non-optional.
#
# KEPT AS TWO FILES, NOT PARAMETERISED:
# this gate and check-core-purity.sh answer the same DEPENDENCY-axis
# question for two crates, and the union above is carried here in full —
# but the two scripts have diverged in MATURITY, not just in crate name.
# This one carries the full house self-test idiom (exit 0/1/2, scratch
# fixtures, a planted red per arm); check-core-purity.sh has none of
# that. Collapsing them into one parameterised script means either
# downgrading this one to check-core-purity.sh's untested shape (a
# regression for granary-vfs, against the exact self-test culture this
# gate is enforcing) or upgrading check-core-purity.sh to this
# one's shape (a rewrite of a script granary-core's own CI has relied on
# unchanged, beyond the scope of a gate whose job is verified surgical
# fixes). A third engine crate would tip that balance; one does not exist
# yet. What this gate CAN and must do instead: close every divergence
# the two scripts have actually grown (arm 3's missing non-empty guard,
# this arm 4) and add a tripwire so the NEXT divergence cannot go
# unnoticed the way this one did — `check_tree_flags_match_core`, below,
# reads check-core-purity.sh's own tree-diff flags and refuses the
# moment they stop matching this file's TREE_FLAGS/TREE_FLAGS_NOPM.
#
# House gate idiom: exit 0 pass / 1 fail / 2 the check could not run —
# and an unreadable input, or a tree that fails to compute at all, is
# ALWAYS a refusal, never read as clean.
#
#   scripts/check-vfs-deps.sh              run the gate
#   scripts/check-vfs-deps.sh --self-test  prove it can fail
set -euo pipefail

# ARGUMENT VALIDATION. An argv that is not exactly
# `--self-test` must not fall through to the real gate and
# exit 0 — if it did, `check-vfs-deps.sh self-test` (dashes
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
  echo "vfs-deps: unrecognised argument(s): $* — the only accepted form is '--self-test' (or no argument, to run the gate). Refused rather than silently running the gate and reporting green." >&2
  exit 2
fi

# Self-locate like every sibling gate rather than requiring the caller's
# cwd to be the repo root.
cd "$(dirname "$0")/.."

VFS_MANIFEST=crates/granary-vfs/Cargo.toml
DENY_CONFIG=deny.core.toml

# shellcheck source=vfs-scratch-fixture.sh
source "$(pwd)/scripts/vfs-scratch-fixture.sh"
vfs_ws_edition_and_rust_version

# CLEANUP TRAP: every self-test control below builds a
# scratch fixture (a copied crate, a fake `cargo` shim, a mutated copy
# of check-core-purity.sh) in $TMPDIR, and several exit 2 or hit
# `set -e` partway through — before their own `rm -rf` runs.
# check-core-purity.sh's own `trap '…' EXIT` closes the identical class
# for its two temp files. One shared registry and trap here instead, so
# no failure path — planted or genuine — can skip cleanup.
_VFS_DEPS_CLEANUP=()
_vfs_deps_track() { _VFS_DEPS_CLEANUP+=("$1"); }
_vfs_deps_cleanup() {
  local d
  for d in "${_VFS_DEPS_CLEANUP[@]+"${_VFS_DEPS_CLEANUP[@]}"}"; do
    rm -rf "$d"
  done
}
trap _vfs_deps_cleanup EXIT

# Same edge/target/feature set check-core-purity.sh's own mechanism 3
# uses for granary-core — written down here because it answers a
# DIFFERENT, WIDER question than the default `cargo tree -p X` flags do.
TREE_FLAGS=(-e normal,dev --target all --all-features --prefix none)
TREE_FLAGS_NOPM=(-e normal,dev,no-proc-macro --target all --all-features --prefix none)

# --------------------------------------------------- stay-in-step with core
# check_tree_flags_match_core <core-purity-script-path>
# The H4 tripwire: reads the two `cargo tree` invocations inside
# <core-purity-script-path> (real gate: scripts/check-core-purity.sh;
# self-test: a mutated scratch copy) and refuses the moment their flag
# SETS (order-independent — `-e`'s value, `--target`'s value,
# `--all-features`, `--prefix`'s value; never the crate name or the
# lock/offline mode, which are expected to differ) stop matching this
# file's own TREE_FLAGS/TREE_FLAGS_NOPM. A parsing failure (the script
# unreadable, or its tree invocations not found at all) is refused, not
# read as "nothing to compare" — the same closure-premise reasoning
# check-vfs-purity.sh's item 3 gives for its own floor.
check_tree_flags_match_core() {
  local core_path="$1" out rc
  set +e
  out="$(python3 - "$core_path" "${TREE_FLAGS[*]}" "${TREE_FLAGS_NOPM[*]}" <<'PYEOF'
import re
import sys

core_path, mine_full, mine_nopm = sys.argv[1], sys.argv[2], sys.argv[3]

def flag_set(tokens):
    """Order-independent flag identity: -e's value, --target's value,
    --all-features (present/absent), --prefix's value. Ignores every
    other token (-p NAME, --locked, --offline, redirects)."""
    out = set()
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in ("-e", "--target", "--prefix") and i + 1 < len(tokens):
            out.add((t, tokens[i + 1]))
            i += 2
        elif t == "--all-features":
            out.add((t, None))
            i += 1
        else:
            i += 1
    return out

try:
    with open(core_path, encoding="utf-8") as f:
        text = f.read()
except OSError as e:
    print(f"ERROR could not read {core_path}: {e}", file=sys.stderr)
    sys.exit(2)

# Join backslash-newline continuations the way the shell would, then
# pull out every `cargo tree ...` invocation up to its terminator
# (redirect or end of line).
#
# ANCHORED TO THE START OF A (joined) LINE — `^[ \t]*cargo tree\b`, not
# a bare `cargo tree` substring search: the bare form
# also matches check-core-purity.sh's own two diagnostics, "ERROR: empty
# cargo tree output (full)" / "(no-proc-macro)" — the match just stops
# at the first `>` (from that line's own `>&2`), which reads as a
# plausible "call". Under the bare form only DOCUMENT ORDER (the real
# invocations sit above those diagnostics) keeps `full_calls[0]`/
# `nopm_calls[0]` correct; move the diagnostics earlier, or add any comment
# mentioning "cargo tree" above the real calls, and a bare regex would
# silently grab the wrong text — a MISMATCH (or worse, a false match) that reddens
# this gate for a reason having nothing to do with a real flag drift.
# Anchoring to the start of a line closes that: neither diagnostic's
# "cargo tree" substring ever begins its own physical line, so no
# ordering or comment placement can make it match, regardless of where
# it sits in the file.
joined = re.sub(r"\\\n[ \t]*", " ", text)
calls = re.findall(r"^[ \t]*cargo tree\b[^\n>]*", joined, re.MULTILINE)
full_calls = [c for c in calls if "no-proc-macro" not in c]
nopm_calls = [c for c in calls if "no-proc-macro" in c]
if not full_calls or not nopm_calls:
    print(
        f"ERROR {core_path}: could not find both a normal,dev and a "
        "normal,dev,no-proc-macro 'cargo tree' invocation to compare",
        file=sys.stderr,
    )
    sys.exit(2)

core_full = flag_set(full_calls[0].split())
core_nopm = flag_set(nopm_calls[0].split())
vfs_full = flag_set(mine_full.split())
vfs_nopm = flag_set(mine_nopm.split())

if core_full != vfs_full or core_nopm != vfs_nopm:
    if core_full != vfs_full:
        print(f"MISMATCH full: {core_path}={sorted(core_full)} vfs-deps.sh={sorted(vfs_full)}")
    if core_nopm != vfs_nopm:
        print(f"MISMATCH nopm: {core_path}={sorted(core_nopm)} vfs-deps.sh={sorted(vfs_nopm)}")
    sys.exit(1)
print("tree flags match")
PYEOF
)"
  rc=$?
  set -e
  if [[ "$rc" -eq 2 ]]; then
    echo "vfs-deps: stay-in-step check could not run — refused, never treated as clean: $out" >&2
    exit 2
  fi
  if [[ "$rc" -ne 0 ]]; then
    echo "vfs-deps: STALE — this script's TREE_FLAGS/TREE_FLAGS_NOPM no longer match $core_path's own tree-diff flags (the two gates have diverged and nobody updated the other):" >&2
    echo "$out" | sed 's/^/  /' >&2
    return 1
  fi
  echo "vfs-deps: stay-in-step ok — TREE_FLAGS/TREE_FLAGS_NOPM still match $core_path's own tree-diff flags"
  return 0
}

# ------------------------------------------------------------------ arm 1
# arm1_report <manifest> <lock-flag>
# <lock-flag> is "--locked" for the tracked crate (sharing the real
# workspace's Cargo.lock) and "--offline" for a freshly-created scratch
# fixture that has no lock file yet (self-test only) — the same
# real-vs-scratch split item2_expand uses in check-vfs-purity.sh.
arm1_report() {
  local manifest="$1" lock_flag="$2" out rc
  set +e
  out="$(cargo deny "$lock_flag" --config "$DENY_CONFIG" --manifest-path "$manifest" check bans licenses 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "vfs-deps: arm 1 FAILED — cargo-deny's bans/build-script/licence policy (deny.core.toml, reused: $manifest's tree is a subset of granary-core's plus itself) refused it:" >&2
    echo "$out" | sed 's/^/  /' >&2
    return 1
  fi
  echo "vfs-deps: arm 1 ok — bans/build-script/licence policy clean for $manifest"
  return 0
}

# ------------------------------------------------------------------ arm 2
# tree_lines <manifest|""> <package-name> <lock-flag> [nopm]
# Empty manifest runs against the tracked workspace; a manifest path runs
# a scratch fixture instead (self-test only). Passing "nopm" as a fourth
# argument adds the no-proc-macro edge (arm 3's own comparison side).
tree_lines() {
  local manifest="$1" name="$2" lock_flag="$3" variant="${4:-}" flags
  if [[ "$variant" == "nopm" ]]; then
    flags=("${TREE_FLAGS_NOPM[@]}")
  else
    flags=("${TREE_FLAGS[@]}")
  fi
  if [[ -n "$manifest" ]]; then
    cargo tree "$lock_flag" --manifest-path "$manifest" -p "$name" "${flags[@]}"
  else
    cargo tree "$lock_flag" -p "$name" "${flags[@]}"
  fi
}

arm2_report() {
  # arm2_report <manifest|""> <package-name> <lock-flag>
  local manifest="$1" name="$2" lock_flag="$3" vfs_set core_set extra rc extra_count
  set +e
  vfs_set="$(tree_lines "$manifest" "$name" "$lock_flag" | sort -u)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "vfs-deps: arm 2 could not compute $name's dependency tree (exit $rc) — refused, never treated as clean" >&2
    exit 2
  fi
  set +e
  core_set="$(tree_lines "" granary-core --locked | sort -u)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "vfs-deps: arm 2 could not compute granary-core's own dependency tree (exit $rc) — refused, never treated as clean" >&2
    exit 2
  fi
  extra="$(comm -23 <(printf '%s\n' "$vfs_set") <(printf '%s\n' "$core_set") | sed '/^$/d')"
  extra_count="$(printf '%s\n' "$extra" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [[ "$extra_count" -ne 1 ]] || ! grep -qE "^$name " <<<"$extra"; then
    echo "vfs-deps: arm 2 FAILED — $name's dependency tree carries something granary-core's does not, beyond $name itself (one-directional diff, $name minus granary-core):" >&2
    printf '%s\n' "$extra" | sed '/^$/d' | sed 's/^/  EXTRA /' >&2
    return 1
  fi
  echo "vfs-deps: arm 2 ok — $name's whole dependency tree is granary-core's plus itself, nothing more"
  return 0
}

# ------------------------------------------------------------------ arm 3
arm3_report() {
  # arm3_report <manifest|""> <package-name> <lock-flag>
  local manifest="$1" name="$2" lock_flag="$3" pm_set nopm_set rc diff_out
  set +e
  pm_set="$(tree_lines "$manifest" "$name" "$lock_flag" | sort -u)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "vfs-deps: arm 3 could not compute $name's dependency tree (exit $rc) — refused, never treated as clean" >&2
    exit 2
  fi
  # NON-EMPTY GUARD — check-core-purity.sh's own `[ -s $tree_full ]`
  # handles the identical hazard: a `cargo tree` that exits 0 while
  # printing NOTHING makes
  # pm_set empty, and an equally-empty nopm_set would then compare equal
  # to it — "arm 3 ok — no proc-macro" having compared nothing at all.
  # Unlike arm 2 (guarded incidentally by its own `extra_count -ne 1`),
  # arm 3's equality check has no such accidental floor, so this crate's
  # own header claim — "a tree that fails to compute at all, is ALWAYS a
  # refusal, never read as clean" — needs an explicit one.
  if [[ -z "$pm_set" ]]; then
    echo "vfs-deps: arm 3 could not confirm $name's dependency tree actually rendered anything (cargo tree exited 0 but printed nothing) — refused, never treated as clean" >&2
    exit 2
  fi
  set +e
  nopm_set="$(tree_lines "$manifest" "$name" "$lock_flag" nopm | sort -u)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "vfs-deps: arm 3 could not compute $name's no-proc-macro dependency tree (exit $rc) — refused, never treated as clean" >&2
    exit 2
  fi
  if [[ -z "$nopm_set" ]]; then
    echo "vfs-deps: arm 3 could not confirm $name's no-proc-macro dependency tree actually rendered anything (cargo tree exited 0 but printed nothing) — refused, never treated as clean" >&2
    exit 2
  fi
  if [[ "$pm_set" != "$nopm_set" ]]; then
    diff_out="$(diff <(printf '%s\n' "$pm_set") <(printf '%s\n' "$nopm_set") || true)"
    echo "vfs-deps: arm 3 FAILED — a proc-macro is present in $name's dependency tree (normal+dev edges differ once proc-macros are excluded):" >&2
    echo "$diff_out" | sed 's/^/  /' >&2
    return 1
  fi
  echo "vfs-deps: arm 3 ok — no proc-macro in $name's dependency tree"
  return 0
}

# ------------------------------------------------------------------ arm 4
# check-core-purity.sh's own mechanism 2 for granary-core, carried over
# here: "isolated resolution: core compiles with ALL
# its features on — a feature-gated impurity must not hide behind a
# default-features check." Currently vacuous for the TRACKED granary-vfs
# crate specifically, and said so rather than left implicit: this crate
# declares no `[features]` table at all today, so `--all-features` and a
# default build are the identical command against the real crate. There
# is no standing ban on it ever declaring one: `check-vfs-purity.sh`
# deleted `check_no_features`, so this arm is the one
# that stops being vacuous the day a feature is added, not merely parity
# with check-core-purity.sh. Its self-test proves the MECHANISM against
# a scratch fixture that legitimately carries a feature, since the
# tracked crate does not today.
arm4_report() {
  # arm4_report <manifest|""> <lock-flag>
  # Empty manifest checks the tracked crate `-p granary-vfs` inside the
  # real workspace — matching check-core-purity.sh's own `-p
  # granary-core`, not `--manifest-path` — a manifest path checks a
  # scratch fixture's own standalone workspace instead (self-test only).
  local manifest="$1" lock_flag="$2" out rc
  set +e
  if [[ -n "$manifest" ]]; then
    out="$(cargo check --manifest-path "$manifest" -p granary-vfs "$lock_flag" --all-features 2>&1)"
  else
    out="$(cargo check -p granary-vfs "$lock_flag" --all-features 2>&1)"
  fi
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "vfs-deps: arm 4 FAILED — granary-vfs does not compile in isolation with --all-features (a feature-gated impurity that a default-features build would never see):" >&2
    echo "$out" | sed 's/^/  /' >&2
    return 1
  fi
  echo "vfs-deps: arm 4 ok — granary-vfs compiles cleanly with --all-features (isolated resolution)"
  return 0
}

# ------------------------------------------------------------------ arm 5
# This gate's own header has asserted since its
# first commit that "granary-vfs names ONLY granary-core in its
# manifest" — and no arm enforced that claim DIRECTLY until this one.
# Arm 2 is a package-NAME SET difference over `cargo tree`'s RESOLVED
# output, which discards both parentage and edge kind: a direct edge
# from granary-vfs to any package ALREADY inside granary-core's own
# closure (whether declared normal, dev, or build) adds NOTHING to that
# one-directional set difference — the package is already on both sides
# — so it passes arm 2 clean regardless of kind. SET INCLUSION CANNOT
# ENFORCE PARENTAGE. This arm reads the MANIFEST-level fact `cargo tree`
# never shows: `cargo metadata`'s own `dependencies` array for the
# `granary-vfs` package, which lists every declared edge — normal, dev
# AND build, uniformly, each with its own `kind`/`optional` fields — and
# asserts the set of NAMES it contains is exactly `{granary-core}`, with
# that one edge non-optional.
arm5_report() {
  # arm5_report <manifest> <lock-flag>
  local manifest="$1" lock_flag="$2" meta_file err_file out rc
  meta_file="$(mktemp)" || { echo "vfs-deps: mktemp failed" >&2; exit 2; }
  _vfs_deps_track "${meta_file}"
  err_file="$(mktemp)" || { echo "vfs-deps: mktemp failed" >&2; exit 2; }
  _vfs_deps_track "${err_file}"
  set +e
  cargo metadata --format-version=1 --no-deps "$lock_flag" --manifest-path "$manifest" \
    >"$meta_file" 2>"$err_file"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "vfs-deps: arm 5 could not run 'cargo metadata' on $manifest (exit $rc) — refused, never treated as clean:" >&2
    tail -20 "$err_file" >&2
    rm -f "$meta_file" "$err_file"
    exit 2
  fi
  rm -f "$err_file"
  set +e
  out="$(python3 - "$meta_file" <<'PYEOF'
import json
import sys

path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
except (OSError, json.JSONDecodeError) as e:
    print(f"could not read/parse cargo metadata output at {path}: {e}", file=sys.stderr)
    sys.exit(2)

pkgs = [p for p in doc.get("packages", []) if p.get("name") == "granary-vfs"]
if len(pkgs) != 1:
    print(
        f"expected exactly one 'granary-vfs' package in cargo metadata's output, found {len(pkgs)}",
        file=sys.stderr,
    )
    sys.exit(2)

deps = pkgs[0].get("dependencies") or []
if not deps:
    print("granary-vfs's manifest declares NO dependency at all (expected exactly one: a non-optional granary-core)")
    sys.exit(1)

bad = [
    f"{d.get('name')} (kind={d.get('kind') or 'normal'}, optional={d.get('optional')})"
    for d in deps
    if d.get("name") != "granary-core" or d.get("optional")
]
if bad:
    print(
        "granary-vfs's manifest declares a dependency edge other than a single non-optional "
        "granary-core: " + ", ".join(bad)
    )
    sys.exit(1)
# The SET of names was checked above (every entry IS
# named granary-core, non-optional) but the COUNT never was — declaring
# granary-core under BOTH [dependencies] and [dev-dependencies] yields
# TWO entries here (kind="normal" and kind="dev"), both pass the filter
# above untouched, and a success message rendering "({len(deps)}
# edge/edges)" would print that number with nothing comparing it to 1 —
# a printed-but-unchecked figure. Assert it.
if len(deps) != 1:
    kinds = ", ".join(f"kind={d.get('kind') or 'normal'}" for d in deps)
    print(
        f"granary-vfs's manifest declares granary-core {len(deps)} times across dependency "
        f"kinds ({kinds}) — exactly ONE edge is required, not merely 'every edge present is "
        "named granary-core'"
    )
    sys.exit(1)
print("granary-vfs's manifest declares exactly granary-core, non-optional, across all kinds (1 edge)")
PYEOF
)"
  rc=$?
  set -e
  rm -f "$meta_file"
  if [[ "$rc" -eq 2 ]]; then
    echo "vfs-deps: arm 5 could not be checked — refused, never treated as clean:" >&2
    echo "$out" >&2
    exit 2
  fi
  if [[ "$rc" -eq 1 ]]; then
    echo "vfs-deps: arm 5 FAILED — $out; a direct edge to a package already inside granary-core's own closure — normal, dev, or build — adds nothing to arm 2's one-directional package-NAME set difference and passes it clean regardless: set inclusion cannot enforce parentage" >&2
    return 1
  fi
  echo "vfs-deps: arm 5 ok — $out"
  return 0
}

# ---------------------------------------------------------- scratch fixtures
# populate_scratch_vfs_deps <tmp-root>
# A minimal single-member workspace depending on the real granary-core by
# path — dependency-closure checks read the MANIFEST graph, not the
# source, so an empty src/lib.rs is enough. Each self-test control layers
# one extra manifest/source change on top before running the arm under
# test. Every control below stays fully local (path dependencies only,
# never a registry crate) so none of this needs network access.
populate_scratch_vfs_deps() {
  local root="$1"
  mkdir -p "$root/vfscopy/src"
  : > "$root/vfscopy/src/lib.rs"
  vfs_write_scratch_manifests "$root"
}

# ------------------------------------------------------------- self-test: 1
selftest_arm1() {
  local tmp out rc

  out="$(arm1_report "$VFS_MANIFEST" --locked)" || {
    echo "self-test FAILED: arm 1 did not pass against the real, unmodified $VFS_MANIFEST" >&2
    exit 2
  }
  echo "self-test: control arm1-positive — $out"

  tmp="$(mktemp -d)"
  _vfs_deps_track "${tmp}"
  populate_scratch_vfs_deps "$tmp"

  # Confirm the fixture is clean BEFORE the mutation — the whole
  # discrimination below rests on the build.rs being what flips this
  # from ok to refused, so if the unmutated scratch fixture already
  # fails (e.g. a manifest gap cargo-deny's licence policy catches
  # regardless of build.rs), the control proves nothing about build
  # scripts at all.
  out="$(arm1_report "$tmp/vfscopy/Cargo.toml" --offline 2>&1)" || {
    echo "self-test BROKEN: control arm1-build-script's fixture is not clean BEFORE the mutation — cargo-deny already refuses it for an unrelated reason, so the mutation below cannot be shown to cause the refusal" >&2
    echo "$out" >&2
    rm -rf "$tmp"
    exit 2
  }

  # Cargo auto-detects a file literally named build.rs at the crate root
  # — no manifest edit needed for it to become the package's build
  # script.
  cat > "$tmp/vfscopy/build.rs" <<'EOF'
fn main() {}
EOF
  set +e
  out="$(arm1_report "$tmp/vfscopy/Cargo.toml" --offline 2>&1)"
  rc=$?
  set -e
  rm -rf "$tmp"
  if [[ "$rc" -eq 0 ]]; then
    echo "self-test FAILED: control arm1-build-script — a build.rs added directly to granary-vfs was NOT refused" >&2
    echo "$out" >&2
    exit 2
  fi
  # The distinctive cargo-deny diagnostic code, not a bare 'build'
  # substring — cargo-deny also prints "build" for [bans.build]
  # diagnostics on OTHER crates, build-dependencies bans, and "could
  # not build [...] metadata", none of which say THIS package's own
  # build script was refused.
  if ! grep -q 'build-script-not-allowed' <<<"$out"; then
    echo "self-test FAILED: control arm1-build-script refused, but not with the build-script-not-allowed diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control arm1-build-script — a build.rs added directly to granary-vfs (no exception names it, unlike blake3/libc) is refused"
}

# ------------------------------------------------------------- self-test: 2
selftest_arm2() {
  local tmp extra_root out rc

  out="$(arm2_report "" granary-vfs --locked)" || {
    echo "self-test FAILED: arm 2 did not pass against the real, tracked granary-vfs" >&2
    exit 2
  }
  echo "self-test: control arm2-positive — $out"

  tmp="$(mktemp -d)"
  _vfs_deps_track "${tmp}"
  extra_root="$(mktemp -d)"
  _vfs_deps_track "${extra_root}"
  populate_scratch_vfs_deps "$tmp"
  # A brand-new, fully local, zero-dependency crate — outside the scratch
  # workspace's own directory tree (so cargo never treats it as an
  # unlisted member), not part of granary-core's tree, and not fetched
  # from any registry. Innocuous and unbanned: arm 1's ban list has no
  # opinion on it at all, which is exactly the escape arm 2 exists to
  # catch on its own.
  mkdir -p "$extra_root/zz_extra_dep/src"
  : > "$extra_root/zz_extra_dep/src/lib.rs"
  cat > "$extra_root/zz_extra_dep/Cargo.toml" <<EOF
[package]
name = "zz-extra-dep"
version = "0.0.1"
edition = "$WS_EDITION"
rust-version = "$WS_RUST_VERSION"
publish = false
EOF
  printf 'zz-extra-dep = { path = "%s/zz_extra_dep" }\n' "$extra_root" >> "$tmp/vfscopy/Cargo.toml"
  set +e
  out="$(arm2_report "$tmp/vfscopy/Cargo.toml" granary-vfs --offline 2>&1)"
  rc=$?
  set -e
  rm -rf "$tmp" "$extra_root"
  if [[ "$rc" -eq 0 ]]; then
    echo "self-test FAILED: control arm2-extra-dep — an extra dependency (zz-extra-dep, not in granary-core's tree and not on any ban list) was NOT refused" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'zz-extra-dep' <<<"$out"; then
    echo "self-test FAILED: control arm2-extra-dep refused, but did not name the extra dependency" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control arm2-extra-dep — a genuinely new dependency (zz-extra-dep — innocuous, unbanned, and absent from granary-core's own tree) is caught by the one-directional tree diff even though arm 1's ban list has no opinion on it"
}

# ------------------------------------------------------------- self-test: 3
selftest_arm3() {
  local tmp pm_root out rc

  out="$(arm3_report "" granary-vfs --locked)" || {
    echo "self-test FAILED: arm 3 did not pass against the real, tracked granary-vfs" >&2
    exit 2
  }
  echo "self-test: control arm3-positive — $out"

  tmp="$(mktemp -d)"
  _vfs_deps_track "${tmp}"
  pm_root="$(mktemp -d)"
  _vfs_deps_track "${pm_root}"
  populate_scratch_vfs_deps "$tmp"
  # A fully local proc-macro crate — zero registry access needed.
  mkdir -p "$pm_root/zz_scratch_proc_macro/src"
  cat > "$pm_root/zz_scratch_proc_macro/Cargo.toml" <<EOF
[package]
name = "zz-scratch-proc-macro"
version = "0.0.1"
edition = "$WS_EDITION"
rust-version = "$WS_RUST_VERSION"
publish = false

[lib]
proc-macro = true
EOF
  cat > "$pm_root/zz_scratch_proc_macro/src/lib.rs" <<'EOF'
extern crate proc_macro;
EOF
  printf 'zz-scratch-proc-macro = { path = "%s/zz_scratch_proc_macro" }\n' "$pm_root" >> "$tmp/vfscopy/Cargo.toml"
  set +e
  out="$(arm3_report "$tmp/vfscopy/Cargo.toml" granary-vfs --offline 2>&1)"
  rc=$?
  set -e
  rm -rf "$tmp" "$pm_root"
  if [[ "$rc" -eq 0 ]]; then
    echo "self-test FAILED: control arm3-proc-macro — a proc-macro dependency was NOT refused" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control arm3-proc-macro — a proc-macro dependency (fully local, zero registry access) is caught by the normal+dev vs normal+dev+no-proc-macro tree diff: $out"
}

# ------------------------------------------------------- self-test: 3 (empty)
# Arm 3's equality check had no non-empty guard — a
# `cargo tree` that exits 0 while printing NOTHING makes both pm_set and
# nopm_set empty, the inequality false, and the gate print "ok" having
# compared nothing. check-core-purity.sh's own `[ -s $tree_full ]` guards
# exactly this shape for granary-core; arm 3 lacked its counterpart.
selftest_arm3_empty_tree() {
  local tmp fake_bin real_cargo out rc probe_out probe_rc

  real_cargo="$(command -v cargo)"
  tmp="$(mktemp -d)"
  _vfs_deps_track "${tmp}"
  fake_bin="$tmp/bin"
  mkdir -p "$fake_bin"
  # A `cargo` stand-in that answers `tree` with exit 0 and NO output —
  # the exact shape the finding names — and defers every other
  # subcommand to the real binary untouched.
  cat > "$fake_bin/cargo" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == "tree" ]]; then
  exit 0
fi
exec "$real_cargo" "\$@"
EOF
  chmod +x "$fake_bin/cargo"

  # Confirm the fixture itself does what it claims BEFORE trusting the
  # refusal below — a mutation that fails to apply looks identical to
  # one that passed.
  set +e
  probe_out="$(PATH="$fake_bin:$PATH" cargo tree -p granary-vfs 2>&1)"
  probe_rc=$?
  set -e
  if [[ "$probe_rc" -ne 0 || -n "$probe_out" ]]; then
    echo "self-test BROKEN: control arm3-empty-tree's fake 'cargo tree' did not exit 0 with empty output as intended (rc=$probe_rc, out=${probe_out:-<none>})" >&2
    rm -rf "$tmp"
    exit 2
  fi

  set +e
  out="$(PATH="$fake_bin:$PATH" arm3_report "" granary-vfs --locked 2>&1)"
  rc=$?
  set -e
  rm -rf "$tmp"
  if [[ "$rc" -ne 2 ]]; then
    echo "self-test FAILED: control arm3-empty-tree — a 'cargo tree' that exits 0 while printing nothing was NOT refused with rc=2 (got rc=$rc) — comparing two equal empty sets must never read as clean" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -qi 'printed nothing' <<<"$out"; then
    echo "self-test FAILED: control arm3-empty-tree refused, but did not name the empty-output hazard" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control arm3-empty-tree — a 'cargo tree' that exits 0 while printing NOTHING is refused (rc=2, could-not-run), not compared as two equal empty sets and read as clean"
}

# ------------------------------------------------------------- self-test: 4
selftest_arm4() {
  local tmp out rc

  out="$(arm4_report "" --locked)" || {
    echo "self-test FAILED: arm 4 did not pass against the real, tracked granary-vfs" >&2
    exit 2
  }
  echo "self-test: control arm4-positive — $out"

  # A feature-gated COMPILE ERROR — invisible to a default-features
  # build (cfg excludes the item entirely) and caught only once
  # --all-features turns the feature on. The tracked crate declares no
  # [features] table today, so this uses a scratch fixture rather than
  # editing the real manifest, same as every other planted red in this
  # file.
  tmp="$(mktemp -d)"
  _vfs_deps_track "${tmp}"
  populate_scratch_vfs_deps "$tmp"
  cat >> "$tmp/vfscopy/Cargo.toml" <<'EOF'

[features]
zz_extra = []
EOF
  cat >> "$tmp/vfscopy/src/lib.rs" <<'EOF'

#[cfg(feature = "zz_extra")]
fn zz_feature_gated_break() -> u32 {
    zz_nonexistent_fn()
}
EOF
  # Confirm the DEFAULT build stays green first — the whole point of
  # this control is that a default-features check cannot see this
  # break at all, so if it already failed here the fixture would be
  # broken (not exercising what arm 4 exists for).
  out="$(cargo check --manifest-path "$tmp/vfscopy/Cargo.toml" -p granary-vfs --offline 2>&1)" || {
    echo "self-test BROKEN: control arm4-feature-impurity's fixture fails to compile under DEFAULT features — it must compile clean there and break only under --all-features" >&2
    echo "$out" >&2
    rm -rf "$tmp"
    exit 2
  }
  set +e
  out="$(arm4_report "$tmp/vfscopy/Cargo.toml" --offline 2>&1)"
  rc=$?
  set -e
  rm -rf "$tmp"
  if [[ "$rc" -eq 0 ]]; then
    echo "self-test FAILED: control arm4-feature-impurity — a feature-gated compile error was NOT refused by --all-features (it would hide behind a default-features check forever)" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'zz_nonexistent_fn' <<<"$out"; then
    echo "self-test FAILED: control arm4-feature-impurity refused, but did not name the broken item" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control arm4-feature-impurity — a feature-gated compile error, invisible to a default-features build (cfg excludes it entirely), is caught once --all-features turns the feature on"
}

# ------------------------------------------------------------- self-test: 5
selftest_arm5() {
  local tmp out rc

  out="$(arm5_report "$VFS_MANIFEST" --locked)" || {
    echo "self-test FAILED: arm 5 did not pass against the real, tracked $VFS_MANIFEST" >&2
    exit 2
  }
  echo "self-test: control arm5-positive — $out"

  # A SECOND direct edge to a package ALREADY inside granary-core's own
  # closure — the exact false negative arm 2's package-NAME set
  # difference cannot see: granary-core's own tree
  # already contains `cfg-if` (EXECUTED:
  # `cargo tree -p granary-core -e normal,dev --target all
  # --all-features` lists it), so a direct granary-vfs -> cfg-if edge
  # adds NOTHING to arm 2's one-directional diff — arm 2 stays green.
  # Arm 5 must catch it anyway: it reads the MANIFEST'S OWN declared
  # edges, not the resolved tree's package-name set.
  tmp="$(mktemp -d)"
  _vfs_deps_track "${tmp}"
  populate_scratch_vfs_deps "$tmp"
  printf 'cfg-if = "1"\n' >> "$tmp/vfscopy/Cargo.toml"
  set +e
  out="$(arm5_report "$tmp/vfscopy/Cargo.toml" --offline 2>&1)"
  rc=$?
  set -e
  rm -rf "$tmp"
  if [[ "$rc" -eq 0 ]]; then
    echo "self-test FAILED: control arm5-second-edge — a second direct dependency (cfg-if, already inside granary-core's own closure) was NOT refused" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'cfg-if' <<<"$out"; then
    echo "self-test FAILED: control arm5-second-edge refused, but did not name the second edge (cfg-if)" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control arm5-second-edge — a second direct dependency (cfg-if — already inside granary-core's own closure, so INVISIBLE to arm 2's set difference whether normal or dev) is caught by reading the manifest's own declared edges directly: $out"

  # DUPLICATE granary-core edge: the SAME dependency
  # declared under BOTH [dependencies] and [dev-dependencies] yields TWO
  # entries in cargo metadata's own `dependencies` array for the
  # package — one kind=normal, one kind=dev — and BOTH are named
  # granary-core, non-optional, so the name/optional filter alone passes
  # both clean. Only a COUNT check catches this.
  tmp="$(mktemp -d)"
  _vfs_deps_track "${tmp}"
  populate_scratch_vfs_deps "$tmp"
  python3 - "$tmp/vfscopy/Cargo.toml" <<'PYEOF'
import re
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
pattern = re.compile(r'^granary-core = \{ path = "([^"]*)" \}$', re.MULTILINE)
matches = list(pattern.finditer(text))
if len(matches) != 1:
    print(f"self-test fixture BROKEN: expected exactly one granary-core dependency line, found {len(matches)}", file=sys.stderr)
    sys.exit(2)
m = matches[0]
path_value = m.group(1)
with open(path, "a", encoding="utf-8") as f:
    f.write(f'\n[dev-dependencies]\ngranary-core = {{ path = "{path_value}" }}\n')
PYEOF
  if [[ "$(grep -c '^\[dev-dependencies\]$' "$tmp/vfscopy/Cargo.toml")" -ne 1 ]]; then
    echo "self-test BROKEN: control arm5-duplicate-edge's mutation did not apply — no [dev-dependencies] section found" >&2
    rm -rf "$tmp"
    exit 2
  fi
  set +e
  out="$(arm5_report "$tmp/vfscopy/Cargo.toml" --offline 2>&1)"
  rc=$?
  set -e
  rm -rf "$tmp"
  if [[ "$rc" -eq 0 ]]; then
    echo "self-test FAILED: control arm5-duplicate-edge — granary-core declared under BOTH [dependencies] and [dev-dependencies] (two edges, both non-optional and named granary-core) was NOT refused" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'kind=normal' <<<"$out" || ! grep -q 'kind=dev' <<<"$out"; then
    echo "self-test FAILED: control arm5-duplicate-edge refused, but did not name both edge kinds" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control arm5-duplicate-edge — granary-core declared twice (once normal, once dev) is refused on the EDGE COUNT, not merely the edge names: $out"

  # OPTIONAL granary-core, kept as its ONLY named dependency — a
  # manifest-level property arm 2 (which diffs the RESOLVED tree, and an
  # optional dependency's package still resolves into the tree once
  # anything at all turns its feature on) has no particular reason to
  # see either.
  tmp="$(mktemp -d)"
  _vfs_deps_track "${tmp}"
  populate_scratch_vfs_deps "$tmp"
  python3 - "$tmp/vfscopy/Cargo.toml" <<'PYEOF'
import re
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
pattern = re.compile(r'^granary-core = \{ path = "([^"]*)" \}$', re.MULTILINE)
matches = list(pattern.finditer(text))
if len(matches) != 1:
    print(f"self-test fixture BROKEN: expected exactly one granary-core dependency line, found {len(matches)}", file=sys.stderr)
    sys.exit(2)
m = matches[0]
replacement = f'granary-core = {{ path = "{m.group(1)}", optional = true }}'
open(path, "w", encoding="utf-8").write(text[: m.start()] + replacement + text[m.end() :])
PYEOF
  if ! grep -q 'optional = true' "$tmp/vfscopy/Cargo.toml"; then
    echo "self-test BROKEN: control arm5-optional's mutation did not apply" >&2
    rm -rf "$tmp"
    exit 2
  fi
  set +e
  out="$(arm5_report "$tmp/vfscopy/Cargo.toml" --offline 2>&1)"
  rc=$?
  set -e
  rm -rf "$tmp"
  if [[ "$rc" -eq 0 ]]; then
    echo "self-test FAILED: control arm5-optional — granary-core marked 'optional = true', still the crate's only NAMED dependency, was NOT refused" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'optional=True' <<<"$out"; then
    echo "self-test FAILED: control arm5-optional refused, but did not name the optional flag" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control arm5-optional — granary-core marked 'optional = true' (still its only declared name, but no longer an unconditional edge) is refused: $out"
}

# ------------------------------------------------------- self-test: stay-in-step
selftest_stay_in_step() {
  local tmp out rc

  out="$(check_tree_flags_match_core "scripts/check-core-purity.sh")" || {
    echo "self-test FAILED: stay-in-step check did not pass against the real, unmodified scripts/check-core-purity.sh" >&2
    exit 2
  }
  echo "self-test: control stay-in-step-positive — $out"

  tmp="$(mktemp -d)"
  _vfs_deps_track "${tmp}"
  cp scripts/check-core-purity.sh "$tmp/check-core-purity.sh"
  # Mutate ONE flag on the "full" tree call — a divergence exactly like
  # the one H3/H4 found (arm 3's guard, layer 2) going unnoticed if this
  # gate started diffing a different target set than granary-core's.
  python3 - "$tmp/check-core-purity.sh" <<'PYEOF'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
needle = "cargo tree --locked -p granary-core -e normal,dev --target all \\\n  --all-features --prefix none > \"$tree_full\""
replacement = "cargo tree --locked -p granary-core -e normal,dev --target host \\\n  --all-features --prefix none > \"$tree_full\""
if text.count(needle) != 1:
    print(f"self-test fixture BROKEN: expected exactly one occurrence of the full tree-flags line, found {text.count(needle)}", file=sys.stderr)
    sys.exit(2)
open(path, "w", encoding="utf-8").write(text.replace(needle, replacement))
PYEOF
  if ! grep -q -- '--target host' "$tmp/check-core-purity.sh"; then
    echo "self-test BROKEN: control stay-in-step-drift's mutation did not apply" >&2
    rm -rf "$tmp"
    exit 2
  fi
  set +e
  out="$(check_tree_flags_match_core "$tmp/check-core-purity.sh" 2>&1)"
  rc=$?
  set -e
  rm -rf "$tmp"
  if [[ "$rc" -eq 0 ]]; then
    echo "self-test FAILED: control stay-in-step-drift — a --target flag changed from 'all' to 'host' in the (scratch copy of) check-core-purity.sh was NOT caught" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'MISMATCH full' <<<"$out"; then
    echo "self-test FAILED: control stay-in-step-drift refused, but did not name the mismatched 'full' arm" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control stay-in-step-drift — a --target flag drifting between the two scripts (all -> host, on a scratch copy of check-core-purity.sh) is caught rather than staying silent: $out"

  # DIAGNOSTIC-LINE FALSE POSITIVE: check-core-purity.sh
  # carries `echo "ERROR: empty cargo tree output (full)"` — a line whose
  # own TEXT contains the substring "cargo tree", stopping at that line's
  # `>&2` exactly the way a real invocation's redirect stops the match.
  # Before the anchor fix, `full_calls[0]` was correct only because the
  # two real invocations happen to sit ABOVE those diagnostics in the
  # file; this control puts an EARLIER "cargo tree" mention (a plain
  # comment) before the real invocations on a scratch copy and confirms
  # the comparison still resolves the REAL flags, not the diagnostic's.
  tmp="$(mktemp -d)"
  _vfs_deps_track "${tmp}"
  cp scripts/check-core-purity.sh "$tmp/check-core-purity.sh"
  python3 - "$tmp/check-core-purity.sh" <<'PYEOF'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
needle = "set -euo pipefail\n"
if text.count(needle) != 1:
    print(f"self-test fixture BROKEN: expected exactly one occurrence of {needle!r}, found {text.count(needle)}", file=sys.stderr)
    sys.exit(2)
# An EARLIER mention of "cargo tree" that is not a real invocation at
# all — a plain comment, matching neither TREE_FLAGS nor TREE_FLAGS_NOPM
# — placed well above the two real `cargo tree` calls this file diffs.
replacement = needle + "# see the cargo tree tips in the project wiki for background\n"
open(path, "w", encoding="utf-8").write(text.replace(needle, replacement, 1))
PYEOF
  if ! grep -q 'cargo tree tips' "$tmp/check-core-purity.sh"; then
    echo "self-test BROKEN: control stay-in-step-diagnostic's mutation did not apply" >&2
    rm -rf "$tmp"
    exit 2
  fi
  set +e
  out="$(check_tree_flags_match_core "$tmp/check-core-purity.sh" 2>&1)"
  rc=$?
  set -e
  rm -rf "$tmp"
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: control stay-in-step-diagnostic — an EARLIER, non-invocation mention of 'cargo tree' (a plain comment) made the comparison MISFIRE (rc=$rc) against a scratch copy whose real flags are otherwise unchanged; the extraction is still anchored to something a diagnostic or a comment can match" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control stay-in-step-diagnostic — an earlier, non-invocation 'cargo tree' mention (a comment placed above the real calls, and check-core-purity.sh's own 'empty cargo tree output' diagnostics further down) does not confuse the extraction: it is anchored to the START of a line, which neither ever is"
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
  selftest_arm1
  selftest_arm2
  selftest_arm3
  selftest_arm3_empty_tree
  selftest_arm4
  selftest_arm5
  selftest_stay_in_step
  selftest_argv_guard
  echo "vfs-deps self-test: every control behaved as predicted — a build.rs added directly to granary-vfs is refused (arm 1), a genuinely new dependency outside granary-core's tree is caught by the one-directional diff even though it is not banned by anything (arm 2), a local proc-macro dependency is caught by the no-proc-macro diff (arm 3), a 'cargo tree' that exits 0 while printing nothing is refused rather than compared as two equal empty sets (arm 3's non-empty guard), a feature-gated compile error invisible to a default-features build is caught by an isolated --all-features check (arm 4, check-core-purity.sh's own mechanism 2, carried over), a second direct edge to a package already inside granary-core's own closure AND an optional granary-core are both caught by reading the manifest's own declared dependencies directly, where arm 2's resolved-tree diff sees neither (arm 5), and a tree-flag drift between this script and check-core-purity.sh — or an earlier, non-invocation 'cargo tree' mention confusing the extraction — is caught rather than staying silent (the stay-in-step tripwire)"
  exit 0
fi

stay_in_step_out="$(check_tree_flags_match_core "scripts/check-core-purity.sh")"
arm1_out="$(arm1_report "$VFS_MANIFEST" --locked)"
arm2_out="$(arm2_report "" granary-vfs --locked)"
arm3_out="$(arm3_report "" granary-vfs --locked)"
arm4_out="$(arm4_report "" --locked)"
arm5_out="$(arm5_report "$VFS_MANIFEST" --locked)"
echo "$stay_in_step_out"
echo "$arm1_out"
echo "$arm2_out"
echo "$arm3_out"
echo "$arm4_out"
echo "$arm5_out"
echo "vfs-deps: ok — crates/granary-vfs's manifest carries no banned crate and no unauthorized build script (arm 1), its whole dependency tree is granary-core's plus itself (arm 2), it carries no proc-macro (arm 3), it compiles cleanly in isolation with --all-features (arm 4), its manifest names exactly granary-core, non-optional, across every dependency kind (arm 5), and this gate's own tree-diff flags still match check-core-purity.sh's"
