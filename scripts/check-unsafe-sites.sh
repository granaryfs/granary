#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# The workspace forbids `unsafe_code`. A crate may be licensed to `deny` it
# instead, for EXACTLY the sites the table below names and NOTHING beyond
# them. That is a normative claim about the tree, and until this gate existed
# nothing checked it: the count went stale in the prose while the code moved,
# and a further site could appear with no gate noticing.
#
# This asserts each licensed crate's count, and asserts that NO crate outside
# the table diverges from the workspace's `unsafe_code = "forbid"`.
#
#   scripts/check-unsafe-sites.sh              run the gate
#   scripts/check-unsafe-sites.sh --self-test  prove it can fail
set -euo pipefail

# ARGUMENT VALIDATION. An argv that is not exactly
# `--self-test` must not fall through to the real gate and
# exit 0 — if it did, `check-unsafe-sites.sh self-test`
# (dashes dropped) would print a GREEN verdict having run ZERO
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
# adding a new shared file for it is the trade check-vfs-root-shape.sh's
# "git-floor duplication tripwire" section declines for its own pair. The
# red that guards it is `selftest_argv_guard` in the three vfs gates.
if [[ $# -gt 1 || ( $# -eq 1 && "${1:-}" != "--self-test" ) ]]; then
  echo "unsafe-sites: unrecognised argument(s): $* — the only accepted form is '--self-test' (or no argument, to run the gate). Refused rather than silently running the gate and reporting green." >&2
  exit 2
fi


# THE LICENSED CRATES, AS A TABLE — `<crate>:<sites>`. The licence to `deny`
# rather than forbid is granted per crate, and this table is both halves
# of it in one place: which crates may diverge from the workspace
# `unsafe_code = "forbid"`, and how many `#[expect(unsafe_code)]` sites each
# is licensed for. It was two scalars (`EXPECTED=5`, `CRATE=…client/src`) with
# the crate name also spelled into the exclusivity check below, so a second
# licensed crate could not be expressed at all — which the `granary-cli`
# extraction needed. It has TWO rows since that landed; while it had
# one, the table was the mechanism, landed and self-tested before it was
# needed, and no control reading the real table could tell a whole-table
# loop from a first-row loop.
UNSAFE_LICENSED_CRATES=(
  # 5 -> 3 at the granary-cli extraction: the two main.rs sites went with the
  # binary. The table is why this is one line per crate rather than a rewrite
  # — the set mechanism and its five controls landed on a stable tree, before
  # the tree moved.
  "granary-client:6"   # cache x3, Apple extended ACL x1, descriptor-relative archive no-replace rename x2 (Linux syscall/macOS renameatx_np)
  "granary-cli:1"      # the process-credential/set-ID-taint snapshot
)

# An EMPTY table is a refusal, not a run. Under `set -u` on bash 3.2 — the
# macOS system shell, which this script is run with — `"${arr[@]}"` on an
# empty array is an UNBOUND VARIABLE, so emptying the table would kill the
# gate with "UNSAFE_LICENSED_CRATES[@]: unbound variable" instead of saying
# what is wrong. The condition is legitimate to check for its own sake as
# well: a table with no rows licenses nothing, and silently running a gate
# that checks nothing is the shape this repository refuses everywhere else.
if [[ ${#UNSAFE_LICENSED_CRATES[@]} -eq 0 ]]; then
  echo "unsafe-sites: UNSAFE_LICENSED_CRATES is empty — no crate is licensed to diverge from the workspace 'unsafe_code = \"forbid\"'. Licensing one is a deliberate change to this table, and an empty table is not it." >&2
  exit 2
fi

# MATCHED ON THE FULL PATH, never on the crate name as a substring, and this
# is not a style preference. `granary-cli` is a proper string PREFIX of
# `granary-client` (`echo crates/granary-client/Cargo.toml | grep -c granary-cli`
# prints 1), so a membership test written as a substring match would accept
# BOTH the day the second row lands — and the exclusivity check below would
# then pass on the crate it exists to refuse. Every comparison here is `==`
# against the assembled path.
licensed_manifest() {
  local m="$1" row
  for row in "${UNSAFE_LICENSED_CRATES[@]}"; do
    [[ "$m" == "crates/${row%%:*}/Cargo.toml" ]] && return 0
  done
  return 1
}

# RECURSIVE. A command shaped as `grep -r dir/*.rs` expands the glob in the
# SHELL, so `-r` never sees a directory and every `.rs` file under a
# SUBDIRECTORY is invisible to it. The fail-open is the
# quiet direction: moving a LICENSED site into `src/cache/` makes the count
# fall and the gate shouts, but a NEW unsafe site added under `src/cache/`
# would never be counted at all, and this gate's whole purpose is to notice a
# site nobody licensed.
#
# `grep -Hc`, AND THE `-H` IS LOad-BEARING. `find … -exec grep -c … +` hands
# grep one argument list; when that list holds exactly ONE file, grep omits
# the filename and prints a bare count, so `awk -F: '{s+=$2}'` sums an absent
# field two and the function returns 0. EXECUTED against a directory holding
# only `main.rs`: **0 without `-H`, 2 with it.** Dormant today because every
# scanned crate has many files — and armed the moment a scanned crate has
# one, which is exactly the shape a freshly extracted binary crate has. Control
# S below is that case.
#
# `|| true`, AND IT IS AS LOAD-BEARING AS THE `-H`. `grep` exits 1 when it
# selects no lines, `find -exec … +` propagates that, and under
# `set -euo pipefail` the whole gate then dies with NO OUTPUT AT ALL — not a
# refusal, an abort that reads in CI as a failure naming nothing. It fires in
# two ways: a licensed row whose `src/` carries no site YET (`<crate>:0`, the
# transitional shape of a freshly extracted crate), and — nondeterministically
# — whenever `find` splits its argument list and one BATCH happens to hold no
# match, which makes it argv-size dependent and able to differ between a dev
# shell and CI. Both `name_sites` and the counting half require `|| true`.
# Control E is the red.
#
# The directory check is not decoration: with `|| true` in place, a scan root
# that does not exist would otherwise count 0 silently, and 0 is a legitimate
# expected value. A missing root is REFUSED, never counted.
count_sites() {
  local dir="$1"
  if [[ ! -d "$dir" ]]; then
    echo "unsafe-sites: scan root '$dir' is not a directory — refusing rather than counting zero, because zero is a legitimate licensed count and the two must stay distinguishable." >&2
    return 2
  fi
  { find "$dir" -name '*.rs' -exec grep -Hc '^[[:space:]]*unsafe_code,$' {} + || true; } \
    | awk -F: '{s+=$2} END {print s+0}'
}

# The DIAGNOSTIC half takes `-H` for the same reason: with one file `grep -n`
# prints line numbers and no path, so a gate that fired would refuse to name
# the file. Fixing the count and leaving its explanation behind is the
# fix-by-site control N below guards against.
name_sites() { find "$1" -name '*.rs' -exec grep -Hn -B1 '^[[:space:]]*unsafe_code,$' {} + | grep 'expect(' || true; }

# Nothing outside the licensed set may relax the workspace forbid. Takes a
# ROOT so the self-test can plant a stray crate in a fixture tree instead of
# in the real one. Control X is the positive control.
check_exclusivity() {
  local root="$1" line m stray=""
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    m="${line%%:*}"
    licensed_manifest "${m#"$root/"}" || stray+="$line"$'\n'
  done < <(grep -rn 'unsafe_code' "$root"/crates/*/Cargo.toml 2>/dev/null || true)
  [[ -z "$stray" ]] && return 0
  printf '%s' "$stray" >&2
  return 1
}

if [[ "${1:-}" == "--self-test" ]]; then
  # Positive control: a gate with no demonstrated failure mode is not a gate.
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

  # THE COUNTING CONTROLS RUN PER ROW, not against one hard-coded crate, so a
  # second licensed crate gets the same two proofs the first one has rather
  # than riding on them.
  for row in "${UNSAFE_LICENSED_CRATES[@]}"; do
    crate="${row%%:*}"; expected="${row##*:}"
    fx="$tmp/count/$crate"; mkdir -p "$fx"
    # `cp -R` of the DIRECTORY, not a flat glob: the fixture's baseline is the
    # real crate's site count, so once `src/` gains a subdirectory a flat copy
    # would seed a fixture missing those files and the self-test would assert
    # against the wrong baseline.
    cp -R "crates/$crate/src"/. "$fx/"
    base="$(count_sites "$fx")"
    if [[ "$base" -ne "$expected" ]]; then
      echo "unsafe-sites self-test FAILED: $crate's fixture baseline is $base, the table says $expected — the fixture and the table disagree before anything is planted" >&2; exit 2
    fi
    printf '#[expect(\n    unsafe_code,\n    reason = "self-test"\n)]\nfn planted() {}\n' > "$fx/planted.rs"
    got="$(count_sites "$fx")"
    if [[ "$got" -ne $((expected + 1)) ]]; then
      echo "unsafe-sites self-test FAILED: planted a site in $crate, counted $got (want $((expected + 1)))" >&2; exit 2
    fi
    echo "unsafe-sites self-test: a planted site in $crate is counted ($got) — the gate can fail"

    # AND THE SAME SITE ONE DIRECTORY DOWN, because that is the case the
    # recursive scan must see and the one a module split creates.
    rm -f "$fx/planted.rs"
    mkdir -p "$fx/child"
    printf '#[expect(\n    unsafe_code,\n    reason = "self-test, one directory down"\n)]\nfn planted_deeper() {}\n' > "$fx/child/planted.rs"
    got="$(count_sites "$fx")"
    if [[ "$got" -ne $((expected + 1)) ]]; then
      echo "unsafe-sites self-test FAILED: a site in a SUBDIRECTORY of $crate was not counted (got $got, want $((expected + 1))). A module split would disarm this gate." >&2; exit 2
    fi
    echo "unsafe-sites self-test: a site one directory down in $crate is counted ($got) — a module split cannot blind the gate"
  done

  # CONTROL S — THE SINGLE-FILE SCAN ROOT, and this one has a RED against the
  # form it replaced. `find … -exec grep -c … +` on a directory holding ONE
  # `.rs` file makes grep omit the filename, so the `awk -F:` sum reads an
  # absent field two and returns 0. This control counts 2 and fails at 0,
  # which is exactly what the pre-`-H` form returns. It is not hypothetical:
  # a freshly extracted binary crate has precisely this shape.
  mkdir -p "$tmp/solo"
  printf '#[expect(\n    unsafe_code,\n    reason = "self-test, solo file A"\n)]\nfn a() {}\n#[expect(\n    unsafe_code,\n    reason = "self-test, solo file B"\n)]\nfn b() {}\n' > "$tmp/solo/only.rs"
  got="$(count_sites "$tmp/solo")"
  if [[ "$got" -ne 2 ]]; then
    echo "unsafe-sites self-test FAILED: control S — a scan root holding ONE .rs file counted $got, want 2. Without 'grep -H' this returns 0 and a single-file crate is scanned as if it were empty." >&2; exit 2
  fi
  echo "unsafe-sites self-test: control S — a single-file scan root counts correctly ($got); the -H that makes it so cannot be dropped silently"

  # CONTROL E — A SCAN ROOT WITH NO LICENSED SITE MUST COUNT 0, NOT ABORT.
  # `grep` exits 1 when it selects nothing and `find -exec … +` propagates it,
  # so without the `|| true` in `count_sites` this row kills the gate under
  # `set -e` with no output whatsoever — which is why it asserts on the VALUE
  # after a successful call rather than just on the value. A licensed row of
  # `<crate>:0` is the transitional shape of a freshly extracted crate, and the
  # batch-splitting form of the same fault is argv-size dependent.
  mkdir -p "$tmp/none"
  printf 'fn nothing_here() {}\n' > "$tmp/none/a.rs"
  if ! got="$(count_sites "$tmp/none")"; then
    echo "unsafe-sites self-test FAILED: control E — counting a scan root with no licensed site ABORTED instead of returning 0. grep exits 1 on no match and find propagates it; count_sites needs its '|| true'." >&2; exit 2
  fi
  if [[ "$got" -ne 0 ]]; then
    echo "unsafe-sites self-test FAILED: control E — a scan root with no licensed site counted $got, want 0" >&2; exit 2
  fi
  # And a root that does NOT EXIST is refused, not counted as 0 — the two must
  # stay distinguishable now that 0 is a legitimate licensed count.
  if count_sites "$tmp/no-such-root" >/dev/null 2>"$tmp/e.err"; then
    echo "unsafe-sites self-test FAILED: control E — a NONEXISTENT scan root was counted instead of refused. A renamed crate would then satisfy a licensed count of 0." >&2; exit 2
  fi
  echo "unsafe-sites self-test: control E — an empty scan root counts 0 without aborting, and a missing one is refused"

  # CONTROL N — THE DIAGNOSTIC HALF'S `-H`, which control S does not cover.
  # `name_sites` takes the same `-H` as `count_sites` and for the same reason,
  # but reverting it alone left the whole self-test green while a fired gate
  # printed `1-#[expect(` with no path on a single-file root. An uncontrolled
  # half of a two-part fix is the fix-by-site this script's own comment warns
  # about, one line below the warning.
  if ! name_sites "$tmp/solo" | grep -q 'only\.rs'; then
    echo "unsafe-sites self-test FAILED: control N — the DIAGNOSTIC half did not name the file on a single-file root. Without 'grep -H' a fired gate refuses to say which file it fired on. Got: $(name_sites "$tmp/solo" | head -1)" >&2; exit 2
  fi
  echo "unsafe-sites self-test: control N — the diagnostic names its file on a single-file root"

  # CONTROL X — THE EXCLUSIVITY CHECK'S FIRST POSITIVE CONTROL. It had none:
  # nothing proved it could refuse anything. A fixture tree with one licensed
  # crate and one stray must be refused, naming the stray and not the licensed.
  mkdir -p "$tmp/x/crates/granary-client" "$tmp/x/crates/granary-store"
  printf '[lints.rust]\nunsafe_code = "deny"\n' > "$tmp/x/crates/granary-client/Cargo.toml"
  printf '[package]\nname = "granary-store"\n'   > "$tmp/x/crates/granary-store/Cargo.toml"
  if ! check_exclusivity "$tmp/x" 2>"$tmp/x.err"; then
    echo "unsafe-sites self-test FAILED: control X negative half — a tree whose ONLY unsafe_code line is the licensed crate's was refused: $(cat "$tmp/x.err")" >&2; exit 2
  fi
  printf '[lints.rust]\nunsafe_code = "deny"\n' > "$tmp/x/crates/granary-store/Cargo.toml"
  if check_exclusivity "$tmp/x" 2>"$tmp/x.err"; then
    echo "unsafe-sites self-test FAILED: control X — an UNLICENSED crate setting unsafe_code was not refused" >&2; exit 2
  elif ! grep -q 'granary-store' "$tmp/x.err" || grep -q 'granary-client' "$tmp/x.err"; then
    echo "unsafe-sites self-test FAILED: control X refused, but named the wrong crate: $(cat "$tmp/x.err")" >&2; exit 2
  fi
  echo "unsafe-sites self-test: control X — an unlicensed crate is refused and named, the licensed one is not"

  # CONTROL P — THE PREFIX TRAP, and the DIRECTION of it is the whole point.
  # `granary-cli` is a proper string PREFIX of `granary-client`, so the string
  # that contains the other is `granary-client`. A substring membership test
  # therefore mis-accepts in exactly ONE direction: with `granary-cli` in the
  # licensed set, `crates/granary-client/Cargo.toml` CONTAINS `granary-cli`
  # and is waved through unlicensed. (Planted the other way round —
  # licensed client, stray cli — this control would PASS under a
  # deliberately substring-matching mutant, because `granary-cli` contains no
  # `granary-client`, and so would prove nothing. Only the mutant shows
  # that, and a control that survives its own mutant is not a control.)
  #
  # The set is overridden for this row alone and restored immediately: the
  # hazard only exists once `granary-cli` is licensed, which came with that
  # crate's extraction, and this control landed BEFORE it so the mechanism arrives
  # already proven.
  p_saved=("${UNSAFE_LICENSED_CRATES[@]}")
  UNSAFE_LICENSED_CRATES=("granary-cli:2")
  mkdir -p "$tmp/p/crates/granary-cli" "$tmp/p/crates/granary-client"
  printf '[lints.rust]\nunsafe_code = "deny"\n' > "$tmp/p/crates/granary-cli/Cargo.toml"
  printf '[package]\nname = "granary-client"\n'  > "$tmp/p/crates/granary-client/Cargo.toml"
  if ! check_exclusivity "$tmp/p" 2>"$tmp/p.err"; then
    echo "unsafe-sites self-test FAILED: control P negative half — a tree whose only unsafe_code line is the licensed granary-cli's was refused: $(cat "$tmp/p.err")" >&2; exit 2
  fi
  printf '[lints.rust]\nunsafe_code = "deny"\n' > "$tmp/p/crates/granary-client/Cargo.toml"
  if check_exclusivity "$tmp/p" 2>"$tmp/p.err"; then
    UNSAFE_LICENSED_CRATES=("${p_saved[@]}")
    echo "unsafe-sites self-test FAILED: control P — 'granary-client' was accepted on the strength of 'granary-cli' being licensed. The membership test is matching a SUBSTRING, not a path." >&2; exit 2
  elif ! grep -q 'granary-client/Cargo.toml' "$tmp/p.err"; then
    UNSAFE_LICENSED_CRATES=("${p_saved[@]}")
    echo "unsafe-sites self-test FAILED: control P refused but did not name granary-client: $(cat "$tmp/p.err")" >&2; exit 2
  fi
  UNSAFE_LICENSED_CRATES=("${p_saved[@]}")
  echo "unsafe-sites self-test: control P — 'granary-client' is refused while 'granary-cli' is licensed; a substring cannot pass for the path"
  exit 0
fi

summary=""
for row in "${UNSAFE_LICENSED_CRATES[@]}"; do
  crate="${row%%:*}"; expected="${row##*:}"
  got="$(count_sites "crates/$crate/src")"
  if [[ "$got" -ne "$expected" ]]; then
    echo "unsafe-sites: $crate has $got '#[expect(unsafe_code)]' sites; this gate's table licenses $expected." >&2
    name_sites "crates/$crate/src" >&2
    echo "  Adding or removing one changes a licensed unsafe surface: justify it, then update this gate's table deliberately." >&2
    exit 1
  fi
  summary="${summary:+$summary, }$crate $got"
done

# Nothing outside the licensed set may relax the workspace forbid. The stray
# list is captured in a VARIABLE, not a temp file: a predictable name under a
# world-writable /tmp opened with a truncating `>` is a symlink-follow that
# lets any local user zero a file of their choosing, and a PID is five digits
# and cheap to blanket. This repo's CI runs on shared self-hosted runners.
if ! stray="$(check_exclusivity "." 2>&1 >/dev/null)"; then
  echo "unsafe-sites: a crate outside the licensed set sets unsafe_code in its lint table:" >&2
  printf '%s\n' "$stray" >&2
  exit 1
fi

# The COUNTS stay in this line. A green line that says only "counts match"
# costs a reader the number they came for, and the number is the thing a
# reviewer checks against the table above.
echo "unsafe-sites: $summary licensed sites, matching this gate's table; no other crate diverges"
