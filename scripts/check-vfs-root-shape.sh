#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# The root-shape rule: `granary-vfs`'s crate root is NOT permanently frozen at its
# initially measured twenty items, but its SHAPE is: `crates/granary-vfs/src/
# lib.rs`'s crate scope may contain only attributes, a non-`pub` `extern
# crate`/`mod`/`use`, and a `pub use` of named leaves — the INDEX
# property this gate enforces: every public item of `granary-vfs`
# is named by exactly one line at the crate root. A SEPARATE, NEW script
# from `scripts/check-vfs-purity.sh` on purpose — that script's own
# header declares its subject as the `no_std` guarantee ("THREE ITEMS");
# folding a root-shape rule in there would recreate the banner conflation
# caused by putting a curated public-item census inside the no_std gate.
#
# WHAT THIS GATE IS, STATED PLAINLY:
# the literal-source limitations in this header bound what this gate claims.
# It is a LITERAL-SOURCE shape scanner over `lib.rs`'s crate scope — it
# catches the honest mistake and the careless one. It is **not** complete
# public-surface enforcement and does **not** resist a determined
# bypass: closing what it misses (a cfg-disabled module spoofing its own
# inventory, or a macro built to expand into the exact text it looks
# for) needs the compiler's own cfg-evaluation or macro-expansion
# answer, which a text scanner does not have. This is not a closed list
# — the literal-source limitations stated in this header describe what is
# caught deliberately and what is not, but are not a closed list.
#
# Nested decoy modules do not enter the
# crate-root module inventory.
# `_collect_root_module_names` walks depth
# zero and skips an inline module body as
# one block, so a nested module with the
# same name as an external crate cannot
# masquerade as a root module. A cfg-disabled
# root module can still affect the inventory
# because the scanner does not evaluate
# cfg. That limitation differs from nesting:
# the walk knows syntactic depth but not
# the compiler's active configuration.
#
# THIS IS AN ALLOW-LIST. A deny-list admits an unnamed
# construct unless it happens to match a known refusal.
# This gate instead recognises a closed set of root
# shapes and refuses unrecognised declarations. That
# matters for routes such as a public module, a public
# extern crate, a glob, or an item-position macro
# invocation: each can expose more than a named leaf.
# Root-shape scanning and the separate child-module
# macro-export scan cover different parts of that
# boundary. The allowed constructs and explicit
# exceptions determine what passes, rather than an
# assumption that every unlisted construct is harmless.
#
# Mechanism: PURE TEXT, on scripts/fsguard-scan.py's comment/string
# stripper and brace/attribute matching (via
# scripts/vfs-root-shape-scan.py, which imports it the same way
# scripts/vfs-purity-scan.py does — never a second, re-derived lexer). No
# cargo, no rustdoc, no `format_version`, no unstable flag: this runs in
# milliseconds and is silent on nothing it can read.
#
# TWO ARMS, run against the GATED CRATE SET — `granary-vfs` and
# `granary-fuse`. Never a workspace rule.
# The gated roots are indexes, but the enforced
# rule is a crate-scope allow-list. Private and
# crate-visible constructs matter as well as
# public exports. This is not a workspace-wide
# restriction: `root_allowlist` declares the
# exceptions for each gated crate, keeping each
# permitted root construct explicit rather than
# treating every existing construct as an exception.
#
#   ARM A — the allow-list walk of `lib.rs`'s crate scope, PLUS a
#   FIRST-SEGMENT check that a `pub use`'s path is
#   rooted in one of this crate's own root-level `mod` declarations
#   (never a foreign crate — refusing `pub use granary_core::manifest;`)
#   and a purely syntactic check that the bare, path-less spelling of a
#   whole-module re-export (`pub use snapshot;`, no `::` at all) is
#   refused too. See scripts/vfs-root-shape-scan.py's own header for the
#   exact grammar, including the GLOB route: closed here, by this gate's
#   own named-leaf check; workspace clippy configuration
#   provides an additional check. Compiler namespace
#   questions remain outside this text scan. An `impl`
#   inside a private inline module is deliberately
#   not checked because determining whether its `Self`
#   type is externally reachable requires compiler
#   resolution. With `snapshot` declared at the root, the gate accepts
#   `crate::snapshot`, `self::snapshot`, `crate::{snapshot}`, `{snapshot}`,
#   and `snapshot::sibling` as `pub use` bodies without resolving the leaf.
#   Bare `snapshot` and `snapshot::{self}` are refused. Controls plant
#   `snapshot::{Entry, ReaddirEntry}` and `snapshot::Snapshot`, which have
#   grouped and ungrouped named-leaf shapes. They do not plant the exact
#   `crate::snapshot`, `self::snapshot`, `crate::{snapshot}`, `{snapshot}`,
#   or `snapshot::sibling` spellings. The scanner does not distinguish
#   module leaves from item leaves.
#
#   ARM B — no `#[macro_export]` anywhere under
#   `crates/granary-vfs/src/`, not just in `lib.rs`. A `#[macro_export]
#   macro_rules!` defined in a CHILD module lands in the crate ROOT
#   namespace with zero lines changed in `lib.rs` — the one route ARM A
#   cannot see at all, because ARM A only ever reads `lib.rs`. **This arm
#   is an explicitly LITERAL-SOURCE defence, not a semantic closer.** It
#   matches the attribute's own TEXT, so it fails in both directions: a macro
#   built to EXPAND into `#[macro_export]` through an indirection like
#   `#[$attr] macro_rules! …; plant!(macro_export);` passes undetected, and —
#   the opposite error — a dormant macro TEMPLATE that merely CONTAINS the
#   literal `macro_export` inside a body it never expands is reported as
#   though it had exported something.
#
# WHAT THE COMPILER ALREADY HOLDS, so this gate does not have to: the
# `unreachable_pub` plus warnings-denied compiler backstop consists of the
# workspace's `unreachable_pub = "warn"`
# (Cargo.toml) plus CI's `CARGO_BUILD_WARNINGS=deny` means an un-named
# `pub` item DEFINED INSIDE the crate (a `pub struct Uncurated;` added to
# `snapshot.rs` with no re-export at the root) already fails
# `cargo check` on its own. What is left for a text gate to close is
# narrower than "additions" as a class: the few NAMED syntactic routes
# that add a root-namespace item without ever naming it as such —
# `pub mod`, `pub extern crate`, a bare macro invocation, and
# `#[macro_export]` in a child file.
#
# House gate idiom: exit 0 pass / 1 fail / 2 the check could not run —
# and an unreadable or unparseable input, or a walk that enumerates zero
# files, is ALWAYS a refusal, never read as clean.
#
#   scripts/check-vfs-root-shape.sh              run the gate
#   scripts/check-vfs-root-shape.sh --self-test  prove it can fail
set -euo pipefail

# Validate arguments before setup.
# Only no arguments or exactly
# `--self-test` is accepted; a
# misspelling must not silently run
# the ordinary gate and report
# success after executing no self-test
# controls. Unknown instructions
# receive their own refusal before
# any top-level setup can fail
# for an unrelated reason. Both
# the argument count and permitted
# spelling are checked here.
#
# The argv guard is local to this gate.
# `selftest_argv_guard` exercises the
# permitted self-test form and the refusal
# of invalid arguments without adding
# another sourced helper to the scripts.
if [[ $# -gt 1 || ( $# -eq 1 && "${1:-}" != "--self-test" ) ]]; then
  echo "vfs-root-shape: unrecognised argument(s): $* — the only accepted form is '--self-test' (or no argument, to run the gate). Refused rather than silently running the gate and reporting green." >&2
  exit 2
fi

cd "$(dirname "$0")/.."

# THE GATED CRATE SET. The gated-set criterion was never "granary-vfs"; it is
# **a root that is already an index**,
# so the gate states a property the crate has rather than one imposed on it.
# Exactly two crates satisfy it. The other eight carry 55 `pub mod` between
# them, and a rule with 55 named exceptions records what happens to be there
# instead of constraining anything — that is a DECISION, not a deferral.
GATED_CRATES=(granary-vfs granary-fuse)

# root_allowlist <crate> — the EXACT crate-scope constructs, beyond the
# universal allow-list, that this crate's root may carry.
#
# The allow-list applies to crate SCOPE,
# including constructs that are not public
# exports. The fuse root therefore needs entries
# for its compile-time wall, crate-visible
# constant and static assertion as well as its
# public constant. An estimate based only on
# public index entries would miss those other
# constructs. `root_allowlist` names the exact
# permitted forms; the match-count checks
# below ensure that an exception still
# corresponds to the intended source construct.
#
# EVERY ENTRY MUST MATCH EXACTLY ONE CONSTRUCT. An entry matching NONE is a
# stale widening that no verdict would ever reveal — the gate would stay green
# while silently permitting a shape nobody re-examined. An entry matching
# SEVERAL is a pattern wearing a named exception's clothes. Both are rc=2, and
# both have a planted red in --self-test.
root_allowlist() {
  case "$1" in
    granary-vfs) : ;;  # none — this root is a pure index, which is why it went first
    granary-fuse)
      # the release wall in `crates/granary-fuse/src/lib.rs`
      printf '%s\n' 'compile_error!('
      # the readlink ceiling and the static assertion that pins its absolute
      # value — a gate that forced either
      # out would be trading a live safety assertion for a style rule
      printf '%s\n' 'pub(crate) const FUSE_READLINK_TARGET_MAX_4K_PAGE'
      printf '%s\n' 'const _: () = assert!('
      # the one genuinely public non-`mod` construct permitted for
      # `granary-fuse`: `pub const FUSE_SERVE_LIMITS`
      printf '%s\n' 'pub const FUSE_SERVE_LIMITS'
      ;;
    *)
      echo "vfs-root-shape: no allow-list entry for crate '$1' — a crate cannot enter GATED_CRATES without one (write an empty case arm if it needs none). Refused, never treated as clean." >&2
      return 1
      ;;
  esac
}

# Retained for the self-test controls, which all operate on granary-vfs.
CRATE_DIR=crates/granary-vfs
CRATE_SRC="$CRATE_DIR/src"
LIB_RS="$CRATE_SRC/lib.rs"
SCAN_PY="$(pwd)/scripts/vfs-root-shape-scan.py"

# CLEANUP TRAP — one shared registry, the same shape check-vfs-purity.sh
# and check-core-purity.sh both use, so no self-test failure path
# (planted or genuine) can skip cleanup of its own scratch files —
# PROVIDED the file/dir is registered from THIS shell's own top-level
# context, never from inside a function that is itself always invoked
# through a `$( )` command substitution. A command substitution forks a
# SUBSHELL: `_vfs_shape_track` there only ever mutates that subshell's
# own copy of `_VFS_SHAPE_CLEANUP`, and bash does not run the parent's
# `EXIT` trap for a subshell either, so nothing registered there is ever
# swept by this trap (the subshell hazard: `macro_export_report`'s own `list_file`
# leaked exactly this way — every `tmp="$(mktemp -d)"` in the self-test
# controls below is safe because it runs directly in THIS shell, never
# inside a `$( )`; `macro_export_report` instead protects its own
# `list_file` with a LOCAL trap, not this registry).
_VFS_SHAPE_CLEANUP=()
_vfs_shape_track() { _VFS_SHAPE_CLEANUP+=("$1"); }
_vfs_shape_cleanup() {
  local d
  for d in "${_VFS_SHAPE_CLEANUP[@]+"${_VFS_SHAPE_CLEANUP[@]}"}"; do
    rm -rf "$d"
  done
}
trap _vfs_shape_cleanup EXIT

# plant_once_or_die <file> <needle> <replacement>
#
# Matches <needle> only as a WHOLE LINE, never as a substring — the same
# discipline check-vfs-purity.sh's replace_once_or_die uses and for the
# same reason: a fixture that silently matched zero or several times
# would prove nothing about the control built on it. Confirms the
# mutation actually applied before returning.
plant_once_or_die() {
  local file="$1" needle="$2" replacement="$3"
  python3 - "$file" "$needle" "$replacement" <<'PYEOF'
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

# append_and_confirm <file> <text> <grep-pattern>
#
# Appends <text> and confirms <grep-pattern> now matches exactly once —
# a fixture that failed to apply must not silently read as a control
# that passed for the right reason.
append_and_confirm() {
  local file="$1" text="$2" pattern="$3" count
  printf '%s\n' "$text" >> "$file"
  count="$(grep -c -- "$pattern" "$file")"
  if [[ "$count" -ne 1 ]]; then
    echo "self-test fixture BROKEN: expected exactly one occurrence of pattern $pattern in $file after appending, found $count" >&2
    exit 2
  fi
}

# extract_allowed_count <label> <out>
#
# Parses the ONE "N allowed" count out of root_shape_report's own success
# message and echoes N — never a hardcoded literal, never a second, direct
# scanner invocation (see control arm-a-positive's own comment on why).
# Exits 2, diagnosing itself by <label>, if no count can be parsed at all.
# Kept separate from assert_allowed_count below because control
# not-a-freeze needs a BASELINE read with nothing yet to compare it to.
#
# `extract_allowed_count` reports the control label
# and the unparseable output. It does not infer why
# the count is missing. A fixture may fail to produce
# the expected scanner response, or the response
# format may differ from the pattern this helper
# recognises. `append_and_confirm` separately checks
# that a fixture append changed the file; a later
# count-parse failure is not itself evidence that
# the append did nothing. The shared helper keeps
# extraction and its failure handling in one
# place, while callers remain responsible for
# establishing their fixture premises and comparing
# the returned count with their expectation.
extract_allowed_count() {
  local label="$1" out="$2" count count_rc
  set +e
  count="$(grep -oE '[0-9]+ allowed' <<<"$out" | grep -oE '^[0-9]+')"
  count_rc=$?
  set -e
  if [[ "$count_rc" -ne 0 || -z "$count" ]]; then
    echo "self-test FAILED: control $label — could not parse a pub-use count out of root_shape_report's own success message: $out" >&2
    exit 2
  fi
  echo "$count"
}

# assert_allowed_count <control> <expected> <out>
#
# Every "N allowed pub use line(s)" assertion uses this helper.
# One extraction-plus-compare implementation serves every control that
# asserts an allowed pub-use count. String comparison rejects a
# multiline count, which arithmetic comparison errors on and passes.
#
# Two `clean_root_hits` refusal-count blocks are outside this helper:
# `ws-around-coloncolon-foreign-still-refused` uses arithmetic `-ne`,
# and `ws-lrm-foreign-still-refused` uses string `!=`. Both count with
# `grep -c`, which prints one line, so the hazard below cannot fire there.
#
# Use string comparison for the extracted
# count. `grep -oE` can produce a match on
# each line, so multiple occurrences can
# yield a multiline value. Feeding that value
# to an arithmetic comparison can produce
# an arithmetic syntax error instead of the
# intended inequality result; inside an `if`
# test, errexit does not turn that error
# into the assertion's failure branch. String
# inequality compares the whole value with
# the expected single number, so a value
# such as two newline-separated counts
# is unequal without arithmetic parsing.
assert_allowed_count() {
  local control="$1" expected="$2" out="$3" count
  count="$(extract_allowed_count "$control" "$out")"
  if [[ "$count" != "$expected" ]]; then
    echo "self-test FAILED: control $control — expected exactly $expected allowed \`pub use\` line(s), got $count" >&2
    echo "$out" >&2
    exit 2
  fi
}

# ------------------------------------------------------------------ arm A
# root_shape_report <path>
#
# THE ONE comparison the real gate and every self-test control below
# calls — a control that re-derived the classification separately would
# prove nothing about THIS function's actual pass/fail branch; that exact
# root-extraction gap is what this shared path prevents.
root_shape_report() {
  local path="$1" crate="${2:-}" out rc pubuse_count pubuse_rc refuse_lines refused_pubuse_count total_pubuse_attempts
  set +e
  out="$(python3 "$SCAN_PY" --root-shape "$path" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "vfs-root-shape: arm A scanner failed reading $path (exit $rc) — refused, never treated as clean:" >&2
    echo "$out" >&2
    exit 2
  fi
  # The pipefail hazard: this assignment MUST run under its own set +e/set -e,
  # exactly like every other pipeline-into-a-variable in this file (arm B's own
  # macro_export_git_floor is the sibling case) — under this script's
  # top-level `set -euo pipefail`, a `$SCAN_PY` output with no
  # `PUBUSE-COUNT` line at all makes `grep` exit 1, `pipefail` carries
  # that through the `| sed` stage, and a BARE assignment form dies to
  # errexit right here, before the `-z "$pubuse_count"` guard below ever
  # runs — a plain, undiagnosed rc=1 with empty stdout+stderr.
  # MUTATION-PROVED: commenting out vfs-root-shape-scan.py's own
  # `print(f"PUBUSE-COUNT {pubuse_count}")` reproduced exactly that
  # before this guard existed; see the dedicated self-test control
  # below, which drives this same function against a scratch copy of
  # the scanner carrying that exact mutation.
  set +e
  pubuse_count="$(grep '^PUBUSE-COUNT ' <<<"$out" | sed 's/^PUBUSE-COUNT //')"
  pubuse_rc=$?
  set -e
  refuse_lines="$(grep '^REFUSE ' <<<"$out" || true)"
  # PER-CRATE ALLOW-LIST SUBTRACTION. Runs BEFORE the zero-pub-use
  # could-not-run guard below on purpose: a root whose every construct is
  # allowed still had to be WALKED, and the walk is what that guard checks.
  if [[ -n "$crate" ]]; then
    local allow_spec
    allow_spec="$(root_allowlist "$crate")" || exit 2
    if [[ -n "$allow_spec" ]]; then
      local -a allow_entries=() allow_hits=()
      local entry line kept="" i matched
      while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        allow_entries+=("$entry")
        allow_hits+=(0)
      done <<<"$allow_spec"
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        matched=-1
        # the construct's own source text follows the scanner's ` :: `
        local rest tail_char entry_last
        rest="${line##* :: }"
        for i in "${!allow_entries[@]}"; do
          entry="${allow_entries[$i]}"
          [[ "$rest" == "$entry"* ]] || continue
          # AN ENTRY NAMES A CONSTRUCT, NOT AN
          # IDENTIFIER PREFIX. When the entry ends
          # in an identifier character, the next
          # character must not extend the identifier:
          # otherwise `FUSE_SERVE_LIMITS_V2` would
          # match the entry for `FUSE_SERVE_LIMITS`.
          # Entries ending in punctuation
          # take the plain prefix comparison.
          entry_last="${entry: -1}"
          if [[ "$entry_last" == [A-Za-z0-9_] ]]; then
            tail_char="${rest:${#entry}:1}"
            [[ -n "$tail_char" && "$tail_char" == [A-Za-z0-9_] ]] && continue
          fi
          matched="$i"
          break
        done
        if [[ "$matched" -ge 0 ]]; then
          allow_hits[$matched]=$(( allow_hits[matched] + 1 ))
        else
          kept+="${line}"$'\n'
        fi
      done <<<"$refuse_lines"
      for i in "${!allow_entries[@]}"; do
        if [[ "${allow_hits[$i]}" -ne 1 ]]; then
          echo "vfs-root-shape: arm A allow-list for $crate is STALE — entry '${allow_entries[$i]}' matched ${allow_hits[$i]} crate-scope construct(s) in $path, expected exactly 1. An entry matching NONE silently widens this gate and no verdict would show it; an entry matching SEVERAL is a pattern, not a named exception. Refused, never treated as clean." >&2
          exit 2
        fi
      done
      refuse_lines="${kept%$'\n'}"
    fi
  fi
  if [[ "$pubuse_rc" -ne 0 || -z "$pubuse_count" ]]; then
    echo "vfs-root-shape: arm A could not confirm the scanner ran at all (no PUBUSE-COUNT line) against $path — refused, never treated as clean" >&2
    exit 2
  fi
  # THE "ZERO pub use LINES" COULD-NOT-RUN CHECK COUNTS ATTEMPTS, NOT
  # SURVIVORS. A root every one of whose `pub use` statements was
  # REFUSED (a fixture that is entirely one bad glob, say) is a
  # legitimate rc=1 FAIL, with the refusal named — not the same
  # condition as a root that never had a `pub use` line to begin with
  # (a genuinely gutted or malformed root, which is what this
  # could-not-run guard exists to catch). Conflating the two would make
  # every all-glob fixture read as "could not run" instead of "failed
  # for a named reason", which is a worse diagnostic and was caught
  # directly against the glob self-test control below before this
  # comment existed.
  refused_pubuse_count="$(grep -c '^REFUSE .*: pub use — ' <<<"$out" || true)"
  total_pubuse_attempts=$((pubuse_count + refused_pubuse_count))
  if [[ "$total_pubuse_attempts" -eq 0 ]]; then
    echo "vfs-root-shape: arm A FAILED TO RUN — $path carries ZERO \`pub use\` lines at all (allowed or refused); a root this scanner could not walk as the crate's real root must not read the same as a root that was walked and found clean (refused, never treated as clean):" >&2
    if [[ -n "$refuse_lines" ]]; then
      echo "$refuse_lines" | sed 's/^/  /' >&2
    fi
    exit 2
  fi
  if [[ -n "$refuse_lines" ]]; then
    echo "vfs-root-shape: arm A FAILED — $path carries construct(s) not on this gate's allow-list (attributes; a non-pub extern crate/mod/use; a pub use of named leaves only):" >&2
    echo "$refuse_lines" | sed 's/^REFUSE /  line /' >&2
    return 1
  fi
  echo "vfs-root-shape: arm A ok — $path's crate scope is entirely attributes, non-pub extern crate/mod/use, and $pubuse_count allowed \`pub use\` line(s) of named leaves"
  return 0
}

# ------------------------------------------------------------------ arm B
# macro_export_git_floor <dir> — a floor derived from `git ls-files`
# (check-vfs-purity.sh's own vfs_src_file_floor idiom), refusing on a git
# failure rather than reading a dead `git` as an empty, clean tree. ONLY
# meaningful for a directory actually tracked in THIS repo — the real
# gate call and one dedicated self-test control (against the tracked
# crate) use it; every other self-test control builds its fixture
# OUTSIDE the repo (`git ls-files` on a path outside the working tree
# fails outright) and passes a floor of its own sized to that fixture,
# the same division item3_report's own comment in check-vfs-purity.sh
# uses for the identical reason.
macro_export_git_floor() {
  local dir="$1" rc floor
  set +e
  floor="$(git ls-files "${dir}/*.rs" | wc -l | tr -d ' ')"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 || -z "$floor" || "$floor" -lt 1 ]]; then
    echo "vfs-root-shape: could not derive arm B's source-file floor from 'git ls-files ${dir}/*.rs' (exit $rc) — refused, never treated as clean" >&2
    return 2
  fi
  echo "$floor"
  return 0
}

# macro_export_report <dir> <floor>
#
# Enumerates <dir>'s .rs files with a PLAIN `find` (the walk arm A's
# scanner is handed) and cross-checks its count against `find -L`'s (a
# symlinked directory the plain walk never descends, though rustc
# compiles the modules behind it) and against <floor> — independent
# readings that must agree before a "found nothing" result is trusted as
# a clean scan rather than a walk that never really happened. <floor> is
# a PARAMETER (see macro_export_git_floor's own comment on why).
macro_export_report() {
  local dir="$1" floor="$2" list_file plain_count followed_count out rc hits

  list_file="$(mktemp)" || { echo "vfs-root-shape: mktemp failed" >&2; exit 2; }
  # The subshell hazard: this function is ALWAYS invoked inside a `$( )` command
  # substitution (the real gate call and every self-test control below
  # alike) — a SUBSHELL, whose `_vfs_shape_track` call above would only
  # ever mutate that subshell's own forked COPY of `_VFS_SHAPE_CLEANUP`,
  # never the parent's. Bash does not run the parent's `EXIT` trap for a
  # subshell either, so `_vfs_shape_cleanup` never even runs there.
  # MEASURED: the real gate leaked +1 `$TMPDIR` entry per run,
  # `--self-test` +4 (one per call site below) before this trap existed.
  # A trap set HERE, local to this invocation, fires on every exit path
  # this function actually takes — `return` (RETURN) and the `exit 2`
  # calls below (EXIT) alike — so `_vfs_shape_track`'s registry-based
  # cleanup is not what protects this file; this local trap is.
  # `${list_file:-}` (not a bare `$list_file`): the RETURN trap fires
  # and cleans up correctly on a normal `return`, but the EXIT trap
  # stays armed afterward — under this script's own `set -u`, firing it
  # again at the real process exit, once `list_file` (a `local`) has
  # gone out of scope, would itself abort with "unbound variable"
  # rather than the diagnostic this control exists to produce.
  trap 'rm -f "${list_file:-}"' RETURN EXIT
  if ! find "$dir" -name '*.rs' -print0 > "$list_file"; then
    echo "vfs-root-shape: arm B's .rs walk of $dir failed — refused, never treated as clean" >&2
    exit 2
  fi
  # The mixed-delimiter file-count hazard: BOTH counts must be read the same
  # way — NUL-separated entries, counted as NUL bytes, never one side counted by newline-split `wc
  # -l`. A `.rs` filename containing a newline would make `plain_count`
  # (NUL-based) and a `wc -l`-based `followed_count` disagree for a
  # reason that has nothing to do with a symlinked directory — refusing
  # a perfectly clean tree at rc=2 with a symlink diagnostic naming the
  # wrong cause.
  # The pipefail hazard: both of these assignments run
  # their own pipeline into a variable and so get their own set +e /
  # set -e, exactly like every other one in this file — a bare
  # assignment form here would die to errexit on the first pipe stage
  # that ever returns nonzero, before either could-not-run guard below
  # ever runs.
  set +e
  plain_count="$(tr -cd '\0' < "$list_file" | wc -c | tr -d ' ')"
  set -e
  set +e
  followed_count="$(find -L "$dir" -name '*.rs' -print0 2>/dev/null | tr -cd '\0' | wc -c | tr -d ' ')"
  set -e

  if [[ "$plain_count" -eq 0 ]]; then
    echo "vfs-root-shape: arm B's walk of $dir enumerated ZERO .rs files — a walk that found nothing must not read the same as a walk that scanned the crate and found it clean (refused, never treated as clean)" >&2
    exit 2
  fi
  if [[ "$plain_count" -lt "$floor" ]]; then
    echo "vfs-root-shape: arm B's walk of $dir enumerated $plain_count .rs file(s), below the git-derived floor of $floor — refused, never treated as clean" >&2
    exit 2
  fi
  if [[ "$plain_count" != "$followed_count" ]]; then
    echo "vfs-root-shape: arm B's plain \`find\` walk of $dir enumerated $plain_count .rs file(s) but \`find -L\` (following symlinks) enumerated $followed_count — a symlinked directory under the crate's source would be silently invisible to the walk this gate actually scans while rustc compiles the modules behind it; refused, never treated as clean" >&2
    exit 2
  fi

  set +e
  out="$(python3 "$SCAN_PY" --macro-export < "$list_file" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "vfs-root-shape: arm B scanner failed scanning $dir (exit $rc) — refused, never treated as clean:" >&2
    echo "$out" >&2
    exit 2
  fi
  hits="$(grep '^MACRO-EXPORT ' <<<"$out" || true)"
  if [[ -n "$hits" ]]; then
    echo "vfs-root-shape: arm B FAILED — a #[macro_export] was found under $dir (a child-module macro_export lands in the crate ROOT's namespace with zero lines changed in lib.rs):" >&2
    echo "$hits" | sed 's/^MACRO-EXPORT /  /' >&2
    return 1
  fi
  echo "vfs-root-shape: arm B ok — no #[macro_export] anywhere under $dir ($plain_count .rs file(s) scanned, agreeing with \`find -L\` and the git-derived floor of $floor)"
  return 0
}

# ---------------------------------------------------------- self-test: A
selftest_arm_a() {
  local tmp scratch out rc baseline_count expected_count

  out="$(root_shape_report "$LIB_RS")" || {
    echo "self-test FAILED: arm A did not pass against the real, unmodified $LIB_RS" >&2
    exit 2
  }
  echo "self-test: control arm-a-positive — $out"
  # The same-call baseline rule: the BASELINE pub-use count, read from
  # THIS SAME production-function call (root_shape_report), never a
  # hardcoded literal and never a second, direct scanner invocation — a legitimate new
  # pub use added to the real root before this self-test next runs must
  # not turn CI red just because a count moved. Read via
  # extract_allowed_count, which carries the pipefail hazard's own guard inside
  # it, one place for every count parse (see that helper's own comment).
  baseline_count="$(extract_allowed_count "arm-a-positive" "$out")"

  tmp="$(mktemp -d)"
  _vfs_shape_track "${tmp}"
  scratch="$tmp/lib.rs"

  # THE SINGLE MOST IMPORTANT CONTROL: this is a SHAPE rule, not a
  # resurrected census. Adding a genuinely new named leaf `pub use` —
  # one plain, one ALIASED — must stay GREEN.
  cp "$LIB_RS" "$scratch"
  append_and_confirm "$scratch" \
    'pub use handle::HandleKind as ExtraHandleKind;' \
    'pub use handle::HandleKind as ExtraHandleKind;'
  append_and_confirm "$scratch" \
    'pub use attr::Attr as PublicAttr;' \
    'pub use attr::Attr as PublicAttr;'
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: control not-a-freeze — a new named \`pub use\` leaf AND an aliased one were REFUSED (rc=$rc); this gate must be a shape rule, not a census of exactly twenty names" >&2
    echo "$out" >&2
    exit 2
  fi
  # Derive the baseline from this
  # `root_shape_report` call, then require
  # the count to rise by exactly two. A
  # hardcoded baseline could reject a legitimate
  # addition to the real root. `assert_allowed_count`
  # compares the returned count as text,
  # so multiple extracted numbers cannot
  # enter an arithmetic comparison and
  # bypass the intended mismatch branch.
  # `expected_count` holds the expected value
  # computed from the baseline. It is set before
  # `assert_allowed_count` compares it with
  # the observed output. A mismatch exits
  # through that helper, so reaching the echo
  # means the expectation was confirmed. The
  # echo describes that expectation; it does
  # not represent another independent scanner
  # call. Parse failures are reported by
  # `extract_allowed_count` with this control's
  # label and the output it could not parse.
  expected_count=$((baseline_count + 2))
  assert_allowed_count "not-a-freeze" "$expected_count" "$out"
  echo "self-test: control not-a-freeze — a new named \`pub use\` leaf ('ExtraHandleKind') AND an aliased one ('PublicAttr') both stay GREEN (rc=0, pub-use count $baseline_count -> $expected_count, expected and confirmed): this gate is a shape rule, not a resurrected twenty-item census"
  rm -f "$scratch"

  # RED (MUTATION-PROVED): `_normalize_ws_class`'s
  # length/line-preservation property — one `WS`-class character in, one
  # ASCII space out, so `clean` keeps `raw`'s exact length and every
  # newline stays in place — is the load-bearing safety claim every REFUSE
  # line's own `line_of`/`orig_line` math depends on, and no control in
  # this file asserted a REFUSE line number OR its quoted source text
  # against a KNOWN planted line. Widening
  # `_WS_CHAR_RE = re.compile(WS)` to `re.compile(WS + "+")` (collapsing a
  # RUN of WS-class characters — including a run of plain ASCII spaces or
  # blank-line newlines — to ONE output character, shrinking `clean`
  # relative to `raw`) leaves `--self-test` at rc=0 with every other
  # control green AND the real gate at rc=0: every existing count/rc/
  # diagnostic-text assertion in this file is blind to `clean` merely
  # being the WRONG LENGTH, because none of them names a line number. This
  # fixture plants its refusable construct on a KNOWN line, reached only
  # after two blank lines (collapsible newline runs) and a multi-space
  # indentation/interior-space run (collapsible space runs), so a
  # length-changing mutation cannot land on the right answer by accident.
  cat > "$scratch" <<'EOF'
mod attr;


    pub  mod  leaky {}
pub use attr::Attr;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control refuse-line-number — a \`pub mod\` planted after two blank lines and a multi-space run was NOT refused (rc=$rc, wanted 1)" >&2
    echo "$out" >&2
    exit 2
  fi
  # `root_shape_report`'s own FAILED path rewrites the scanner's raw
  # `REFUSE N: ...` prefix to `  line N: ...` (`sed 's/^REFUSE /  line /'`)
  # before printing it — the format every caller (and every other rc=1
  # control in this file) actually sees, so the line number is asserted
  # against THAT text, not the scanner's own unrewritten prefix.
  if ! grep -qE '^  line 4: .*`pub mod`.* :: pub  mod  leaky \{\}$' <<<"$out"; then
    echo "self-test FAILED: control refuse-line-number — expected a line naming LINE 4 and quoting the EXACT original source 'pub  mod  leaky {}' (double spaces preserved, no truncation); got: $out" >&2
    exit 2
  fi
  if [[ "$(grep -c '^  line ' <<<"$out")" != "1" ]]; then
    echo "self-test FAILED: control refuse-line-number — expected exactly one refused line; got: $out" >&2
    exit 2
  fi
  echo "self-test: control refuse-line-number — a \`pub mod\` construct planted after two blank lines and a multi-space run is refused naming the CORRECT line (4) and quoting the EXACT original source text, double spaces included (rc=1): the line/column math every REFUSE line depends on is exercised directly against a KNOWN planted line, not merely assumed from rc and a diagnostic's own wording"
  rm -f "$scratch"

  # GREEN: a prefix-less `pub use` brace
  # group can contain leaves with their
  # own full paths, such as
  # `pub use {attr::Attr, handle::HandleKind};`.
  # The lack of a shared prefix is not
  # itself a violation. Each leaf gets its
  # own shape and first-segment checks.
  # With a root `mod snapshot;`, even
  # `pub use {snapshot};` is accepted.
  cat > "$scratch" <<'EOF'
mod attr;
mod handle;
pub use {attr::Attr, handle::HandleKind};
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: control prefixless-brace-group — \`pub use {attr::Attr, handle::HandleKind};\` (no common path:: prefix, but every leaf is a fully-qualified named item) was REFUSED (rc=$rc); the named-leaf grammar stated in the header allows a brace list of named leaves with no requirement that they share a prefix" >&2
    echo "$out" >&2
    exit 2
  fi
  # Assert the COUNT too, not only rc==0 — the green-control silent-omission hazard's own
  # rationale (a bare rc==0 cannot see a scanned line vanish from the
  # walk) applies to every GREEN control, not only the two it was
  # first added to.
  assert_allowed_count "prefixless-brace-group" 1 "$out"
  echo "self-test: control prefixless-brace-group — \`pub use {attr::Attr, handle::HandleKind};\` (a brace group with no common path:: prefix, EXECUTED to compile clean) stays GREEN (rc=0): each leaf is validated on its own terms instead of the whole group being refused for lacking a shared prefix"
  rm -f "$scratch"

  # RED: a FOREIGN-crate path nested inside a prefix-less brace group
  # passed because only shared prefixes received the foreign-root check.
  # `pub use granary_core::manifest;` was refused while the identical
  # `pub use {granary_core::manifest, attr::Attr};` passed, because
  # the first-segment foreign-root check only ever ran on a group's SHARED
  # prefix, and a prefix-less group has none. Each entry's own first
  # segment is now checked at that call site.
  cat > "$scratch" <<'EOF'
mod attr;
pub use {granary_core::manifest, attr::Attr};
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control prefixless-foreign-leaf — a foreign-crate path inside a prefix-less brace group (\`pub use {granary_core::manifest, attr::Attr};\`) was NOT refused (rc=$rc, wanted 1); the first-segment foreign-root check has a hole the shared-prefix spelling does not" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'rooted at `granary_core`' <<<"$out"; then
    echo "self-test FAILED: control prefixless-foreign-leaf — refused (rc=1) but NOT by the first-segment foreign-root check's own diagnostic, so this control does not prove which arm fired: $out" >&2
    exit 2
  fi
  echo "self-test: control prefixless-foreign-leaf — a foreign-crate path inside a prefix-less brace group is refused by the first-segment foreign-root check's own diagnostic (rc=1), proving entries of a prefix-less group receive the same foreign-root check as an ungrouped path"
  rm -f "$scratch"

  # GREEN: a leaf check is skipped only when
  # the prefix's first-segment check has already
  # run. A merely present prefix does not
  # establish that. Conversely, checking every
  # leaf as a new root would refuse legitimate
  # nested paths: in `snapshot::{inner::Thing}`,
  # `inner` is a submodule rather than a
  # root-level module. These controls cover
  # the prefixed group and a local nested
  # group inside a prefixless group, requiring
  # both to pass while the foreign-root
  # controls still refuse their planted leaves.
  cat > "$scratch" <<'EOF'
mod attr;
mod handle;
mod snapshot;
pub use snapshot::{Entry, ReaddirEntry};
pub use {attr::{Attr, NodeKind}, handle::HandleKind};
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: control nested-subpath-green — a prefixed brace group and a prefix-less group carrying a nested LOCAL group were refused (rc=$rc); the foreign-crate check has leaked into the recursion or into the prefixed path, which refuses valid Rust" >&2
    echo "$out" >&2
    exit 2
  fi
  # Assert the COUNT too — see prefixless-brace-group's
  # own comment above for why.
  assert_allowed_count "nested-subpath-green" 2 "$out"
  echo "self-test: control nested-subpath-green — a prefixed brace group (\`snapshot::{Entry, ReaddirEntry}\`) stays GREEN because its shared prefix was checked once and its bare leaves are not re-checked, and a prefix-less group's own nested LOCAL group (\`attr::{Attr, NodeKind}\`) stays GREEN because ITS entry gets the foreign-crate check on its own first segment exactly once, with the check dropped for its inner leaves once that segment is found to be one of this crate's own modules — narrower than 'nowhere else', which control leading-nested-group-green and anchored-nested-group-green below now also exercise the check running on"
  rm -f "$scratch"

  # RED (the bare-anchor propagation hazard): while closing the prefix-less
  # group gap above, the scanner left a bare `crate::`/`self::` ANCHOR prefix as a shared
  # prefix that never actually runs the first-segment foreign-root check (`crate`/`self`
  # carry no crate-of-origin information of their own), because the
  # `"::" in prefix` branch treated "a prefix is present" as "the check
  # ran" and dropped `module_names` from the recursion unconditionally.
  # EXECUTED against the real crate root: appending this exact line
  # gave `PUBUSE-COUNT 8`, zero REFUSE, rc=0 — one brace away from the
  # bare `pub use alloc::boxed::Box;` spelling the first-segment foreign-root check already
  # refuses. `mod attr;`/`pub use attr::Attr;` sit alongside it to prove
  # the classification stays per-line, matching control foreign-crate.
  cat > "$scratch" <<'EOF'
mod attr;
pub use attr::Attr;
pub use crate::{alloc::boxed::Box};
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control bare-anchor-foreign-leaf — a foreign-crate path behind a bare \`crate::\` anchor (\`pub use crate::{alloc::boxed::Box};\`) was NOT refused (rc=$rc, wanted 1); a bare anchor prefix took the 'the check already ran' branch without the check ever having run" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'rooted at `alloc`' <<<"$out"; then
    echo "self-test FAILED: control bare-anchor-foreign-leaf refused, but not by the first-segment foreign-root check's own diagnostic naming \`alloc\`: $out" >&2
    exit 2
  fi
  if grep -q 'attr::Attr' <<<"$(grep '^REFUSE ' <<<"$out")"; then
    echo "self-test FAILED: control bare-anchor-foreign-leaf — the legitimate \`pub use attr::Attr;\` line was ALSO refused; only the \`crate::{alloc::boxed::Box}\` line should be named" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control bare-anchor-foreign-leaf — a foreign-crate path behind a bare \`crate::\` anchor (\`pub use crate::{alloc::boxed::Box};\`, EXECUTED to compile clean under rustc; appended to the real root, a scanner whose bare-anchor branch skipped the foreign-root check passed it at PUBUSE-COUNT 8) is refused by the first-segment foreign-root check's own diagnostic (rc=1); the legitimate \`pub use attr::Attr;\` beside it stays unnamed"
  rm -f "$scratch"

  # GREEN (the leading-nested-group brace-truncation hazard): the attempted
  # repair REFUSED valid Rust — a `pub use` whose FIRST entry is a nested group with no
  # prefix of its own (a leading `{attr::Attr}`), and the same shape
  # reached through a bare `crate::` anchor — both EXECUTED to compile
  # clean, and both PASSED before that repair. After it,
  # both were refused with "a pub use rooted at `{attr`" — the raw,
  # un-truncated entry text `{attr::Attr}` leaking its own leading `{`
  # into `_first_own_segment` as if it were a crate name. This is the
  # false-refusal failure mode the deleted census exhibited, arriving through
  # its own repair.
  cat > "$scratch" <<'EOF'
mod attr;
mod handle;
pub use {{attr::Attr}, handle::HandleKind};
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: control leading-nested-group-green — \`pub use {{attr::Attr}, handle::HandleKind};\` (EXECUTED to compile clean) was REFUSED (rc=$rc); a leading nested brace group with no prefix of its own must not leak its literal '{' into the foreign-crate check" >&2
    echo "$out" >&2
    exit 2
  fi
  # Assert the COUNT too — see prefixless-brace-group's
  # own comment above for why.
  assert_allowed_count "leading-nested-group-green" 1 "$out"
  echo "self-test: control leading-nested-group-green — \`pub use {{attr::Attr}, handle::HandleKind};\` (a leading nested brace group with no prefix of its own, EXECUTED to compile clean) stays GREEN (rc=0)"
  rm -f "$scratch"

  cat > "$scratch" <<'EOF'
mod attr;
mod handle;
pub use {crate::{attr::Attr}, handle::HandleKind};
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: control anchored-nested-group-green — \`pub use {crate::{attr::Attr}, handle::HandleKind};\` (EXECUTED to compile clean) was REFUSED (rc=$rc); a nested group reached through a bare \`crate::\` anchor must not leak '{attr' into the foreign-crate check either" >&2
    echo "$out" >&2
    exit 2
  fi
  # Assert the COUNT too — see prefixless-brace-group's
  # own comment above for why.
  assert_allowed_count "anchored-nested-group-green" 1 "$out"
  echo "self-test: control anchored-nested-group-green — \`pub use {crate::{attr::Attr}, handle::HandleKind};\` (a nested group reached through a bare \`crate::\` anchor, EXECUTED to compile clean) stays GREEN (rc=0)"
  rm -f "$scratch"

  # GREEN (keeper for the bare-anchor
  # propagation and leading-nested-group
  # brace-truncation hazards): the anchored,
  # PREFIXED spelling. The first-segment
  # foreign-root check still runs here,
  # checking the plain anchored-prefix case:
  # `mod attr; pub use crate::{attr::Attr};`.
  cat > "$scratch" <<'EOF'
mod attr;
pub use crate::{attr::Attr};
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: control anchored-prefixed-green — \`pub use crate::{attr::Attr};\` (EXECUTED to compile clean) was REFUSED (rc=$rc)" >&2
    echo "$out" >&2
    exit 2
  fi
  # Assert the COUNT too — see prefixless-brace-group's
  # own comment above for why.
  assert_allowed_count "anchored-prefixed-green" 1 "$out"
  echo "self-test: control anchored-prefixed-green — \`pub use crate::{attr::Attr};\` (EXECUTED to compile clean) stays GREEN (rc=0)"
  rm -f "$scratch"

  # GREEN: the nested SUB-PATH
  # fixture uses `snapshot::{inner::Thing}`
  # with inner declared inside
  # snapshot. At that depth, inner
  # need not be a crate-root module.
  # The fixture supplies a real
  # nested declaration, rather
  # than only naming it in a
  # comment. It checks that the
  # scanner does not apply a
  # crate-root foreign-path test to
  # a nested sub-path whose prefix
  # already establishes its scope.
  cat > "$scratch" <<'EOF'
mod snapshot {
    pub mod inner {
        pub struct Thing;
    }
}
pub use snapshot::{inner::Thing};
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: control nested-subpath-real-green — \`pub use snapshot::{inner::Thing};\` (with a real \`pub mod inner\`, EXECUTED to compile clean) was REFUSED (rc=$rc); the foreign-crate check has leaked past the already-validated shared prefix onto a genuine submodule" >&2
    echo "$out" >&2
    exit 2
  fi
  # Assert the COUNT too — see prefixless-brace-group's
  # own comment above for why.
  assert_allowed_count "nested-subpath-real-green" 1 "$out"
  echo "self-test: control nested-subpath-real-green — \`pub use snapshot::{inner::Thing};\` (a real nested submodule behind an already-checked shared prefix, EXECUTED to compile clean) stays GREEN (rc=0): a checked shared prefix prevents the foreign-root check from being reapplied to a genuine nested submodule, and this file exercises that shape directly"
  rm -f "$scratch"

  # RED: leaf-shape checks must precede the
  # foreign-root diagnostic. In `alloc::boxed::*`,
  # the glob is the prohibited leaf shape;
  # reporting only that alloc is a foreign
  # root would obscure that cause. The
  # control requires the glob diagnostic,
  # checking precision as well as nonzero
  # status. Foreign-root classification
  # applies after an entry is otherwise
  # a well-formed named leaf.
  cat > "$scratch" <<'EOF'
mod attr;
pub use {alloc::boxed::*, attr::Attr};
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control glob-diagnostic-precision — \`pub use {alloc::boxed::*, attr::Attr};\` was NOT refused (rc=$rc, wanted 1)" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'glob re-export' <<<"$out"; then
    echo "self-test FAILED: control glob-diagnostic-precision — refused (rc=1) but by the first-segment foreign-root check's message (\`rooted at \`alloc\`\`) instead of the glob's own distinctive diagnostic: $out" >&2
    exit 2
  fi
  echo "self-test: control glob-diagnostic-precision — \`pub use {alloc::boxed::*, attr::Attr};\` is refused (rc=1) by its own glob diagnostic, not by the first-segment foreign-root check's message — the leaf's shape is checked before its root, so the glob route stays closed by THIS gate's own named-leaf check with its own name attached"
  rm -f "$scratch"

  # RED (the leaf-shape diagnostic-ordering hazard, second shape): a bare `*`
  # as the FIRST entry of a prefix-less group — `_first_own_segment('*')` would otherwise read
  # as a crate literally named `*`, reporting "a pub use rooted at
  # \`*\`\`" instead of naming the glob.
  cat > "$scratch" <<'EOF'
mod attr;
pub use {*, attr::Attr};
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control glob-first-entry — \`pub use {*, attr::Attr};\` was NOT refused (rc=$rc, wanted 1)" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'glob re-export' <<<"$out"; then
    echo "self-test FAILED: control glob-first-entry — refused (rc=1) but not by the glob's own diagnostic: $out" >&2
    exit 2
  fi
  echo "self-test: control glob-first-entry — \`pub use {*, attr::Attr};\` is refused (rc=1) by its own glob diagnostic, never read as \"a crate literally named \`*\`\""
  rm -f "$scratch"

  # RED: `pub mod`.
  cat > "$scratch" <<'EOF'
mod attr;
pub mod snapshot;
pub use attr::Attr;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control pub-mod — a \`pub mod\` at crate scope was NOT refused (rc=$rc, wanted 1)" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q '`pub mod`' <<<"$out"; then
    echo "self-test FAILED: control pub-mod refused, but not with its own distinctive diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control pub-mod — a \`pub mod\` at crate scope is refused by its own distinctive diagnostic (rc=1)"

  # RED: `pub extern crate`.
  cat > "$scratch" <<'EOF'
pub extern crate granary_core;
mod attr;
pub use attr::Attr;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control pub-extern-crate — a \`pub extern crate\` was NOT refused (rc=$rc, wanted 1)" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q '`pub extern crate`' <<<"$out"; then
    echo "self-test FAILED: control pub-extern-crate refused, but not with its own distinctive diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control pub-extern-crate — \`pub extern crate granary_core;\` at crate scope (rustdoc's own root-children count moves 20 -> 21 on this shape, EXECUTED) is refused by its own distinctive diagnostic (rc=1)"

  # RED: glob.
  cat > "$scratch" <<'EOF'
mod snapshot;
pub use snapshot::*;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control glob — \`pub use snapshot::*;\` was NOT refused (rc=$rc, wanted 1)" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'glob re-export' <<<"$out"; then
    echo "self-test FAILED: control glob refused, but not with its own distinctive diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control glob — \`pub use snapshot::*;\` is refused by its own distinctive diagnostic (rc=1) — the named-leaf check closes the glob route; clippy is defence-in-depth only"

  # RED: self.
  cat > "$scratch" <<'EOF'
mod snapshot;
pub use snapshot::{self};
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control self-reexport — \`pub use snapshot::{self};\` was NOT refused (rc=$rc, wanted 1)" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'self.*re-export' <<<"$out"; then
    echo "self-test FAILED: control self-reexport refused, but not with its own distinctive diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control self-reexport — \`pub use snapshot::{self};\` is refused by its own distinctive diagnostic (rc=1)"

  # RED: bare whole-module re-export, no `::` at all.
  cat > "$scratch" <<'EOF'
mod snapshot;
pub use snapshot;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control bare-module — \`pub use snapshot;\` was NOT refused (rc=$rc, wanted 1)" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'whole-module re-export with no' <<<"$out"; then
    echo "self-test FAILED: control bare-module refused, but not with its own distinctive diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control bare-module — \`pub use snapshot;\` (no \`::\` at all) is refused by its own distinctive diagnostic (rc=1)"

  # With `snapshot` declared as a root module,
  # the gate accepts these `pub use` bodies:
  # `crate::snapshot`, `self::snapshot`,
  # `crate::{snapshot}`, `{snapshot}`, and
  # `snapshot::sibling`. It checks the first
  # module segment and the leaf's spelling,
  # without resolving whether that leaf
  # names a module or another item.
  # Bare `pub use snapshot;` is refused
  # because the ungrouped path lacks `::`.
  # `pub use snapshot::{self};` is also
  # refused: a `self` leaf is forbidden.
  # Controls plant `snapshot::{Entry, ReaddirEntry}` and `snapshot::Snapshot`,
  # which have grouped and ungrouped named-leaf shapes. They do not plant
  # the exact `crate::snapshot`, `self::snapshot`, `crate::{snapshot}`,
  # `{snapshot}`, or `snapshot::sibling` spellings. The scanner does not
  # distinguish module leaves from item leaves.

  # RED: a foreign-crate root. `pub use granary_core::manifest;`
  # would allow-list the ENTIRE granary_core::manifest namespace — node,
  # tree, name, and every future addition — behind one root line.
  # The first-segment foreign-root check: the engine root re-exports only its own items.
  cat > "$scratch" <<'EOF'
mod attr;
pub use attr::Attr;
pub use granary_core::manifest;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control foreign-crate — \`pub use granary_core::manifest;\` was NOT refused (rc=$rc, wanted 1)" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q "not one of this crate's own declared modules" <<<"$out"; then
    echo "self-test FAILED: control foreign-crate refused, but not with the first-segment foreign-root check's own distinctive diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  if grep -q 'attr::Attr' <<<"$(grep '^REFUSE ' <<<"$out")"; then
    echo "self-test FAILED: control foreign-crate — the legitimate \`pub use attr::Attr;\` line was ALSO refused; only \`granary_core::manifest\` should be named" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control foreign-crate — \`pub use granary_core::manifest;\` is refused by the first-segment foreign-root check's own distinctive diagnostic (rc=1); the legitimate \`pub use attr::Attr;\` beside it in the same fixture is NOT named in any REFUSE line — the classification is per-line, not whole-file"

  # RED: a nested module named core
  # must not make core a crate-root
  # module. In `mod sneaky { mod core {} }`,
  # the nested name is outside
  # the root inventory, so
  # `pub use core::fmt::Debug;`
  # remains a foreign-root path.
  # `_collect_root_module_names`
  # records sneaky and skips its
  # body. A cfg-disabled module
  # at depth zero remains a
  # limitation because cfg is not
  # evaluated; the nesting case does
  # not require cfg evaluation.
  cat > "$scratch" <<'EOF'
mod attr;
mod sneaky {
    mod core {}
}
pub use core::fmt::Debug;
pub use attr::Attr;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control nested-mod-decoy-refused — \`pub use core::fmt::Debug;\` behind a decoy \`mod sneaky { mod core {} }\` was NOT refused (rc=$rc, wanted 1) — a nested decoy module bypassed the depth-zero \`_collect_root_module_names\` inventory" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'rooted at `core`' <<<"$out"; then
    echo "self-test FAILED: control nested-mod-decoy-refused refused, but not with the first-segment foreign-root check's own diagnostic naming \`core\`" >&2
    echo "$out" >&2
    exit 2
  fi
  if grep -q 'attr::Attr;$' <<<"$(grep '^REFUSE ' <<<"$out")"; then
    echo "self-test FAILED: control nested-mod-decoy-refused — the legitimate \`pub use attr::Attr;\` line was ALSO refused" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control nested-mod-decoy-refused — \`pub use core::fmt::Debug;\` behind a decoy \`mod sneaky { mod core {} }\` is refused by the first-segment foreign-root check's own diagnostic naming the clean \`core\` (rc=1); it compiles clean, but a scanner whose module inventory was depth-blind passed it at PUBUSE-COUNT 2 with zero REFUSE lines; the module inventory now comes from this scanner's own depth-0 walk, which never descends into \`sneaky\`'s private body"

  # GREEN: whitespace around \`::\` is valid Rust
  # (EXECUTED to compile clean under rustc, both the plain form and its
  # comment-separated equivalent — the comment/string stripper blanks a
  # \`/* c */\` to whitespace before this scanner ever sees the line, so
  # the two shapes reach \`_first_own_segment\` identically) and must not
  # be refused as though the path were foreign. Without trimming,
  # \`"attr :: Attr".split("::")\` handed the first-segment check the raw
  # piece \`"attr "\` — trailing space still attached — which could never
  # equal the clean \`"attr"\` this crate's own module inventory holds,
  # refusing valid Rust with \`a pub use rooted at \`attr \`\`\` (the space
  # visible inside the backticks): exactly the "refuses valid Rust"
  # class the gate must not reproduce: it must not refuse valid same-crate
  # paths because of separator whitespace.
  cat > "$scratch" <<'EOF'
mod attr;
pub use attr :: Attr;
pub use attr /* c */ :: Attr as OtherAttr;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: control ws-around-coloncolon-green — \`pub use attr :: Attr;\` and its comment-separated equivalent (both EXECUTED to compile clean) were REFUSED (rc=$rc)" >&2
    echo "$out" >&2
    exit 2
  fi
  # The green-control silent-omission hazard: assert the COUNT, not only rc==0 — a future change
  # that made the comment-separated form drop out of the walk entirely
  # (never reaching PUBUSE-COUNT at all) would still read rc=0 here,
  # with `root_shape_report`'s own zero-attempts floor never tripping
  # either (that floor needs ALL lines gone, not just one), so the
  # bare rc==0 check above cannot see a scanned line silently vanishing
  # from the walk. `assert_allowed_count` is the count check every
  # control that needs this extraction and comparison goes through.
  assert_allowed_count "ws-around-coloncolon-green" 2 "$out"
  echo "self-test: control ws-around-coloncolon-green — \`pub use attr :: Attr;\` and \`pub use attr /* c */ :: Attr as OtherAttr;\` (both EXECUTED to compile clean, whitespace and a blanked comment around \`::\`) stay GREEN (rc=0, 2 allowed pub use line(s)): a path segment is stripped before comparison, never compared with its separator's own adjacent whitespace still attached"

  # RED companion: the same whitespace shape must not defeat the
  # foreign-crate check either — \`pub use granary_core :: manifest;\`
  # stays refused, and refused CLEANLY: the diagnostic must name
  # \`granary_core\`, not \`granary_core \` with the space leaking through
  # into the diagnostic, as observed with an untrimmed segment.
  # The comment-separated form gets a RED here too —
  # ws-around-coloncolon-green's own GREEN half covers a blanked comment
  # (`attr /* c */ :: Attr`), but a RED half testing
  # only plain ASCII space leaves the refuse direction fail-open
  # against a change to the comment stripper's blanking.
  cat > "$scratch" <<'EOF'
mod attr;
pub use attr::Attr;
pub use granary_core :: manifest;
pub use granary_core /* c */ :: manifest as OtherManifest;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control ws-around-coloncolon-foreign-still-refused — \`pub use granary_core :: manifest;\` and its comment-separated equivalent were NOT refused (rc=$rc, wanted 1)" >&2
    echo "$out" >&2
    exit 2
  fi
  set +e
  clean_root_hits="$(grep -c 'rooted at `granary_core`' <<<"$out")"
  set -e
  if [[ "$clean_root_hits" -ne 2 ]]; then
    echo "self-test FAILED: control ws-around-coloncolon-foreign-still-refused — expected exactly 2 refusals naming the CLEAN \`granary_core\` (plain whitespace AND the comment-separated form), got ${clean_root_hits:-0} (whitespace or a blanked comment leaked into a diagnostic, or the wrong diagnostic fired)" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control ws-around-coloncolon-foreign-still-refused — \`pub use granary_core :: manifest;\` (whitespace around \`::\`) AND \`pub use granary_core /* c */ :: manifest as OtherManifest;\` (a blanked comment around \`::\`) are both still refused (rc=1), each naming the clean \`granary_core\`, never a whitespace- or comment-padded segment"

  # GREEN: U+200E (LEFT-TO-RIGHT MARK) around \`::\` is
  # ALSO valid Rust — EXECUTED to compile clean under rustc, both with
  # the mark immediately before the separator and immediately after —
  # and must not be refused as though the path were foreign either.
  # This is the same class ws-around-coloncolon-green above locks in
  # for ASCII space, one character class wider: normalizing only in
  # \`_first_own_segment\`, that site stripped with the file's own
  # \`WS\` class, while \`_leaf_ok\` and \`classify_pub_use_top\`'s
  # no-brace path each still trimmed with Python's bare \`.strip()\`,
  # which does not remove U+200E/U+200F — so the plain-space form above
  # went green while this one stayed refused.
  cat > "$scratch" <<'EOF'
mod attr;
pub use attr‎::Attr;
pub use attr::‎Attr as OtherAttr;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: control ws-lrm-around-coloncolon-green — \`pub use attr‎::Attr;\` and \`pub use attr::‎Attr as OtherAttr;\` (both EXECUTED to compile clean) were REFUSED (rc=$rc)" >&2
    echo "$out" >&2
    exit 2
  fi
  # `assert_allowed_count` is the extraction and comparison every
  # count-asserting control shares, so each gets the same
  # missing-count refusal, just as three scanner sites
  # share segment normalization through `_norm_segment`.
  assert_allowed_count "ws-lrm-around-coloncolon-green" 2 "$out"
  echo "self-test: control ws-lrm-around-coloncolon-green — \`pub use attr‎::Attr;\` and \`pub use attr::‎Attr as OtherAttr;\` (both EXECUTED to compile clean, a LEFT-TO-RIGHT MARK on either side of \`::\`) stay GREEN (rc=0, 2 allowed pub use line(s)): a path segment is normalized on this file's own WS class, not Python's str.strip(), before comparison"

  # RED companion: the same mark shape must not defeat the foreign-crate
  # check either — \`pub use granary_core<mark>::manifest;\` stays
  # refused, and refused CLEANLY: the diagnostic must name
  # \`granary_core\`, with no stray character attached, the same
  # assertion ws-around-coloncolon-foreign-still-refused makes for
  # ASCII space.
  #
  # Testing the mark on only ONE side of \`::\` (immediately before
  # it) leaves the AFTER-\`::\` refusal direction without coverage,
  # even though the GREEN sibling (ws-lrm-around-coloncolon-green,
  # above) covers BOTH sides — that asymmetry lets an AFTER-\`::\`
  # regression go undetected here. Separately, U+200F
  # (RIGHT-TO-LEFT MARK) — named in this file's own \`WS\` comment and
  # in three places in \`vfs-root-shape-scan.py\`'s header as exactly
  # half of what \`WS\` covers alongside U+200E — appeared in NO fixture
  # anywhere in this file. Both gaps close here: all four combinations
  # of {before, after} x {U+200E, U+200F}.
  cat > "$scratch" <<'EOF'
mod attr;
pub use attr::Attr;
pub use granary_core‎::manifest;
pub use granary_core::‎manifest as OtherManifest;
pub use granary_core‏::manifest as YetAnotherManifest;
pub use granary_core::‏manifest as StillAnotherManifest;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control ws-lrm-foreign-still-refused — the four before/after x LRM/RLM \`granary_core\` spellings were NOT all refused (rc=$rc, wanted 1)" >&2
    echo "$out" >&2
    exit 2
  fi
  set +e
  clean_root_hits="$(grep -c 'rooted at `granary_core`' <<<"$out")"
  set -e
  if [[ "$clean_root_hits" != "4" ]]; then
    echo "self-test FAILED: control ws-lrm-foreign-still-refused — expected exactly 4 refusals naming the CLEAN \`granary_core\` (both sides of \`::\`, both U+200E and U+200F), got ${clean_root_hits:-0} (a mark leaked into a diagnostic, or the wrong diagnostic fired)" >&2
    echo "$out" >&2
    exit 2
  fi
  if grep -q 'attr::Attr' <<<"$(grep '^REFUSE ' <<<"$out")"; then
    echo "self-test FAILED: control ws-lrm-foreign-still-refused — the legitimate \`pub use attr::Attr;\` line was ALSO refused" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control ws-lrm-foreign-still-refused — \`pub use granary_core<mark>::manifest;\` and \`pub use granary_core::<mark>manifest;\`, for BOTH a LEFT-TO-RIGHT MARK and a RIGHT-TO-LEFT MARK (four combinations total), are all still refused (rc=1), each naming the clean \`granary_core\`, never a mark-padded segment"

  # RED: A WS-class mark after `pub` must not hide public declarations.
  # `PUB_RE` already matches a WS-class mark right after the `pub`
  # keyword (the mark sits inside `PUB_RE`'s own `WS*`), so a bare
  # `.strip()` in `_is_full_pub` left the mark attached —
  # `pub_text.strip() == "pub"` came back False — and a FULLY public
  # `mod`/`extern crate`/`use` silently read as though it carried no
  # visibility at all: the ONE discriminator every arm below depends on
  # to decide whether a `mod`/`extern crate` promotes a name across the
  # crate boundary, and whether a `pub use`'s named-leaf shape is
  # checked in the first place. EXECUTED with bare `.strip()` in
  # `_is_full_pub`: all four lines below passed with
  # \`PUBUSE-COUNT 1\`, zero \`REFUSE\` — a root publicly exporting a
  # whole module, a whole crate, a foreign path, AND a glob, all
  # unnamed. All four (and their U+200F siblings in the next control)
  # are EXECUTED to compile clean under rustc 1.97.1 — \`alloc\` stands
  # in for a foreign crate here, the same substitution
  # \`bare-anchor-foreign-leaf\` already uses in this file, since a
  # real foreign dependency needs its own build to resolve and \`alloc\`
  # needs only its own \`extern crate\` line.
  cat > "$scratch" <<'EOF'
mod attr;
pub‎mod leaky {
    pub struct Leaky;
}
pub‎extern crate alloc;
pub‎use alloc::boxed::Box;
pub‎use attr::*;
pub use attr::Attr;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control ws-lrm-pub-keyword-fail-open-closed — a pub<LRM>mod, a pub<LRM>extern crate, a pub<LRM>use of a foreign path, and a pub<LRM>use of a glob were NOT all refused (rc=$rc, wanted 1) — a WS-class mark after \`pub\` has again hidden fully public declarations from these checks" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q '`pub mod`' <<<"$out"; then
    echo "self-test FAILED: control ws-lrm-pub-keyword-fail-open-closed — pub<LRM>mod leaky was not refused by its own \`pub mod\` diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q '`pub extern crate`' <<<"$out"; then
    echo "self-test FAILED: control ws-lrm-pub-keyword-fail-open-closed — pub<LRM>extern crate alloc was not refused by its own \`pub extern crate\` diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'rooted at `alloc`' <<<"$out"; then
    echo "self-test FAILED: control ws-lrm-pub-keyword-fail-open-closed — pub<LRM>use alloc::boxed::Box was not refused by the first-segment foreign-root check's own diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'glob re-export' <<<"$out"; then
    echo "self-test FAILED: control ws-lrm-pub-keyword-fail-open-closed — pub<LRM>use attr::* was not refused by its own glob diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  if grep -q 'attr::Attr;$' <<<"$(grep '^REFUSE ' <<<"$out")"; then
    echo "self-test FAILED: control ws-lrm-pub-keyword-fail-open-closed — the legitimate \`pub use attr::Attr;\` line was ALSO refused" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control ws-lrm-pub-keyword-fail-open-closed — pub<LRM>mod, pub<LRM>extern crate, pub<LRM>use of a foreign path, and pub<LRM>use of a glob (a LEFT-TO-RIGHT MARK immediately after the \`pub\` keyword, all four EXECUTED to compile clean under rustc) are each refused by their own distinctive diagnostic (rc=1); the legitimate \`pub use attr::Attr;\` beside them stays unnamed"

  # RED: the U+200F (RIGHT-TO-LEFT MARK) sibling of the control above —
  # the other half of `WS` alongside U+200E — had been named in comments
  # but had no fixture in this file, so this control exercises it
  # explicitly.
  cat > "$scratch" <<'EOF'
mod attr;
pub‏mod leaky {
    pub struct Leaky;
}
pub‏extern crate alloc;
pub‏use alloc::boxed::Box;
pub‏use attr::*;
pub use attr::Attr;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control ws-rlm-pub-keyword-fail-open-closed — a pub<RLM>mod, a pub<RLM>extern crate, a pub<RLM>use of a foreign path, and a pub<RLM>use of a glob were NOT all refused (rc=$rc, wanted 1)" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q '`pub mod`' <<<"$out"; then
    echo "self-test FAILED: control ws-rlm-pub-keyword-fail-open-closed — pub<RLM>mod leaky was not refused by its own \`pub mod\` diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q '`pub extern crate`' <<<"$out"; then
    echo "self-test FAILED: control ws-rlm-pub-keyword-fail-open-closed — pub<RLM>extern crate alloc was not refused by its own \`pub extern crate\` diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'rooted at `alloc`' <<<"$out"; then
    echo "self-test FAILED: control ws-rlm-pub-keyword-fail-open-closed — pub<RLM>use alloc::boxed::Box was not refused by the first-segment foreign-root check's own diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'glob re-export' <<<"$out"; then
    echo "self-test FAILED: control ws-rlm-pub-keyword-fail-open-closed — pub<RLM>use attr::* was not refused by its own glob diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control ws-rlm-pub-keyword-fail-open-closed — the U+200F (RIGHT-TO-LEFT MARK) sibling of ws-lrm-pub-keyword-fail-open-closed (all four EXECUTED to compile clean under rustc) is refused the same way (rc=1): the pub-keyword check is mark-agnostic, not LRM-specific"

  # GREEN: the fail-CLOSED half of the same bug class
  # — a mark on the ALIAS side of a \`pub use\`, bare and brace-grouped,
  # both EXECUTED to compile clean under rustc, were REFUSED with "an
  # unrecognised alias in pub use", because the alias
  # text in both \`_leaf_ok\` and \`classify_pub_use_top\`'s no-brace path
  # was never routed through \`_norm_segment\` at all — this is a
  # FOURTH bare \`.strip()\` site omitted by the three-site enumeration.
  # The control also covers a separate case: a mark
  # immediately INSIDE a brace group with no alias at all
  # (\`pub use attr::{<LRM>Attr};\`) already passed: \`_leaf_ok\`'s own
  # \`_norm_segment\` call already covered it, but no fixture in this file
  # exercised it directly until this control (the mutation note just
  # below says what that coverage does and does not prove).
  #
  # The `_leaf_ok` fixture exercises the path but does not prove
  # `_norm_segment` is load-bearing: a mutation showed that removing
  # its own \`_norm_segment\` call left the fixture passing because
  # the whitespace pre-pass had already normalized the input.
  cat > "$scratch" <<'EOF'
mod attr;
mod handle;
pub use attr::Attr as Other‎;
pub use attr::{NodeKind as OtherNodeKind‏};
pub use handle::{‎HandleKind};
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: control ws-lrm-alias-and-leaf-mark-green — a mark-suffixed bare alias, a mark-suffixed brace alias, and a mark-prefixed brace leaf (all EXECUTED to compile clean) were REFUSED (rc=$rc)" >&2
    echo "$out" >&2
    exit 2
  fi
  assert_allowed_count "ws-lrm-alias-and-leaf-mark-green" 3 "$out"
  echo "self-test: control ws-lrm-alias-and-leaf-mark-green — \`pub use attr::Attr as Other<LRM>;\` (a LEFT-TO-RIGHT MARK trailing a bare alias), \`pub use attr::{NodeKind as OtherNodeKind<RLM>};\` (a RIGHT-TO-LEFT MARK trailing a braced alias), and \`pub use handle::{<LRM>HandleKind};\` (a mark leading a braced leaf with no alias at all) — all EXECUTED to compile clean — stay GREEN (rc=0, 3 allowed pub use line(s)): the alias side of a pub use is normalized on this file's own WS class exactly as its path side already was"

  # RED: the EXACT scenario proving the glob route is closed by
  # THIS SCRIPT, not by the workspace clippy config — a real clippy run
  # against this identical shape (mod extra; carrying pub items; pub
  # use extra::*;) produces ZERO wildcard_imports warnings (EXECUTED;
  # see control `glob-not-clippy` below). Locked in here as a direct
  # self-test control so the claim never again rests on an
  # out-of-band, undocumented experiment.
  cat > "$scratch" <<'EOF'
mod attr;
mod extra;
pub use attr::Attr;
pub use extra::*;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control glob-not-clippy — \`mod extra; pub use extra::*;\` was NOT refused BY THE SCRIPT (rc=$rc, wanted 1)" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'glob re-export' <<<"$out"; then
    echo "self-test FAILED: control glob-not-clippy refused, but not by naming the glob" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control glob-not-clippy — \`mod extra; pub use extra::*;\` (the exact shape a real clippy run leaves with ZERO wildcard_imports warnings, since clippy skips the lint when names_imported_by_glob_use is empty and unused_imports never fires on a re-export) IS refused, by THIS SCRIPT's own named-leaf check (rc=1) — the deliberate closing mechanism; the clippy key is defence-in-depth, not the closer"

  # RED: `pub(crate) const` — the shape a naive `^(pub\s+)?const` matcher
  # silently passes, because after "pub" comes "(crate)", not whitespace,
  # so the whole match fails and the line reads as though it named no
  # const at all. THIS gate's allow-list never tries to recognise
  # `const` in the first place — it only recognises `extern crate`/
  # `mod`/`use` heads, so anything else, `pub`-qualified or not, falls
  # straight to "not on the allow-list" with no pub-awareness bug
  # possible. Proven here directly, against granary-fuse's own real
  # shape (`crates/granary-fuse/src/lib.rs:87` carries exactly this
  # form) rather than an invented one.
  cat > "$scratch" <<'EOF'
mod attr;
pub(crate) const FUSE_READLINK_TARGET_MAX_4K_PAGE: usize = 4095;
pub use attr::Attr;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control pub-crate-const — \`pub(crate) const ...;\` was NOT refused (rc=$rc, wanted 1) — a naive pub-unaware matcher would silently pass this exact shape (granary-fuse/src/lib.rs:87 carries it verbatim)" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'not on the allow-list' <<<"$out"; then
    echo "self-test FAILED: control pub-crate-const refused, but not with the allow-list's own distinctive diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control pub-crate-const — \`pub(crate) const FUSE_READLINK_TARGET_MAX_4K_PAGE: usize = 4095;\` (granary-fuse/src/lib.rs:87's own real shape) is refused (rc=1): the allow-list design makes the naive pub\\s+const matcher bug structurally impossible rather than fixing it case by case"

  # RED: `impl` written straight into the root.
  cat > "$scratch" <<'EOF'
mod snapshot;
impl Snapshot {
    pub fn extra_surface() -> u32 { 0 }
}
pub use snapshot::Snapshot;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control impl-block — an \`impl\` block written directly into the root was NOT refused (rc=$rc, wanted 1)" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'not on the allow-list' <<<"$out"; then
    echo "self-test FAILED: control impl-block refused, but not with the allow-list's own distinctive diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control impl-block — \`impl Snapshot { pub fn extra_surface() ... }\` written straight into the root (widens an existing type's surface with the root's own line count and \`pub use\` list both unchanged) is refused (rc=1)"

  # RED: an item-position macro invocation. A deny-list design would
  # need its own "unclassifiable, exit 2" bucket
  # (std::thread_local!'s own `pub static` tokens contain no direct item
  # definition a deny-list could name); under the allow-list, "not on
  # the list" is already a confident, complete answer, so this is a
  # plain rc=1 refusal like any other, not an uncertain rc=2.
  cat > "$scratch" <<'EOF'
mod attr;
std::thread_local! {
    pub static ZZ_ROOT_STATIC: u32 = 0;
}
pub use attr::Attr;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control macro-invocation — \`std::thread_local! { pub static ...; }\` at crate scope was NOT refused at rc=1 (got rc=$rc) — an allow-list's 'not on the list' is a confident refusal, not an uncertain one" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'not on the allow-list' <<<"$out"; then
    echo "self-test FAILED: control macro-invocation refused, but not with the allow-list's own distinctive diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control macro-invocation — \`std::thread_local! { pub static ...; }\` at crate scope (expands to a public item with no item-definition keyword a deny-list could name) is refused at a plain rc=1, not an uncertain rc=2 — the allow-list makes 'unclassifiable' the same answer as any other unrecognised shape"

  # DECOY: the same forbidden text inside a doc comment and inside a
  # string literal must NOT count.
  cat > "$scratch" <<'EOF'
//! pub use evil::*;
#[doc = "pub mod evil { pub struct Evil; }"]
mod attr;
// pub use another_evil::*;
pub use attr::Attr;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: control decoy — forbidden text inside a doc comment, a #[doc] string, and a // comment was treated as real source (rc=$rc)" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control decoy — the same forbidden text ('pub use evil::*;', 'pub mod evil { ... }') inside a \`//!\` doc comment, a \`#[doc = \"...\"]\` string, and a \`//\` comment does not count (rc=0): comment/string stripping runs before this scanner ever sees the text"

  # NESTING GREEN: a private inline module's body is skipped as one
  # block, whatever is inside it — proven with a SYNTHETIC fixture
  # carrying constructs that would all be refused at crate scope, plus
  # confirmed against the REAL root_surface_probe test module below.
  # The fixture also includes return-position
  # and argument-position `impl Trait`. The
  # scanner skips the entire private inline
  # module body as one block. It does not
  # classify individual implementations
  # there: whether a `Self` type is
  # externally reachable requires compiler
  # name resolution. This control checks
  # that the opaque-body skip still holds.
  cat > "$scratch" <<'EOF'
mod attr;
#[cfg(test)]
mod root_surface_probe {
    pub struct NotARootItem;
    pub mod nested_pub_mod_is_fine_here;
    pub use attr::Attr as ThisWouldBeRefusedAtCrateScope;
    fn helper() -> u32 { 0 }
    fn make_iter() -> impl Iterator<Item = u32> { std::iter::empty() }
    fn take(x: impl Into<u32>) -> u32 { x.into() }
}
pub use attr::Attr;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: control nesting-green — a private inline module's body (containing shapes that would all be refused at crate scope, plus an opaque-return-type and argument-position \`impl Trait\`) was inspected instead of skipped as one block (rc=$rc)" >&2
    echo "$out" >&2
    exit 2
  fi
  # Assert the COUNT too — see prefixless-brace-group's
  # own comment above for why. This fixture's ONE crate-scope `pub use` is
  # the trailing `pub use attr::Attr;`; the private mod body's own
  # `pub use attr::Attr as ThisWouldBeRefusedAtCrateScope;` is skipped as
  # part of that block and never reaches the count.
  assert_allowed_count "nesting-green" 1 "$out"
  echo "self-test: control nesting-green — a private \`#[cfg(test)] mod { ... }\`'s body (a pub struct, a pub mod, a pub use, a plain fn, a return-position \`impl Trait\` and an argument-position \`impl Trait\`) is skipped as ONE block and stays green (rc=0); the real crate root's own \`root_surface_probe\` is an out-of-line declaration with no inline body, so arm-a-positive does not exercise the inline-module-skipping path and this synthetic control does"

  # An impl inside a private inline
  # module is not checked: deciding
  # whether its Self type is externally
  # reachable requires compiler name
  # resolution. A textual check can
  # both miss an impl behind attributes
  # and reject a legitimate private
  # test-double impl. The fixtures
  # document the accepted scope instead
  # of treating source spelling
  # alone as proof of reachability.

  # GREEN: a private test module declares
  # its own test double and a trait
  # implementation. The scanner must
  # skip the inline module body as one
  # block. This fixture exercises that
  # body-skipping path directly,
  # including syntax inside the module
  # that would be refused at crate
  # scope. An out-of-line
  # `mod root_surface_probe;` declaration
  # has no body in the root file, so
  # scanning that declaration alone
  # cannot exercise the inline-body case.
  cat > "$scratch" <<'EOF'
mod source;
#[cfg(test)]
mod tests {
    struct Fake;
    impl crate::source::GrainFetch for Fake {
        fn fetch(&self) {}
    }
}
pub use source::GrainFetch;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "self-test FAILED: control impl-in-private-mod-green — a private test-double \`impl\` inside \`#[cfg(test)] mod tests { ... }\` was REFUSED (rc=$rc); an \`impl\` inside a private inline module is deliberately not checked because deciding whether its \`Self\` type is externally reachable requires compiler name resolution" >&2
    echo "$out" >&2
    exit 2
  fi
  # Assert the COUNT too — see prefixless-brace-group's
  # own comment above for why.
  assert_allowed_count "impl-in-private-mod-green" 1 "$out"
  echo "self-test: control impl-in-private-mod-green — a private test-double \`impl\` inside \`#[cfg(test)] mod tests { struct Fake; impl crate::source::GrainFetch for Fake { ... } }\` stays GREEN (rc=0): the next engineer adding a test double beside \`root_surface_probe\` does not redden CI"
  rm -f "$scratch"

  # THE LONG-DECLARATION CONTROL. A terminator
  # search bounded to 2,000 characters could
  # miss a glob at the end of a longer declaration.
  # Plant a public-use brace list longer than
  # that bound and require the scanner to refuse
  # the tail glob, so the declaration cannot
  # disappear merely because it is long.
  python3 - "$scratch" <<'PYEOF'
import sys
path = sys.argv[1]
names = [f"Item{i}" for i in range(1, 200)]
with open(path, "w", encoding="utf-8") as f:
    f.write("mod snapshot;\n")
    f.write("pub use snapshot::{\n")
    for n in names:
        f.write(f"    {n},\n")
    f.write("    Evil::*,\n")
    f.write("};\n")
PYEOF
  if ! python3 - "$scratch" <<'PYEOF'
import sys
data = open(sys.argv[1], encoding="utf-8").read()
u = data.find("use")
semi = data.rfind(";")
sys.exit(0 if (semi - u) > 2000 else 1)
PYEOF
  then
    echo "self-test fixture BROKEN: control beyond-2000-chars did not actually place its terminator past 2000 characters from 'use'" >&2
    exit 2
  fi
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control beyond-2000-chars — a glob buried past a 2000-character \`pub use\` brace list was NOT refused (rc=$rc, wanted 1); a bounded terminator search would have silently dropped this statement entirely" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'glob re-export' <<<"$out"; then
    echo "self-test FAILED: control beyond-2000-chars refused, but not by naming the glob" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control beyond-2000-chars — a glob buried inside a \`pub use\` brace list whose terminating \`;\` lies past 2,000 characters from the \`use\` keyword is caught (rc=1): this scanner's terminator search is unbounded, unlike fsguard-scan.py's own use_statements (bounded at 2000 chars for an unrelated caller's quadratic-blowup concern), which would silently drop this exact statement"

  # COULD-NOT-RUN: missing file.
  set +e
  out="$(root_shape_report "$tmp/does-not-exist.rs" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 2 ]]; then
    echo "self-test FAILED: control missing-file — a nonexistent lib.rs was NOT refused with rc=2 (got rc=$rc)" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control missing-file — a nonexistent path is refused with rc=2, never read as a clean (zero-construct) root"

  # COULD-NOT-RUN: empty file (zero pub-use lines).
  : > "$scratch"
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 2 ]]; then
    echo "self-test FAILED: control empty-file — an empty lib.rs was NOT refused with rc=2 (got rc=$rc)" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control empty-file — an empty lib.rs (zero \`pub use\` lines) is refused with rc=2"

  # COULD-NOT-RUN: valid-looking source, but zero pub-use lines (a root
  # gutted of its whole surface must not read as "clean, nothing to
  # refuse").
  cat > "$scratch" <<'EOF'
mod attr;
mod snapshot;
use attr::Attr as _;
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 2 ]]; then
    echo "self-test FAILED: control zero-pubuse — a syntactically valid root with ZERO \`pub use\` lines was NOT refused with rc=2 (got rc=$rc)" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control zero-pubuse — a syntactically valid root carrying zero \`pub use\` lines is refused with rc=2, not read as a root that was walked and found to have nothing wrong"

  # COULD-NOT-RUN: malformed source — an unterminated \`use\` (no \`;\` at
  # all before EOF).
  cat > "$scratch" <<'EOF'
mod attr;
pub use attr::Attr
EOF
  set +e
  out="$(root_shape_report "$scratch" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 2 ]]; then
    echo "self-test FAILED: control unterminated-use — a \`pub use\` with no terminating \`;\` was NOT refused with rc=2 (got rc=$rc)" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control unterminated-use — an unterminated \`use\` (no \`;\` before EOF — malformed or truncated source) is refused with rc=2"

  # The pipefail hazard, MUTATION-PROVED: root_shape_report's OWN pipefail guard around
  # its `pubuse_count=...` assignment. Comments out
  # vfs-root-shape-scan.py's own `print(f"PUBUSE-COUNT
  # {pubuse_count}")` on a SCRATCH COPY (never the real scanner) and
  # drives root_shape_report itself — never a reimplementation of its
  # rc/diagnostic logic — against the real, unmodified $LIB_RS through
  # that broken scanner. Before the guard existed, this reproduced a
  # BARE, UNDIAGNOSED rc=1 with empty stdout+stderr: under this script's
  # `set -euo pipefail`, `grep` finding no `PUBUSE-COUNT` line makes the
  # `| sed` pipeline fail, and a bare assignment form dies to errexit
  # right there, before the `-z "$pubuse_count"` check downstream ever
  # runs — the wrong exit class (1, not 2) with no diagnostic at all.
  local scan_scratch
  scan_scratch="$(mktemp -d)"
  _vfs_shape_track "${scan_scratch}"
  cp "$SCAN_PY" "$scan_scratch/vfs-root-shape-scan.py"
  cp "$(dirname "$SCAN_PY")/fsguard-scan.py" "$scan_scratch/fsguard-scan.py"
  plant_once_or_die "$scan_scratch/vfs-root-shape-scan.py" \
    '        print(f"PUBUSE-COUNT {pubuse_count}")' \
    '        pass  # PUBUSE-COUNT print REMOVED — planted by --self-test control pipefail-guard'
  if grep -q 'print(f"PUBUSE-COUNT' "$scan_scratch/vfs-root-shape-scan.py"; then
    echo "self-test BROKEN: control pipefail-guard's mutation did not apply — the PUBUSE-COUNT print is still present in the scratch scanner copy" >&2
    exit 2
  fi
  local saved_scan_py="$SCAN_PY"
  SCAN_PY="$scan_scratch/vfs-root-shape-scan.py"
  set +e
  out="$(root_shape_report "$LIB_RS" 2>&1)"
  rc=$?
  set -e
  SCAN_PY="$saved_scan_py"
  if [[ "$rc" -ne 2 ]]; then
    echo "self-test FAILED: control pipefail-guard — a scanner with no PUBUSE-COUNT print was NOT refused with rc=2 (got rc=$rc) — the guard around the pubuse_count assignment did not hold" >&2
    echo "$out" >&2
    exit 2
  fi
  if [[ -z "$out" ]]; then
    echo "self-test FAILED: control pipefail-guard — refused with rc=2 but printed NO diagnostic at all — exactly the silent errexit death this control exists to catch" >&2
    exit 2
  fi
  if ! grep -q 'could not confirm the scanner ran at all' <<<"$out"; then
    echo "self-test FAILED: control pipefail-guard refused, but not with its own diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control pipefail-guard — a scanner whose PUBUSE-COUNT print is missing (planted on a scratch copy, never the real scanner) is refused with rc=2 AND its own diagnostic, never a bare undiagnosed rc=1 with empty output"

  rm -f "$scratch"
}

# ---------------------------------------------------------- self-test: B
selftest_arm_b() {
  local tmp real_floor out rc fake_bin real_git

  if ! real_floor="$(macro_export_git_floor "$CRATE_SRC")"; then
    echo "self-test FAILED: could not derive the real git floor for $CRATE_SRC against the unmodified repo" >&2
    exit 2
  fi
  out="$(macro_export_report "$CRATE_SRC" "$real_floor")" || {
    echo "self-test FAILED: arm B did not pass against the real, unmodified $CRATE_SRC" >&2
    exit 2
  }
  echo "self-test: control arm-b-positive — $out (git-derived floor $real_floor)"

  # COULD-NOT-RUN: a `git ls-files` failure (check-vfs-purity.sh's own
  # selftest_vfs_src_file_floor idiom: a fake `git` that fails on
  # `ls-files` specifically and defers everything else to the real
  # binary), proving the floor derivation refuses rather than dying
  # silently at a bare 127/128/129 before its own diagnostic ever runs.
  real_git="$(command -v git)"
  fake_bin="$(mktemp -d)"
  _vfs_shape_track "${fake_bin}"
  cat > "$fake_bin/git" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == "ls-files" ]]; then
  echo "fatal: fake git failure planted by check-vfs-root-shape.sh --self-test" >&2
  exit 128
fi
exec "$real_git" "\$@"
EOF
  chmod +x "$fake_bin/git"
  if PATH="$fake_bin:$PATH" git ls-files >/dev/null 2>&1; then
    echo "self-test BROKEN: control git-floor-failure's fake 'git ls-files' did not fail as intended" >&2
    exit 2
  fi
  set +e
  out="$(PATH="$fake_bin:$PATH" macro_export_git_floor "$CRATE_SRC" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 2 ]]; then
    echo "self-test FAILED: control git-floor-failure — a 'git ls-files' failure was NOT refused with rc=2 (got rc=$rc)" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'could not derive' <<<"$out"; then
    echo "self-test FAILED: control git-floor-failure refused, but did not print its own diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control git-floor-failure — a 'git ls-files' failure is refused with rc=2 and its own diagnostic, not a silent bare 127/128/129"

  tmp="$(mktemp -d)"
  _vfs_shape_track "${tmp}"
  mkdir -p "$tmp/src"

  # RED: a direct #[macro_export].
  cat > "$tmp/src/zz_exported.rs" <<'EOF'
#[macro_export]
macro_rules! zz_evil_macro {
    () => { pub struct ZzEvil; };
}
EOF
  # REQUIRED GREEN: the purity gate permits ordinary non-exported
  # `macro_rules!` definitions, so keep one beside the exported macro.
  cat > "$tmp/src/zz_internal.rs" <<'EOF'
macro_rules! zz_internal_macro {
    () => { pub(crate) fn zz_helper() -> u32 { 0 } };
}
EOF
  # cfg_attr-nested form.
  cat > "$tmp/src/zz_cfg_attr.rs" <<'EOF'
#[cfg_attr(feature = "zz_extra", macro_export)]
macro_rules! zz_maybe_exported {
    () => {};
}
EOF
  # DECOY: macro_export named in a comment and inside a string.
  cat > "$tmp/src/zz_decoy.rs" <<'EOF'
// #[macro_export]
#[doc = "an example writes #[macro_export] here but this is a string"]
macro_rules! zz_decoy_macro {
    () => {};
}
EOF
  set +e
  out="$(macro_export_report "$tmp/src" 1 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: arm B did not FAIL (rc=$rc, wanted 1) against a fixture carrying two real #[macro_export] attributes" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'zz_exported.rs' <<<"$out" || ! grep -q 'zz_cfg_attr.rs' <<<"$out"; then
    echo "self-test FAILED: arm B FAILED but did not name BOTH the direct and the cfg_attr-nested #[macro_export]" >&2
    echo "$out" >&2
    exit 2
  fi
  if grep -q 'zz_internal.rs\|zz_decoy.rs' <<<"$out"; then
    echo "self-test FAILED: arm B reported the non-exported macro_rules! or the decoy file — must stay green" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control macro-export — a direct #[macro_export] and a #[cfg_attr(cond, macro_export)] in CHILD module files are both named (rc=1); a non-exported macro_rules! beside them, and the same text inside a comment and a string, all stay green"

  # COULD-NOT-RUN: an empty directory (zero .rs files).
  rm -f "$tmp/src"/*.rs
  set +e
  out="$(macro_export_report "$tmp/src" 1 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 2 ]]; then
    echo "self-test FAILED: control empty-dir — a directory with zero .rs files was NOT refused with rc=2 (got rc=$rc)" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control empty-dir — a walk enumerating zero .rs files is refused with rc=2, not read as a scan of the crate that found nothing"

  # COULD-NOT-RUN: a symlinked directory that plain find never descends,
  # making the plain-vs-`find -L` counts disagree.
  mkdir -p "$tmp/outside"
  cat > "$tmp/outside/hidden.rs" <<'EOF'
pub fn hidden() -> u32 { 0 }
EOF
  cat > "$tmp/src/zz_present.rs" <<'EOF'
pub fn present() -> u32 { 0 }
EOF
  ln -s "$tmp/outside" "$tmp/src/zz_linked_dir"
  set +e
  out="$(macro_export_report "$tmp/src" 1 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 2 ]]; then
    echo "self-test FAILED: control symlinked-dir — a symlinked directory under the scanned src (making plain \`find\` and \`find -L\` disagree) was NOT refused with rc=2 (got rc=$rc)" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control symlinked-dir — a symlinked directory under the crate's source, invisible to the plain \`find\` this gate scans but followed by \`find -L\`, is refused with rc=2 rather than silently scanning fewer files than rustc would compile"

  rm -rf "$tmp"
}

# ------------------------------------------- self-test: the SECOND crate
# The second-crate extension requires positive and negative controls. It gets
# four controls, because the ALLOW-LIST is new
# machinery and a named exception has two failure modes a verdict cannot show:
# an entry that matches nothing (silent widening) and one that matches several
# (a pattern in a named exception's clothes).
selftest_arm_a_second_crate() {
  local tmp scratch out rc fuse_lib
  fuse_lib="crates/granary-fuse/src/lib.rs"

  # GREEN — the real, unmodified granary-fuse root passes WITH its allow-list.
  # This is the control that would fail the day someone adds a fifth construct
  # to that root, which is the whole point of extending the gate to it.
  out="$(root_shape_report "$fuse_lib" granary-fuse)" || {
    echo "self-test FAILED: control fuse-positive — arm A did not pass against the real, unmodified $fuse_lib with its own allow-list" >&2
    exit 2
  }
  echo "self-test: control fuse-positive — $out"

  # GREEN, and it is the one that proves the allow-list is not a blanket:
  # granary-fuse's root passes only because FOUR named constructs are allowed,
  # so running it with NO allow-list must FAIL. If this ever went green the
  # allow-list would be doing nothing and the four entries would be decoration.
  set +e
  out="$(root_shape_report "$fuse_lib" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control fuse-allowlist-load-bearing — $fuse_lib with NO allow-list gave rc=$rc, expected exactly 1 (a FAIL for named constructs). rc=0 would mean the four allow-list entries are doing nothing; rc=2 would mean the control passed for a could-not-run reason and proved nothing" >&2
    echo "$out" >&2
    exit 2
  fi

  # RED — a genuinely NEW construct at granary-fuse's root is refused. The
  # allow-list names four constructs; it must not licence a fifth.
  tmp="$(mktemp -d)"
  _vfs_shape_track "${tmp}"
  scratch="$tmp/fuse_lib.rs"
  cp "$fuse_lib" "$scratch"
  append_and_confirm "$scratch" \
    'pub const FUSE_EXTRA_LIMITS: usize = 1;' \
    'pub const FUSE_EXTRA_LIMITS'
  set +e
  out="$(root_shape_report "$scratch" granary-fuse 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "self-test FAILED: control fuse-new-construct-refused — a NEW \`pub const\` at granary-fuse's root gave rc=$rc, expected 1; the allow-list must name four constructs, not licence a class" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q "FUSE_EXTRA_LIMITS" <<<"$out"; then
    echo "self-test FAILED: control fuse-new-construct-refused — refused, but the diagnostic does not name the offending construct" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control fuse-new-construct-refused — a fifth root construct is refused by name at rc=1, and the four allowed ones are load-bearing (with no allow-list the same root FAILS)"

  # RED: extending an allowed identifier does not
  # preserve its exception. The renamed construct
  # must be refused by the identifier-boundary check.
  scratch="$tmp/fuse_lib_rename.rs"
  sed 's/pub const FUSE_SERVE_LIMITS:/pub const FUSE_SERVE_LIMITS_V2:/' "$fuse_lib" > "$scratch"
  if ! grep -q 'FUSE_SERVE_LIMITS_V2' "$scratch"; then
    echo "self-test fixture BROKEN: control allowlist-prefix-rename — the rename did not apply to $scratch" >&2
    exit 2
  fi
  set +e
  out="$(root_shape_report "$scratch" granary-fuse 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    echo "self-test FAILED: control allowlist-prefix-rename — renaming an allowed \`pub const\` to a name that merely EXTENDS it stayed GREEN; an allow-list entry names a construct, it is not a prefix pattern" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control allowlist-prefix-rename — extending an allowed item's identifier (FUSE_SERVE_LIMITS -> FUSE_SERVE_LIMITS_V2) is refused at rc=$rc, so a rename cannot slip a new public root item past a named exception"

  # RED — an allow-list entry that matches NOTHING is rc=2, not a silent
  # widening. Driven by pointing granary-fuse's allow-list at granary-vfs's
  # root, where none of its four constructs exist: exactly the state the real
  # allow-list would be in the day one of those constructs is deleted.
  set +e
  out="$(root_shape_report "$LIB_RS" granary-fuse 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 2 ]]; then
    echo "self-test FAILED: control allowlist-stale-entry — an allow-list entry matching ZERO constructs gave rc=$rc, expected 2; a stale entry silently widens this gate and no verdict would ever reveal it" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q "is STALE" <<<"$out"; then
    echo "self-test FAILED: control allowlist-stale-entry — refused at rc=2 but without the STALE diagnostic, so the reason is unreadable" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control allowlist-stale-entry — an entry matching zero constructs is rc=2 with a diagnostic naming the entry"

  # RED — an allow-list entry matching SEVERAL constructs is also rc=2. A
  # named exception that matches twice is a pattern, and a pattern is what
  # this gate's allow-list architecture exists to refuse.
  # The duplicate must match the entry at its
  # identifier boundary. Extending the name with
  # `_TWO` instead makes a new construct, so use a
  # genuine second occurrence. This is a text-scanner
  # fixture and does not compile the duplicate name.
  scratch="$tmp/fuse_lib_dup.rs"
  cp "$fuse_lib" "$scratch"
  append_and_confirm "$scratch" \
    'pub const FUSE_SERVE_LIMITS: usize = 2;' \
    'pub const FUSE_SERVE_LIMITS: usize'
  set +e
  out="$(root_shape_report "$scratch" granary-fuse 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 2 ]]; then
    echo "self-test FAILED: control allowlist-duplicate-match — an allow-list entry matching TWO constructs gave rc=$rc, expected 2; \`pub const FUSE_SERVE_LIMITS\` is a named exception and must not act as a prefix pattern" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control allowlist-duplicate-match — an entry matching two constructs is rc=2, so a named exception cannot drift into a prefix pattern"
}

# ------------------------------- self-test: git-floor duplication tripwire
# selftest_git_floor_duplication_tripwire — macro_export_git_floor and
# check-vfs-purity.sh's vfs_src_file_floor are a near-verbatim ~50-line
# duplicated pair: both the git-derived-floor idiom and its fake-git-PATH
# self-test control are duplicated. A same-class pipefail drift shows the
# duplication is dangerous: the `set +e`/`set -e` guard around the
# `git ls-files` pipeline existed in ONE copy and had drifted missing
# from the other (root_shape_report's separate `pubuse_count=...`
# hazard, not this floor function itself — but the SAME class, and the
# same lesson: two near-identical copies drift). Extraction into a
# shared `scripts/lib/gate-floor.sh` was judged RISKIER than a tripwire here:
# `check-vfs-purity.sh` is a separate, already-shipped gate with its
# own extensively self-tested 1156-line suite. Making it source a new
# shared library solely to deduplicate this floor risks regressing that
# gate. This
# control does not re-derive either function's logic — it asserts the
# one STRUCTURAL property whose silent absence would reopen exactly the pipefail hazard's
# class of defect: both copies' `git ls-files` pipeline still sits
# between a `set +e` and a `set -e`, in that order, ADJACENT to it,
# inside the same function body.
#
# Require ORDER AND ADJACENCY, not three
# independent substring matches. A function
# can contain `set +e`, `git ls-files` and
# `set -e` while leaving pipefail active
# across the pipeline. The Python pattern
# below matches the complete adjacent sequence:
# disable errexit, capture the pipeline,
# capture its status, restore errexit. The
# planted-red control in
# `selftest_git_floor_duplication_tripwire`
# reorders those statements and requires refusal.
# It checks the structural relationship rather
# than mere presence somewhere in the function.
_check_duplicated_git_floor_guard() {
  local file="$1" fn_name="$2" fn_body="$3"
  if [[ -z "$fn_body" ]]; then
    echo "self-test FAILED: control git-floor-duplication-tripwire — could not locate ${fn_name}() in ${file}; it may have been renamed or already extracted without updating this tripwire" >&2
    exit 2
  fi
  # `fn_body` travels as an ARGV argument: `python3
  # -` below reads its OWN script text from stdin
  # to EOF before the script body runs. Reading
  # the function body from that same stream
  # would yield nothing, making the input check
  # vacuous. The function text must remain
  # available separately from the Python source.
  if ! python3 - "$file" "$fn_name" "$fn_body" <<'PYEOF'
import re
import sys

file, fn_name, body = sys.argv[1], sys.argv[2], sys.argv[3]
# The four lines, ADJACENT and IN ORDER: `set +e`, the `git ls-files`
# pipeline assignment, `rc=$?`, `set -e`. Whitespace-tolerant on
# indentation and on the assignment's own variable name/quoting (the
# two copies this tripwire compares differ in both), but the sequence
# itself must appear with nothing else interleaved.
pattern = re.compile(
    r"set \+e\s*\n"
    r"\s*\S+=\"\$\(git ls-files[^\n]*\)\"\s*\n"
    r"\s*rc=\$\?\s*\n"
    r"\s*set -e\b"
)
if not pattern.search(body):
    print(
        f"self-test FAILED: control git-floor-duplication-tripwire — {fn_name}() in {file} "
        "no longer wraps its 'git ls-files' pipeline in an ADJACENT set +e / "
        "assignment / rc=$? / set -e sequence, matched as ONE multiline pattern "
        "rather than three independent greps; the pipefail hazard reopens the "
        "moment one of these two near-duplicate copies drifts from the other "
        "(git-floor duplication tripwire — extract scripts/lib/gate-floor.sh, or restore the guard)",
        file=sys.stderr,
    )
    sys.exit(1)
PYEOF
  then
    exit 2
  fi
}

selftest_git_floor_duplication_tripwire() {
  local purity_fn root_shape_fn reordered_fn_body out rc

  purity_fn="$(sed -n '/^vfs_src_file_floor() {/,/^}/p' "$(pwd)/scripts/check-vfs-purity.sh")"
  root_shape_fn="$(sed -n '/^macro_export_git_floor() {/,/^}/p' "$(pwd)/scripts/check-vfs-root-shape.sh")"

  _check_duplicated_git_floor_guard "check-vfs-purity.sh" "vfs_src_file_floor" "$purity_fn"
  _check_duplicated_git_floor_guard "check-vfs-root-shape.sh" "macro_export_git_floor" "$root_shape_fn"
  echo "self-test: control git-floor-duplication-tripwire — both check-vfs-purity.sh's vfs_src_file_floor and check-vfs-root-shape.sh's own macro_export_git_floor wrap their 'git ls-files' pipeline in an ADJACENT set +e/assignment/rc=\$?/set -e sequence; the pair is a KNOWINGLY duplicated near-verbatim copy rather than a shared helper, and this control stands in for that extraction"

  # RED (git-floor duplication tripwire self-check): a
  # SYNTHETIC function body with `set +e` and `set -e` REORDERED around the
  # pipeline (`set -e` before it, `set +e` after: semantically broken,
  # since errexit stays active for the very pipeline this guard exists
  # to protect). Proves the adjacency check catches a reordering, not
  # just a deletion: all three substrings a three-grep tripwire would
  # check ('set +e', 'git ls-files', 'set -e') are present here, in
  # this exact function body, just in the wrong order.
  reordered_fn_body="$(cat <<'FNEOF'
macro_export_git_floor() {
  local dir="$1" rc floor
  set -e
  floor="$(git ls-files "${dir}/*.rs" | wc -l | tr -d ' ')"
  rc=$?
  set +e
  if [[ "$rc" -ne 0 || -z "$floor" || "$floor" -lt 1 ]]; then
    return 2
  fi
  echo "$floor"
  return 0
}
FNEOF
)"
  set +e
  out="$(_check_duplicated_git_floor_guard "synthetic-reordered-copy.sh" "macro_export_git_floor" "$reordered_fn_body" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 2 ]]; then
    echo "self-test FAILED: control git-floor-duplication-tripwire-reorder-caught — a REORDERED guard (set -e before the git ls-files pipeline, set +e after) was NOT refused by the tripwire's own adjacency check (rc=$rc, wanted 2)" >&2
    echo "$out" >&2
    exit 2
  fi
  if ! grep -q 'ADJACENT' <<<"$out"; then
    echo "self-test FAILED: control git-floor-duplication-tripwire-reorder-caught refused, but not with the adjacency check's own diagnostic" >&2
    echo "$out" >&2
    exit 2
  fi
  echo "self-test: control git-floor-duplication-tripwire-reorder-caught — a synthetic function body with 'set +e'/'set -e' REORDERED around its git ls-files pipeline (a three-grep form would accept it because all three substrings are present, just out of order) is refused by the tripwire's own one-pattern adjacency check (rc=2)"
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
    echo "self-test FAILED: control argv-guard — the no-argument form (the real gate) does not run (rc=$rc)" >&2
    exit 1
  fi
  echo "self-test: control argv-guard — a bogus argv is refused at rc=2 naming the argument, and the no-argument form runs the real gate at rc=0; a mistyped '--self-test' is refused instead of printing a green verdict having run zero controls"
}

# --------------------------------------------------------------------- main
if [[ "${1:-}" == "--self-test" ]]; then
  selftest_arm_a
  selftest_arm_a_second_crate
  selftest_arm_b
  selftest_git_floor_duplication_tripwire
  selftest_argv_guard
  echo "vfs-root-shape self-test: every control behaved as predicted — a new named pub use leaf AND an aliased one stay green (not a census), a prefix-less pub use brace group of fully-qualified leaves stays green (prefixless-brace-group), a foreign-crate leaf inside a prefix-less brace group IS refused (prefixless-foreign-leaf) while a prefixed brace group's bare leaves and a prefix-less group's own nested LOCAL group stay green (nested-subpath-green), a foreign-crate leaf behind a bare crate:: anchor IS ALSO refused (bare-anchor-foreign-leaf) while a leading nested brace group with no prefix of its own, the same reached through a bare crate:: anchor, the plain anchored-prefixed form, and a real nested SUBmodule sub-path behind an already-checked prefix all stay green (leading-nested-group-green / anchored-nested-group-green / anchored-prefixed-green / nested-subpath-real-green), whitespace (ASCII space and a blanked comment, a LEFT-TO-RIGHT MARK, AND a RIGHT-TO-LEFT MARK — this file's own WS class, not Python's str.strip()) around :: is not read as a foreign path root and stays green while a genuinely foreign root behind the same whitespace is still refused with a CLEAN, untrimmed segment name free of both space and stray marks (ws-around-coloncolon-green / ws-around-coloncolon-foreign-still-refused / ws-lrm-around-coloncolon-green / ws-lrm-foreign-still-refused), a mark trailing a bare alias, a mark trailing a braced alias, and a mark leading a braced leaf with no alias at all all stay green too (ws-lrm-alias-and-leaf-mark-green), a LEFT-TO-RIGHT MARK OR A RIGHT-TO-LEFT MARK immediately after the \`pub\` keyword does not silently downgrade a fully public \`mod\`/\`extern crate\`/\`use\` to an unchecked private declaration (ws-lrm-pub-keyword-fail-open-closed / ws-rlm-pub-keyword-fail-open-closed), a nested DECOY \`mod\` whose name merely collides with a real external crate's is refused by this scanner's own depth-0 module inventory rather than shadowing the first-segment foreign-root check (nested-mod-decoy-refused), a REFUSE line's own reported LINE NUMBER and QUOTED SOURCE TEXT are asserted directly against a construct planted after blank lines and a multi-space run, not merely assumed from rc and a diagnostic's own wording (refuse-line-number), a glob inside a prefix-less group (bare, and behind a foreign-looking path) is refused by its OWN glob diagnostic rather than the first-segment foreign-root check's message (glob-diagnostic-precision / glob-first-entry — the leaf's shape governs before its root does), pub mod / pub extern crate / a glob / a self re-export / a bare whole-module re-export (no ::) / a foreign-crate root / a pub(crate) const / an item-position macro invocation are each refused by their own distinctive diagnostic at rc=1 (never an uncertain rc=2 — the allow-list makes 'unrecognised' a confident answer), decoys in a doc comment/string/plain comment do not count, a private inline module's body (including an impl block and an opaque-return-type impl Trait) is skipped as one block WHATEVER IS INSIDE IT — a private test-double impl inside a #[cfg(test)] mod stays green and the two deliberate limits are explicit: An \`impl\` inside a private inline module is deliberately not checked because deciding whether its \`Self\` type is externally reachable requires compiler name resolution. With \`snapshot\` declared at the root, the gate accepts \`crate::snapshot\`, \`self::snapshot\`, \`crate::{snapshot}\`, \`{snapshot}\`, and \`snapshot::sibling\` as \`pub use\` bodies without resolving the leaf. Controls plant \`snapshot::{Entry, ReaddirEntry}\` and \`snapshot::Snapshot\`, which have grouped and ungrouped named-leaf shapes. They do not plant the exact \`crate::snapshot\`, \`self::snapshot\`, \`crate::{snapshot}\`, \`{snapshot}\`, or \`snapshot::sibling\` spellings. The scanner does not distinguish module leaves from item leaves. Bare \`snapshot\` and \`snapshot::{self}\` are refused; a pub use buried past 2,000 characters from its own 'use' keyword is still caught (unlike a bounded terminator search), a missing/empty/zero-pub-use/malformed root is refused at rc=2, a scanner missing its own PUBUSE-COUNT print is refused at rc=2 with a diagnostic rather than a bare undiagnosed rc=1, arm B catches a direct and a cfg_attr-nested #[macro_export] in CHILD module files (mod extra; pub use extra::*; included, closed by THIS script, not clippy) while a non-exported macro_rules! and text decoys stay green, an empty or symlink-divergent source walk is refused at rc=2 rather than read as a clean scan, and the git-floor-duplication-tripwire holds against both a deletion and a reordering of its guard — and, for the SECOND gated crate, granary-fuse's real root passes WITH its four-entry allow-list and FAILS without it (so the entries are load-bearing, not decoration), a FIFTH construct planted at that root is refused by name at rc=1, an allow-list entry matching ZERO constructs is rc=2 rather than a silent widening, and an entry matching TWO is rc=2 rather than a named exception drifting into a prefix pattern, and RENAMING an allowed item to a name that merely EXTENDS its identifier (FUSE_SERVE_LIMITS -> FUSE_SERVE_LIMITS_V2) does not slip past its entry"
  exit 0
fi

# ONE PASS PER GATED CRATE. Both arms are already path-parameterised, so the
# extension is a loop and an allow-list — not a second gate. The literal-source
# limitations stated in this header apply unchanged to the second crate: this
# is a text scanner,
# it catches the honest mistake and the careless one, and it does not resist a
# determined bypass.
#
# A ZERO-LENGTH CRATE SET IS A REFUSAL, never a silent pass: an enumeration
# that walks nothing must not read the same as one that walked and found
# everything clean. This is the same rule the arms apply to their own inputs.
if [[ "${#GATED_CRATES[@]}" -eq 0 ]]; then
  echo "vfs-root-shape: the gated crate set is EMPTY — refused, never treated as clean" >&2
  exit 2
fi

for gated_crate in "${GATED_CRATES[@]}"; do
  gated_dir="crates/$gated_crate"
  gated_src="$gated_dir/src"
  gated_lib="$gated_src/lib.rs"
  if [[ ! -f "$gated_lib" ]]; then
    echo "vfs-root-shape: $gated_lib does not exist — refused, never treated as clean" >&2
    exit 2
  fi
  arm_a_out="$(root_shape_report "$gated_lib" "$gated_crate")"
  if ! ARM_B_FLOOR="$(macro_export_git_floor "$gated_src")"; then
    exit 2
  fi
  arm_b_out="$(macro_export_report "$gated_src" "$ARM_B_FLOOR")"
  echo "$arm_a_out"
  echo "$arm_b_out"
done

echo "vfs-root-shape: ok — each of ${#GATED_CRATES[@]} gated crate roots (${GATED_CRATES[*]}) is entirely attributes, non-pub extern crate/mod/use, and a pub use of named leaves rooted in one of that crate's own modules (arm A, through the first-segment check and the named-leaf check), plus that crate's own named allow-list entries, and no #[macro_export] exists anywhere under its src/ (arm B). Not frozen at any item count: a new named pub use (plain or aliased) is exactly as green as it was before this gate existed — see the not-a-freeze control in --self-test. The glob route IS closed here, by this gate's own named-leaf check; the workspace clippy config (warn-on-all-wildcard-imports) is defence-in-depth, not the closing mechanism. The per-crate allow-list is granary-vfs: none; granary-fuse: four named constructs (the release wall, the readlink ceiling, its static assert, and FUSE_SERVE_LIMITS) — each REQUIRED to match exactly one construct, so a stale entry is rc=2 rather than a silent widening. The gated set is exactly these two crates, and none of the other eight, whose roots carry 55 pub mod between them."
