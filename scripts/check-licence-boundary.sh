#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# Three per-file/per-manifest guards on the AGPL boundary. The source-header
# scan catches AGPL-headered source pasted into an Apache crate, which
# manifest licence metadata and header-validity checks do not detect.
# Checks 2 and 3 forbid other crates from depending on granary-server's
# library or naming a path into its directory, either of which crosses the
# same boundary.
#
# Called by .github/workflows/ci.yml (purity job).
#
# THE THREAT IT IS BUILT FOR is a careless or mistaken contributor on an
# ordinary checkout: a path typed the long way round, a case that only APFS
# forgives, a fixture read that became an include. It also pins the git
# settings that would reshape its scans' SELECTION or OUTPUT on an ordinary
# machine (GIT_PIN and the pathspec variables below); ignore rules are left as
# the contributor has them, for the reason given at GIT_PIN. It is NOT a
# defence against a contributor who sets
# out to evade it: the spellings a content scan cannot reach are listed at
# checks 2 and 3, and what closes them is reading what the build resolved —
# `cargo metadata`'s dependency graph for check 2, rustc's dep-info for check 3
# — rather than what the text spells.
# `scripts/check-licence-resolved.py` is that structural check, over BOTH
# gaps at once (its own check A is the resolved dependency graph, its own
# check B is rustc's dep-info); it runs in `.github/workflows/ci.yml`'s
# `test` job, right after `cargo nextest run`, and in
# `scripts/local-gates.sh`'s mirror of that same job.
#
#
# EXIT: 0 clean, 1 a boundary violation (named at file:line), 2 THE GATE
# COULD NOT RUN. The third status is the whole reason for `scan` below.
set -euo pipefail

# ---- --self-test: the real script against a planted repository -----------
# Every row copies THIS file into a scratch git repository that satisfies all
# three checks, plants one file, runs the copy and compares its exit status.
# A row is the refusal it names: deleting either side of the needle, the
# `-i`, either `-a`, a positive control, the fixture's closing quote, the
# admitted-file anchor, the strip or the re-sieve each turns a row red.
# ANY other argument is refused rather than falling through to the gate:
# `self-test` with its dashes dropped would otherwise print nothing, exit 0
# and read as a passing deck — the class `check-vfs-deps.sh` records.
if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != "--self-test" ]; }; then
  echo "usage: $0 [--self-test]" >&2
  exit 2
fi
# The planted headers below are the markers' reason: see check 1.
# REUSE-IgnoreStart
if [ "${1:-}" = "--self-test" ]; then
  self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  # An inherited git environment would point every fixture at the CALLER's
  # repository — `git add -A` into its real index.
  unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR
  # And inherited CONFIG would reach every fixture: a global ignore file —
  # including the default `$XDG_CONFIG_HOME/git/ignore`, which git reads with
  # no config key at all — can hide a planted file from `--untracked`.
  # XDG_CONFIG_HOME points into the scratch directory for that reason.
  # The gate's own defences against output-shaping config (`--no-color`,
  # `--no-column`) have their own row, which sets that config deliberately.
  # `GIT_CONFIG_GLOBAL` is pinned for the same reason, and it overrides the
  # `~/.gitconfig` lookup, so HOME needs no pin of its own. A
  # `GIT_TEMPLATE_DIR` would copy an `info/exclude` into every `git init`,
  # which `fixture`'s `--template=` refuses. No row below can see these pins:
  # they only matter under a hostile CALLER environment. To prove one, run this
  # deck with a caller whose global config and XDG ignore file hide `*.in` and
  # `loose.rs`, and remove the pin: rows turn red.
  unset GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT
  tmp=$(mktemp -d)
  export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null XDG_CONFIG_HOME="$tmp/xdg"
  trap 'rm -rf "$tmp"' EXIT
  fails=0 rows=0
  fixture() {
    rm -rf "$tmp/r" && mkdir -p "$tmp/r/scripts" "$tmp/r/crates/granary-server/src" "$tmp/r/crates/a/src"
    cp "$self" "$tmp/r/scripts/gate.sh"
    printf '// SPDX-License-Identifier: AGPL-3.0-or-later\n//! see `crates/granary-server/tests/`\n' \
      > "$tmp/r/crates/granary-server/src/lib.rs"
    printf '[package]\nname = "granary-server"\n' > "$tmp/r/crates/granary-server/Cargo.toml"
    # The real root manifest names the server in a comment; so does this one.
    printf '[workspace]\n# granary-server is the AGPL crate\n' > "$tmp/r/Cargo.toml"
    printf '[package]\nname = "a"\n' > "$tmp/r/crates/a/Cargo.toml"
    printf '// SPDX-License-Identifier: Apache-2.0\n' > "$tmp/r/crates/a/src/lib.rs"
    git -C "$tmp/r" init -q --template= && git -C "$tmp/r" add -A
  }
  # run_gate <expected rc> <label> [gate args...] — runs the planted copy,
  # counts the row and reports it; every row below ends here.
  run_gate() {
    local want=$1 label=$2 rc=0
    shift 2
    bash "$tmp/r/scripts/gate.sh" "$@" >/dev/null 2>&1 || rc=$?
    rows=$((rows + 1))
    if [ "$rc" -eq "$want" ]; then echo "ok    $label"
    else echo "FAIL  $label (exit $rc, expected $want)" >&2; fails=$((fails + 1)); fi
  }
  row() {  # row <expected rc> <label> <file> <content>
    fixture
    mkdir -p "$(dirname "$tmp/r/$3")"
    printf '%s\n' "$4" >> "$tmp/r/$3"
    run_gate "$1" "$2"
  }
  # A row whose fixture is broken on purpose: <expected rc> <label> <command run in the repo>
  broken() {
    fixture
    (cd "$tmp/r" && eval "$3")
    run_gate "$1" "$2"
  }
  L=crates/a/src/lib.rs T=crates/granary-bench/tests/verify_wallclock.rs
  row 0 "a clean tree passes" "$L" ''
  row 0 "the crate NAME as data passes" "$L" 'const K: &str = "granary-server";'
  row 0 "a run-time read of a server JSON fixture from an admitted reader passes" "$T" \
    'const G: &str = "crates/granary-server/tests/fixtures/wire_golden.json";'
  row 1 "the literal src path is refused" "$L" '#[path = "../../granary-server/src/wire.rs"] mod w;'
  row 1 "a ./ spelling is refused" "$L" '#[path = "../../granary-server/./src/wire.rs"] mod w;'
  row 1 "a // spelling is refused" "$L" '#[path = "../../granary-server//src/wire.rs"] mod w;'
  row 1 "a ../ detour is refused" "$L" '#[path = "../../granary-server/tests/../src/wire.rs"] mod w;'
  row 1 "a backslash spelling is refused" "$L" '#[path = "..\\..\\granary-server\\src\\wire.rs"] mod w;'
  row 1 "a path into benches is refused" "$L" 'include!("../../granary-server/benches/x.rs");'
  row 1 "a loose crates/*.rs naming the crate with no separator before it is refused" \
    crates/loose.rs '#[path = "granary-server/src/wire.rs"] mod w;'
  row 1 "an inline-mod directory ending at the crate is refused" "$L" \
    '#[path = "../../granary-server"] mod s { pub mod src { pub mod wire; } }'
  row 1 "a concat! piece ending at the crate is refused" "$L" \
    'include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../granary-server", "/src/wire.rs"));'
  row 1 "a different case is refused" "$L" '#[path = "../../Granary-Server/src/wire.rs"] mod w;'
  row 1 "a fixture beside a source path on one line is refused" "$T" \
    'const G: &str = "crates/granary-server/tests/fixtures/g.json"; include!("../../granary-server/src/x.rs");'
  row 1 "a fixture name with a suffix is refused" "$T" \
    '#[path = "crates/granary-server/tests/fixtures/g.json/../../src/wire.rs"] mod w;'
  row 1 "a fixture named from src/ is refused" "$L" \
    'const G: &str = include_str!("crates/granary-server/tests/fixtures/g.json");'
  row 0 "a fixture named from an admitted reader passes, include_str! included" \
    "$T" 'const G: &str = include_str!(
    "crates/granary-server/tests/fixtures/g.json");'
  row 1 "a path in a non-Rust file an include! could read is refused" \
    crates/a/src/gen.in 'include!("../../granary-server/src/wire.rs");'
  row 0 "a TOML comment naming the server creates no edge" crates/a/Cargo.toml \
    'tracing = "1"  # mirrors granary-server'
  row 1 "a manifest target path into the server in another case is refused" crates/a/Cargo.toml \
    '[lib]
path = "../Granary-Server/src/lib.rs"'
  row 1 "an AGPL header outside the server is refused" "$L" \
    '// SPDX-License-Identifier: AGPL-3.0-or-later'
  row 1 "a workspace dependency on the server is refused by check 2 alone" crates/a/Cargo.toml \
    '[dependencies]
granary-server = { workspace = true }'
  row 0 "a sibling crate whose name extends the server's passes" "$L" \
    '//! see `crates/granary-server-api/src/lib.rs`'
  broken 0 "a sibling crate's own manifest passes check 2" \
    "mkdir -p crates/granary-server-api && printf '[package]\\nname = \"granary-server-api\"\\n' > crates/granary-server-api/Cargo.toml"
  broken 1 "a path hidden in a file with a NUL byte is refused" \
    "printf '#[path = \"../../granary-server/src/wire.rs\"] mod w; // \\000\\n' >> $L"
  row 1 "the same fixture read from a tests/ file NOT on the admitted list is refused" \
    crates/a/tests/t.rs 'const G: &str = "crates/granary-server/tests/fixtures/g.json";'
  row 1 "an admitted-file address that the content fakes is refused" crates/loose.rs \
    "x $T:1: \"crates/granary-server/tests/fixtures/g.json\""
  row 0 "a column-0 TOML comment naming the server creates no edge" crates/a/Cargo.toml \
    '# mirrors granary-server'
  row 0 "the strip cuts at the FIRST whitespace-led #, not the last" crates/a/Cargo.toml \
    'tracing = "1"  # mirrors granary-server # and more'
  broken 0 "a manifest whose DIRECTORY name holds the server's name cannot decide check 2" \
    "mkdir -p vendor/granary-server.x && printf '[package]\\nname = \"v\"  # see granary-server\\n' > vendor/granary-server.x/Cargo.toml"
  broken 2 "a manifest outside crates/ whose path holds ':' is refused before any parse" \
    "mkdir -p 'vendor/x:1:dep #1' && printf '[dependencies]\\ngranary-server = \"*\"\\n' > 'vendor/x:1:dep #1/Cargo.toml'"
  broken 2 "a path holding ':' is refused before any parse" \
    "mkdir -p 'crates/v:1:granary-server.d' && printf '[package]\\nname = \"x\"\\n' > 'crates/v:1:granary-server.d/Cargo.toml'"
  broken 1 "a manifest directory whose name holds ' #' cannot strip its own content" \
    "mkdir -p 'crates/x #y' && printf '[dependencies]\\ngranary-server = { workspace = true }\\n' > 'crates/x #y/Cargo.toml'"
  row 1 "a dependency on the server is refused" crates/a/Cargo.toml \
    '[dependencies]
granary-server = { path = "../granary-server" }'
  row 1 "a differently-cased dependency path is refused by its package name" crates/a/Cargo.toml \
    '[dependencies]
gs = { path = "../Granary-Server", package = "granary-server" }'
  broken 2 "check 1 is blind, not clean, when the server carries no AGPL header" \
    "printf '//! see \`crates/granary-server/tests/\`\\n' > crates/granary-server/src/lib.rs"
  broken 2 "check 2 is blind, not clean, when the server's own manifest does not name it" \
    "printf '[package]\\nname = \"s\"\\n' > crates/granary-server/Cargo.toml"
  broken 2 "check 3 is blind, not clean, when the server names no path into itself" \
    "printf '// SPDX-License-Identifier: AGPL-3.0-or-later\\n' > crates/granary-server/src/lib.rs"
  # EQUIVALENT MUTANTS, named rather than chased: a git that cannot run is
  # refused first by the path listing, then by `scan`'s `-gt 1`, then by check
  # 1's positive control, so disabling any ONE of the three leaves this row
  # green. The row asserts the OUTCOME; the three are defence in depth.
  broken 2 "a git failure is exit 2, never a pass" \
    "rm -rf .git && printf 'gitdir: /nonexistent\\n' > .git"
  fixture
  run_gate 2 "an argument other than --self-test is refused, not run as the gate" self-test
  # Output-shaping config the gate must ignore: colour codes and a column field
  # would each shift the `path:line:` prefix every anchor below is written for.
  fixture
  printf '# mirrors granary-server\n' >> "$tmp/r/crates/a/Cargo.toml"
  GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=color.grep GIT_CONFIG_VALUE_0=always \
    GIT_CONFIG_KEY_1=grep.column GIT_CONFIG_VALUE_1=true \
    run_gate 0 "colour and column config do not turn a column-0 comment into a refusal"
  fixture
  printf '#[path = "../../granary-server/src/wire.rs"] mod w;\n' >> "$tmp/r/$L"
  GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=color.grep GIT_CONFIG_VALUE_0=always \
    run_gate 1 "colour config does not turn a path into the server into a blind gate"
  # Pathspec magic from the environment narrows the scans — glob mode makes
  # check 2's `*Cargo.toml` the root manifest only; literal and noglob make
  # check 1's `crates/*.rs` match nothing, so those rows go red at check 1.
  # The gate clears all of it, so a dependency is still found. Icase mode only
  # widens a match and is cleared for uniformity, not for a row.
  for mode in GIT_GLOB_PATHSPECS GIT_LITERAL_PATHSPECS GIT_NOGLOB_PATHSPECS; do
    fixture
    printf '[dependencies]\ngranary-server = { workspace = true }\n' >> "$tmp/r/crates/a/Cargo.toml"
    export "$mode=1"
    run_gate 1 "$mode does not narrow the scans"
    unset "$mode"
  done
  # The caller's git config the gate pins for itself (GIT_PIN), each set here
  # the way an ordinary contributor's global config would set it.
  fixture
  printf '#[path = "../../granary-server/src/wire.rs"] mod w;\n' >> "$tmp/r/$L"
  GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=submodule.recurse GIT_CONFIG_VALUE_0=true \
    run_gate 1 "submodule.recurse does not stop the scans"
  fixture
  mkdir -p "$tmp/r/crates/granary-server/tests"
  printf 'see crates/granary-server/tests/x\n' > "$tmp/r/crates/granary-server/tests/caf$(printf '\303\251').txt"
  GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.quotePath GIT_CONFIG_VALUE_0=true \
    run_gate 0 "a non-ASCII file name inside the server stays exempt"
  # Ignore rules stay the contributor's (see GIT_PIN): a file their own
  # excludes hide is not refused locally. Pins the decision in both directions.
  fixture
  mkdir -p "$tmp/r/crates/granary-bench/tests"
  printf '*.orig\n' > "$tmp/ign"
  printf '"crates/granary-server/tests/fixtures/g.json"\n' > "$tmp/r/$T.orig"
  GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.excludesFile GIT_CONFIG_VALUE_0="$tmp/ign" \
    run_gate 0 "a file the contributor's own excludes hide is not refused locally"
  broken 1 "a crate nested inside the server's directory depending on it is refused" \
    "mkdir -p crates/granary-server/fuzz && printf '[dependencies.granary-server]\\npath = \"..\"\\n' > crates/granary-server/fuzz/Cargo.toml"
  broken 1 "a manifest marked binary in .gitattributes is still read" \
    "printf 'crates/a/Cargo.toml -diff\\n' > .gitattributes && printf '[dependencies]\\ngranary-server = { workspace = true }\\n' >> crates/a/Cargo.toml"
  echo "check-licence-boundary --self-test: $rows row(s), $fails FAILED" >&2
  # A deck that ran no row verified nothing, whatever `fails` says.
  [ "$rows" -gt 0 ] && [ "$fails" -eq 0 ]
  exit
fi
# REUSE-IgnoreEnd

cd "$(dirname "$0")/.."
# Pathspec magic from the environment would change what every pathspec below
# selects (`GIT_GLOB_PATHSPECS=1` makes `*Cargo.toml` the root manifest only).
unset GIT_GLOB_PATHSPECS GIT_NOGLOB_PATHSPECS GIT_ICASE_PATHSPECS GIT_LITERAL_PATHSPECS
# And the config every git call here runs under, whatever the caller's is:
# `core.quotePath` would wrap a non-ASCII path in quotes and escapes, so no
# `^crates/granary-server/` exemption matches it; `submodule.recurse` makes
# `git grep --untracked` refuse outright. Ignore rules are deliberately NOT
# pinned: dropping a contributor's own excludes would refuse whatever debris
# they tell git to ignore (say a `*.orig` pattern, and a merge's copy of an
# admitted reader, which is not on the admitted list). The cost, stated: a
# file their excludes hide is invisible to this LOCAL run even though cargo
# still compiles it; it cannot reach CI without `git add -f`, and there it is
# scanned.
GIT_PIN=(-c core.quotePath=false -c submodule.recurse=false)

status=0
RESULT=""

# ---- a path holding `:` breaks every `path:line:` parse below -------------
# Checks 2 and 3 read `git grep -n` output and anchor on the prefix it adds, so
# a directory named `v:1:x` would move the boundary a strip or a sieve cuts
# at. Refused outright rather than parsed around: no crate needs one.
# The listing covers what every scan below reads: `crates/` for checks 1 and
# 3, and every `Cargo.toml` in the repository for check 2. Git's status is
# read on its own, never through a pipe, where `grep`'s would replace it.
paths_rc=0
scanned_paths=$(git "${GIT_PIN[@]}" ls-files --cached --others --exclude-standard -- 'crates/' '*Cargo.toml') \
  || paths_rc=$?
if [ "$paths_rc" -ne 0 ]; then
  echo "THE LICENCE GATE COULD NOT RUN — listing the scanned paths failed (git exited $paths_rc)." >&2
  exit 2
fi
# One more walk of the untracked tree than the scans make on their own; the
# price of placing every cut below on a known boundary.
if [[ $scanned_paths == *:* ]]; then
  echo "THE LICENCE GATE COULD NOT RUN — a scanned path holds ':':" >&2
  while IFS= read -r p; do
    if [[ $p == *:* ]]; then echo "  $p" >&2; fi
  done <<<"$scanned_paths"
  echo "  every check here parses 'path:line:' and cannot place its cuts." >&2
  exit 2
fi

# ---- how a git failure is told apart from a clean run --------------------
# `git grep` exits 1 for "no match" and GREATER than 1 for a real failure —
# not a git repository, an unreadable index, or the "dubious ownership"
# refusal git raises when a checkout's owner is not the calling user.
# `hits=$(git grep … || true)` erases that difference: both cases hand back
# an empty string, so a gate written that way prints nothing, exits 0, and
# reports success while sitting on a live violation. Measured, not reasoned:
# `GIT_DIR=/nonexistent ./scripts/check-licence-boundary.sh` over a planted
# AGPL header exited 0 before this function existed.
#
# The realistic trigger is not exotic. The purity job runs on a self-hosted
# runner, where a dubious-ownership refusal breaks `git grep` while every
# cargo step in the same job keeps working — so this gate would be the only
# thing silently passing. A gate printed ALL GREEN over a failing lint for
# six tasks.
#
#
# So every git call goes through here, and only 0 and 1 are allowed through.
# It assigns to a global rather than printing, deliberately: called as
# `hits=$(scan …)` the `exit` below would leave only the command
# substitution's SUBSHELL and the script would carry on — the same fail-open
# in a new costume.
scan() {
  local rc=0
  RESULT=$(git "${GIT_PIN[@]}" grep --no-color --no-column "$@") || rc=$?
  if [ "$rc" -gt 1 ]; then
    echo "THE LICENCE GATE COULD NOT RUN — it verified NOTHING." >&2
    echo "  \`git grep $*\` exited $rc. 1 means 'no match'; anything above" >&2
    echo "  it is a git failure (not a repository, an unreadable index, a" >&2
    echo "  'dubious ownership' refusal on a shared runner)." >&2
    echo "  The AGPL boundary is UNCHECKED until that is fixed. This is a" >&2
    echo "  failure and not a pass, because the two are indistinguishable" >&2
    echo "  from the output of a git that did not run." >&2
    exit 2
  fi
  # rc 1 is "no match", whose output is empty anyway; said out loud so the
  # caller never reads a stale $RESULT from an earlier scan.
  [ "$rc" -eq 0 ] || RESULT=""
}

# The post-filters, under the same discipline: `grep` also exits 1 for "no
# line selected" — the clean case here — and greater than 1 for a real
# error. Filters $RESULT in place, so two of them chain.
sieve() {
  local rc=0
  [ -n "$RESULT" ] || return 0
  RESULT=$(printf '%s\n' "$RESULT" | grep "$@") || rc=$?
  if [ "$rc" -gt 1 ]; then
    echo "THE LICENCE GATE COULD NOT RUN — it verified NOTHING." >&2
    echo "  \`grep $*\` exited $rc, which is an error and not 'no match'." >&2
    exit 2
  fi
  [ "$rc" -eq 0 ] || RESULT=""
}

# `sed -E` over $RESULT, under the same discipline: any non-zero exit is an
# error, because sed has no "no match" status.
strip() {
  local rc=0
  [ -n "$RESULT" ] || return 0
  RESULT=$(printf '%s\n' "$RESULT" | sed -E "$@") || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "THE LICENCE GATE COULD NOT RUN — it verified NOTHING." >&2
    echo "  \`sed -E $*\` exited $rc." >&2
    exit 2
  fi
}

# ---- 1. AGPL headers live only in granary-server -------------------------
# The hard rule in machine form. Manifest metadata (cargo-deny's
# licenses.exceptions) is blind to individual file headers, and REUSE
# validates that a header is VALID, never that it belongs to this crate.
#
# TWO pathspecs and not one: `crates/**/*.rs` does not match a `.rs` file
# sitting directly under `crates/` — `**` matches path components, and the
# `/` after it is still required. Scan EVERY `*.rs` under `crates/`,
# including a file directly beneath it, such as `crates/loose.rs`.
#
# Searched with `git grep --untracked` and NOT `grep -r`, for a reason
# measured here: tooling materialises linked worktrees under
# .claude/worktrees/, and a plain recursive grep from the repo root walks
# straight into one and reports the checked-out COPY of this repo as a
# violation. `git grep` is index-scoped, honours .gitignore (where that
# path now lives) and so cannot descend into one; `--untracked` keeps a
# brand-new unstaged file in scope, which is the whole point of the local
# lane. A licence gate that cries wolf whenever such a worktree exists is
# worse than no gate, because it teaches everyone to skip it.
#
# The markers below are load-bearing and are reuse's own documented fix:
# `reuse lint` content-scans this file, reads the grep PATTERN as a licence
# expression, and fails with "invalid SPDX License Expressions". Same class
# as the docs-quoting-SPDX-examples failure REUSE.toml's comment records —
# the workflow copy escaped it only because `.github/**` is annotated
# there. Do not delete them to tidy up; the lint goes red immediately.
# REUSE-IgnoreStart
scan -l --untracked "SPDX-License-Identifier: AGPL" -- 'crates/*.rs' 'crates/**/*.rs'
# REUSE-IgnoreEnd
# POSITIVE CONTROL, before the filter. granary-server's own sources carry
# this header by the hard rule, so a scan that matched NOTHING did not find
# a clean tree — it found a broken query: a renamed crate, a moved
# `crates/`, a pathspec that stopped matching, or a changed header spelling.
# Exit 1 from `git grep` is a legitimate "no match" for the OTHER two
# checks; here it is proof the gate is blind, and without this a vacuous
# pass is indistinguishable from a clean one.
if [ -z "$RESULT" ]; then
  echo "THE LICENCE GATE COULD NOT RUN — it verified NOTHING." >&2
  echo "  No file under crates/ carries an AGPL header, but granary-server's" >&2
  echo "  own sources must. The pattern, the pathspec or the crate layout" >&2
  echo "  has moved, so this check is blind rather than satisfied." >&2
  exit 2
fi
sieve -v '^crates/granary-server/'
if [ -n "$RESULT" ]; then
  echo "AGPL SPDX header outside crates/granary-server/:" >&2
  echo "$RESULT" >&2
  status=1
fi

# ---- 2. Nothing depends on granary-server --------------------------------
# granary-server has a `[lib]` target, so other crates can technically
# depend on it. An Apache crate must not take that dependency:
# doing so compiles AGPL server logic into the consuming dependency graph.
# Check 1 cannot detect this route because no AGPL header moves.
# `cargo deny check licenses` can also report `licenses ok`:
# its exception is scoped by crate NAME and does not constrain
# which crates may consume the server library.
#
# Every route to the dependency spells the crate name — a rename carries
# `package = "granary-server"`, a path dep carries `../granary-server` —
# so the name in a non-comment line of any manifest but the server's own is
# the test. Read
# as TEXT (`-a`): a `.gitattributes` or attributes file marking a manifest
# binary would otherwise turn its lines into one `Binary file … matches`.
# Comments are exempt: a comment creates no edge.
# Named, not handled: TOML can spell the name without the literal — a
# `\u002D` escape, a line-continued multi-line string — and the comment
# strip below also cuts a ` #` inside a quoted value. Reading the resolved
# dependency graph (`cargo metadata`) rather than the text closes all three.
scan -na --untracked 'granary-server' -- '*Cargo.toml'
# POSITIVE CONTROL, before the filter, for the reason check 1 gives:
# granary-server's OWN manifest names the crate, so a scan matching nothing
# means the pathspec or the name has moved and this check is blind.
# EXACT, not "any manifest": the root manifest names the server in comments,
# so a scope narrowed to it alone (a pathspec mode) would
# satisfy a looser control while reading no crate's manifest at all.
if ! grep -q '^crates/granary-server/Cargo.toml:' <<<"$RESULT"; then
  echo "THE LICENCE GATE COULD NOT RUN — it verified NOTHING." >&2
  echo "  crates/granary-server/Cargo.toml does not name granary-server, but it must." >&2
  echo "  The crate has been renamed or moved; this check is blind." >&2
  exit 2
fi
# Only the server's OWN manifest is exempt, not its directory, unlike checks 1
# and 3: those exempt a file's LOCATION, this one exempts a PACKAGE, and a
# manifest nested in the directory is a package with its own `license` field.
# This repository's fuzz manifests declare Apache-2.0 in their own
# `[workspace]`, so a copied one under the server would link AGPL code into an
# Apache package. The rule is that no crate but the server depends on it.
sieve -v '^crates/granary-server/Cargo.toml:'
# Strip TOML comments before deciding, rather than exempting whole-line
# ones. `tracing = { workspace = true }  # mirrors granary-server` creates
# no dependency edge, and a whole-line-only exemption hard-failed CI's
# purity job on it. Cut from an unquoted `#` to end of line — at column 0
# (right after the `path:line:` prefix `git grep -n` adds) or mid-line — then
# keep only what still names the crate in the CONTENT field, bounded on the
# right so a sibling such as `granary-server-api` is not the server.
strip 's/^([^:]*:[0-9]+:)(([^#]*[[:space:]])?)#.*$/\1\2/'
# Both edits start after the `path:line:` prefix, so a manifest's directory
# name decides neither: the strip cuts only from the first `#` in the content
# that opens the line or follows whitespace (a line whose first `#` is neither
# is kept whole, which errs towards refusing), and the name must appear after
# the prefix. That parse is sound because no path here holds a `:` — refused
# at the top of the gate.
sieve -E '^[^:]*:[0-9]+:.*granary-server([^A-Za-z0-9_-]|$)'
if [ -n "$RESULT" ]; then
  echo "a manifest other than granary-server's own names granary-server:" >&2
  echo "$RESULT" >&2
  echo "  granary-server is AGPL-3.0-or-later and every other crate is" >&2
  echo "  Apache-2.0. A dependency on it makes the consumer's distribution" >&2
  echo "  terms the server's — the licence boundary running backwards." >&2
  echo "  Move what is needed into an Apache crate as a pure primitive" >&2
  echo "  instead; the server's own logic never migrates outward." >&2
  status=1
fi

# ---- 3. Nothing names a path into granary-server's directory -------------
# Including server source is a route around both checks above.
# An include makes the source a module of the INCLUDING target,
# so an Apache crate can compile AGPL code with no manifest edge
# for check 2 to see.
# Check 1 sees nothing either: the file with the AGPL header
# still sits inside crates/granary-server/, where it belongs.
# DO NOT match the attribute syntax. Two attempts did, and both shipped a
# bypass: Rust accepts `# [path = "…"]` (the `#` and `[` are separate
# tokens, so whitespace between them is legal) and the fully split form
# with `#[`, `path = "…"` and `]` on three lines, which no line-scoped grep
# for `#[path` can see. `#[cfg_attr(…, path = "…")]` and `include!` are two
# more routes, and chasing each spelling is a game the gate loses one
# spelling at a time.
#
# Match the one thing EVERY route must spell instead: a filesystem path
# into the server's sources. `#[path]`, `#[cfg_attr(…, path)]`, `include!`
# and `include_str!` all carry it, and it is a string literal, so it sits
# on one line whatever the surrounding syntax does.
#
# This OVER-approximates — a doc comment pointing a reader at
# `granary-server/src/wire.rs` is flagged too — and that is the right
# direction for a licence gate. A false positive costs one reworded
# comment; a false negative is a licence violation that ships. The gaps
# no content scan reaches are listed below.
#
# The needle is the crate DIRECTORY with a path separator on either side,
# not the literal `granary-server/src`. The compiler normalises
# `granary-server/./src`, `granary-server//src`, `granary-server/tests/../src`
# and, on Windows, `granary-server\src` to the same file, and none of them
# contains that literal. Every file under the directory is AGPL — tests and
# benches as much as `src/` — so the directory is the boundary. A separator
# BEFORE the name is the second half: `#[path = "../../granary-server"]` on an
# inline `mod` sets the directory its child modules load from, and
# `concat!(…, "/../granary-server", "/src/wire.rs")` splits the path after the
# name; that half ends at a separator, a quote or the line's end, so a
# sibling such as `crates/granary-server-api/` is not the server. A bare
# `"granary-server"` has neither and is the crate's NAME used as
# data (a snapshot's `writer_kind`), which compiles nothing in.
#
# Case-INSENSITIVE, because the dev host's filesystem (APFS) and Windows are:
# `Granary-Server/src/wire.rs` opens the same file there, and a `cfg_attr`
# can make that spelling live on those platforms alone.
#
# EVERY file under `crates/` is scanned, not only `*.rs`: `include!` takes
# any file, so a `gen.in` beside `lib.rs` can carry the path, and a manifest's
# own target paths (`[lib] path`, `[[bin]] path`, `build =`) name no package
# for check 2 to see. And every file is read as TEXT (`-a`): rustc compiles a
# source file carrying a NUL byte, which `-I` would skip as binary.
#
# ONE shape is exempt, in NAMED files only: a JSON fixture under the server's
# `tests/fixtures/`, named in full up to its closing quote, in a file on
# ADMITTED_READERS. Those fixtures are DATA with their own AGPL annotation in
# REUSE.toml (the wire-snapshot golden), and each admitted file is an
# integration test that reads one at run time. The list is of FILES, not a
# directory class, because what ships is decided by the manifest — a
# `[lib] path = "tests/lib.rs"` or a package nested under `tests/` makes a
# file there part of a library — so admitting a reader is a reviewed edit to
# this list. The exemption replaces the exact occurrence with `<fixture>` and
# re-tests what is left, so a line naming a fixture AND another path into the
# crate is still refused.
#
# Spellings no content scan reaches, named rather than implied: an escape
# inside the literal (`granary\x2dserver`); the name split across `concat!`
# pieces, or standing alone as a piece with the separators in its neighbours
# (`concat!("../../", "granary-server", "/src/wire.rs")`); a bare
# `#[path = "granary-server"]` on an inline mod nested inside one whose path
# climbs to `crates/`; a `tests/` file whose exempted fixture is pulled into
# `src/` by a `#[path]` that names no server path itself; and a symlink.
# What closes them is reading what rustc COMPILED — its dep-info lists every
# `#[path]` and `include*!` input — with each entry resolved to its real path,
# which a symlink needs, rather than what the source spells.
NEEDLE='[/\\]granary-server([/\\"]|$)|granary-server[/\\]'
FIXTURE='"crates/granary-server/tests/fixtures/[A-Za-z0-9_-]+\.json"'
ADMITTED_READERS='crates/granary-bench/tests/verify_wallclock\.rs'
scan -niaE --untracked "$NEEDLE" -- 'crates/'
# POSITIVE CONTROL, before the filter, for the reason check 1 gives: the
# server's own sources name paths inside their crate (`crates/granary-server/
# tests/` in their module docs), so a scan matching nothing there means the
# needle or the crate layout has moved and this check is blind. It proves the
# NEEDLE, not the scope: a pathspec narrowed to the server alone still passes
# it, and the self-test's rows planted in other crates are what prove the scope.
if ! grep -q '^crates/granary-server/' <<<"$RESULT"; then
  echo "THE LICENCE GATE COULD NOT RUN — it verified NOTHING." >&2
  echo "  No file under crates/granary-server/ names a path into its own crate," >&2
  echo "  but the server's sources do. The needle or the layout has moved, so" >&2
  echo "  check 3 is blind rather than satisfied." >&2
  exit 2
fi
sieve -v '^crates/granary-server/'
strip "\#^(${ADMITTED_READERS}):[0-9]+:#s#${FIXTURE}#<fixture>#g"
sieve -iE "$NEEDLE"
if [ -n "$RESULT" ]; then
  echo "a crate outside granary-server names a path into its directory:" >&2
  echo "$RESULT" >&2
  echo "  An include compiles AGPL source INTO the including crate, which" >&2
  echo "  is the same boundary violation as a dependency and is invisible" >&2
  echo "  to both checks above." >&2
  status=1
fi

exit "$status"
