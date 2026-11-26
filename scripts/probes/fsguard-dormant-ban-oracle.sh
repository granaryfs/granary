#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# Inverted oracle for the fsguard DORMANT-BAN mutation probe.
#
# A ban row whose path clippy cannot resolve does NOT go quiet, BUT NOT
# because the lanes deny warnings: clippy's `<path> does not refer to a
# reachable function` is emitted by the config LOADER, not a registered
# lint (`code.code` is `null` in `--message-format=json`), so denying
# warnings does not promote it and a typo'd or renamed row does NOT fail
# the build this way — measured against a deliberately broken row under
# `CARGO_BUILD_WARNINGS=deny` and `cargo clippy -- -D warnings` alike,
# both exit 0. What actually catches a typo'd or renamed row not marked
# `allow-invalid = true` is `scripts/check-fsguard-sites.sh`'s own
# resolution check, which reads this SAME diagnostic from a real clippy
# run and refuses on it directly. `allow-invalid = true` is the ONE
# shape that suppresses that diagnostic on purpose — clippy.toml's
# header states why the rows that still carry it have it, and the same
# resolution check also refuses one that has started resolving again
# (a re-arm falling due).
#
# What this oracle proves is the other half, the one no config check
# can: that the BAN ROW ITSELF is what refuses a planted bare call —
# not the `#[expect]` annotations, not the crate's lint level, not any
# other gate standing nearby. It is the TEST COMMAND for a mutation
# probe against that row: it plants a bare `std::fs::create_dir_all`
# call in granary-client, runs clippy on the crate, restores the file,
# and exits 0 ONLY IF clippy reported `clippy::disallowed_methods`
# against THAT plant. Unmutated, the ban refuses -> exit 0 (baseline
# green). With the row's path mutated so it no longer names the banned
# function, clippy accepts the plant -> exit 1 -> the probe reports
# KILLED.
#
# Reading clippy's EXIT STATUS instead would be a proxy, and a wrong
# one: a crate that fails to compile exits nonzero on the baseline AND
# on the mutant, so the oracle would say "the ban fired" both times and
# the probe would report a spurious SURVIVED on a mechanism that is
# working. A nonzero exit without the diagnostic below is therefore
# exit 2 — the probe could not be run — with the tail of clippy's own
# rendered output on stderr, never a verdict. Run it on every
# rust-toolchain.toml bump, where the ban list is re-audited: what
# changes under a new toolchain is clippy's own handling of the list,
# which no amount of reading the config can tell you.
#
# WHY JSON AND NOT TWO GREPS OVER THE RENDERED TEXT. The rendered form
# is a HUMAN artifact and it is not stable: rustc trims a long source
# line to fit the terminal, so the plant's own name can be absent from
# the snippet of a perfectly healthy run in a narrow window — the
# oracle would then read "did not build", exit 2, and the probe would
# lose its baseline. Two independent greps are also two independent
# questions: `use of a disallowed method` from some OTHER call the
# crate makes, plus `dormant_ban_plant` rendered by an unrelated
# diagnostic, satisfy both while the row under test was dormant. So the
# verdict is read from `--message-format=json` instead, and it requires
# ONE message to carry every half: `code.code ==
# "clippy::disallowed_methods"` AND a PRIMARY span whose `file_name` is
# `crates/granary-client/src/lib.rs` EXACTLY, beginning past the last
# line the file had before this script appended to it, AND whose own
# source `text` names the planted function. Nothing about the rendering
# — width, colour, `COLUMNS` — can change that answer.
#
# THE PATH IS THE WHOLE CRATE-RELATIVE PATH, not a `src/lib.rs` suffix:
# every workspace member has a `src/lib.rs` and every one of them is
# linted by the same command class, so a suffix test names five files
# rather than one. Measured on the pinned toolchain: cargo emits
# `"file_name": "crates/granary-client/src/lib.rs"` — WORKSPACE-RELATIVE
# — for this plant (the absolute-suffix arm below is the fallback for a
# cargo that ever emits an absolute path, and it still carries the full
# crate-relative tail). And the LINE test alone is a coincidence of file
# lengths: it says "past line N of some lib.rs", which another member's
# longer file satisfies for free. The `text` test is what makes the
# diagnostic be about THIS plant — the span's `text` entries are the raw
# source lines, never the width-trimmed rendering (measured: the entry
# is the plant's whole line).
#
#   scripts/mutation-probe.sh --file crates/granary-client/clippy.toml \
#     --from 'path = "std::fs::create_dir_all"' \
#     --to   'path = "std::fs::create_dir_all_x"' --count 1 \
#     --name dormant-ban -- scripts/probes/fsguard-dormant-ban-oracle.sh
#
# Runs from any directory inside the repo; honours CARGO_TARGET_DIR if
# the caller exports one (a worktree sharing the main tree's target).
#
# It is also the LINT LANE's standing positive control:
# ci.yml's lint job runs it after the regular clippy steps, so every run
# proves the whole mechanism live — the config clippy actually loaded, the
# level it applied, and that no --cap-lints or wrapper upstream relevelled
# the ban — rather than proving that the files describing it still parse.
set -uo pipefail
# `cd "$(git rev-parse --show-toplevel)" || exit 2` is inert: when the
# command substitution fails the shell runs `cd ""`, which is a NO-OP that
# returns 0, so the guard can never fire and the oracle plants into
# whatever directory the caller happened to be in. Capture git's status
# and its output separately, and refuse an empty toplevel by name.
top=$(git rev-parse --show-toplevel) \
  || { echo "oracle: not inside a git worktree — refusing to plant" >&2; exit 2; }
[ -n "$top" ] \
  || { echo "oracle: not inside a git worktree — refusing to plant" >&2; exit 2; }
cd "$top" || { echo "oracle: cannot enter $top" >&2; exit 2; }
f=crates/granary-client/src/lib.rs
# THE REFUSAL STAYS, and the message says what to do about it. A
# positive control that plants into a file someone is editing would
# either destroy the edit on restore or measure a tree nobody has. The
# cost is real and worth naming: while this one file is dirty,
# the lint lane cannot complete, because it runs
# this probe.
# BOTH HALVES OF "uncommitted". `git diff --quiet` compares the WORKING
# TREE against the INDEX, so a change that has been `git add`ed and not
# committed reads as clean to it — and the restore below is
# `git checkout -- "$f"`, which rewrites the file from the index and
# then, on the next commit, silently carries or drops the plant. The
# staged half is `--cached` (index against HEAD), and the two together
# are what "unchanged since the last commit" actually means.
if ! git diff --quiet -- "$f" || ! git diff --cached --quiet -- "$f"; then
  echo "oracle: $f has uncommitted changes (staged, unstaged or both) and this probe plants into it, then restores it from git — refusing, because the restore would discard your edit." >&2
  echo "oracle: commit or stash $f and run again." >&2
  exit 2
fi

work="$(mktemp -d)" || exit 2
# An interrupt between the plant and the restore below leaves the plant
# in the working tree, and the next run then refuses to start on a file
# this script wrote itself.
trap 'git checkout -- "$f" > /dev/null 2>&1; rm -rf "$work"' EXIT
trap 'git checkout -- "$f" > /dev/null 2>&1; rm -rf "$work"; exit 2' INT TERM

# The line count BEFORE the append is what makes "the diagnostic is
# about the plant" a structural test rather than a name match: every
# line the plant occupies is strictly greater than this.
before="$(wc -l < "$f" | tr -d '[:space:]')"
# ONE definition of the planted name, used by both the plant and the
# reader below — a second spelling in the python would go stale
# silently, and "the diagnostic names the plant" would quietly become
# "no diagnostic ever matches".
plant_fn=dormant_ban_plant
printf '\n#[doc(hidden)]\npub fn %s() { let _ = std::fs::create_dir_all("/nonexistent/dormant-ban-plant"); }\n' "$plant_fn" >> "$f"
# `warn`, explicitly.
# It does not protect against the row's own config warning: measured
# directly, in this exact mutated-row-plus-plant shape, `cargo clippy -p
# granary-client --lib` exits 0 under `CARGO_BUILD_WARNINGS=deny` too —
# that diagnostic is the config loader's, not a registered lint, so
# denying warnings never reaches it (the same measurement this file's
# own header states). `warn` is kept anyway as defence in depth
# against two things this ONE measurement does not rule out for every
# future run: a clippy version that starts promoting the config
# diagnostic, and an unrelated pre-existing warning elsewhere in the
# crate that would otherwise turn a clean baseline into a misleading
# "could not run" (exit 2) rather than the real answer.
CARGO_BUILD_WARNINGS=warn cargo clippy -p granary-client --lib --message-format=json \
  > "$work/messages.json" 2> "$work/cargo.err"
rc=$?
git checkout -- "$f"
git diff --quiet -- "$f" || { echo "oracle: restore of $f failed" >&2; exit 2; }

# The JSON arrives as a PATH, never on stdin: `python3 -` reads the
# program itself from stdin, so a heredoc program and piped input cannot
# share it (scripts/fsguard-scan.py's header records the same trap).
python3 - "$before" "$work/messages.json" "$work/tail.txt" "$plant_fn" "$f" <<'ORACLE_PY'
import json
import sys

before = int(sys.argv[1])
messages_path = sys.argv[2]
tail_path = sys.argv[3]
plant_fn = sys.argv[4]
planted_file = sys.argv[5]

found = False
rendered = []
try:
    with open(messages_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("reason") != "compiler-message":
                continue
            message = msg.get("message") or {}
            text = message.get("rendered")
            if text:
                rendered.append(text)
            code = (message.get("code") or {}).get("code")
            if code != "clippy::disallowed_methods":
                continue
            for span in message.get("spans") or []:
                # PRIMARY only: a note or a secondary span can point at
                # any line of any file, so a non-primary match would
                # make the location test decorative.
                if not span.get("is_primary"):
                    continue
                file_name = span.get("file_name") or ""
                line_start = span.get("line_start")
                # The span's own source text, joined: `text` is a list
                # of the raw lines the span covers, each already the
                # untrimmed source.
                span_text = "".join(
                    (piece.get("text") or "") for piece in (span.get("text") or [])
                )
                if (
                    (file_name == planted_file or file_name.endswith("/" + planted_file))
                    and isinstance(line_start, int)
                    and line_start > before
                    and plant_fn in span_text
                ):
                    found = True
except OSError as e:
    print(f"oracle: could not read {messages_path}: {e}", file=sys.stderr)
    sys.exit(3)

if found:
    sys.exit(0)

try:
    with open(tail_path, "w", encoding="utf-8") as f:
        for text in rendered[-3:]:
            f.write(text)
except OSError as e:
    print(f"oracle: could not write {tail_path}: {e}", file=sys.stderr)
    sys.exit(3)
sys.exit(1)
ORACLE_PY
verdict=$?

if [ "$verdict" -eq 0 ]; then
  exit 0
fi
if [ "$verdict" -ne 1 ]; then
  echo "oracle: the JSON reader itself failed (exit $verdict) — refusing to answer." >&2
  exit 2
fi
if [ "$rc" -eq 0 ]; then
  # Clippy accepted the plant. Under a mutated ban row that is the
  # expected result and the probe reads it as MUTATION KILLED.
  exit 1
fi
echo "oracle: clippy exited $rc with no clippy::disallowed_methods diagnostic whose primary span is the plant." >&2
echo "oracle: that is 'the crate did not build', not 'the ban fired' — refusing to answer. Last rendered diagnostics:" >&2
cat "$work/tail.txt" >&2
tail -5 "$work/cargo.err" >&2
exit 2
