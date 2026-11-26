#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# Mutation probe that FAILS THE RUN when the mutation does not land.
#
# A mutation probe answers "does the suite notice this break?". It is a
# gate, and like every gate it can fail open: a stale anchor, a
# re-indented copy, a renamed symbol or an off-by-one leaves the file
# UNMUTATED, and the suite then prints a green summary that reads
# exactly like "the mutation survived". Checking by hand missed it four
# times in one session, so this probe checks, every run.
#
# Usage:
#   scripts/mutation-probe.sh --file <path> --from <exact text> --to <text>
#                             [--count N] [--name LABEL] [--no-baseline]
#                             -- <test command...>
#
# Exit codes:
#   0  MUTATION KILLED   — the test command failed, as a probe wants
#   1  MUTATION SURVIVED — the test command passed; a coverage question
#   2  PROBE FAILED      — the test command was already failing before the
#                          mutation, or the anchor did not match exactly
#                          --count times, or the file did not change, or the
#                          restore did not verify, or MP_BASELINE_LOG names a
#                          path that cannot be written. NOT a result. This code
#                          has always covered several causes — usage errors and
#                          a missing --file exit 2 as well — so it means "no
#                          result", never one specific failure; each cause
#                          prints its own message.
set -uo pipefail

file=""; from=""; to=""; count=1; name="mutation"; baseline="yes"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --file)  file="$2"; shift 2 ;;
    --from)  from="$2"; shift 2 ;;
    --to)    to="$2";   shift 2 ;;
    --count) count="$2"; shift 2 ;;
    --name)  name="$2"; shift 2 ;;
    --no-baseline) baseline="no"; shift ;;
    --)      shift; break ;;
    *) echo "mutation-probe: unknown argument $1" >&2; exit 2 ;;
  esac
done

[[ -n "$file" && -n "$from" && $# -gt 0 ]] || {
  echo "mutation-probe: need --file, --from and a -- <test command>" >&2; exit 2; }
[[ -f "$file" ]] || { echo "mutation-probe: no such file: $file" >&2; exit 2; }
[[ "$from" != "$to" ]] || { echo "mutation-probe: --from and --to are identical" >&2; exit 2; }

snapshot="$(mktemp -t mutation-probe)"
cp "$file" "$snapshot"
restore() {
  cp "$snapshot" "$file"
  if ! cmp -s "$snapshot" "$file"; then
    echo "mutation-probe: FAILED TO RESTORE $file — snapshot at $snapshot" >&2
    exit 2
  fi
  rm -f "$snapshot"
}
trap 'restore' EXIT

# --- baseline first. A probe on an ALREADY-RED suite is meaningless: every
# --- mutation "kills" it, including one that never lands.
# --- The baseline output goes to $MP_BASELINE_LOG when the caller sets it,
# --- because discarding it loses the ONE piece of evidence a red baseline
# --- exists to provide: WHICH row failed. Across 21 full-suite runs, one
# --- baseline failed once. The default stays /dev/null: this
# --- widens what a caller CAN keep, and changes nothing for one that does
# --- not ask.
if [[ "$baseline" == "yes" ]]; then
  # A log path that cannot be written would make the redirect below fail
  # BEFORE the test command runs, and the failure would then be reported
  # as "the suite is already red" — a false diagnosis that sends someone
  # hunting a test failure that never happened. Prove the path is
  # writable first, and fail with the real reason.
  if [[ -n "${MP_BASELINE_LOG:-}" ]] && ! { : > "$MP_BASELINE_LOG"; } 2>/dev/null; then
    echo "mutation-probe: MP_BASELINE_LOG=$MP_BASELINE_LOG is not writable." >&2
    echo "  No mutation was applied and the suite was NOT run." >&2
    exit 2
  fi
  echo "=== mutation-probe [$name]: baseline (unmutated) run"
  if ! "$@" > "${MP_BASELINE_LOG:-/dev/null}" 2>&1; then
    echo "mutation-probe: THE TEST COMMAND ALREADY FAILS UNMUTATED — a probe" >&2
    echo "  cannot distinguish a kill from the pre-existing failure. Fix the" >&2
    echo "  suite, or narrow the command, then rerun. No mutation was applied." >&2
    if [[ -n "${MP_BASELINE_LOG:-}" ]]; then
      echo "  The baseline run's output is in $MP_BASELINE_LOG." >&2
    else
      echo "  Set MP_BASELINE_LOG=<path> and rerun to capture which row failed." >&2
    fi
    exit 2
  fi
  echo "    baseline green"
fi

# --- apply, counting first. An anchor that matches 0 times, or more
# --- times than declared, is a probe defect and never a test result.
MP_FILE="$file" MP_FROM="$from" MP_TO="$to" MP_COUNT="$count" python3 - <<'PY' || exit 2
import os, sys
path, frm, to = os.environ["MP_FILE"], os.environ["MP_FROM"], os.environ["MP_TO"]
want = int(os.environ["MP_COUNT"])
src = open(path, encoding="utf-8").read()
got = src.count(frm)
if got != want:
    print(f"mutation-probe: ANCHOR MATCHED {got} TIME(S), DECLARED {want} — probe failed, "
          f"no test was run", file=sys.stderr)
    print(f"  anchor: {frm!r}", file=sys.stderr)
    sys.exit(1)
open(path, "w", encoding="utf-8").write(src.replace(frm, to))
PY

if cmp -s "$snapshot" "$file"; then
  echo "mutation-probe: THE FILE DID NOT CHANGE after a matching replace — probe failed" >&2
  exit 2
fi

echo "=== mutation-probe [$name]: the edit that landed"
diff -u "$snapshot" "$file" | sed -n '1,40p'
echo "=== running: $*"
"$@"
rc=$?
echo
if [[ $rc -eq 0 ]]; then
  echo "mutation-probe [$name]: *** MUTATION SURVIVED *** (test command exited 0)"
  echo "  Untested mechanism, or an equivalent mutant. It is a question, not a verdict."
  exit 1
fi
echo "mutation-probe [$name]: MUTATION KILLED (test command exited $rc)"
exit 0
