#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# Runs ShellCheck over every tracked shell script: every tracked `*.sh`
# file, plus every OTHER tracked file whose first line names an
# interpreter this gate recognises (sh, bash, dash, ksh, zsh) -- directly
# (`#!/bin/bash`) or through `env`, with or without `env`'s `-S` flag
# (`#!/usr/bin/env bash`, `#!/usr/bin/env -S bash -e`). A trailing CR on
# the shebang line does not defeat recognition.
#
# ShellCheck cannot analyse zsh. A discovered zsh script MUST carry an
# exclusion-table row naming a shell override (below); one that does not
# is refused BY NAME rather than silently skipped or silently scanned
# under the wrong dialect.
#
# SEVERITY: `-S style`, the lowest of ShellCheck's four levels (style <
# info < warning < error), so nothing is filtered OUT -- consistent with
# this tree's zero-tolerance posture on lint output elsewhere
# (`CARGO_BUILD_WARNINGS=deny` covers clippy's style-level lints too,
# `RUSTDOCFLAGS="-D warnings"`). A style-level finding is still a finding,
# and it is exactly the class a reviewer is least likely to notice
# unaided.
#
# NOTHING OUTSIDE THIS INVOCATION MAY QUIET A FINDING. `-x` follows a
# `source`d file so a `source`/`.` target is read and checked too, instead
# of stopping at the boundary with an unresolvable-file diagnostic
# (SC1091). `--norc` ignores every `.shellcheckrc` a scanned file's
# directory or its parents carry. `SHELLCHECK_OPTS` is unset before
# ShellCheck ever runs, because ShellCheck itself reads that variable and
# appends its content to its own argument list -- an inherited
# `SHELLCHECK_OPTS='-e SC2086'` would otherwise silently exclude a code
# for every invocation this gate makes. A scanned file's OWN inline
# `# shellcheck ...` directive comments are neutralised before scanning
# (below) for the same reason: this gate's business is what ShellCheck
# finds with nothing -- not a config file, not an environment variable,
# not a comment in the file itself -- able to quiet it first.
#
# EVERY INVOCATION'S EXIT STATUS MUST BE 0 OR 1. ShellCheck 0.11.0's own
# documented return values are 0 (all files scanned, no issues), 1 (all
# files scanned, some issues), 2 (some files could not be processed, e.g.
# not found) and 3 (ShellCheck was invoked with bad syntax, e.g. an
# unknown flag). A status outside {0,1} is refused, naming the file: a
# missing or unreadable file prints valid, EMPTY JSON on an exit-2 status
# (`{"comments":[]}`), which reads as "clean" to anything that inspects
# only the JSON body -- so the exit status is always checked FIRST, before
# the body is trusted at all.
#
# KEEP EXCLUSIONS OUTSIDE THE FILES THEY NAME. Several of the files below are cited by exact line number
# from ADRs and session records that are not revisited to correct a
# citation that still resolves at a shifted line -- `check-citations.py`
# refuses a citation only when it runs past its target's end, and cannot
# see one that now points at the wrong statement. A suppression recorded
# as a comment inside a file moves every later line in that file; a
# suppression recorded here moves nothing outside this file.
#
# THE TABLE ROW SHAPE: `path|counts|shell`.
#   path    a single tracked file, exactly as `git ls-files` prints it --
#           not a directory, not a pathspec, and one row per path.
#   counts  a comma-separated `SC####:N` list: the EXACT number of
#           ShellCheck comments of each code this file carries today, at
#           $SEVERITY, with `--norc` and every inline directive
#           neutralised. Empty when the row exists only for its shell
#           override.
#   shell   a ShellCheck `--shell` value, or empty to let ShellCheck infer
#           the dialect from the file's own shebang. Mandatory (non-
#           empty) for a zsh file, and the ONLY source of a dialect
#           override this gate honours: a file's own inline
#           `# shellcheck shell=...` line is neutralised along with every
#           other directive it carries, so it cannot set one itself.
#
# THE RATCHET IS EQUALITY, per file, every run. A count higher than
# banked is a NEW finding and refuses. A count lower than banked is
# STALE -- the fix landed and the table was not shrunk to match -- and
# refuses just as hard, naming the code that no longer matches. Either
# direction is closed only by editing this table, deliberately, in the
# commit that changes the count it disagrees with; the gate cannot close
# it itself.
#
# A file with no row here must have a $SEVERITY-clean scan, under the same
# neutralisation, with nothing else to appeal to.
#
#   scripts/check-shellcheck.sh              run the gate
#   scripts/check-shellcheck.sh --self-test  prove it can fail
#   scripts/check-shellcheck.sh --extra-exclusions FILE [--self-test]
#
# Run from the repository root. File discovery and exclusions use paths
# relative to that working directory. The self-test sets its working
# directory to a fixture repository, then invokes the same script to
# exercise discovery and checking on those files.
#
#
set -euo pipefail

# An explicit supplement supports additional tracked files in a source checkout.
# The default always uses the table below.
extra_exclusions=""
if [ "${1:-}" = "--extra-exclusions" ] && [ "$#" -ge 2 ] && [ -n "$2" ]; then
  extra_exclusions="$2"
  shift 2
fi
if [[ $# -gt 1 || ($# -eq 1 && "${1:-}" != "--self-test") ]]; then
  echo "check-shellcheck: unrecognised argument(s): $* — use [--extra-exclusions FILE] [--self-test]." >&2
  exit 2
fi

# ShellCheck reads this variable and appends its content to its own
# argument list on every invocation -- unset it here, before the first
# invocation below, so nothing in the calling environment can slip a
# `-e`/`-i`/`-S` past the flags this gate itself passes.
unset SHELLCHECK_OPTS

# TOOL PRESENCE AND VERSION are preconditions of every other check below,
# so they are asserted before anything else runs, including the
# self-test (which exercises real ShellCheck invocations against
# fixtures and proves nothing without one). The version is pinned exactly
# -- not a floor -- because the table's banked counts are ShellCheck's
# own output for a specific release, and a different release is free to
# add, drop, renumber or recount a check.
SHELLCHECK_REQUIRED_VERSION="0.11.0"
if ! command -v shellcheck >/dev/null 2>&1; then
  echo "check-shellcheck: REFUSED — shellcheck is not on PATH. Install shellcheck ${SHELLCHECK_REQUIRED_VERSION} (macOS: brew install shellcheck; CI: taiki-e/install-action installs shellcheck@${SHELLCHECK_REQUIRED_VERSION})." >&2
  exit 2
fi
_sc_version="$(shellcheck --version 2>/dev/null | awk '/^version:/{print $2}')"
if [ "$_sc_version" != "$SHELLCHECK_REQUIRED_VERSION" ]; then
  echo "check-shellcheck: REFUSED — shellcheck reports version '${_sc_version:-unreadable}', this gate requires exactly ${SHELLCHECK_REQUIRED_VERSION}. Install shellcheck ${SHELLCHECK_REQUIRED_VERSION} (macOS: brew install shellcheck; CI: taiki-e/install-action installs shellcheck@${SHELLCHECK_REQUIRED_VERSION})." >&2
  exit 2
fi

SEVERITY=style

# The in-tree scan copy _scan_counts writes is removed on any exit, an
# interrupt included (the EXIT trap runs on the `exit` the INT and TERM
# traps call). _scan_counts runs inside a command substitution, whose
# assignments never reach this shell, so its caller names the copy here
# before the substitution starts.
_NEUTRAL_COPY=""
_remove_neutral_copy() {
  [ -z "${_NEUTRAL_COPY:-}" ] || rm -f "$_NEUTRAL_COPY"
}
# The scan copy's path for $1. `$$` is this shell's pid in a command
# substitution too, so the caller and _scan_counts agree on it.
_neutral_copy_path() {
  printf '%s/.check-shellcheck.neutral.%s.%s' "$(dirname -- "$1")" "$$" "$(basename -- "$1")"
}
trap _remove_neutral_copy EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---- the exclusion table -----------------------------------------------
# `EXCLUSIONS_OVERRIDE`, a newline-separated block of the same
# "path|counts|shell" rows, REPLACES the table below when set -- the
# self-test's own hook for pointing the real, unmodified gate at a
# fixture tree's rows instead of this one. The override follows the same
# validation and is honoured ONLY when
# `_CHECK_SHELLCHECK_SELFTEST_CHILD` also carries the sentinel value
# the self-test sets on its own child invocations ($_SELFTEST_SENTINEL,
# below). That is a guard against an ACCIDENTAL override -- a stray
# `EXCLUSIONS_OVERRIDE` left set in a shell from an earlier debugging
# session -- and not a security boundary: the sentinel's value is sitting
# in this same file, so anyone who can read the gate can also read it.
_SELFTEST_SENTINEL="the self-test set this"
EXCLUSIONS=()
if [ "${EXCLUSIONS_OVERRIDE+set}" = set ]; then
  if [ "${_CHECK_SHELLCHECK_SELFTEST_CHILD:-}" != "$_SELFTEST_SENTINEL" ]; then
    echo "check-shellcheck: REFUSED — EXCLUSIONS_OVERRIDE is honoured only inside a --self-test child run." >&2
    exit 2
  fi
  while IFS= read -r _ex_row; do
    [ -n "$_ex_row" ] && EXCLUSIONS+=("$_ex_row")
  done <<<"$EXCLUSIONS_OVERRIDE"
else
  # A sourced fixture with no shebang by design.
  EXCLUSIONS+=("scripts/vfs-scratch-fixture.sh||bash")                              # sourced, no shebang by design
  EXCLUSIONS+=("scripts/authority-venue.sh|SC1087:1,SC2016:4,SC2329:1|")
  EXCLUSIONS+=("scripts/bench/dedup-bench-crosscheck.sh|SC2034:3,SC2206:2|")
  EXCLUSIONS+=("scripts/blocked-stderr.sh|SC2174:1|")
  EXCLUSIONS+=("scripts/check-file-dispositions.sh|SC2001:5|")
  EXCLUSIONS+=("scripts/check-fsguard-sites.sh|SC2001:2,SC2016:10,SC2028:1,SC2064:4|")
  EXCLUSIONS+=("scripts/check-licence-boundary.sh|SC2016:2|")
  EXCLUSIONS+=("scripts/check-server-log-path.sh|SC2016:1,SC2034:1|")
  EXCLUSIONS+=("scripts/check-vfs-deps.sh|SC2001:4,SC2054:2|")
  EXCLUSIONS+=("scripts/check-vfs-purity.sh|SC2001:3|")
  EXCLUSIONS+=("scripts/check-vfs-root-shape.sh|SC2001:3,SC2004:1,SC2016:14|")
  EXCLUSIONS+=("scripts/ci-mounts.sh|SC1003:1,SC2015:29|")
  EXCLUSIONS+=("scripts/conformance.sh|SC2154:1,SC2329:3|")
  EXCLUSIONS+=("scripts/demo-self-check.sh|SC2034:1|")
  EXCLUSIONS+=("scripts/demo.sh|SC2016:1,SC2154:1,SC2329:2|")
  EXCLUSIONS+=("scripts/infra/runner-check.sh|SC2016:1,SC2329:4|") # mount variables expand in bash -c; four functions reached through check
  EXCLUSIONS+=("scripts/linux-container.sh|SC2016:1,SC2086:4,SC2329:2|")
  EXCLUSIONS+=("scripts/m10-propagate.sh|SC2016:1,SC2034:4,SC2086:1|")
  EXCLUSIONS+=("scripts/m10-venue.sh|SC2016:1|")
  EXCLUSIONS+=("scripts/mutation-probe.sh|SC2329:1|")
  EXCLUSIONS+=("scripts/stack-self-check.sh|SC1090:1,SC2016:6,SC2034:6,SC2086:1|")
  EXCLUSIONS+=("scripts/stack.sh|SC2034:1,SC2086:1|")
  EXCLUSIONS+=("scripts/unit-check.sh|SC2012:3,SC2016:1,SC2034:2,SC2329:2|")
fi

if [ -n "$extra_exclusions" ]; then
  if [[ ! -f "$extra_exclusions" || -L "$extra_exclusions" || ! -r "$extra_exclusions" ||
        "$(git --literal-pathspecs ls-files -- "$extra_exclusions")" != "$extra_exclusions" ]]; then
    echo "check-shellcheck: REFUSED — the supplemental table must be a readable, regular tracked file: $extra_exclusions" >&2
    exit 2
  fi
  _extra_count=0
  _extra_shape='^[^|]+[|](SC[0-9]{4}:[1-9][0-9]*(,SC[0-9]{4}:[1-9][0-9]*)*)?[|](sh|bash|dash|ksh|busybox)?$'
  while IFS= read -r _ex_row || [ -n "$_ex_row" ]; do
    case "$_ex_row" in '' | '#'*) continue ;; esac
    if [[ ! "$_ex_row" =~ $_extra_shape ]]; then
      echo "check-shellcheck: REFUSED — malformed row in the supplemental table: $extra_exclusions" >&2
      exit 2
    fi
    EXCLUSIONS+=("$_ex_row")
    _extra_count=$((_extra_count + 1))
  done < "$extra_exclusions"
  if [ "$_extra_count" -eq 0 ]; then
    echo "check-shellcheck: REFUSED — empty supplemental table: $extra_exclusions" >&2
    exit 2
  fi
fi

# Prints the interpreter name (sh, bash, dash, ksh or zsh) for a
# recognised shebang line, else prints nothing and returns 1. Recognises
# a direct interpreter path, `env NAME`, and `env -S "NAME args..."`; a
# trailing CR (a CRLF file) is stripped before matching.
_shebang_shell() {
  local line="${1%$'\r'}" w1 w2 w3 rest name
  case "$line" in '#!'*) ;; *) return 1 ;; esac
  read -r w1 w2 w3 rest <<<"${line#\#!}"
  : "$rest"
  case "${w1##*/}" in
    env)
      if [ "$w2" = "-S" ]; then name="$w3"; else name="$w2"; fi
      ;;
    *) name="${w1##*/}" ;;
  esac
  case "$name" in
    sh | bash | dash | ksh | zsh)
      printf '%s\n' "$name"
      return 0
      ;;
    *) return 1 ;;
  esac
}

# Every tracked `*.sh` under `$1` (a repo root -- `.` for the real run, a
# fixture tree for the self-test), plus every other tracked file whose
# first line is a recognised shebang. Populates the global array FOUND
# with paths relative to `$1`, exactly as `git ls-files` prints them.
FOUND=()
_discover() {
  local root="$1" f path first_line
  FOUND=()
  while IFS= read -r -d '' f; do
    case "$f" in
      *.sh)
        FOUND+=("$f")
        continue
        ;;
    esac
    path="$f"
    [ "$root" = "." ] || path="$root/$f"
    [ -f "$path" ] || continue
    # `-c 128`, NOT `-n 1`: a binary tracked file (a fuzz corpus seed, a
    # tar fixture) may carry no newline for a long stretch, and `head -n1`
    # on one reads the whole file hunting for a line break that never
    # comes. A shebang line is at most a few dozen bytes, so 128 is
    # generous and the read is O(1) regardless of the file behind it.
    #
    # THE BLOCK-LEVEL `2>/dev/null` IS LOAD-BEARING, not decoration on top
    # of `head`'s own `2>/dev/null`: a binary file's first 128 bytes often
    # carry an embedded NUL, and inside a `while read -d ''` loop fed by
    # process substitution, bash prints "warning: command substitution:
    # ignored null byte in input" to ITS OWN stderr for that -- a warning
    # `head`'s own redirect cannot reach, because it is bash's, not
    # head's.
    { first_line="$(head -c 128 -- "$path" 2>/dev/null || true)"; } 2>/dev/null
    first_line="${first_line%%$'\n'*}"
    # `if`, not a bare `cmd && FOUND+=(...)`: under `set -e` a standalone
    # `&&` statement whose FIRST half fails aborts the whole script right
    # there -- the common case here, since most tracked files are not
    # shell scripts. Wrapping it as an `if` condition is what the `while`
    # loop above already relies on for the same reason.
    if _shebang_shell "$first_line" >/dev/null; then
      FOUND+=("$f")
    fi
  done < <(git -C "$root" ls-files -z 2>/dev/null)
}

# `path|counts|shell` -> prints "counts|shell" and returns 0 if `$1` has a
# table row; prints nothing and returns 1 otherwise. ALWAYS called from an
# `if`/`if !` at its call sites, so its non-zero "not found" return is the
# ordinary, exempted case, never a bare failing statement.
_lookup_exclusion() {
  local path="$1" row row_path
  for row in ${EXCLUSIONS[@]+"${EXCLUSIONS[@]}"}; do
    row_path="${row%%|*}"
    if [ "$row_path" = "$path" ]; then
      printf '%s\n' "${row#*|}"
      return 0
    fi
  done
  return 1
}

# Sorted `CODE:N` lines from a comma-separated `$1` (possibly empty).
# Prints nothing for an empty `$1` -- NEVER a single blank line, which
# would make an empty set compare unequal to a genuinely empty stream
# from `_scan_counts`.
_counts_lines() {
  [ -n "$1" ] || return 0
  printf '%s' "$1" | tr ',' '\n' | sort
}

# Writes $1's content into $2, with every ShellCheck directive comment
# neutralised -- `#`, optional blanks, then `shellcheck` and a blank,
# anywhere on a line (a trailing comment too). KNOWN LIMIT: a
# directive after a no-break space, and a bare `# shellcheck`, are not
# neutralised, so either can still quiet findings in its file; whatever keys it carries
# (disable=, enable=, shell=, source=, several at once, disable=all), has
# its `shellcheck` token replaced, so ShellCheck reads it as a plain
# comment instead of acting on it. The same text inside a string is
# rewritten too; the copy is only scanned, never run, so that can only add
# a finding, never hide one. `LC_ALL=C` makes sed read bytes: under a
# UTF-8 locale BSD sed stops at an invalid byte and writes a truncated
# copy, which would scan clean past it. Returns sed's status. Line count and every
# other line are unchanged: this replaces IN PLACE, never deletes a line,
# because a `source`d file and every other citation into this file is
# still addressed by its ORIGINAL line numbers.
#
# The replacement word must not itself START WITH `shellcheck`.
# ShellCheck's own directive parser recognises a comment by its FIRST
# word beginning with `shellcheck`, prefix included -- a replacement like
# `shellcheck-neutralised` is still read as an attempted directive,
# fails to parse, and reports its own parse-confusion codes (which can
# swallow every later finding in the file) instead of neutralising
# anything.
_neutralize_into() {
  local src="$1" dst="$2"
  # `./` rather than `--`: BSD sed does not take `--` as an end of
  # options, and a relative path from `git ls-files` may begin with `-`.
  case "$src" in
    /*) ;;
    *) src="./$src" ;;
  esac
  LC_ALL=C sed -E 's/(#[[:space:]]*)shellcheck([[:space:]])/\1neutralised-shellcheck\2/g' "$src" >"$dst"
}

# The file's CURRENT `CODE:N` counts at $SEVERITY, with `--norc` and every
# inline directive neutralised, sorted by code (possibly none). Returns 1
# -- with its own diagnostic already on stderr -- when ShellCheck's own
# exit status is neither 0 nor 1, or when its json1 body does not parse:
# either is ShellCheck itself misbehaving, never "no findings", and must
# never be read as a clean pass. `$2`, the shell override, may be empty.
#
# The neutralised copy is written NEXT TO the original, under the
# original's own name with a dotfile prefix, so `-x` source-following
# resolves a relative `source`/`.` target exactly as it would from the
# original's own directory -- a copy in some other directory would need
# `--source-path` pointed back at this one, which is more moving parts
# for the same result.
#
# A `$1` that discovery found but that is missing or unreadable at scan
# time is given NO copy at all: ShellCheck then sees a genuinely absent
# path and reports its own exit status 2 for it, which the check below
# refuses -- rather than this function manufacturing an empty file that
# would scan as trivially clean.
_scan_counts() {
  local file="$1" shell="$2" json rc err neutral
  neutral="$(_neutral_copy_path "$file")"
  if [ -r "$file" ]; then
    if ! _neutralize_into "$file" "$neutral"; then
      echo "check-shellcheck: FAILED — could not write the scan copy of ${file}" >&2
      rm -f "$neutral"
      return 1
    fi
  fi
  err="$(mktemp)"
  if [ -n "$shell" ]; then
    if json="$(shellcheck --norc -x -S "$SEVERITY" -f json1 --shell="$shell" -- "$neutral" 2>"$err")"; then rc=0; else rc=$?; fi
  else
    if json="$(shellcheck --norc -x -S "$SEVERITY" -f json1 -- "$neutral" 2>"$err")"; then rc=0; else rc=$?; fi
  fi
  rm -f "$neutral"
  case "$rc" in
    0 | 1) ;;
    *)
      echo "check-shellcheck: FAILED — shellcheck exited ${rc} (neither 0 nor 1) on ${file}:" >&2
      sed 's/^/    /' "$err" >&2
      rm -f "$err"
      return 1
      ;;
  esac
  rm -f "$err"
  if ! printf '%s' "$json" | python3 -c "
import json, sys, collections
data = json.load(sys.stdin)
counts = collections.Counter()
for c in data.get('comments', []):
    code = c.get('code')
    if code is not None:
        counts['SC%d' % code] += 1
for code in sorted(counts):
    print('%s:%d' % (code, counts[code]))
"; then
    echo "check-shellcheck: FAILED — shellcheck's json1 output for ${file} did not parse." >&2
    return 1
  fi
  return 0
}

# Three properties of the table itself, none about any file's findings:
# every row names a path `git ls-files` resolves to EXACTLY that one
# string (never a pathspec or a directory, which would resolve to zero or
# to several); every named path is one discovery actually found (an entry
# for a file that is not a recognised shell script is a stale row, not a
# gate that silently stops checking something); and no path is named
# twice.
_validate_table() {
  local row path bad=0 dups f in_found matches
  dups="$(for row in ${EXCLUSIONS[@]+"${EXCLUSIONS[@]}"}; do printf '%s\n' "${row%%|*}"; done | sort | uniq -d)"
  if [ -n "$dups" ]; then
    echo "check-shellcheck: REFUSED — the exclusion table names the same path more than once: $(printf '%s' "$dups" | tr '\n' ' ')" >&2
    bad=1
  fi
  for row in ${EXCLUSIONS[@]+"${EXCLUSIONS[@]}"}; do
    path="${row%%|*}"
    matches="$(git ls-files -- "$path" 2>/dev/null || true)"
    if [ "$matches" != "$path" ]; then
      echo "check-shellcheck: REFUSED — the exclusion table names '${path}', which is not a literal tracked file (a pathspec, a directory, or an untracked path)." >&2
      bad=1
      continue
    fi
    in_found=1
    for f in ${FOUND[@]+"${FOUND[@]}"}; do
      [ "$f" = "$path" ] && { in_found=0; break; }
    done
    if [ "$in_found" -eq 1 ]; then
      echo "check-shellcheck: REFUSED — the exclusion table names '${path}', which discovery did not find as a shell script." >&2
      bad=1
    fi
  done
  return "$bad"
}

# The per-file verdict. $1 is a path relative to the repo root (as
# `_discover` returns it). Prints its own diagnostics on refusal; returns
# 0 (pass) or 1 (refuse) -- always called via `if !` at its call site, so
# every bare assignment inside this function, and inside what it calls,
# sits inside that same exempted context.
_check_one() {
  local path="$1" rest counts shell actual extra missing first_line detected

  { first_line="$(head -c 128 -- "$path" 2>/dev/null || true)"; } 2>/dev/null
  first_line="${first_line%%$'\n'*}"
  detected="$(_shebang_shell "$first_line" 2>/dev/null || true)"

  if rest="$(_lookup_exclusion "$path")"; then
    IFS='|' read -r counts shell <<<"$rest"
    if [ "$detected" = zsh ] && [ -z "$shell" ]; then
      echo "check-shellcheck: FAILED — ${path} is a zsh script (ShellCheck cannot analyse zsh) and its exclusion-table entry carries no shell override." >&2
      return 1
    fi

    _NEUTRAL_COPY="$(_neutral_copy_path "$path")"
    if actual="$(_scan_counts "$path" "$shell")"; then
      _NEUTRAL_COPY=""
    else
      _NEUTRAL_COPY=""
      return 1
    fi
    extra="$(comm -23 <(printf '%s' "$actual") <(_counts_lines "$counts"))"
    missing="$(comm -13 <(printf '%s' "$actual") <(_counts_lines "$counts"))"
    if [ -n "$extra" ]; then
      echo "check-shellcheck: FAILED — ${path} trips a finding its exclusion-table entry does not cover: $(printf '%s' "$extra" | tr '\n' ' ')" >&2
      return 1
    fi
    if [ -n "$missing" ]; then
      echo "check-shellcheck: FAILED — ${path}'s exclusion-table entry records $(printf '%s' "$missing" | tr '\n' ' ') that it no longer trips — STALE; shrink the table entry." >&2
      return 1
    fi
    return 0
  fi

  if [ "$detected" = zsh ]; then
    echo "check-shellcheck: FAILED — ${path} is a zsh script (ShellCheck cannot analyse zsh) with no exclusion-table entry naming a shell override." >&2
    return 1
  fi

  _NEUTRAL_COPY="$(_neutral_copy_path "$path")"
  if actual="$(_scan_counts "$path" "")"; then
    _NEUTRAL_COPY=""
  else
    _NEUTRAL_COPY=""
    return 1
  fi
  if [ -n "$actual" ]; then
    echo "check-shellcheck: FAILED — ${path} (no exclusion-table entry) trips: $(printf '%s' "$actual" | tr '\n' ' ')" >&2
    return 1
  fi
  return 0
}

if [ "${1:-}" = "--self-test" ]; then
  me="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  fails=0
  cases=0

  # `case` and not `grep -q` for the substring check, same reasoning this
  # tree's other self-tests give: a `grep -q` on a long capture can SIGPIPE
  # its producer under `pipefail` and turn a passing control into a
  # falsely-failed one on nothing more than a long enough log.
  _assert() { # $1=label $2=got_rc $3=want_rc $4=output $5=want_substr(optional) $6=want_substr2(optional)
    cases=$((cases + 1))
    if [ "$2" -eq "$3" ]; then
      if [ -z "${5:-}" ]; then
        echo "check-shellcheck self-test: $1 -> ok"
        return 0
      fi
      case "$4" in
        *"$5"*)
          if [ -z "${6:-}" ]; then
            echo "check-shellcheck self-test: $1 -> ok"
            return 0
          fi
          case "$4" in
            *"$6"*)
              echo "check-shellcheck self-test: $1 -> ok"
              return 0
              ;;
          esac
          ;;
      esac
    fi
    echo "check-shellcheck self-test: $1 -> FAILED (rc=$2, want rc=$3${5:+, output containing [$5]}${6:+ and [$6]})" >&2
    printf '%s\n' "$4" | sed 's/^/    /' >&2
    fails=$((fails + 1))
  }

  _fixture_repo() { # prints the new fixture's path
    local d
    d="$(mktemp -d)"
    (cd "$d" && git init -q . && git config user.email t@t && git config user.name t)
    printf '%s' "$d"
  }
  _commit() { # $1=fixture dir
    (cd "$1" && git add -A && git commit -qm f >/dev/null)
  }
  # $1=fixture dir; $2...=further `env` arguments (VAR=val words, or a
  # leading PATH=... to point at a stub tool). Always carries the
  # self-test sentinel, so a fixture may freely set EXCLUSIONS_OVERRIDE.
  _run() {
    local d="$1"
    shift
    if out="$(cd "$d" && env "_CHECK_SHELLCHECK_SELFTEST_CHILD=$_SELFTEST_SENTINEL" "$@" bash "$me" 2>&1)"; then rc=0; else rc=$?; fi
  }

  # R1 -- a clean tracked script, no exclusion-table entry, passes.
  d="$(_fixture_repo)"
  cat >"$d/clean.sh" <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "hello"
FIXTURE
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE="
  _assert "a clean file with no table entry passes" "$rc" 0 "$out"
  rm -rf "$d"

  # R2 -- a planted defect (SC2086, unquoted expansion), no table entry,
  # is refused.
  d="$(_fixture_repo)"
  cat >"$d/broken.sh" <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
name=$1
echo $name
FIXTURE
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE="
  _assert "a planted defect with no table entry is refused" "$rc" 1 "$out" "SC2086"
  rm -rf "$d"

  # R3 -- a table entry naming the file's ONLY code, at its exact count,
  # passes; the SAME entry does NOT silence a second, different code in
  # another file (SC2006) -- proving the exclusion is scoped to what it
  # lists, not a blanket pass.
  d="$(_fixture_repo)"
  cat >"$d/one-code.sh" <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
name=$1
echo $name
FIXTURE
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE=one-code.sh|SC2086:1|"
  _assert "a table entry at the file's exact code count passes" "$rc" 0 "$out"
  rm -rf "$d"

  d="$(_fixture_repo)"
  cat >"$d/two-codes.sh" <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
name=$1
echo $name
x=`echo hi`
FIXTURE
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE=two-codes.sh|SC2086:1|"
  _assert "a table entry naming only ONE of two codes still refuses on the other (SC2006)" "$rc" 1 "$out" "SC2006"
  rm -rf "$d"

  # R4 -- a STALE entry: the table's count for a code is HIGHER than what
  # the file now trips (the fix landed) -- refused, naming the code and
  # "STALE".
  d="$(_fixture_repo)"
  cat >"$d/fixed.sh" <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "hello"
FIXTURE
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE=fixed.sh|SC2086:1|"
  _assert "a stale entry (banked code no longer tripped) is refused" "$rc" 1 "$out" "SC2086" "STALE"
  rm -rf "$d"

  # R4b -- the COUNT ratchet specifically: the table's count for a code
  # the file DOES still trip is LOWER than what it now trips (a new
  # occurrence, same code) -- refused as uncovered, not silently passed
  # because the code itself was already known.
  d="$(_fixture_repo)"
  cat >"$d/more-occurrences.sh" <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
name=$1
other=$2
echo $name
echo $other
FIXTURE
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE=more-occurrences.sh|SC2086:1|"
  _assert "a banked code at a count lower than actual is refused (a new occurrence is not covered by an old count)" "$rc" 1 "$out" "SC2086:2"
  rm -rf "$d"

  # R5 -- an entry naming an UNTRACKED path is refused, before any file is
  # even scanned.
  d="$(_fixture_repo)"
  cat >"$d/clean2.sh" <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "hello"
FIXTURE
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE=does-not-exist.sh|SC2086:1|"
  _assert "an exclusion-table entry naming an untracked path is refused" "$rc" 1 "$out" "not a literal tracked file"
  rm -rf "$d"

  # R5b -- an entry naming a DIRECTORY (a real, tracked prefix, not a
  # literal file) is refused the same way.
  d="$(_fixture_repo)"
  mkdir -p "$d/adir"
  cat >"$d/adir/f.sh" <<'FIXTURE'
#!/usr/bin/env bash
printf 'ok\n'
FIXTURE
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE=adir|SC2086:1|"
  _assert "an exclusion-table entry naming a directory is refused" "$rc" 1 "$out" "not a literal tracked file"
  rm -rf "$d"

  # R5c -- two rows for the same path are refused, naming the path, before
  # anything else is checked.
  d="$(_fixture_repo)"
  cat >"$d/clean3.sh" <<'FIXTURE'
#!/usr/bin/env bash
printf 'ok\n'
FIXTURE
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE=$(printf 'clean3.sh|SC2086:1|\nclean3.sh|SC2086:1|')"
  _assert "a path named by two rows is refused" "$rc" 1 "$out" "more than once"
  rm -rf "$d"

  # R5d -- an entry for a path discovery does NOT recognise as a shell
  # script (no `.sh`, no recognised shebang) is refused.
  d="$(_fixture_repo)"
  cat >"$d/clean4.sh" <<'FIXTURE'
#!/usr/bin/env bash
printf 'ok\n'
FIXTURE
  printf 'print("not shell")\n' >"$d/notshell.py"
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE=notshell.py|SC2086:1|"
  _assert "an entry for a path discovery did not find is refused" "$rc" 1 "$out" "discovery did not find"
  rm -rf "$d"

  # R6 -- discovery end to end: a `.sh` file and a shebang'd extensionless
  # file, DIRECT and via `env`, are found and scanned -- each carrying its
  # OWN planted defect, so the gate refuses NAMING EACH ONE, which a
  # missed file could not do. A python shebang and a no-shebang
  # extensionless file are not scanned at all (their own "defects", if
  # any, cannot surface).
  d="$(_fixture_repo)"
  cat >"$d/dotsh.sh" <<'FIXTURE'
#!/usr/bin/env bash
printf 'ok\n'
FIXTURE
  cat >"$d/noext-bash" <<'FIXTURE'
#!/bin/bash
name=$1
echo $name
FIXTURE
  cat >"$d/noext-sh" <<'FIXTURE'
#!/usr/bin/env sh
name=$1
echo $name
FIXTURE
  cat >"$d/noext-python" <<'FIXTURE'
#!/usr/bin/env python3
print("not shell")
FIXTURE
  cat >"$d/noext-noshebang" <<'FIXTURE'
just text, no shebang at all
FIXTURE
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE="
  _assert "discovery finds and scans both extensionless shebangs, naming each planted defect" "$rc" 1 "$out" "noext-bash" "noext-sh"
  rm -rf "$d"

  # R7 -- a zsh script discovered with NO table entry is refused by name;
  # ShellCheck cannot analyse zsh at all.
  d="$(_fixture_repo)"
  cat >"$d/z.sh" <<'FIXTURE'
#!/bin/zsh
printf 'ok\n'
FIXTURE
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE="
  _assert "a zsh script with no table entry is refused by name" "$rc" 1 "$out" "z.sh is a zsh script"
  rm -rf "$d"

  # R7b -- a zsh script WITH a table entry but no shell override is
  # refused the same way -- the override itself is mandatory, not merely
  # the row's existence.
  d="$(_fixture_repo)"
  cat >"$d/z2.sh" <<'FIXTURE'
#!/bin/zsh
printf 'ok\n'
FIXTURE
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE=z2.sh||"
  _assert "a zsh script with a table entry but no shell override is refused" "$rc" 1 "$out" "no shell override"
  rm -rf "$d"

  # R8 -- EXCLUSIONS_OVERRIDE set WITHOUT the self-test sentinel is
  # refused outright, before any file is scanned: the override is not a
  # public interface.
  d="$(_fixture_repo)"
  cat >"$d/clean5.sh" <<'FIXTURE'
#!/usr/bin/env bash
printf 'ok\n'
FIXTURE
  _commit "$d"
  if out="$(cd "$d" && env "EXCLUSIONS_OVERRIDE=" bash "$me" 2>&1)"; then rc=0; else rc=$?; fi
  _assert "EXCLUSIONS_OVERRIDE without the self-test sentinel is refused" "$rc" 2 "$out" "honoured only inside a --self-test"
  rm -rf "$d"

  # R9 -- ShellCheck itself exiting neither 0 nor 1 is refused, naming the
  # file -- proven with a stub `shellcheck` ahead of it on PATH that
  # answers `--version` honestly but exits 3 on any real scan (an
  # internal failure, or a file it could not open, per its own documented
  # exit codes).
  d="$(_fixture_repo)"
  cat >"$d/clean6.sh" <<'FIXTURE'
#!/usr/bin/env bash
printf 'ok\n'
FIXTURE
  _commit "$d"
  stubdir="$(mktemp -d)"
  cat >"$stubdir/shellcheck" <<STUB
#!/usr/bin/env bash
if [ "\$1" = "--version" ]; then
  printf 'ShellCheck - shell script analysis tool\nversion: ${SHELLCHECK_REQUIRED_VERSION}\n'
  exit 0
fi
# Prints valid, EMPTY json1 on its "failure" path, the same as real
# ShellCheck does for a file it could not open (exit 2) -- the shape that
# makes the exit-status check load-bearing rather than redundant with the
# json1-parse check just below it: a well-formed empty body reads as
# "clean" to anything that does not look at the exit status first.
echo '{"comments":[]}'
echo "stub: simulated internal failure" >&2
exit 3
STUB
  chmod +x "$stubdir/shellcheck"
  _run "$d" "PATH=$stubdir:$PATH" "EXCLUSIONS_OVERRIDE="
  _assert "a shellcheck exit status outside {0,1} is refused, naming the file" "$rc" 1 "$out" "clean6.sh" "exited 3"
  rm -rf "$d" "$stubdir"

  # R9b -- exit status 2 specifically, from REAL ShellCheck rather than a
  # stub: a file discovery found (a `.sh` file is never existence-checked
  # by discovery itself) but that is gone from the working tree by the
  # time the gate scans it. ShellCheck then reports ITS OWN exit 2 with
  # valid, EMPTY json1 for the missing path -- exactly the body that would
  # read as a clean pass if the exit status were not checked first.
  d="$(_fixture_repo)"
  cat >"$d/gone.sh" <<'FIXTURE'
#!/usr/bin/env bash
printf 'ok\n'
FIXTURE
  _commit "$d"
  rm -f "$d/gone.sh"
  _run "$d" "EXCLUSIONS_OVERRIDE="
  _assert "a file discovery found but that is missing on disk is refused (real exit 2)" "$rc" 1 "$out" "gone.sh" "exited 2"
  rm -rf "$d"

  # R10 -- a shellcheck reporting the wrong VERSION is refused with an
  # install hint, before any file is scanned.
  d="$(_fixture_repo)"
  cat >"$d/clean7.sh" <<'FIXTURE'
#!/usr/bin/env bash
printf 'ok\n'
FIXTURE
  _commit "$d"
  stubdir="$(mktemp -d)"
  cat >"$stubdir/shellcheck" <<'STUB'
#!/usr/bin/env bash
if [ "$1" = "--version" ]; then
  printf 'ShellCheck - shell script analysis tool\nversion: 0.10.0\n'
  exit 0
fi
exit 0
STUB
  chmod +x "$stubdir/shellcheck"
  _run "$d" "PATH=$stubdir:$PATH" "EXCLUSIONS_OVERRIDE="
  _assert "a shellcheck version other than the pinned one is refused with an install hint" "$rc" 2 "$out" "0.10.0" "Install shellcheck"
  rm -rf "$d" "$stubdir"

  # R11 -- `--norc`: a `.shellcheckrc` sitting in the fixture that
  # disables the planted code must NOT be allowed to quiet it.
  d="$(_fixture_repo)"
  printf 'disable=SC2086\n' >"$d/.shellcheckrc"
  cat >"$d/rc.sh" <<'FIXTURE'
#!/usr/bin/env bash
name=$1
echo $name
FIXTURE
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE="
  _assert "a local .shellcheckrc cannot quiet a finding (--norc)" "$rc" 1 "$out" "SC2086"
  rm -rf "$d"

  # R11b -- `SHELLCHECK_OPTS` in the environment must NOT be allowed to
  # quiet the planted code either; ShellCheck itself appends this
  # variable's content to its own argument list.
  d="$(_fixture_repo)"
  cat >"$d/opts.sh" <<'FIXTURE'
#!/usr/bin/env bash
name=$1
echo $name
FIXTURE
  _commit "$d"
  _run "$d" "SHELLCHECK_OPTS=-e SC2086" "EXCLUSIONS_OVERRIDE="
  _assert "SHELLCHECK_OPTS in the environment cannot quiet a finding" "$rc" 1 "$out" "SC2086"
  rm -rf "$d"

  # R12 -- a directive carrying SEVERAL keys at once does not quiet the
  # planted code: every key on the line is neutralised, not only the
  # first.
  d="$(_fixture_repo)"
  cat >"$d/multi.sh" <<'FIXTURE'
#!/usr/bin/env bash
# shellcheck disable=SC2086 enable=all
name=$1
echo $name
FIXTURE
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE="
  _assert "a multi-key directive does not quiet its own disable= key" "$rc" 1 "$out" "SC2086"
  rm -rf "$d"

  # R12b -- `disable=all` does not quiet the planted code either.
  d="$(_fixture_repo)"
  cat >"$d/all.sh" <<'FIXTURE'
#!/usr/bin/env bash
# shellcheck disable=all
name=$1
echo $name
FIXTURE
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE="
  _assert "disable=all does not quiet a finding" "$rc" 1 "$out" "SC2086"
  rm -rf "$d"

  # R12c -- a `shell=` directive does not survive neutralisation either:
  # the file's dialect comes ONLY from the table's shell field, never from
  # a line inside the file. `[[ ]]` is clean under bash and SC3010 under
  # sh, so this row passes only when the directive was neutralised.
  d="$(_fixture_repo)"
  cat >"$d/shellkey.sh" <<'FIXTURE'
#!/usr/bin/env bash
# shellcheck shell=sh
x=1
if [[ -n "$x" ]]; then echo ok; fi
FIXTURE
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE="
  _assert "an inline shell= directive does not change the dialect" "$rc" 0 "$out"
  rm -rf "$d"

  # R12d -- a directive in a trailing comment is neutralised too:
  # ShellCheck honours `true; # shellcheck disable=...` for the next line.
  d="$(_fixture_repo)"
  cat >"$d/trailing.sh" <<'FIXTURE'
#!/usr/bin/env bash
name=$1
true; # shellcheck disable=SC2086
echo $name
FIXTURE
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE="
  _assert "a trailing-comment directive does not quiet a finding" "$rc" 1 "$out" "SC2086"
  rm -rf "$d"

  # R12e -- an invalid UTF-8 byte before a finding: the scan copy is made
  # byte for byte, so the finding after it still counts.
  d="$(_fixture_repo)"
  {
    printf '#!/usr/bin/env bash\n# caf\351\n'
    cat <<'FIXTURE'
name=$1
echo $name
FIXTURE
  } >"$d/bytes.sh"
  _commit "$d"
  # A UTF-8 locale is where BSD sed stopped at the byte, so the row pins
  # one: under C the byte never mattered.
  _run "$d" "LC_ALL=en_US.UTF-8" "EXCLUSIONS_OVERRIDE="
  _assert "a finding after an invalid UTF-8 byte still counts" "$rc" 1 "$out" "SC2086"
  rm -rf "$d"

  # R12f -- a tracked path beginning with `-` is scanned, not read as an
  # option by sed.
  d="$(_fixture_repo)"
  cat >"$d/-dash.sh" <<'FIXTURE'
#!/usr/bin/env bash
name=$1
echo $name
FIXTURE
  _commit "$d"
  _run "$d" "EXCLUSIONS_OVERRIDE="
  _assert "a path beginning with a dash is scanned" "$rc" 1 "$out" "SC2086"
  rm -rf "$d"

  # R12g -- the scan copy's writer failing is refused, never scanned as an
  # empty (clean) file: a stub sed fails the neutraliser's call only.
  d="$(_fixture_repo)"
  stubdir="$(mktemp -d)"
  cat >"$d/clean7.sh" <<'FIXTURE'
#!/usr/bin/env bash
printf '%s\n' "hello"
FIXTURE
  _commit "$d"
  cat >"$stubdir/sed" <<STUB
#!/usr/bin/env bash
case "\$*" in
  *neutralised-shellcheck*) exit 4 ;;
esac
exec $(command -v sed) "\$@"
STUB
  chmod +x "$stubdir/sed"
  _run "$d" "PATH=$stubdir:$PATH" "EXCLUSIONS_OVERRIDE="
  _assert "a failure writing the scan copy is refused" "$rc" 1 "$out" "could not write the scan copy"
  rm -rf "$d" "$stubdir"

  # R12h -- an interrupt during a scan leaves no scan copy behind. A stub
  # shellcheck marks that the scan has reached it, then blocks; once the
  # marker exists, the whole process group gets SIGINT, as a terminal's ^C
  # sends it, and then no copy may remain in the fixture. The harness polls
  # for the marker or the gate's exit under bounded waits, names a wait
  # that expires with the gate's stderr, and kills the gate's group however
  # it ends.
  d="$(_fixture_repo)"
  stubdir="$(mktemp -d)"
  cat >"$d/slow.sh" <<'FIXTURE'
#!/usr/bin/env bash
printf '%s\n' "hello"
FIXTURE
  _commit "$d"
  cat >"$stubdir/shellcheck" <<STUB
#!/usr/bin/env bash
case "\$1" in
  --version) exec $(command -v shellcheck) --version ;;
esac
: > "$stubdir/scanning"
exec sleep 600
STUB
  chmod +x "$stubdir/shellcheck"
  out="$(python3 - "$d" "$me" "$stubdir" "$_SELFTEST_SENTINEL" <<'PY'
import glob, os, signal, subprocess, sys, time
d, me, stub, sentinel = sys.argv[1:5]
env = dict(os.environ, _CHECK_SHELLCHECK_SELFTEST_CHILD=sentinel,
           PATH=stub + os.pathsep + os.environ["PATH"], EXCLUSIONS_OVERRIDE="")
# A shell started with SIGINT ignored (a background job) cannot trap it,
# so then, and only then, the child gets the default disposition, as a
# terminal's job would. preexec_fn runs Python in the forked child, which
# can deadlock, so the ordinary path does without it.
extra = {}
if signal.getsignal(signal.SIGINT) == signal.SIG_IGN:
    extra["preexec_fn"] = lambda: signal.signal(signal.SIGINT, signal.SIG_DFL)
pattern = os.path.join(d, ".check-shellcheck.neutral.*")
marker = os.path.join(stub, "scanning")
errpath = os.path.join(stub, "gate.err")
with open(errpath, "wb") as err:
    p = subprocess.Popen(["bash", me], cwd=d, env=env, start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=err, **extra)

def stderr_tail():
    with open(errpath, "rb") as f:
        return f.read()[-400:].decode("utf-8", "replace").replace("\n", " | ")

def abort(what):
    print("%s; stderr: %s" % (what, stderr_tail()))
    sys.exit(0)

try:
    deadline = time.monotonic() + 120
    while not os.path.exists(marker) and p.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    if not os.path.exists(marker):
        if p.poll() is not None:
            abort("gate-exited-before-scan rc=%d" % p.returncode)
        abort("scan-never-reached-stub within 120s")
    if p.poll() is not None:
        abort("gate-exited-after-marker rc=%d" % p.returncode)
    copies = glob.glob(pattern)
    os.killpg(p.pid, signal.SIGINT)
    try:
        p.wait(timeout=60)
    except subprocess.TimeoutExpired:
        abort("gate-ignored-sigint for 60s")
    # Only the INT trap's own exit (130) counts: the stub sleeps far longer
    # than the wait, so an ignored interrupt can never end the scan in time.
    print("result copy-at-interrupt=%s gate-rc=%d copies-left=%d"
          % ("yes" if copies else "no", p.returncode, len(glob.glob(pattern))))
finally:
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except OSError:
        pass
    p.wait()
PY
)" && rc=0 || rc=$?
  _assert "an interrupt during a scan leaves no scan copy" "$rc" 0 "$out" "result copy-at-interrupt=yes gate-rc=130 copies-left=0"
  rm -rf "$d" "$stubdir"

  # Exercise the explicit supplemental file through the real CLI and scanner.
  _run_extra() {
    if out="$(cd "$d" && env "_CHECK_SHELLCHECK_SELFTEST_CHILD=$_SELFTEST_SENTINEL" \
      "EXCLUSIONS_OVERRIDE=$1" bash "$me" --extra-exclusions "$2" 2>&1)"; then
      rc=0
    else
      rc=$?
    fi
  }

  d="$(_fixture_repo)"
  cat >"$d/extra.sh" <<'FIXTURE'
#!/usr/bin/env bash
set -euo pipefail
name=$1
echo $name
FIXTURE
  printf '%s\n' '# exact findings' 'extra.sh|SC2086:1|' >"$d/allowlist.txt"
  _commit "$d"
  _run_extra "" allowlist.txt
  _assert "tracked supplemental table covers its one finding" "$rc" 0 "$out"
  _run_extra "extra.sh|SC2086:1|" allowlist.txt
  _assert "duplicate across the two tables is refused" "$rc" 1 "$out" "more than once"
  _run_extra "" missing.txt
  _assert "missing supplemental table is refused" "$rc" 2 "$out" "regular tracked file"
  cp "$d/allowlist.txt" "$d/untracked.txt"
  _run_extra "" untracked.txt
  _assert "untracked supplemental table is refused" "$rc" 2 "$out" "regular tracked file"
  printf '%s\n' '# no active rows' >"$d/allowlist.txt"
  _run_extra "" allowlist.txt
  _assert "empty supplemental table is refused" "$rc" 2 "$out" "empty supplemental table"
  printf '%s\n' 'extra.sh|SC2086:0|' >"$d/allowlist.txt"
  _run_extra "" allowlist.txt
  _assert "malformed supplemental row is refused" "$rc" 2 "$out" "malformed row"
  printf '%s\n' 'extra.sh|SC2086:1|' >"$d/allowlist.txt"
  cat >"$d/extra.sh" <<'FIXTURE'
#!/usr/bin/env bash
echo "$1"
FIXTURE
  _run_extra "" allowlist.txt
  _assert "stale supplemental count is refused" "$rc" 1 "$out" "STALE"
  rm -rf "$d"

  echo "check-shellcheck self-test: $((cases - fails))/$cases passed"
  [ "$fails" -eq 0 ] || exit 1
  exit 0
fi

_discover .
if [ "${#FOUND[@]}" -eq 0 ]; then
  echo "check-shellcheck: the discovery loop found ZERO tracked shell scripts — refusing rather than reporting a vacuous pass over nothing. Either this tree genuinely has none (update this message) or the discovery loop broke." >&2
  exit 2
fi

if ! _validate_table; then
  exit 1
fi

_failed=0
_covered=0
for _f in "${FOUND[@]}"; do
  if _lookup_exclusion "$_f" >/dev/null; then
    _covered=$((_covered + 1))
  fi
  if ! _check_one "$_f"; then
    _failed=1
  fi
done

if [ "$_failed" -ne 0 ]; then
  echo "check-shellcheck: FAILED — see the findings above." >&2
  exit 1
fi
echo "check-shellcheck: ok, ${#FOUND[@]} tracked shell script(s) (${_covered} with a standing exclusion-table entry), zero uncovered findings at severity >= $SEVERITY"
