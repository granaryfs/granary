#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# The server logging floor, in machine form: **every log line the granary
# server writes from a runtime worker goes through `tracing`, and only
# the two files listed in ALLOWED_STDERR may touch a real
# standard-stream handle.**
#
# WHY THIS IS A GATE AND NOT A COMMENT. `sink.rs` exists because a
# synchronous write to a backpressured stderr blocks the thread doing it;
# blocked workers do not park on the runtime's I/O-and-time driver, and with
# enough of them stranded the drain deadline never fires and the process is
# unkillable short of SIGKILL. A peer that can provoke a log line can fill
# the pipe remotely. So ONE `eprintln!` added to a request path is not an
# untidy log line, it is the shutdown wedge — and it is invisible to every
# other lane in this repo: it compiles, it lints clean, and the suite that
# would catch it does not exist because a test cannot see a write that only
# blocks when someone else's pipe is full.
#
# WHY IT IS NOT A `#[test]`. This is fixed as a source scan
# rather than a unit row, and the reason survives inspection: the property
# is about the WHOLE crate's source, including files a test binary does not
# link (`main.rs` is a separate target), and about files that do not exist
# yet.
#
# WHY THE NEEDLE SET IS WHAT IT IS, each entry with the reason it is there
# rather than a family swept in for symmetry:
#
#   eprintln! eprint!   the original pair: a formatted synchronous write on
#                       the process's real stderr.
#   dbg!                the SAME write, and the one a person types while
#                       debugging rather than while logging. It locks
#                       `std::io::stderr()` and writes synchronously, so it
#                       wedges identically — and unlike the other four it is
#                       caught by NOTHING else here: `clippy::dbg_macro` is
#                       a `restriction` lint, allow-by-default, and this
#                       workspace enables `pedantic` only (root Cargo.toml,
#                       `[workspace.lints.clippy]`). It compiles clean, it
#                       lints clean, and it survives review as scaffolding.
#   println! print!     STDOUT, and stdout belongs in a stderr gate for a
#                       reason that is mechanical rather than tidy: under
#                       every supervisor this server actually runs beneath —
#                       `2>&1`, journald, a docker log driver — fd 1 and fd 2
#                       are THE SAME PIPE. A `println!` on a request path is
#                       therefore a direct synchronous write to the very
#                       destination the lossy sink exists to keep workers off,
#                       bypassing the bounded queue. Even when they are two
#                       pipes, a blocked `write(2)` strands a worker the same
#                       way; the fd number is not part of the mechanism. The
#                       crate uses stdout NOWHERE today (`git grep -F stdout
#                       -- crates/granary-server/src` is empty, and main.rs
#                       says the readiness line the process tests read is on
#                       stderr), so this costs no allowlist.
#
# DELIBERATELY NOT NEEDLES, so the omissions are decisions rather than
# oversights:
#
#   panic! unreachable! assert! todo!
#                       these do reach stderr, through the panic HOOK. They
#                       are governed by a different and stronger rule (the
#                       rule forbidding panics on untrusted input, and
#                       `unwrap_used`/`expect_used`/`indexing_slicing` at
#                       deny), the write is one-shot rather than per-request,
#                       and putting them here would need an allowlist for
#                       every legitimate `unreachable!` in the crate — which
#                       is how a gate becomes a thing people edit rather than
#                       obey.
#   write!/writeln!     they need a HANDLE, and check 2 is the check that
#                       owns handles. Naming the macro as well would fire on
#                       every `write!` into a `String`.
#
# WHAT IT WILL NOT CATCH, said out loud rather than left to be discovered: a
# write reached through a handle this scan does not name — a `File` opened on
# `/dev/stderr`, a raw `write(2)` on fd 2, a dependency writing on its own
# account. The needles above are the shapes a person actually types.
#
# WHAT IT MUST NOT MISTAKE FOR CODE: three simpler forms of check 3 each
# read green on a mutated file. Passing both needles to one `git grep` and
# counting matching LINES lets `"served"` alone satisfy the count once
# `grain_request` is renamed out of the file. Asserting each needle
# separately over the production half still counts a `grain_request` in a
# DOC COMMENT above the test module — a doc comment sits above the test
# module like any other line — so renaming the production
# `info_span!("grain_request"` to `"MUTATED"` would still print ok.
# Dropping LEADING-comment lines and pairing the two needles by LINE
# DISTANCE still reads a needle in a TRAILING comment
# (`let x = 1; // served`) as code, while "within 24 lines of each other"
# lets any `info_span!` in the file be paired with any string containing
# `grain_request`, which is not the conjunction the check claims to be
# making.
#
# SO CHECKS 1-2 AND CHECK 3 READ THE FILE DIFFERENTLY, ON PURPOSE.
# Checks 1 and 2 assert an ABSENCE and stay line-oriented and fail-CLOSED:
# their filter drops a line whose first non-blank characters are `//` or
# `/*` and NOTHING ELSE (see `non_comment_hits`), so a mention in a trailing
# comment raises a false alarm — the safe direction, fixed by deleting the
# mention. Check 3 asserts a PRESENCE, where every scanner confusion has to
# fail towards "not found" instead, so it runs a character scanner that
# tracks string literals and drops `//` and `/*` wherever they start on a
# code line. That scanner is NOT shared with checks 1 and 2 and must not be:
# `*handle = std::io::stderr();` is the measured case where widening the
# checks-1-and-2 filter took them fail-OPEN.
set -euo pipefail

# ARGUMENT VALIDATION. An argv that is not exactly
# `--self-test` must not fall through to the real gate and
# exit 0 — if it did, `check-server-log-path.sh self-test`
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
  echo "server-log-path: unrecognised argument(s): $* — the only accepted form is '--self-test' (or no argument, to run the gate). Refused rather than silently running the gate and reporting green." >&2
  exit 2
fi

cd "$(dirname "$0")/.."

SRC='crates/granary-server/src'
ADAPTER="$SRC/adapter.rs"

# The three files this gate reads by name. Check 0 proves `git grep` can
# still see all three before any verdict is taken: a moved crate, a renamed
# file or a pathspec that stopped matching otherwise reads as a clean tree.
REQUIRED_SOURCES=(
  "$ADAPTER"
  "$SRC/main.rs"
  "$SRC/sink.rs"
)

# The ONLY two files permitted to hold a real standard-stream handle, each
# with the reason it is permitted. A file is named here or it fails — this
# is not an occurrence COUNT, because a count is satisfied by a new write
# appearing in an old file, which is precisely the regression that matters
# most. The list is named for stderr because stderr is what both files
# actually hold; it governs `io::stdout` too, and neither file has one.
#
#   sink.rs   the lossy sink itself. Its writer thread is the one place in
#             the process that may block on stderr, and it is a plain
#             `std::thread` outside the runtime for exactly that reason.
#   main.rs   `startup_failure` only. It writes DIRECTLY and deliberately
#             (see its own doc comment): every startup failure exits the
#             same EXIT_STARTUP_FAILED, so the reason string is the only
#             discriminator an operator has, and `std::process::exit` kills
#             the sink's queued line with the process. Bounded on a helper
#             thread so a wedged stderr cannot hang a server that never
#             served. Shutdown observability is the exit CODE;
#             this diagnostic reports a startup failure.
#   serve.rs  `write_wire_snapshot`, on the SAME `startup_failure`
#             reasoning at the OTHER end of the process: it runs strictly
#             AFTER `runtime.block_on` returns — every worker is idle, so
#             the backpressure rule keeping ordinary request logging off
#             the direct stderr path does not apply here — and strictly
#             BEFORE `std::process::exit`, which kills the sink's queued
#             line with the process exactly as it does at startup. A
#             refused wire-snapshot write does not change the exit code
#             (the drain itself succeeded, which is what `EXIT_DRAINED`
#             records), so this line is the only place the reason is
#             visible at all.
#
#             It is now HELPER-THREAD-BOUNDED, the
#             same `STARTUP_REPORT_BOUND` shape `main.rs`'s own write
#             uses, and for the same reason rather than a copied
#             mechanism. Sitting "behind an operator-supplied path that
#             must already exist as a directory" does not make the write
#             safe unbounded: a PRE-EXISTING SNAPSHOT DESTINATION is
#             exactly the input that reaches this line at all (`write_
#             server_snapshot` refuses `AlreadyExists`), and that is an
#             ordinary operator mistake, not a privileged one; nothing
#             about "operator-supplied" bounds how full stderr's pipe
#             is when the write happens. Unbounded, a wedged stderr here
#             does not just lose the diagnostic — it blocks the thread
#             that was about to call `std::process::exit`, so a drain
#             that earned `EXIT_DRAINED` would hang instead of exiting.
#             Bounded, the wedged case still costs only the bound before
#             falling through to the same exit.
ALLOWED_STDERR=(
  "$SRC/sink.rs"
  "$SRC/main.rs"
  "$SRC/serve.rs"
)

# How many lines one `tracing::` macro CALL may span and still be scanned
# for its own literal. This is a bound on the argument-list scan, not a
# proximity rule: the literal has to sit inside the call's own parentheses
# (see `paired_in_production`), and this only says how far the scanner
# chases a closing paren before giving up and calling the pair absent —
# which is the fail-CLOSED direction. A `rustfmt`-broken macro puts the
# opening `macro!(` on one line and the arguments under it; the shipped
# `served` event spans 8 lines and the slack is for fields added to it
# later.
MACRO_ARG_WINDOW=24

# ---------------------------------------------------------------------------
# --self-test: a CI gate must prove that it can detect a missing scan boundary.
#
# Before changing adapter.rs's production/test boundary, establish a control
# that makes this gate refuse when the boundary is absent.
# Moving tests out of line changes `mod tests {` to `mod tests;`;
# the production scan and its awk twin must recognise the accepted boundary.
# Control S3 proves refusal when neither accepted spelling is present.
#
# WHY IT NEEDS NO HOOK IN THE PRODUCTION PATH: this script's first act is
# `cd "$(dirname "$0")/.."`, so a COPY of it inside a fixture's scripts/
# directory runs against that fixture's root. The fixture is a real git repo
# because `scan` is `git grep`, and a non-repo exits 2 — a refusal, which
# would prove nothing about the checks.
#
# The WHOLE crate src/ is copied, not the three named files: a three-file
# fixture failed its own BASELINE (rc 2), because ALLOWED_STDERR requires its
# files to actually CONTAIN a writer. A fixture red for its own reasons makes
# every control vacuous — so the baseline is asserted first, and again at the
# end so a control that failed to restore cannot read as a passing suite.
if [ "${1:-}" = "--self-test" ]; then
  st_tmp="$(mktemp -d)"; trap 'rm -rf "$st_tmp"' EXIT
  mkdir -p "$st_tmp/scripts" "$st_tmp/crates/granary-server"
  cp "$0" "$st_tmp/scripts/"
  cp -R "$SRC" "$st_tmp/crates/granary-server/"
  ( cd "$st_tmp" \
    && git init -q . \
    && git add -A \
    && git -c user.email=self-test@invalid -c user.name=self-test commit -qm fixture )
  st_gate="$st_tmp/scripts/$(basename "$0")"
  st_adapter="$st_tmp/$ADAPTER"
  cp "$st_adapter" "$st_tmp/adapter.pristine"

  # Literal, first-occurrence replacement. `index`/`substr` rather than
  # `sub()`: the needle is `mod tests {` and `{` is a regex metacharacter.
  st_replace_first() {
    awk -v old="$2" -v new="$3" '
      !d { p = index($0, old)
           if (p > 0) { $0 = substr($0, 1, p - 1) new substr($0, p + length(old)); d = 1 } }
      { print }
    ' "$1" > "$1.st" && mv "$1.st" "$1"
  }
  st_run() { "$st_gate" > "$st_tmp/out" 2>&1; echo $?; }
  st_restore() { cp "$st_tmp/adapter.pristine" "$st_adapter"; }
  st_expect() {   # id want-rc message-fragment description
    st_got="$(st_run)"
    if [ "$st_got" != "$2" ]; then
      echo "server-log-path self-test FAILED: control $1 ($4) exited $st_got, want $2" >&2
      sed -n '1,40p' "$st_tmp/out" >&2; exit 2
    fi
    if ! grep -qF "$3" "$st_tmp/out"; then
      echo "server-log-path self-test FAILED: control $1 exited $2 but never said \"$3\" — it may be failing for the wrong reason" >&2
      sed -n '1,40p' "$st_tmp/out" >&2; exit 2
    fi
    echo "self-test: $1 — $4 -> rc=$st_got, and it named its own reason"
  }

  st_base="$(st_run)"
  if [ "$st_base" != 0 ]; then
    echo "server-log-path self-test FAILED: the UNMUTATED fixture is not clean (rc $st_base); every control below would be vacuous" >&2
    sed -n '1,40p' "$st_tmp/out" >&2; exit 2
  fi
  echo "self-test: baseline — the unmutated fixture passes (rc=0)"

  # S0: a named source stops being visible. Refuse, never read as clean.
  mv "$st_tmp/$SRC/sink.rs" "$st_tmp/sink.away"
  st_expect S0 2 "THE GATE IS BLIND" "a required source is invisible to git grep"
  mv "$st_tmp/sink.away" "$st_tmp/$SRC/sink.rs"

  # S1: a direct standard-stream macro on the server's sources.
  printf '\nfn self_test_planted_macro() { eprintln!("planted"); }\n' >> "$st_adapter"
  st_expect S1 1 "a direct standard-stream macro" "eprintln! in production"
  st_restore

  # S2: a stream handle in a file not on ALLOWED_STDERR.
  printf '\nfn self_test_planted_handle() { let _ = std::io::stderr(); }\n' >> "$st_adapter"
  st_expect S2 1 "a stream handle outside the two files" "io::stderr outside the allow list"
  st_restore

  # WHICH SPELLING IS LIVE? Both controls below build their fixture by
  # MUTATING a copy of the real adapter.rs, so both must start from
  # whichever ceiling that file actually carries.
  # Hardcoding `mod tests {` is invalid when the file uses `mod tests;`:
  # `st_replace_first` can then find nothing and leave the fixture
  # byte-identical to the pristine one.
  # S3 requires a mutation that removes the accepted ceiling, so a clean
  # result from an unchanged fixture cannot test the required refusal.
  # Detect the live spelling before mutation; otherwise a harness failure
  # can be misreported as the gate failing to detect the planted fault.
  if grep -q 'mod tests {' "$st_adapter"; then
    st_live='mod tests {'; st_other='mod tests;'
  elif grep -q 'mod tests;' "$st_adapter"; then
    st_live='mod tests;'; st_other='mod tests {'
  else
    echo "server-log-path self-test BROKEN: the real adapter.rs carries NEITHER ceiling spelling, so the fixture below cannot be built from it — refusing rather than running controls that would mutate nothing" >&2
    exit 2
  fi

  # S3 — REQUIRE REFUSAL WHEN THE PRODUCTION/TEST CEILING IS ABSENT.
  # With NEITHER accepted spelling present, the gate must FAIL CLOSED
  # rather than silently widening its production scan to the whole file.
  # The planted name matches neither `mod tests {` nor `mod tests;`,
  # so this control must report that the gate is blind.
  st_replace_first "$st_adapter" "$st_live" "mod tests_moved_out_of_line {"
  st_expect S3 2 "THE GATE IS BLIND" "neither ceiling spelling is present"
  st_restore

  # S4 — THE OTHER HALF OF S3. S3 alone would stay green if the ceiling
  # widened to NOTHING, because S3 only ever proves the gate CAN go blind.
  #
  # Testing only `$st_other` covers only the spelling the live file does
  # NOT use. With `mod tests;` live, that would test acceptance of the
  # inline `mod tests {` form while leaving acceptance of the out-of-line
  # form to the unlabelled baseline.
  # The out-of-line form needs its own named accepting control:
  # deleting the `mod tests;` fallback from check 3 must not leave the
  # named ceiling controls passing.
  #
  # Assert BOTH spellings, each as its own named control. Whichever is
  # live, one of these two is a no-op mutation against an already-correct
  # fixture and the other is a real one; both must find a ceiling.
  st_replace_first "$st_adapter" "$st_live" "mod tests {"
  st_expect S4a 0 "" "an INLINE \`mod tests {\` ceiling is ACCEPTED, not blind"
  st_restore
  st_replace_first "$st_adapter" "$st_live" "mod tests;"
  st_expect S4b 0 "" "an OUT-OF-LINE \`mod tests;\` ceiling is ACCEPTED, not blind"
  st_restore

  st_end="$(st_run)"
  if [ "$st_end" != 0 ]; then
    echo "server-log-path self-test FAILED: the fixture did not restore to clean (rc $st_end)" >&2
    sed -n '1,40p' "$st_tmp/out" >&2; exit 2
  fi
  echo "self-test: restored to clean — 6 controls (S4a and S4b are GREEN controls: they prove the ceiling ACCEPTS each accepted spelling in turn, which S3 alone cannot — S3 only ever proves the gate CAN go blind)"
  exit 0
fi

# Every git call goes through here, and only exit 0 and 1 are allowed
# through. `|| true` around a `git grep` erases the difference between "no
# match" (the clean case) and "git never ran" (a verdict about nothing), and
# this repo has shipped that fail-open three times. Assigns to a global
# rather than printing, deliberately: called as `hits=$(scan …)` the `exit`
# below would leave only the command substitution's SUBSHELL and the script
# would carry on — the same fail-open in a new costume.
# (The shape is `check-licence-boundary.sh`'s, on purpose.)
scan() {
  local rc=0
  RESULT=$(git grep "$@") || rc=$?
  if [ "$rc" -gt 1 ]; then
    echo "THE SERVER LOG-PATH GATE COULD NOT RUN — it verified NOTHING." >&2
    echo "  \`git grep $*\` exited $rc. 1 means 'no match'; anything above" >&2
    echo "  it is a git failure (not a repository, an unreadable index, a" >&2
    echo "  'dubious ownership' refusal on a shared runner)." >&2
    exit 2
  fi
  # rc 1 is "no match", whose output is empty anyway; said out loud so the
  # caller never reads a stale $RESULT from an earlier scan.
  [ "$rc" -eq 0 ] || RESULT=""
}

# `$RESULT` reduced to the hits that are CODE. Assigns to globals for
# `scan`'s reason: inside a command substitution an `exit` would leave only
# the subshell.
#
# USED BY CHECKS 1 AND 2 ONLY. Check 3 does not call this and must not:
# see the "SO CHECKS 1-2 AND CHECK 3 READ THE FILE DIFFERENTLY" note in
# the header. Every change here is a change to the two SHUTDOWN-WEDGE
# checks, where a filter that drops too much is a fail-open.
#
# Two filters, and the first closes the prose-satisfies-the-gate fail-open:
# check 2's positive control, run unfiltered, would be met by a comment
# naming `std::io::stderr` once the real handle is gone (see check 2 below).
#
#   - a line whose first non-blank characters are `//` or `/*` is DROPPED.
#     Prose that names the code is not the code, and a gate a doc comment
#     can satisfy is checking the documentation.
#
#     `//` and `/*` ONLY — deliberately NOT `*`, which would also match a
#     block comment's continuation lines. No Rust statement begins `//` or
#     `/*`, and several begin `*`: `*request.method_mut() = …` is in this
#     very file, and `*handle = std::io::stderr()` is the shape that would
#     then walk past checks 1 and 2. Those two are the shutdown-wedge
#     checks and must not be weakened to tidy up check 3. Deliberately NOT
#     a trailing-comment filter either, for the same reason and measured
#     the same way: dropping everything after a `//` on a code line would
#     drop the code before it whenever the `//` is inside a STRING, and
#     these two checks would rather raise a false alarm than miss a write.
#     The cost is that the CONTINUATION lines of a `/* … */` block, and any
#     needle sitting in a trailing comment or a string literal, read as
#     code — which fails checks 1 and 2 CLOSED (a false alarm, fixed by
#     deleting the mention). House style here is `//`; rustfmt writes `//`.
#   - `$1`, when non-empty, is the `mod tests {` line number: a hit at or
#     below it is test code, and checks 1-3 are about the shipped half.
#
# Sets HITS (the surviving `path:line:content` lines) and HIT_LINES (their
# numbers alone, space-separated).
non_comment_hits() {
  local ceiling="$1"
  local hit rest line content
  HITS=""
  HIT_LINES=""
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    rest="${hit#*:}"
    line="${rest%%:*}"
    content="${rest#*:}"
    case "$line" in ''|*[!0-9]*) continue ;; esac
    if [ -n "$ceiling" ] && [ "$line" -ge "$ceiling" ]; then
      continue
    fi
    if [[ "$content" =~ ^[[:space:]]*(//|/\*) ]]; then
      continue
    fi
    HITS="$HITS$hit"$'\n'
    HIT_LINES="$HIT_LINES $line"
  done <<< "$RESULT"
}

# ---- 0. the files this gate reads are where it looks for them ------------
# THE BLIND-DETECTOR FOR CHECK 1, which cannot have one of its own: check 1
# asserts an ABSENCE, so "no eprintln! in the server" and "no server" print
# the same line. Check 2's positive control would also trip on a broken
# pathspec — but only because it happens to run afterwards, and a
# reordering would take that cover away with nothing saying so.
#
# Every source file in this repo must carry an SPDX header (gated
# separately), so a scan for it that does not see all three named files is
# a broken query rather than a clean tree.
echo "-- 0. the three files this gate names are visible to git grep"
scan -n --untracked -F -e 'SPDX-License-Identifier' -- "$SRC"
for required in "${REQUIRED_SOURCES[@]}"; do
  case "$RESULT" in
    *"$required:"*) ;;
    *)
      echo "   THE GATE IS BLIND — it verified NOTHING." >&2
      echo "   $required did not turn up in a scan of every SPDX header" >&2
      echo "   under $SRC. The crate moved, the file was renamed, or the" >&2
      echo "   pathspec stopped matching. Do NOT read the checks below as" >&2
      echo "   a clean tree — fix the paths first." >&2
      exit 2
      ;;
  esac
done
echo "   ok: ${#REQUIRED_SOURCES[@]} named files present"

# ---- 1. no direct standard-stream macro anywhere in the crate ------------
# No allowlist and no exceptions. Nothing in this crate has ever needed one,
# `startup_failure` included — it holds a handle explicitly so the write can
# be put on a thread the process may walk away from, which `eprintln!`
# cannot do. The needle set and its two deliberate omissions are argued in
# the header; read that before adding or removing one.
#
# `eprint!` is a substring of nothing here but contains `print!`, so the
# `print!` needle would find it anyway. Both are listed because a gate that
# relies on substring luck is a gate whose next edit breaks it silently.
#
# Comment lines are dropped here too, and that is the SAFE direction: a
# commented-out `eprintln!` executes nothing, while a doc comment naming the
# macro would otherwise fail a clean tree. The absence this asserts is about
# code.
echo "-- 1. no eprintln!/eprint!/println!/print!/dbg! in $SRC"
scan -n --untracked -F \
  -e 'eprintln!' -e 'eprint!' -e 'println!' -e 'print!' -e 'dbg!' -- "$SRC"
non_comment_hits ""
if [ -n "$HITS" ]; then
  echo "   FAIL: a direct standard-stream macro in the server's sources:" >&2
  printf '%s' "$HITS" >&2
  echo "   Use \`tracing::\`. One of these on a request path is the" >&2
  echo "   shutdown wedge sink.rs exists to prevent, not a log line —" >&2
  echo "   stdout included: under 2>&1, journald and every container log" >&2
  echo "   driver, fd 1 and fd 2 are the same pipe." >&2
  exit 1
fi
echo "   ok: none"

# ---- 2. a real stream handle only in the two named files -----------------
# `io::stdout` is named alongside `io::stderr` for check 1's reason: the
# handle is the thing a `write!` needs, and a stdout handle on a request
# path wedges a worker exactly as a stderr one does. The crate holds none
# today, so this adds no allowlist entry.
echo "-- 2. io::stderr/io::stdout only in the allowed files"
scan -n --untracked -F -e 'io::stderr' -e 'io::stdout' -- "$SRC"
non_comment_hits ""
stderr_hits="$HITS"

# POSITIVE CONTROL, and it runs BEFORE the verdict. Both allowed files hold
# a known `std::io::stderr()` today; a scan that did not find them did not
# find a clean tree, it found a broken query — a moved crate, a renamed
# file, a pathspec that stopped matching, a changed spelling. Without this,
# "scanned nothing" and "found nothing wrong" print the same line, which is
# how a source scan in this repo has failed open twice.
#
# It runs on the COMMENT-FILTERED hits, and that is not tidiness:
# `main.rs:61` names `std::io::stderr` in a comment about the sink, so an
# unfiltered control is satisfied by prose the moment `startup_failure`'s
# real handle is refactored away — the same fail-open check 3 shipped.
#
# If a permitted write is legitimately REMOVED, this fails and the removal
# updates ALLOWED_STDERR in the same commit. That is the intended cost: the
# allowlist is the gate's, never the caller's.
for allowed in "${ALLOWED_STDERR[@]}"; do
  case "$stderr_hits" in
    *"$allowed:"*) ;;
    *)
      echo "   THE GATE IS BLIND — it verified NOTHING." >&2
      echo "   $allowed holds a known io::stderr writer and the scan did" >&2
      echo "   not see it in CODE (comments do not count). Either the file" >&2
      echo "   moved (fix the pathspec and ALLOWED_STDERR) or the writer is" >&2
      echo "   gone (drop it from ALLOWED_STDERR). Do NOT read this as a" >&2
      echo "   clean tree." >&2
      exit 2
      ;;
  esac
done

unclassified=""
while IFS= read -r hit; do
  [ -n "$hit" ] || continue
  file="${hit%%:*}"
  ok=no
  for allowed in "${ALLOWED_STDERR[@]}"; do
    [ "$file" = "$allowed" ] && { ok=yes; break; }
  done
  [ "$ok" = yes ] || unclassified="$unclassified
$hit"
done <<< "$stderr_hits"
if [ -n "$unclassified" ]; then
  echo "   FAIL: a stream handle outside the two files that may hold one:" >&2
  printf '%s\n' "$unclassified" >&2
  echo "   Log through \`tracing::\` instead. If a new file genuinely needs" >&2
  echo "   the real handle, it needs sink.rs's argument made again for it," >&2
  echo "   written down, and a line in ALLOWED_STDERR." >&2
  exit 1
fi
echo "   ok: ${#ALLOWED_STDERR[@]} allowed files, 0 elsewhere"

# ---- 3. the adapter's request span and served counter are present --------
# The other half of the row, and the reason the name is "no NEW stderr write
# BYPASSES tracing" rather than "no stderr write exists": a crate with no
# `eprintln!` and no instrumentation at all passes checks 1 and 2 perfectly.
# This asserts the thing the writes are supposed to be going through.
#
# Read the fail-open history in this file's header before touching the
# needles. They are macro-CALL forms on purpose — an identifier is a thing
# prose says, a `macro!(` with its literal is a thing only code does.
echo "-- 3. the request span and served counter exist"

# Check the production/test split before narrowing the scan:
# without a recognised marker, a scan can silently include the whole file
# and allow test-only instrumentation to satisfy a production requirement.
# Accept TWO ceiling spellings: `mod tests {` and `mod tests;`.
# An out-of-line test module uses `#[cfg(test)]` followed by `mod tests;`,
# so a gate that accepts only the inline spelling cannot find its boundary.
# S3 removes both accepted spellings and requires a BLIND refusal;
# S4a and S4b separately require acceptance of the inline and out-of-line forms.
# Establish these controls before changing the boundary the gate recognises.
# Both spellings mark the SAME production/test boundary, so accept either
# and stay blind only when NEITHER is present. Use two fixed-string scans:
# `scan` deliberately passes `-F` to `git grep`, avoiding dependence on
# alternation behaviour that differs between grep implementations.
scan -n --untracked -F -e 'mod tests {' -- "$ADAPTER"
if [ -z "$RESULT" ]; then
  scan -n --untracked -F -e 'mod tests;' -- "$ADAPTER"
fi
# `path:line:content` — the line number is the SECOND field, so the path
# comes off first and the number comes off what is left.
tests_at="${RESULT%%$'\n'*}"
tests_at="${tests_at#*:}"
tests_at="${tests_at%%:*}"
case "$tests_at" in
  ''|*[!0-9]*)
    echo "   THE GATE IS BLIND — it verified NOTHING." >&2
    echo "   adapter.rs has neither a \`mod tests {\` nor a \`mod tests;\`" >&2
    echo "   line, so this check cannot" >&2
    echo "   narrow to production and would be satisfied by test code." >&2
    exit 2
    ;;
esac

# THE ARGUMENT-LIST SCANNER, and why check 3 needs one at all.
#
# The pairing rule this replaces was "a macro line and a literal line
# within N lines of each other", which is not a statement about one call:
# with the real `info_span!("grain_request", …)` deleted, any OTHER
# `info_span!` in the file paired with any line mentioning `grain_request`
# and the check passed. The rule now is the one its own comment always
# claimed: **the literal has to sit inside the macro call's OWN
# parentheses**, found by balancing from the `(` the needle ends with. That
# tolerates `rustfmt` splitting the call across lines — which is why the
# alternative rule, "same line", was rejected: the shipped span puts
# `tracing::info_span!(` on one line and `"grain_request",` on the next, so
# a same-line rule fails the clean tree.
#
# It is a character scanner rather than a line filter because check 3
# asserts a PRESENCE, and the two failure directions are not symmetric
# here: anything that makes the scanner see LESS code makes the check FAIL,
# which is safe. So it:
#
#   - tracks double-quoted strings, marking their characters `S`. A macro
#     needle whose first character is inside a string does NOT open a call
#     (`let s = "tracing::info_span!(";` is data), and a paren inside a
#     string does not change the nesting depth (`format!("bytes {}-{}/*")`
#     is real, at adapter.rs:1614, and its `/*` is not a comment either).
#   - ends a line at the first `//` reached OUTSIDE a string, which is the
#     trailing-comment fix: `let x = 1; // served` contributes no `served`,
#     and neither does `tracing::info!(… "MUTATED" // "served"` — the shape
#     that lets a needle-pairing check pass with the real literal gone.
#   - consumes `'x'` and `'\n'` as character literals so `trim_matches('"')`
#     (`adapter/tests.rs`'s `Fields::record_debug`) does not flip the string state for the rest of the
#     file, and leaves a lone `'` alone so lifetimes stay ordinary code.
#   - tracks `/* … */` as a NESTING block whose body contributes nothing,
#     because a line-oriented filter cannot: a mutation probe put a
#     complete `tracing::info_span!("grain_request", request_id)` on a
#     block comment's CONTINUATION line — which begins with neither `//`
#     nor `/*` — with the real span renamed away, and a line-oriented
#     check printed ok. Nesting rather than "up to the first `*/`" because
#     Rust's block comments nest, so a non-nesting scanner resumes reading
#     comment prose as code at the inner terminator. Rust does not treat a
#     string inside a block comment as a string, and neither does this.
#     Note that this is NOT the line-dropping `non_comment_hits`
#     deliberately omits: that one would weaken an ABSENCE check by
#     dropping lines, this one narrows a PRESENCE check by dropping them,
#     and the same edit is a fail-open in the first place and a
#     fail-close in the second.
#
# Every one of those, wrong, leaves code looking like a comment or a
# string, and check 3 then reports the instrumentation ABSENT. There is no
# arrangement of scanner confusion that turns prose into a passing pair,
# because a pair can only be OPENED at a `c`-masked needle and confusion
# only ever adds `S`.
#
# The scanner also reports where IT thinks `mod tests {` is, and the caller
# refuses to proceed unless that agrees with `git grep`'s answer. That is
# the positive control for the scanner itself: two independent readers of
# the same file agreeing on one line number is what says the character
# scan is aligned with the file rather than desynchronised inside a string.
ARG_SCANNER='
function pair(startline, startcol,   d, m, i, len, ch, mk, buf) {
  d = 1
  buf = ""
  for (m = startline; m <= startline + window + 0 && m < ceiling + 0 && m <= last; m++) {
    i = 1
    if (m == startline) { i = startcol }
    len = length(code[m])
    for (; i <= len; i++) {
      ch = substr(code[m], i, 1)
      mk = substr(mask[m], i, 1)
      if (mk == "c") {
        if (ch == "(") { d = d + 1 }
        else if (ch == ")") {
          d = d - 1
          if (d == 0) { return index(buf, literal) > 0 }
        }
      }
      buf = buf ch
    }
  }
  return 0
}
{
  q = "\047"
  line = $0
  out = ""
  msk = ""
  len = length(line)
  i = 1
  while (i <= len) {
    ch = substr(line, i, 1)
    if (inblock) {
      if (substr(line, i, 2) == "/*") { bdepth = bdepth + 1; i = i + 2; continue }
      if (substr(line, i, 2) == "*/") {
        bdepth = bdepth - 1
        i = i + 2
        if (bdepth <= 0) { inblock = 0; bdepth = 0 }
        continue
      }
      i++
      continue
    }
    if (instr) {
      if (ch == "\\") {
        out = out ch; msk = msk "S"; i++
        if (i <= len) { out = out substr(line, i, 1); msk = msk "S"; i++ }
        continue
      }
      out = out ch; msk = msk "S"
      if (ch == "\"") { instr = 0 }
      i++
      continue
    }
    if (ch == "\"") { instr = 1; out = out ch; msk = msk "S"; i++; continue }
    if (ch == q) {
      w = 1
      if (substr(line, i + 1, 1) == "\\" && substr(line, i + 3, 1) == q) { w = 4 }
      else if (substr(line, i + 1, 1) != q && substr(line, i + 2, 1) == q) { w = 3 }
      out = out substr(line, i, w)
      for (k = 0; k < w; k++) { msk = msk "c" }
      i = i + w
      continue
    }
    if (substr(line, i, 2) == "//") { break }
    if (substr(line, i, 2) == "/*") { inblock = 1; bdepth = 1; i = i + 2; continue }
    out = out ch; msk = msk "c"
    i++
  }
  code[NR] = out
  mask[NR] = msk
  last = NR
}
END {
  if (last == 0) { print "BLIND|0||"; exit 0 }
  mt = 0
  for (n = 1; n <= last; n++) {
    # SAME PRECEDENCE AS THE SHELL SCAN ABOVE, and it has to be: the two
    # readers are cross-checked against each other and a disagreement is
    # reported as blindness. The shell prefers the inline spelling
    # FILE-WIDE and falls back to the out-of-line one only when there are
    # zero hits, so this walk must not stop at whichever spelling comes
    # first by line -- an adapter.rs holding the out-of-line form above a
    # nested inline one would otherwise make the two disagree and refuse a
    # healthy tree. Newly plausible now that out-of-line is the default.
    # (No backticks in this comment: the awk body is not single-quoted
    # here, so a backtick would open a shell command substitution.)
    p = index(code[n], "mod tests {")
    if (p > 0 && substr(mask[n], p, 1) == "c") { mt = n; break }
  }
  if (mt == 0) {
    for (n = 1; n <= last; n++) {
      p = index(code[n], "mod tests;")
      if (p > 0 && substr(mask[n], p, 1) == "c") { mt = n; break }
    }
  }
  macro_at = ""
  literal_at = ""
  paired = 0
  for (n = 1; n < ceiling + 0 && n <= last; n++) {
    if (index(code[n], literal) > 0) { literal_at = literal_at " " n }
    start = 1
    while (1) {
      p = index(substr(code[n], start), macro)
      if (p == 0) { break }
      abs = start + p - 1
      if (substr(mask[n], abs, 1) == "c") {
        macro_at = macro_at " " n
        if (paired == 0 && pair(n, abs + length(macro))) { paired = 1 }
      }
      start = abs + 1
    }
  }
  verdict = "UNPAIRED"
  if (paired) { verdict = "PAIRED" }
  print verdict "|" mt "|" macro_at "|" literal_at
}
'

# Sets PAIRED=yes/no and, when no, MACRO_LINES/LITERAL_LINES for the
# message. Globals again, for `scan`'s reason: an `exit` inside a command
# substitution would leave only the subshell.
paired_in_production() {
  local rc=0 rest
  PAIR_OUT=$(awk -v macro="$1" -v literal="$2" -v ceiling="$tests_at" \
                 -v window="$MACRO_ARG_WINDOW" "$ARG_SCANNER" "$ADAPTER") || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "   THE GATE IS BLIND — it verified NOTHING." >&2
    echo "   awk exited $rc scanning $ADAPTER. That is the scanner failing" >&2
    echo "   to RUN, not adapter.rs failing the check." >&2
    exit 2
  fi
  case "$PAIR_OUT" in
    "PAIRED|"*|"UNPAIRED|"*) ;;
    *)
      echo "   THE GATE IS BLIND — it verified NOTHING." >&2
      echo "   The argument-list scanner printed something this script does" >&2
      echo "   not understand: [$PAIR_OUT]" >&2
      exit 2
      ;;
  esac
  rest="${PAIR_OUT#*|}"
  SCANNER_TESTS_AT="${rest%%|*}"
  rest="${rest#*|}"
  MACRO_LINES="${rest%%|*}"
  LITERAL_LINES="${rest#*|}"
  # The scanner's own positive control: `git grep` and the character scan
  # are two independent readers of adapter.rs, and they have to agree on
  # where the test module starts. They disagree when the scan is
  # desynchronised (an unbalanced quote above line $tests_at) or when the
  # git-grep answer came off a comment line — either way the narrowing
  # below is being done against a line number nobody has confirmed.
  if [ "$SCANNER_TESTS_AT" != "$tests_at" ]; then
    echo "   THE GATE IS BLIND — it verified NOTHING." >&2
    echo "   git grep puts \`mod tests {\` at line $tests_at; the argument" >&2
    echo "   scanner puts it at [$SCANNER_TESTS_AT]. Two readers of the same" >&2
    echo "   file disagree, so the production/test split this check narrows" >&2
    echo "   to is not established. Do NOT read this as a clean tree." >&2
    exit 2
  fi
  if [ "${PAIR_OUT%%|*}" = PAIRED ]; then
    PAIRED=yes
  else
    PAIRED=no
  fi
}

# `needle` `literal` `what` — the whole verdict for one half.
require_pair() {
  paired_in_production "$1" "$2"
  if [ "$PAIRED" != yes ]; then
    echo "   FAIL: adapter.rs's PRODUCTION half no longer carries $3." >&2
    echo "   No \`$1\` on a CODE line above $tests_at whose OWN argument list" >&2
    echo "   — balanced from that \`(\`, across at most $MACRO_ARG_WINDOW lines —" >&2
    echo "   contains \`$2\`. Being NEAR each other is not enough and is no" >&2
    echo "   longer accepted. The per-request span and its \`served\` counter" >&2
    echo "   are what checks 1 and 2 assume the writes go through." >&2
    echo "   \`$1\` opens a call at:[$MACRO_LINES ]" >&2
    echo "   \`$2\` appears on code lines:[$LITERAL_LINES ]" >&2
    exit 1
  fi
}

require_pair 'tracing::info_span!(' '"grain_request"' 'the request SPAN'
require_pair 'tracing::info!(' '"served"' 'the SERVED counter'

echo "   ok: the span opens and the served counter is emitted, both from" \
     "code above line $tests_at"

echo "server log path: ok"
