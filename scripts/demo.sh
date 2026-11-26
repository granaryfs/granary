#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# A smoke demo of a `gran` mount, end to end: publish a small tree, mount
# it read-only with --root-key, read the tree back out through that
# mount, tear the mount down again, and prove to itself that the
# teardown actually happened.
#
# Root, Linux, `/dev/fuse` + CAP_SYS_ADMIN. Takes NO arguments and reads NO
# configuration from the environment (R-E): there is no mountpoint parameter
# and no trust-mode parameter. Every knob a demo grows is a hook --
# `target/` inside the container is itself a FUSE-typed virtiofs bind and
# cannot host a cache directory, which is why the work directory lives under
# /tmp rather than under the repo.
#
# Venue departure, and it is deliberate: `docs/dev-environment.md` says "do
# not containerise the mount you are proving", and this does -- the bare
# podman VM cannot run the stack, because scripts/minio-harness.sh needs
# shasum and CoreOS lacks it. A container hides the host mount-table
# properties, which `linux-container.sh mount` and the systemd unit check
# prove instead; this script proves the smoke mount, read-back and teardown.
#
# Liveness predicate: this script is the daemon's PARENT and does not
# `wait` on it inside the readiness loop, so a daemon that exits immediately
# (a bad key, an unreachable endpoint) becomes an unreaped ZOMBIE for which
# `kill -0` succeeds -- `kill -0` would then poll the whole bound and report
# a generic timeout instead of the daemon's actual error.
# `proc_state`/`daemon_is_dead` below read `/proc/<pid>/stat` field 3,
# count state `Z` as dead, and are the ONE predicate used by both
# the readiness loop and teardown -- two spellings of "is it alive"
# can drift.
set -euo pipefail

die() {
  echo "demo: $*" >&2
  exit 1
}

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
STACK="$REPO_ROOT/scripts/stack.sh"
GRAN="$REPO_ROOT/target/debug/gran"

# ---------------------------------------------------------------------------
# The liveness predicate shared by readiness and teardown.
# ---------------------------------------------------------------------------

# Reads /proc/<pid>/stat field 3. comm (the parenthesized second field) can
# itself contain ')' and spaces, so this strips up to and including the
# LAST ') ' (bash's ##* is greedy) rather than naively splitting on spaces --
# a naive split would misparse a daemon whose argv[0] or comm needed quoting.
# Prints the state character; returns 1 if the pid has no /proc entry at all
# (fully reaped and gone).
proc_state() {
  local pid="$1" raw rest state
  raw="$(cat "/proc/$pid/stat" 2>/dev/null)" || return 1
  [ -n "$raw" ] || return 1
  rest="${raw##*) }"
  state="${rest%% *}"
  [ -n "$state" ] || return 1
  printf '%s\n' "$state"
}

# Dead iff no /proc entry (fully reaped) OR state Z (a zombie: exited but not
# yet reaped by this shell, which is the daemon's own parent and does not
# `wait` inside the readiness loop). `kill -0` succeeds on BOTH a live
# process and an unreaped zombie and so cannot tell them apart; this can.
daemon_is_dead() {
  local pid="$1" state
  if ! state="$(proc_state "$pid")"; then
    return 0
  fi
  [ "$state" = Z ]
}

# ---------------------------------------------------------------------------
# Mount state is read from the MOUNT TABLE, never from a stat:
# a `stat`/`cat`-based probe both misreads (ENOTCONN is not "unmounted")
# and can block on a wedged-but-alive daemon, while a table read
# does not wait for the daemon.
# ---------------------------------------------------------------------------

# Parsed EXACTLY, never by substring or `grep -q`: exit 0, exactly ONE line,
# exactly TWO whitespace-separated fields. A substring test would accept a
# stacked second row at the same target and a source whose name merely
# CONTAINS "gran".
read_mount_row() {
  local path="$1" out rc lines fields
  set +e
  out="$(findmnt -rn -o SOURCE,FSTYPE --mountpoint "$path" 2>/dev/null)"
  rc=$?
  set -e
  [ "$rc" -eq 0 ] || return 1
  [ -n "$out" ] || return 1
  lines="$(printf '%s\n' "$out" | awk 'END{print NR}')"
  [ "$lines" -eq 1 ] || return 1
  fields="$(printf '%s\n' "$out" | awk '{print NF}')"
  [ "$fields" -eq 2 ] || return 1
  printf '%s\n' "$out"
}

# root with CAP_SYS_ADMIN takes the mount(2) route and this lane enforces
# both, so `fuse.gran` (the unprivileged fusermount3 route) is NOT accepted
# here -- unlike ci-mounts.sh's mount check, whose route is not fixed.
mount_is_ready() {
  local path="$1" row src fst
  row="$(read_mount_row "$path")" || return 1
  src="$(printf '%s\n' "$row" | awk '{print $1}')"
  fst="$(printf '%s\n' "$row" | awk '{print $2}')"
  [ "$src" = gran ] && [ "$fst" = fuse ]
}

# Takes the raw OPTIONS string directly, not a path -- this assertion
# must be callable against a HAND-MADE row
# without a real mount, so a negative (`noexec` present, or
# `default_permissions` absent) can be constructed directly.  Tokens are
# matched WHOLE against a comma split, never by substring: `ro` is a
# substring of `errors=remount-ro` and `exec` of `noexec`.
options_row_passes() {
  local opts="$1" token has_ro=0 has_nosuid=0 has_nodev=0 has_defperm=0 has_noexec=0
  local IFS=,
  # This expansion is deliberately unquoted so the shell splits the field on
  # IFS -- `set -f` first, matching stack.sh's pid_is_alive: without it, a
  # glob character in the options string would be expanded against the
  # current directory instead of parsed as a token.
  set -f
  for token in $opts; do
    case "$token" in
      ro) has_ro=1 ;;
      nosuid) has_nosuid=1 ;;
      nodev) has_nodev=1 ;;
      default_permissions) has_defperm=1 ;;
      noexec) has_noexec=1 ;;
    esac
  done
  set +f
  [ "$has_ro" -eq 1 ] && [ "$has_nosuid" -eq 1 ] && [ "$has_nodev" -eq 1 ] \
    && [ "$has_defperm" -eq 1 ] && [ "$has_noexec" -eq 0 ]
}

# ---------------------------------------------------------------------------
# Bounded checks, exit status diagnosed EXACTLY rather than by a
# two-value rule. 124 timeout; 137 SIGKILL (the FUSE-hang case here -- `-k 5`
# means a task blocked in a killable FUSE wait gets a follow-up SIGKILL --
# but not proof of a timeout on its own); 125 timeout(1) itself failing; 126
# not-executable; 127 not-found; any other 128+n the signal that ended the
# child. Collapsing these hides a demo whose executable was never runnable
# behind a "hung mount" message. Sets BOUNDED_RC; writes combined output to
# $1.
# ---------------------------------------------------------------------------
run_bounded() {
  local out="$1"
  shift
  set +e
  timeout -k 5 30 "$@" >"$out" 2>&1
  BOUNDED_RC=$?
  set -e
  case "$BOUNDED_RC" in
    0) : ;;
    124) echo "demo: bounded check timed out after 30s" >&2 ;;
    137) echo "demo: bounded check killed (SIGKILL) -- hung or killed externally" >&2 ;;
    125) echo "demo: bounded check refused: the timeout(1) invocation itself failed" >&2 ;;
    126) echo "demo: bounded check refused: the command was found but could not be executed" >&2 ;;
    127) echo "demo: bounded check refused: the command was not found" >&2 ;;
    *)
      if [ "$BOUNDED_RC" -ge 128 ]; then
        echo "demo: bounded check was ended by signal $((BOUNDED_RC - 128))" >&2
      fi
      ;;
  esac
}

# ---------------------------------------------------------------------------
# The stack.env contract, verbatim (conformance.sh's validator). Never eval,
# never source: the four values are constrained to a charset carrying no
# shell meaning, which is what lets the caller assign them directly.
# ---------------------------------------------------------------------------
validate_contract() {
  local text_value="$1" line
  local -a lines names
  mapfile -t lines < <(printf '%s\n' "$text_value")
  if [ "${#lines[@]}" -ne 4 ]; then
    printf '%s\n' 'DEMO-CONTRACT: REFUSED line-count'
    return 1
  fi
  for line in "${lines[@]}"; do
    if [[ ! "$line" =~ ^GRAN_(ENDPOINT|PIN|ROOT_KEY|VOLUME)=.+$ ]]; then
      printf '%s\n' 'DEMO-CONTRACT: REFUSED assignment-shape'
      return 1
    fi
    if [[ ! "${line#*=}" =~ ^[][A-Za-z0-9._:/+=@%,-]+$ ]]; then
      printf '%s\n' 'DEMO-CONTRACT: REFUSED value-charset'
      return 1
    fi
    names+=("${line%%=*}")
  done
  local expected got
  expected=$'GRAN_ENDPOINT\nGRAN_PIN\nGRAN_ROOT_KEY\nGRAN_VOLUME'
  got="$(printf '%s\n' "${names[@]}")"
  if [ "$got" != "$expected" ]; then
    printf '%s\n' 'DEMO-CONTRACT: REFUSED name-order'
    return 1
  fi
  printf '%s\n' 'DEMO-CONTRACT: PASS'
}

# ---------------------------------------------------------------------------
# Preflight. The checks run SILENTLY (die()s loudly on stderr on
# failure); nothing is printed here on success -- the work-dir line
# must be the first stdout line, so the witness below it prints only after
# that line, never before.
# ---------------------------------------------------------------------------
preflight() {
  local uid_now capeff capval tool
  [ "$#" -eq 0 ] \
    || die "preflight refused: this script takes no arguments; every knob a demo grows is a hook"
  for tool in awk cat chmod cmp date du find findmnt grep id kill mkdir mktemp mountpoint mv rm sleep stat timeout umount; do
    command -v "$tool" >/dev/null 2>&1 \
      || die "preflight refused: required tool is missing: $tool"
  done
  # sleep must accept a FRACTIONAL argument -- readiness and teardown poll at 0.1s, and this
  # PROBES that rather than assuming it.
  sleep 0.1 \
    || die "preflight refused: sleep does not accept a fractional argument"
  uid_now="$(id -u)"
  [ "$uid_now" -eq 0 ] \
    || die "preflight refused: id -u is $uid_now, not 0"
  [ -c /dev/fuse ] \
    || die "preflight refused: /dev/fuse is not a character device"
  if ! capeff="$(awk '/^CapEff:/ { print $2 }' /proc/self/status)"; then
    die "preflight refused: could not read CapEff from /proc/self/status"
  fi
  case "$capeff" in
    '' | *[!0-9A-Fa-f]*) die "preflight refused: invalid CapEff value: $capeff" ;;
  esac
  capval=$((16#$capeff))
  [ $(((capval >> 21) & 1)) -eq 1 ] \
    || die "preflight refused: CapEff $capeff lacks CAP_SYS_ADMIN (bit 21)"
  # gran/granary-server are NOT re-probed here -- the stack script (below)
  # probes those itself.
  [ -x "$STACK" ] \
    || die "preflight refused: stack driver is not executable: $STACK"
  # Keep a LIVE tripwire for the reason this mount runs inside a container:
  # minio-harness.sh needs shasum, which CoreOS's bare VM lacks, so that VM
  # cannot run the stack directly. Check the dependency in the script,
  # as conformance.sh does; prose alone does not establish it.
  # If minio-harness.sh no longer needs shasum, refuse this run and
  # reassess whether the stack can run on the bare VM before retaining
  # the container venue.
  grep -q 'shasum -a 256' "$REPO_ROOT/scripts/minio-harness.sh" \
    || die "preflight refused: minio-harness.sh no longer needs shasum; reassess whether the stack can run on the bare VM before retaining the container venue"
}

preflight "$@"

# ---------------------------------------------------------------------------
# Work dir. Never under target/ -- inside the container that is a
# FUSE-typed virtiofs bind and cannot host a cache directory.
# ---------------------------------------------------------------------------
W="$(mktemp -d /tmp/demo.XXXXXX)"
printf 'DEMO work dir: %s\n' "$W"
printf 'DEMO-PREFLIGHT: PASS\n'
printf 'DEMO-VENUE-TRIPWIRE: PASS\n'

SRC="$W/src"
STACK_STATE="$W/stack"
CACHE="$W/cache"
MNT="$W/mnt"
DAEMON_LOG="$W/daemon.log"
PID_FILE="$W/daemon.pid"
DAEMON_PID=""

mkdir -p "$SRC" "$STACK_STATE" "$MNT"
mkdir -m 700 "$CACHE"
: >"$DAEMON_LOG"

# ---------------------------------------------------------------------------
# The smoke tree, created here and published by the stack (creation and
# publication apart -- the stack's own contract). RUN_ID is unique per run.
# ---------------------------------------------------------------------------
RUN_ID="$(date +%s%N)-$$"

mkdir -p "$SRC/bin" "$SRC/docs" "$SRC/data"
{
  printf '#!/bin/sh\n'
  printf 'printf '\''DEMO-EXEC %%s %%s\\n'\'' "%s" "$0"\n' "$RUN_ID"
} >"$SRC/bin/hello.sh"
chmod 0755 "$SRC/bin/hello.sh"

printf 'DEMO-NEEDLE %s\n' "$RUN_ID" >"$SRC/docs/needle.txt"
printf 'this is the demo readme; it deliberately says nothing else.\n' \
  >"$SRC/docs/readme.txt"
grep -qF "DEMO-NEEDLE $RUN_ID" "$SRC/docs/readme.txt" \
  && die "internal: readme.txt must not contain the needle"

# 1 MiB, built from bash builtins alone (dd/head/truncate are not in the
# preflight tool list above): printf's width-padding writes exactly
# 1048576 bytes in one call. Content is irrelevant -- this file's only job
# is to supply APPARENT-SIZE bytes for the du check's oracle -- but the byte count
# is asserted with `stat` right after, rather than trusted blind.
printf '%*s' 1048576 '' >"$SRC/data/blob.bin"
blob_size="$(stat -c%s "$SRC/data/blob.bin")"
[ "$blob_size" -eq 1048576 ] \
  || die "internal: data/blob.bin is $blob_size bytes, want 1048576"

# ---------------------------------------------------------------------------
# Teardown. `set +e`, every step reported.
# ---------------------------------------------------------------------------
teardown_on_exit() {
  local failure=0 pid attempts row stack_rc rm_rc
  set +e

  # (1) the daemon, using the SAME liveness predicate the readiness loop
  # used (1ff2997): kill -0 lies about an unreaped zombie, and this shell is
  # the daemon's own parent, so a kill -0 loop would burn its whole bound on
  # a process that is already gone.
  if [ -n "$DAEMON_PID" ]; then
    pid="$DAEMON_PID"
    if ! daemon_is_dead "$pid"; then
      kill -TERM "$pid" 2>/dev/null
      attempts=0
      while ! daemon_is_dead "$pid" && [ "$attempts" -lt 100 ]; do
        sleep 0.1
        attempts=$((attempts + 1))
      done
    fi
    if ! daemon_is_dead "$pid"; then
      kill -KILL "$pid" 2>/dev/null
      attempts=0
      while ! daemon_is_dead "$pid" && [ "$attempts" -lt 50 ]; do
        sleep 0.1
        attempts=$((attempts + 1))
      done
    fi
    if ! daemon_is_dead "$pid"; then
      echo "demo: EXIT teardown: daemon $pid survived SIGTERM and SIGKILL" >&2
      failure=1
    fi
    # This shell is the daemon's own parent; reap it so it does not stay a
    # zombie forever. Its own exit status is not itself scored here -- the
    # row check below is what actually judges the outcome.
    wait "$pid" 2>/dev/null
  fi

  # (2) the row. Never mountpoint -q here -- only the table.
  if row="$(read_mount_row "$MNT" 2>/dev/null)"; then
    echo "DEMO: attempting lazy detach of a surviving mount at $MNT"
    umount -l "$MNT" 2>/dev/null
    if row="$(read_mount_row "$MNT" 2>/dev/null)"; then
      echo "DEMO: FAIL mount survived the EXIT trap at $MNT"
      failure=1
    else
      echo "DEMO: lazily detached a surviving mount at $MNT"
      printf 'DEMO-UNMOUNTED: PASS\n'
    fi
  else
    printf 'DEMO-UNMOUNTED: PASS\n'
  fi

  # (3) the stack.
  "$STACK" stop --state-dir "$STACK_STATE"
  stack_rc=$?
  if [ "$stack_rc" -ne 0 ]; then
    echo "DEMO: FAIL stack stop rc=$stack_rc"
    failure=1
  else
    printf 'DEMO-STACK-STOPPED: PASS\n'
  fi

  # (4) remove the work dir only if no row survived. The removal's own
  # status is checked, not merely run under set +e and ignored -- a failed
  # removal must not still let the final success witness print.
  if [ "$failure" -eq 0 ]; then
    rm -rf -- "$W"
    rm_rc=$?
    if [ "$rm_rc" -ne 0 ]; then
      echo "DEMO: FAIL work dir removal rc=$rm_rc at $W"
      failure=1
    fi
  fi

  return "$failure"
}

# The one and only site that ever prints the final witness. Re-reads
# the table one last time and refuses to print if a row still exists.
emit_final() {
  if read_mount_row "$MNT" >/dev/null 2>&1; then
    echo "demo: refused to print the final witness -- a mount-table row still exists at $MNT" >&2
    return 1
  fi
  printf 'MOUNT-OK\n'
}

# ---------------------------------------------------------------------------
# Arm the EXIT trap BEFORE `stack.sh start` so a failure during startup
# cannot leave MinIO outside the cleanup path. The trap's FIRST statement
# captures $? before `set +e`, before any echo, and before anything else.
# The script's exit status is the body's rc when non-zero,
# else teardown's.
# ---------------------------------------------------------------------------
trap 'rc=$?; teardown_on_exit; s=$?; if [ "$rc" -eq 0 ] && [ "$s" -eq 0 ]; then emit_final; s=$?; fi; trap - EXIT; exit $(( rc != 0 ? rc : s ))' EXIT

# ---------------------------------------------------------------------------
# Start the stack and validate its four-variable output contract.
# ---------------------------------------------------------------------------
stack_contract="$("$STACK" start --source-dir "$SRC" --volume demo --state-dir "$STACK_STATE")"
set +e
contract_verdict="$(validate_contract "$stack_contract")"
contract_rc=$?
set -e
printf '%s\n' "$contract_verdict"
if [ "$contract_verdict" != 'DEMO-CONTRACT: PASS' ] || [ "$contract_rc" -ne 0 ]; then
  die "refused: stack contract was refused"
fi

GRAN_ENDPOINT=""
GRAN_PIN=""
GRAN_ROOT_KEY=""
GRAN_VOLUME=""
mapfile -t CONTRACT_LINES < <(printf '%s\n' "$stack_contract")
GRAN_ENDPOINT="${CONTRACT_LINES[0]#*=}"
GRAN_PIN="${CONTRACT_LINES[1]#*=}"
GRAN_ROOT_KEY="${CONTRACT_LINES[2]#*=}"
GRAN_VOLUME="${CONTRACT_LINES[3]#*=}"
[ -n "$GRAN_ENDPOINT" ] || die "refused: validated GRAN_ENDPOINT evaluated empty"
[ -n "$GRAN_PIN" ] || die "refused: validated GRAN_PIN evaluated empty"
[ -n "$GRAN_ROOT_KEY" ] || die "refused: validated GRAN_ROOT_KEY evaluated empty"
[ "$GRAN_VOLUME" = demo ] \
  || die "refused: validated GRAN_VOLUME is $GRAN_VOLUME, want demo"

# ---------------------------------------------------------------------------
# Mount with --root-key only: the demo has no trust-mode parameter,
# and the unit's own env-file contract relies on the same
# construction.
# ---------------------------------------------------------------------------
if read_mount_row "$MNT" >/dev/null 2>&1; then
  die "refused: the mount table already shows a row at $MNT before launch"
fi

"$GRAN" mount demo "$MNT" \
  --endpoint "$GRAN_ENDPOINT" \
  --pin "$GRAN_PIN" \
  --root-key "$GRAN_ROOT_KEY" \
  --cache-dir "$CACHE" \
  --foreground 2>"$DAEMON_LOG" &
DAEMON_PID=$!
# Write the PID file ATOMICALLY, IMMEDIATELY after spawning and before the
# first probe, so demo-self-check.sh's N1 can stop the demo before readiness.
# `echo $! > f` creates the file before its bytes arrive; an existence-only
# poller can therefore read an empty file.
printf '%s\n' "$DAEMON_PID" >"$PID_FILE.tmp"
mv "$PID_FILE.tmp" "$PID_FILE"

ready=0
attempts=0
while [ "$attempts" -lt 100 ]; do
  # sleep FIRST, then probe -- give demo-self-check.sh's N1 time to stop
  # the demo before its first readiness probe.
  sleep 0.1
  attempts=$((attempts + 1))
  if daemon_is_dead "$DAEMON_PID"; then
    cat "$DAEMON_LOG" >&2
    die "refused: daemon exited before the mount became ready"
  fi
  # mountpoint -q as a CHEAP positive only: never trusted alone, and
  # never used in teardown -- only to skip the exact findmnt parse on most
  # iterations.
  if mountpoint -q "$MNT" 2>/dev/null && mount_is_ready "$MNT"; then
    ready=1
    break
  fi
done
[ "$ready" -eq 1 ] \
  || { cat "$DAEMON_LOG" >&2; die "refused: mount did not become ready within 10s"; }
printf 'DEMO-MOUNTED: gran fuse\n'

# EXACTLY ONE ROW, exactly one field -- the same discipline read_mount_row
# applies to SOURCE,FSTYPE, and it was missing here. `findmnt --mountpoint`
# prints a row per mount STACKED at that target, and options_row_passes then
# scored the token UNION across all of them: a `rw` filesystem mounted over
# this one contributed its own tokens and the required ones still all
# appeared, so the check passed on a mount that was not the one under test.
# (Demonstrated on the shipped function body: a two-row input with a second
# `rw,seclabel` row returns 0.) One mechanism, two call sites, and only one
# of them had the guard.
mount_opts="$(findmnt -rn -o OPTIONS --mountpoint "$MNT" 2>/dev/null)" \
  || die "refused: could not read the mount OPTIONS row at $MNT"
[ -n "$mount_opts" ] \
  || die "refused: the mount OPTIONS row at $MNT is empty"
mount_opts_lines="$(printf '%s\n' "$mount_opts" | awk 'END{print NR}')"
[ "$mount_opts_lines" -eq 1 ] \
  || die "refused: findmnt returned $mount_opts_lines OPTIONS rows at $MNT, want exactly 1 -- a stacked mount at the same target makes the token check score a union across filesystems: $mount_opts"
mount_opts_fields="$(printf '%s\n' "$mount_opts" | awk '{print NF}')"
[ "$mount_opts_fields" -eq 1 ] \
  || die "refused: the OPTIONS row at $MNT has $mount_opts_fields whitespace-separated fields, want exactly 1: $mount_opts"
options_row_passes "$mount_opts" \
  || die "refused: mount options row failed the token check: $mount_opts"
printf 'DEMO-OPTIONS: PASS\n'

# ---------------------------------------------------------------------------
# The three checks, each under `timeout -k 5 30`.
# ---------------------------------------------------------------------------

# 1. du -sh: REPORTED, never compared numerically (synthesised st_blocks
# need not equal the source filesystem's for small files). The ORACLE is
# apparent size: find's byte sum and file count under the mount equal those
# under the source.
run_bounded "$W/du-mnt.out" du -sh "$MNT"
[ "$BOUNDED_RC" -eq 0 ] || die "refused: du -sh \"$MNT\" failed or hung (rc=$BOUNDED_RC)"
[ -s "$W/du-mnt.out" ] || die "refused: du -sh printed no output"
du_lines="$(awk 'END{print NR}' "$W/du-mnt.out")"
[ "$du_lines" -eq 1 ] || die "refused: du -sh printed $du_lines lines, want exactly one"
cat "$W/du-mnt.out"

run_bounded "$W/find-mnt.out" find "$MNT" -type f -printf '%s\n'
[ "$BOUNDED_RC" -eq 0 ] \
  || die "refused: find under the mount failed or hung while computing apparent size (rc=$BOUNDED_RC)"
mnt_stats="$(awk '{n++; s+=$1} END{print s+0, n+0}' "$W/find-mnt.out")"
src_stats="$(find "$SRC" -type f -printf '%s\n' | awk '{n++; s+=$1} END{print s+0, n+0}')"
[ "$mnt_stats" = "$src_stats" ] \
  || die "refused: apparent size mismatch: mnt='$mnt_stats' src='$src_stats'"
mnt_bytes="$(printf '%s\n' "$mnt_stats" | awk '{print $1}')"
mnt_files="$(printf '%s\n' "$mnt_stats" | awk '{print $2}')"
printf 'DEMO du: PASS %s bytes in %s files\n' "$mnt_bytes" "$mnt_files"

# 2. grep -r the needle: exactly one line, equal to the expected path:content.
run_bounded "$W/grep-mnt.out" grep -r "DEMO-NEEDLE $RUN_ID" "$MNT"
[ "$BOUNDED_RC" -eq 0 ] || die "refused: grep for the needle failed or hung (rc=$BOUNDED_RC)"
grep_lines="$(awk 'END{print NR}' "$W/grep-mnt.out")"
[ "$grep_lines" -eq 1 ] || die "refused: grep matched $grep_lines lines, want exactly one"
expected_grep_line="$MNT/docs/needle.txt:DEMO-NEEDLE $RUN_ID"
actual_grep_line="$(cat "$W/grep-mnt.out")"
[ "$actual_grep_line" = "$expected_grep_line" ] \
  || die "refused: grep matched the wrong line: $actual_grep_line"
printf 'DEMO grep: PASS\n'

# 3. a DIRECT exec of hello.sh, never `sh <path>` (which reads instead of
# executing).
run_bounded "$W/exec-mnt.out" "$MNT/bin/hello.sh"
[ "$BOUNDED_RC" -eq 0 ] || die "refused: exec of hello.sh failed or hung (rc=$BOUNDED_RC)"
expected_exec_line="DEMO-EXEC $RUN_ID $MNT/bin/hello.sh"
actual_exec_line="$(cat "$W/exec-mnt.out")"
[ "$actual_exec_line" = "$expected_exec_line" ] \
  || die "refused: exec output mismatch: got '$actual_exec_line' want '$expected_exec_line'"
printf 'DEMO exec: PASS\n'

exit 0
