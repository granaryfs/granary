#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# The demo's negatives.
# Root, Linux; run by the dispatcher (linux-container.sh
# demo) in the same container-root lane, AFTER scripts/demo.sh has
# already run once successfully. Never plants a test-only flag or an
# ephemeral mutated copy of the demo: every case here
# constructs the WORLD around the SHIPPED demo script, so the bytes under
# test are the bytes that ship.
#
#   N1 -- the survivor: a lying `umount` shim first on PATH, the demo frozen
#         and its daemon killed after the pid file appears, so the demo's
#         own EXIT trap discovers a mount that refuses to go away.
#   N2 -- the control that the shim alone does not trip it (no freeze/kill).
#   N3 -- the control that the fallback is a DIFFERENT arm (freeze/kill,
#         no shim): the real `umount -l` self-heals.
#
# Each case is asserted by its own diagnostic string, never by a bare exit
# status. A case whose PHASE assertions do not hold prints "DID NOT TAKE"
# and is scored as a distinct red from the case's own failure -- that is
# what stops a race from being scored as either a pass or a misdiagnosed
# defect.
set -euo pipefail

die() {
  echo "demo-self-check: $*" >&2
  exit 1
}

[ "$#" -eq 0 ] || die "this script takes no arguments"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
DEMO="$REPO_ROOT/scripts/demo.sh"
STACK="$REPO_ROOT/scripts/stack.sh"

[ "$(id -u)" -eq 0 ] || die "must run as root"
[ -x "$DEMO" ] || die "refused: $DEMO is not executable"

# Resolved ONCE, before any PATH is ever shimmed, so cleanup never depends
# on a possibly-poisoned PATH lookup.
REAL_UMOUNT="$(command -v umount)" || die "refused: no umount on PATH"

SC_WORK="$(mktemp -d /tmp/demo-selfcheck.XXXXXX)"
trap 'rm -rf -- "$SC_WORK"' EXIT

FAIL=0

# ---------------------------------------------------------------------------
# Shared helpers (duplicated from demo.sh deliberately -- register row:
# a shared scripts/lib/ helper is the right shape, deferred; see the design
# record sec5).
# ---------------------------------------------------------------------------

proc_state() {
  local pid="$1" raw rest state
  raw="$(cat "/proc/$pid/stat" 2>/dev/null)" || return 1
  [ -n "$raw" ] || return 1
  rest="${raw##*) }"
  state="${rest%% *}"
  [ -n "$state" ] || return 1
  printf '%s\n' "$state"
}

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

mount_is_ready() {
  local path="$1" row src fst
  row="$(read_mount_row "$path")" || return 1
  src="$(printf '%s\n' "$row" | awk '{print $1}')"
  fst="$(printf '%s\n' "$row" | awk '{print $2}')"
  [ "$src" = gran ] && [ "$fst" = fuse ]
}

# A lying umount: exits 0 without unmounting anything, and ALSO records its
# own argv to a witness file -- a shim that proves nothing about its own
# invocation cannot tell "the fallback was tried and lied to" from "the
# fallback was never reached".
make_lying_umount_shim() {
  local dir="$1" witness="$2"
  mkdir -p "$dir"
  cat >"$dir/umount" <<SHIM
#!/bin/sh
printf '%s\n' "\$*" >>"$witness"
exit 0
SHIM
  chmod 0755 "$dir/umount"
}

# Polls a captured combined-output log for the demo's first stdout line
# ("DEMO work dir: <W>"), bounded at 10s. Prints <W> on success.
wait_for_workdir() {
  local log="$1" attempts=0 line
  while [ "$attempts" -lt 100 ]; do
    if [ -s "$log" ]; then
      line="$(awk 'NR==1{print; exit}' "$log")"
      case "$line" in
        "DEMO work dir: "*)
          printf '%s\n' "${line#DEMO work dir: }"
          return 0
          ;;
      esac
    fi
    sleep 0.1
    attempts=$((attempts + 1))
  done
  return 1
}

# [ -s ], never [ -e ]: `echo $! > f` creates the file before the bytes
# reach it, and a poller keyed on mere existence reads it empty.
wait_for_pidfile_nonempty() {
  local pidfile="$1" attempts=0
  while [ "$attempts" -lt 100 ]; do
    [ -s "$pidfile" ] && return 0
    sleep 0.1
    attempts=$((attempts + 1))
  done
  return 1
}

# ---------------------------------------------------------------------------
# Cleans up whatever of a case's construction has been assembled so far:
# kills+reaps the demo if it is still around, kills the daemon if its pid
# is known, lazy-detaches any surviving mount row, stops the stack, and
# removes the work dir. Every DID NOT TAKE exit path in freeze_and_kill
# below calls this (C1) instead of leaving the daemon, its mount, and its
# stack behind: a killed demo can never run its own EXIT trap (SIGKILL
# cannot be trapped), so nothing else would clean up after it. $2 and $3
# are optional -- earlier exit points do not yet know the daemon pid or the
# work dir, and this is a no-op for whichever of them is empty.
# ---------------------------------------------------------------------------
cleanup_did_not_take() {
  local demo_pid="$1" daemon_pid="${2:-}" w="${3:-}"
  kill -CONT "$demo_pid" 2>/dev/null || true
  kill -KILL "$demo_pid" 2>/dev/null || true
  wait "$demo_pid" 2>/dev/null || true
  if [ -n "$daemon_pid" ]; then
    kill -KILL "$daemon_pid" 2>/dev/null || true
  fi
  if [ -n "$w" ]; then
    if read_mount_row "$w/mnt" >/dev/null 2>&1; then
      "$REAL_UMOUNT" -l "$w/mnt" 2>/dev/null || true
    fi
    "$STACK" stop --state-dir "$w/stack" >/dev/null 2>&1 || true
    rm -rf -- "$w"
  fi
}

# ---------------------------------------------------------------------------
# Shared choreography for N1 and N3: launch the demo (optionally with a
# shim dir prepended to PATH), wait for its work dir and a non-empty
# daemon.pid, freeze it with SIGSTOP, optionally assert N1's phase
# invariants, poll the mount table for readiness, SIGKILL the daemon, wait
# for it to stop SERVING (never for its pid to vanish -- with the demo
# SIGSTOPped nothing can reap its own child, so it stays a zombie
# indefinitely and kill -0 would succeed forever), then SIGCONT and wait for
# the demo to exit.
#
# On success sets FL_W, FL_DAEMON_PID, FL_RC and returns 0. On any
# precondition failing to hold, prints "$case_id DID NOT TAKE -- <reason>"
# and returns 1 -- this is a DISTINCT outcome from the case's own
# assertions failing afterward, and it is what stops a race being scored as
# either a pass or a misdiagnosed defect.
# ---------------------------------------------------------------------------
freeze_and_kill() {
  local case_id="$1" path_prefix="$2" check_phase="$3" demo_log="$4"
  local demo_pid w pidfile daemon_pid demo_state daemon_state attempts got_row stopped

  if [ -n "$path_prefix" ]; then
    PATH="$path_prefix:$PATH" "$DEMO" >"$demo_log" 2>&1 &
  else
    "$DEMO" >"$demo_log" 2>&1 &
  fi
  demo_pid=$!

  if ! w="$(wait_for_workdir "$demo_log")"; then
    cleanup_did_not_take "$demo_pid"
    echo "DEMO-SELF-CHECK: $case_id DID NOT TAKE -- the demo never printed its work-dir line" >&2
    return 1
  fi

  pidfile="$w/daemon.pid"
  if ! wait_for_pidfile_nonempty "$pidfile"; then
    cleanup_did_not_take "$demo_pid" "" "$w"
    echo "DEMO-SELF-CHECK: $case_id DID NOT TAKE -- daemon.pid never became non-empty" >&2
    return 1
  fi

  # The instant it is, freeze the demo.
  kill -STOP "$demo_pid"

  daemon_pid="$(cat "$pidfile" 2>/dev/null)"
  case "$daemon_pid" in
    '' | *[!0-9]*)
      cleanup_did_not_take "$demo_pid" "" "$w"
      echo "DEMO-SELF-CHECK: $case_id DID NOT TAKE -- daemon.pid does not hold a complete decimal number: '$daemon_pid'" >&2
      return 1
      ;;
  esac

  if [ "$check_phase" -eq 1 ]; then
    # A successful `kill -STOP` proves only that the signal was SENT, not
    # that the demo has actually transitioned to state T by the time this
    # reads /proc -- retry the sample under a short bound before concluding
    # DID NOT TAKE (C1).
    demo_state=""
    attempts=0
    while [ "$attempts" -lt 30 ]; do
      demo_state="$(proc_state "$demo_pid")" || demo_state=""
      [ "$demo_state" = T ] && break
      sleep 0.1
      attempts=$((attempts + 1))
    done
    if [ "$demo_state" != T ]; then
      cleanup_did_not_take "$demo_pid" "$daemon_pid" "$w"
      echo "DEMO-SELF-CHECK: $case_id DID NOT TAKE -- the demo's own /proc/$demo_pid/stat state is '$demo_state', want T (after retrying for 3s)" >&2
      return 1
    fi
    if grep -qF 'DEMO-MOUNTED' "$demo_log"; then
      cleanup_did_not_take "$demo_pid" "$daemon_pid" "$w"
      echo "DEMO-SELF-CHECK: $case_id DID NOT TAKE -- the demo's log already contains DEMO-MOUNTED before the freeze" >&2
      return 1
    fi
    daemon_state="$(proc_state "$daemon_pid")" || daemon_state=""
    if [ -z "$daemon_state" ] || [ "$daemon_state" = Z ]; then
      cleanup_did_not_take "$demo_pid" "$daemon_pid" "$w"
      echo "DEMO-SELF-CHECK: $case_id DID NOT TAKE -- the daemon (pid $daemon_pid) is not alive at freeze time (state='$daemon_state')" >&2
      return 1
    fi
  fi

  # Phase assertions held (or were not required). Poll the table (bounded)
  # until the mount is ready, then SIGKILL the daemon.
  attempts=0
  got_row=0
  while [ "$attempts" -lt 100 ]; do
    if mount_is_ready "$w/mnt"; then
      got_row=1
      break
    fi
    sleep 0.1
    attempts=$((attempts + 1))
  done
  if [ "$got_row" -ne 1 ]; then
    cleanup_did_not_take "$demo_pid" "$daemon_pid" "$w"
    echo "DEMO-SELF-CHECK: $case_id DID NOT TAKE -- the mount table never showed 'gran fuse' at $w/mnt within the bound" >&2
    return 1
  fi
  kill -KILL "$daemon_pid" 2>/dev/null || true

  # Wait for the daemon to stop SERVING, never for its pid to vanish: with
  # the demo SIGSTOPped, nothing can reap its own child, so it stays a
  # zombie and kill -0 would succeed indefinitely (measured: State Z with
  # kill -0 succeeding for a full 3s bound). The observable is the state
  # reaching Z, or a bounded read through the mount returning ENOTCONN --
  # here, cmp against the SOURCE copy (outside the mount, so this is never
  # the `cmp $MNT/f $MNT/f` degenerate).
  stopped=0
  attempts=0
  while [ "$attempts" -lt 30 ]; do
    daemon_state="$(proc_state "$daemon_pid")" || daemon_state=""
    if [ -z "$daemon_state" ] || [ "$daemon_state" = Z ]; then
      stopped=1
      break
    fi
    if ! timeout 1 cmp -s "$w/src/docs/needle.txt" "$w/mnt/docs/needle.txt" >/dev/null 2>&1; then
      stopped=1
      break
    fi
    sleep 0.1
    attempts=$((attempts + 1))
  done
  if [ "$stopped" -ne 1 ]; then
    cleanup_did_not_take "$demo_pid" "$daemon_pid" "$w"
    echo "DEMO-SELF-CHECK: $case_id DID NOT TAKE -- the daemon never stopped serving within 3s (state='$daemon_state')" >&2
    return 1
  fi

  kill -CONT "$demo_pid"
  set +e
  wait "$demo_pid"
  FL_RC=$?
  set -e
  FL_W="$w"
  FL_DAEMON_PID="$daemon_pid"
  return 0
}

# ---------------------------------------------------------------------------
# N1: the survivor.
# ---------------------------------------------------------------------------
case_n1() {
  local shim_dir="$SC_WORK/n1-shim" witness="$SC_WORK/n1-witness.log" demo_log="$SC_WORK/n1-demo.log"
  : >"$demo_log"
  make_lying_umount_shim "$shim_dir" "$witness"

  if ! freeze_and_kill N1 "$shim_dir" 1 "$demo_log"; then
    FAIL=1
    return
  fi
  local w="$FL_W" mnt rc=$FL_RC
  mnt="$w/mnt"

  local ok=1
  if [ "$rc" -eq 0 ]; then
    echo "DEMO-SELF-CHECK: N1 FAILED -- the demo exited 0, want nonzero" >&2
    ok=0
  fi
  if ! grep -qF 'DEMO: FAIL mount survived the EXIT trap' "$demo_log"; then
    echo "DEMO-SELF-CHECK: N1 FAILED -- the demo's log lacks 'DEMO: FAIL mount survived the EXIT trap'" >&2
    ok=0
  fi
  if grep -qF 'MOUNT-OK' "$demo_log"; then
    echo "DEMO-SELF-CHECK: N1 FAILED -- the demo's log contains the final witness, want absent" >&2
    ok=0
  fi
  local bad
  for bad in 'DEMO du: PASS' 'DEMO grep: PASS' 'DEMO exec: PASS'; do
    if grep -qF "$bad" "$demo_log"; then
      echo "DEMO-SELF-CHECK: N1 FAILED -- the demo's log contains '$bad', want absent (a dead daemon must fail every read)" >&2
      ok=0
    fi
  done
  if ! mount_is_ready "$mnt"; then
    echo "DEMO-SELF-CHECK: N1 FAILED -- the harness's own findmnt no longer shows the row at $mnt" >&2
    ok=0
  fi
  local witness_matched
  witness_matched="$(grep -Fc -- "-l $mnt" "$witness" 2>/dev/null)" || witness_matched=0
  if [ "${witness_matched:-0}" -ne 1 ]; then
    echo "DEMO-SELF-CHECK: N1 FAILED -- the lying umount shim's own witness file does not show exactly one record naming -l and $mnt (got ${witness_matched:-0})" >&2
    ok=0
  fi

  # Cleanup: clear the row with the REAL umount, by an absolute path
  # resolved before any PATH shimming (never through the demo's own PATH).
  "$REAL_UMOUNT" -l "$mnt" 2>/dev/null || true
  if read_mount_row "$mnt" >/dev/null 2>&1; then
    echo "DEMO-SELF-CHECK: N1 FAILED -- the harness's own real umount -l did not clear the row at $mnt" >&2
    ok=0
  fi
  # A failed cleanup must fail the case (C2): discarding this with `|| true`
  # let a surviving granary-server or MinIO process hide behind N1 PASS.
  set +e
  "$STACK" stop --state-dir "$w/stack" >/dev/null 2>&1
  local stack_cleanup_rc=$?
  set -e
  if [ "$stack_cleanup_rc" -ne 0 ]; then
    echo "DEMO-SELF-CHECK: N1 FAILED -- the harness's own stack teardown failed (rc=$stack_cleanup_rc); a process may have survived" >&2
    ok=0
  fi
  rm -rf -- "$w"

  if [ "$ok" -eq 1 ]; then
    echo "DEMO-SELF-CHECK: N1 PASS"
  else
    FAIL=1
  fi
}

# ---------------------------------------------------------------------------
# N2: the control that the shim alone is not what trips it. No freeze, no
# kill -- the daemon unmounts itself cleanly on SIGTERM, so umount(8) (real
# or shimmed) is never even invoked, and the demo must go GREEN.
# ---------------------------------------------------------------------------
case_n2() {
  local shim_dir="$SC_WORK/n2-shim" witness="$SC_WORK/n2-witness.log" demo_log="$SC_WORK/n2-demo.log"
  : >"$demo_log"
  make_lying_umount_shim "$shim_dir" "$witness"

  set +e
  PATH="$shim_dir:$PATH" "$DEMO" >"$demo_log" 2>&1
  local rc=$?
  set -e

  # N2's whole point is that the shim's mere PRESENCE does not trip the
  # demo -- so the control is that the shim is never actually INVOKED, not
  # merely that the demo exits 0. Under load, a daemon that does not
  # self-unmount within teardown's 10s SIGTERM bound makes the demo
  # LEGITIMATELY fall into its lazy-detach fallback, which invokes the
  # (here shimmed, lying) umount -- conflating that with "the shim lied"
  # would red a CORRECT demo. The shim records every invocation's argv;
  # check that FIRST, and report it as its own named diagnostic rather than
  # folding it into a bare FAILED.
  if [ -s "$witness" ]; then
    echo "DEMO-SELF-CHECK: N2 DID NOT TAKE -- the daemon did not self-unmount within the bound; N2's premise did not hold (the umount shim was invoked: $(tr '\n' ';' <"$witness"))" >&2
    FAIL=1
    return
  fi

  local ok=1
  if [ "$rc" -ne 0 ]; then
    echo "DEMO-SELF-CHECK: N2 FAILED -- the demo exited $rc under the shim alone (no freeze/kill), want 0" >&2
    ok=0
  fi
  if ! grep -qF 'MOUNT-OK' "$demo_log"; then
    echo "DEMO-SELF-CHECK: N2 FAILED -- the demo's log lacks the final witness" >&2
    ok=0
  fi

  if [ "$ok" -eq 1 ]; then
    echo "DEMO-SELF-CHECK: N2 PASS"
  else
    FAIL=1
  fi
}

# ---------------------------------------------------------------------------
# N3: the control that the fallback is a DIFFERENT arm. Freeze and kill as
# N1, but WITHOUT the shim: the real `umount -l` self-heals inside the
# demo's own teardown.
# ---------------------------------------------------------------------------
case_n3() {
  local demo_log="$SC_WORK/n3-demo.log"
  : >"$demo_log"

  if ! freeze_and_kill N3 "" 0 "$demo_log"; then
    FAIL=1
    return
  fi
  local w="$FL_W" mnt rc=$FL_RC
  mnt="$w/mnt"

  local ok=1
  if [ "$rc" -eq 0 ]; then
    echo "DEMO-SELF-CHECK: N3 FAILED -- the demo exited 0, want nonzero" >&2
    ok=0
  fi
  if ! grep -qF 'DEMO: lazily detached a surviving mount' "$demo_log"; then
    echo "DEMO-SELF-CHECK: N3 FAILED -- the demo's log lacks 'DEMO: lazily detached a surviving mount'" >&2
    ok=0
  fi
  if grep -qF 'DEMO: FAIL mount survived the EXIT trap' "$demo_log"; then
    echo "DEMO-SELF-CHECK: N3 FAILED -- the demo's log contains the survival FAIL line, want absent" >&2
    ok=0
  fi
  if read_mount_row "$mnt" >/dev/null 2>&1; then
    echo "DEMO-SELF-CHECK: N3 FAILED -- a row still exists at $mnt after the demo's own lazy detach" >&2
    ok=0
  fi

  rm -rf -- "$w"

  if [ "$ok" -eq 1 ]; then
    echo "DEMO-SELF-CHECK: N3 PASS"
  else
    FAIL=1
  fi
}

# ---------------------------------------------------------------------------
# The grep -c pin on the single MOUNT-OK spelling: a TEXT oracle, so it is the
# cheap first check only -- the BEHAVIOURAL pin is N1+N2 together.
# ---------------------------------------------------------------------------
check_grep_c_pin() {
  local n
  n="$(grep -c 'MOUNT-OK' "$DEMO")" || true
  if [ "${n:-0}" -eq 1 ]; then
    echo "DEMO-SELF-CHECK: PIN PASS (grep -c 'MOUNT-OK' $DEMO = 1)"
  else
    echo "demo-self-check: refused: grep -c 'MOUNT-OK' $DEMO = ${n:-0}, want exactly 1" >&2
    FAIL=1
  fi
}

check_grep_c_pin
case_n1
case_n2
case_n3

if [ "$FAIL" -ne 0 ]; then
  echo "DEMO-SELF-CHECK: FAILED" >&2
  exit 1
fi
echo "DEMO-SELF-CHECK: PASS"
