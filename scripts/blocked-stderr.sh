#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# Real Linux mounts, as root, outside a container. No Python, cargo or server
# installation is needed here: the caller supplies a running stack and binaries.
#
# All probes use conformance-breakage, armed with exec-everywhere (which changes
# permissions, never sentinel content). Its forwarded granary-fuse compile_error
# rejects builds without debug_assertions; feature-off builds contain neither
# the panic trigger nor checkpoint writes, and refuse --breakage. The existing
# required-breakage gate runs before the panic trigger. This uses that strict
# wall instead of adding a production panic argument or environment backdoor.
#
# A FIFO is a kernel pipe. Its O_RDWR holder NEVER reads. dd opens a separate
# O_NONBLOCK description and fills it to EAGAIN; the child's separate O_WRONLY
# open is blocking. A one-byte EAGAIN probe proves there is no residual capacity.
# Keep the holder open through exit/wedge: EPIPE is not a blocked-stderr test.
# Markers are files written at the target sites, independently of stderr, before
# the diagnostic. In particular the banner mutant cannot mount; its witness is
# the reached banner site, not a false claim that a kernel mount appeared.
set -euo pipefail
export LC_ALL=C

die() { echo "blocked-stderr: $*" >&2; exit 1; }

required_witnesses() {
  local mode="$1" label
  for label in mount refusal panic snapshot draining; do
    printf 'STDERR: %s PASS\n' "$label"
  done
  for label in mount refusal panic snapshot; do
    printf 'STDERR: %s pipe full, reader held open\n' "$label"
  done
  printf '%s\n' \
    'STDERR: mount banner reached' \
    'STDERR: mount mounted' \
    'STDERR: mount sentinel verified' \
    'STDERR: mount unmounted' \
    'STDERR: refusal cache-dir-refusal reached' \
    'STDERR: panic panic reached' \
    'STDERR: snapshot mounted' \
    'STDERR: snapshot sentinel verified' \
    'STDERR: snapshot unmounted' \
    'STDERR: snapshot wire-snapshot-failed reached' \
    'STDERR: draining mounted' \
    'STDERR: draining sentinel verified' \
    'STDERR: draining unmounted' \
    'STDERR: draining wire-snapshot-failed reached' \
    'STDERR: draining diagnostic received' \
    'STDERR: mount exit 0' \
    'STDERR: refusal exit 1' \
    'STDERR: panic exit 101' \
    'STDERR: snapshot exit 0' \
    'STDERR: draining exit 0'
  if [ "$mode" = controls ]; then
    for label in mount refusal panic snapshot; do
      printf 'STDERR: control-%s WEDGED\n' "$label"
      printf 'STDERR: control-%s pipe full, reader held open\n' "$label"
    done
    printf '%s\n' \
      'STDERR: control-mount banner reached' \
      'STDERR: control-refusal cache-dir-refusal reached' \
      'STDERR: control-panic panic reached' \
      'STDERR: control-snapshot mounted' \
      'STDERR: control-snapshot sentinel verified' \
      'STDERR: control-snapshot unmounted' \
      'STDERR: control-snapshot wire-snapshot-failed reached'
  fi
}

check_witnesses() {
  local log="$1" mode="$2" witness count
  [ "$mode" = fixed ] || [ "$mode" = controls ] || die 'unknown witness mode'
  [ -s "$log" ] || die "missing or empty log: $log"
  while IFS= read -r witness; do
    count="$(grep -cxF -- "$witness" "$log" || true)"
    [ "$count" -eq 1 ] || die "required witness must appear exactly once: $witness"
  done < <(required_witnesses "$mode")
  echo "STDERR-GATE: $mode OK"
}

self_test_witnesses() (
  local scratch witness mode
  scratch="$(mktemp -d)"
  trap 'rm -rf -- "$scratch"' EXIT
  for mode in fixed controls; do
    required_witnesses "$mode" >"$scratch/good"
    check_witnesses "$scratch/good" "$mode"
    while IFS= read -r witness; do
      grep -vxF -- "$witness" "$scratch/good" >"$scratch/bad"
      if (check_witnesses "$scratch/bad" "$mode") >"$scratch/error" 2>&1; then
        die "deleted witness accepted: $witness"
      fi
      grep -qF "required witness must appear exactly once: $witness" "$scratch/error"
      cat "$scratch/good" >"$scratch/bad"
      printf '%s\n' "$witness" >>"$scratch/bad"
      if (check_witnesses "$scratch/bad" "$mode") >"$scratch/error" 2>&1; then
        die "duplicate witness accepted: $witness"
      fi
    done < <(required_witnesses "$mode")
  done
  echo 'STDERR-WITNESSES: PASS'
)

record() {
  printf 'STDERR: %s %s\n' "$LABEL" "$*"
  printf 'STDERR: %s %s\n' "$LABEL" "$*" >>"$WORK/witness.log"
}

# Read the table, never stat a potentially wedged FUSE path. Work paths have no
# mountinfo escapes. Failed/empty captures refuse instead of claiming unmounted.
mount_row() {
  local table
  table="$(cat /proc/self/mountinfo)" || die 'cannot read mountinfo'
  [ -n "$table" ] || die 'empty mountinfo'
  awk -v target="$MOUNT" '$5 == target {
    for (i=7; i<=NF; i++) if ($i == "-") print $(i+2), $(i+1)
  }' <<<"$table"
}

is_mounted() {
  local row
  row="$(mount_row)" || exit 1
  case "$row" in
    'gran fuse'|'gran fuse.gran') return 0 ;;
    '') return 1 ;;
    *) die "unexpected mount row: $row" ;;
  esac
}

alive() { kill -0 "$PID" 2>/dev/null; }
exited() { ! alive; }
drained() { ! kill -0 "$DRAIN" 2>/dev/null; }

await_until() {
  local deadline="$1" description="$2"
  shift 2
  until "$@"; do
    [ "$SECONDS" -lt "$deadline" ] || die "$LABEL exceeded bound: $description"
    sleep 0.05
  done
}

checkpoint() {
  local name="$1" deadline="$2"
  await_until "$deadline" "$name checkpoint" test -s "$CASE/probe/$name"
  [ "$(cat "$CASE/probe/$name")" = reached ] || die 'invalid checkpoint contents'
  record "$name reached"
}

stop_process() {
  if [ -n "$PID" ]; then
    # GNU timeout leads its own process group; kill the daemon and supervisor,
    # even if a signal handler or a synchronous diagnostic cannot return.
    kill -KILL -- "-$PID" 2>/dev/null || kill -KILL "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
    PID=""
  fi
}

cleanup_case() {
  stop_process
  if [ -n "$HOLDER" ]; then
    exec {HOLDER}>&-
    HOLDER=""
  fi
  if [ -n "$DRAIN" ]; then
    kill "$DRAIN" 2>/dev/null || true
    wait "$DRAIN" 2>/dev/null || true
    DRAIN=""
  fi
  if [ -n "$MOUNT" ]; then
    if is_mounted; then
      timeout -s KILL 5 umount -l -- "$MOUNT" || die "cleanup could not detach $MOUNT"
    fi
    [ -z "$(mount_row)" ] || die "cleanup left a mount: $MOUNT"
  fi
}

require_pipe_eagain() {
  local rc="$1" log="$2" message="$3"
  # LC_ALL=C selects GNU dd's strerror text. uutils dd prints its Rust
  # ErrorKind instead. Match only the diagnostic for a full nonblocking pipe.
  if [ "$rc" -ne 1 ] || ! grep -qE '^(dd: error writing .*: Resource temporarily unavailable|dd: IO error: Would block)$' "$log"; then
    cat "$log" >&2
    die "$message (dd exit $rc)"
  fi
}

fill_pipe() {
  local rc
  exec {HOLDER}<>"$CASE/stderr.pipe"
  if dd if=/dev/zero of="$CASE/stderr.pipe" bs=4096 oflag=nonblock status=none 2>"$CASE/fill.log"; then
    die 'nonblocking fill unexpectedly succeeded'
  else
    rc=$?
  fi
  require_pipe_eagain "$rc" "$CASE/fill.log" 'pipe fill failed for a reason other than EAGAIN'
  if dd if=/dev/zero of="$CASE/stderr.pipe" bs=1 count=1 oflag=nonblock status=none 2>"$CASE/full.log"; then
    die 'pipe still accepted a byte after filling'
  else
    rc=$?
  fi
  require_pipe_eagain "$rc" "$CASE/full.log" 'one-byte fullness probe did not report EAGAIN'
  record 'pipe full, reader held open'
}

launch() {
  local binary="$1" kind="$2" destination="$3"
  CASE="$WORK/$LABEL"
  MOUNT="$CASE/mnt"
  mkdir -m 700 -p "$CASE/probe" "$MOUNT" "$CASE/cache"
  [ -z "$(mount_row)" ] || die 'mountpoint was already mounted'
  mkfifo "$CASE/stderr.pipe"
  if [ "$destination" = blocked ]; then
    fill_pipe
  else
    cat "$CASE/stderr.pipe" >"$CASE/stderr.log" &
    DRAIN=$!
  fi
  local -a args=(mount --breakage exec-everywhere "$GRAN_VOLUME" "$MOUNT"
    --endpoint "$GRAN_ENDPOINT" --pin "$GRAN_PIN" --root-key "$GRAN_ROOT_KEY" --foreground)
  [ "$kind" = refusal ] || args+=(--cache-dir "$CASE/cache")
  if [ "$kind" = snapshot ]; then
    # The absent parent is independent of root's ability to bypass permissions.
    args+=(--wire-snapshot "$CASE/absent/snapshot.json" --wire-run-id stderr --wire-role client-1)
  fi
  START=$SECONDS
  (
    [ -z "$HOLDER" ] || exec {HOLDER}>&-
    export GRANARY_STDERR_PROBE="$CASE/probe" GRANARY_STDERR_PANIC=0 RUST_LOG=info RUST_BACKTRACE=0
    [ "$kind" != panic ] || GRANARY_STDERR_PANIC=1
    # Emergency ceiling only. Each assertion below has its own shorter bound;
    # a timeout exit can never satisfy a fixed case's expected 0, 1 or 101.
    exec timeout -s KILL 90 "$binary" "${args[@]}"
  ) >"$CASE/stdout.log" 2>"$CASE/stderr.pipe" &
  PID=$!
}

expect_exit() {
  local expected="$1" deadline="$2" rc
  await_until "$deadline" "exit $expected" exited
  if wait "$PID"; then rc=0; else rc=$?; fi
  PID=""
  [ "$rc" -eq "$expected" ] || die "$LABEL exited $rc, expected $expected"
  record "exit $rc"
}

expect_wedge() {
  local bound="$1"
  alive || die "$LABEL exited before control observation"
  # Start the full observation interval AFTER the checkpoint; startup stalls
  # cannot consume the time credited to the named diagnostic site.
  sleep "$bound"
  alive || die "$LABEL did not wedge past ${bound}s at its checkpoint"
  record WEDGED
}

mounted_and_read() {
  await_until "$((START + 20))" 'kernel mount' is_mounted
  alive || die 'daemon died before mount witness'
  record mounted
  timeout -s KILL 5 cmp "$WORK/expected" "$MOUNT/sentinel.txt" \
    || die 'sentinel read failed or exceeded 5s'
  record 'sentinel verified'
}

unmount_cleanly() {
  timeout -s KILL 5 umount -- "$MOUNT" || die 'unmount failed or exceeded 5s'
  [ -z "$(mount_row)" ] || die 'unmount returned with a kernel mount remaining'
  record unmounted
  UNMOUNTED=$SECONDS
}

run_case() {
  local kind="$1" binary="$2" control="$3" destination="${4:-blocked}"
  LABEL="$kind"
  [ "$destination" != draining ] || LABEL=draining
  [ "$control" != yes ] || LABEL="control-$kind"
  launch "$binary" "$kind" "$destination"
  case "$kind" in
    refusal|panic)
      local name=cache-dir-refusal expected=1
      if [ "$kind" = panic ]; then name=panic; expected=101; fi
      checkpoint "$name" "$((START + 5))"
      if [ "$control" = yes ]; then expect_wedge 5
      else expect_exit "$expected" "$((START + 5))"; fi
      ;;
    mount)
      checkpoint banner "$((START + 20))"
      if [ "$control" = yes ]; then
        expect_wedge 20
        [ -z "$(mount_row)" ] || die 'banner control unexpectedly mounted'
      else
        mounted_and_read
        unmount_cleanly
        expect_exit 0 "$((UNMOUNTED + 5))"
      fi
      ;;
    snapshot)
      mounted_and_read
      unmount_cleanly
      checkpoint wire-snapshot-failed "$((UNMOUNTED + 5))"
      [ ! -e "$CASE/absent" ] || die 'snapshot failure fixture acquired a parent'
      if [ "$control" = yes ]; then expect_wedge 5
      else expect_exit 0 "$((UNMOUNTED + 5))"; fi
      if [ "$destination" = draining ]; then
        await_until "$((SECONDS + 5))" 'draining reader EOF' drained
        wait "$DRAIN" || die 'stderr reader failed'
        DRAIN=""
        grep -q '^wire-snapshot not written: ' "$CASE/stderr.log" \
          || die 'draining stderr lost the snapshot failure diagnostic'
        record 'diagnostic received'
      fi
      ;;
  esac
  cleanup_case
  [ "$control" = yes ] || record PASS
}

run_suite() {
  [ "$#" -eq 4 ] || [ "$#" -eq 5 ] || die 'run requires GRAN ENV SENTINEL WORK [CONTROLS]'
  local gran="$1" environment="$2" sentinel="$3" controls="${5:-}" mode=fixed line i
  WORK="$4"
  [ "$(uname -s)" = Linux ] && [ "$(id -u)" -eq 0 ] || die 'requires Linux and uid 0'
  [ -c /dev/fuse ] || die '/dev/fuse is unavailable'
  for tool in timeout dd cmp umount mkfifo; do command -v "$tool" >/dev/null || die "missing $tool"; done
  [[ "$WORK" =~ ^/[A-Za-z0-9/._-]+$ ]] || die 'work path must be absolute without mountinfo escapes'
  [ ! -e "$WORK" ] && [ ! -L "$WORK" ] || die 'work directory must be fresh'
  [ -x "$gran" ] || die "missing executable: $gran"
  local -a lines names=(GRAN_ENDPOINT GRAN_PIN GRAN_ROOT_KEY GRAN_VOLUME)
  mapfile -t lines <"$environment"
  [ "${#lines[@]}" -eq 4 ] || die 'stack env must have exactly four lines'
  for i in 0 1 2 3; do
    line="${lines[$i]}"
    [[ "$line" =~ ^${names[$i]}=[][A-Za-z0-9._:/+=@%,-]+$ ]] || die 'invalid stack env contract'
    printf -v "${names[$i]}" '%s' "${line#*=}"
  done
  mkdir -m 700 "$WORK"
  printf '%s' "$sentinel" >"$WORK/expected"
  ulimit -c 0
  PID="" HOLDER="" DRAIN="" MOUNT=""
  trap cleanup_case EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  local kind
  for kind in mount refusal panic snapshot; do run_case "$kind" "$gran" no; done
  run_case snapshot "$gran" no draining
  if [ -n "$controls" ]; then
    mode=controls
    for kind in mount refusal panic snapshot; do
      [ -x "$controls/gran-$kind" ] || die "missing control: $kind"
      run_case "$kind" "$controls/gran-$kind" yes
    done
  fi
  check_witnesses "$WORK/witness.log" "$mode"
  echo "STDERR: battery $mode PASS"
}

case "${1:-}" in
  --check-log) [ "$#" -eq 3 ] || die 'expected --check-log LOG fixed|controls'; check_witnesses "$2" "$3" ;;
  --self-test-witnesses) [ "$#" -eq 1 ] || die 'unexpected arguments'; self_test_witnesses ;;
  run) shift; run_suite "$@" ;;
  *) die 'expected run GRAN ENV SENTINEL WORK [CONTROLS], --check-log LOG fixed|controls, or --self-test-witnesses' ;;
esac
