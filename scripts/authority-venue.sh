#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# Run the authority log adapter on ext4 in the Linux VM. The test traces
# normal operation, restart and failed device I/O. The regular container
# test suite skips granary-server and uses an overlay filesystem.
# This driver provides the server's supported storage venue and runs
# the following steps.
#
#   1. builds granary-server's nextest archive in the harness image
#      (container, non-root), with strace in the image;
#   2. in the bare podman VM, as root: a loop file under a device-mapper
#      table, ext4 on it, mounted; the mount's type is checked;
#   3. runs, in a container with that mount bound in (the mount's root and
#      every state directory owned by the user the containers run as, and
#      each state directory provisioned 0700, as the protection walk
#      requires):
#      a. every `authority::file_log` test with TMPDIR on the ext4 mount,
#         and requires a nonzero executed count and no failure; the same
#         run takes the writable client's composed registration (a sync
#         engine uploads and registers through the HTTP authority, the
#         client store is destroyed, recovery rebuilds the registered tree)
#         and requires each of its rows, named from the source, to pass;
#      b. the venue's traced workload, twice (a first process, then a
#         restart over its directory), each under `strace -f -y`, checked
#         by scripts/authority-venue-strace.py;
#      c. the failing device: the run initialises both volumes and blocks;
#         the VM maps the first volume's log's blocks to the `error` target;
#         the run's next append fails its sync; under strace, checked that
#         nothing mutating follows the failed sync;
#      d. the SIGKILL crash harness on the ext4 mount;
#      e. the power-loss attempt: at a sample of crash points the device's
#         table becomes a `flakey` one that drops every write (switched
#         without a flush), the driver is killed and the filesystem
#         unmounted, so what was not yet on the medium is lost; after a
#         remount over the linear table, every record the pipe shows
#         acknowledged must be committed, and a canary written after the
#         switch must be gone (or the attempt is void, not a pass);
#      f. the enrollment verbs' traced workload (a first mint, a revoke)
#         under `strace -f -y`, checked by the same script's enrollment
#         mode: ENROLLMENT.tmp created O_EXCL, written, synced, renamed
#         over ENROLLMENT, the directory synced, the parent too on the
#         first mint, and only then the verb's return;
#      g. tmpfs: an enrollment directory on a tmpfs refused by the walk
#         without the acknowledgement, and a tmpfs ancestor accepted;
#      i. the shipped authority binary process suite, including a second
#         bind alias of the ext4 mount; all process arms must execute;
#      h. the enrollment power loss: an attach held after its rename and
#         before its directory sync, the device switched to lane e's
#         flakey table, the run killed, the filesystem remounted; the
#         name must hold the old set or the new one, passing the reader's
#         checks, the verb must never have returned, and the canary must
#         be gone (or the attempt is void);
#      j. local initialise and unfence, their refusals and publication order;
#         successful unfence uses constructed boot times, never a host reboot;
#   4. tears the mount, the table, the loop device and the files down,
#      whatever happened.
#
# Usage: scripts/authority-venue.sh
# Exit 0 only when every lane ran and held. Each lane prints a line
# `VENUE <lane>: OK` or `VENUE <lane>: FAILED`; the last line is the verdict.
#
# SHELL DISCIPLINE: every exit status is captured on its own line, never
# through a pipe. Requires bash >= 4 (as linux-container.sh does).
set -euo pipefail
venue_publish_restart=0
venue_operator_lifecycle=0
case "$*" in
  "") ;;
  --publish-restart) venue_publish_restart=1 ;;
  --operator-lifecycle) venue_operator_lifecycle=1 ;;
  *) echo "usage: scripts/authority-venue.sh [--publish-restart|--operator-lifecycle]" >&2; exit 2 ;;
esac
cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO_ROOT="$(pwd -P)"

IMAGE="${GRANARY_LINUX_IMAGE:-localhost/linux-container:latest}"
# The build's memory: the feature-on build of every granary-server test
# binary was killed for memory in the podman VM (12 GiB, shared with other
# long-running containers) three times on 2026-09-29, once in the linker.
# So it builds two jobs at a time, with line tables only for debug info
# (the venue reads no debugger state).
# One target per checkout: a target shared between worktrees reused another
# worktree's test binaries, whose compiled-in source paths are not mounted here.
TARGET="${GRANARY_AUTHORITY_TARGET_DIR:-$REPO_ROOT/../granary-target-authority-$(basename "$REPO_ROOT")}"
CONTAINERFILE="$REPO_ROOT/scripts/linux-container.Containerfile"
CHECK="$REPO_ROOT/scripts/authority-venue-strace.py"
ARCHIVE_NAME="authority-tests.tar.zst"
VENUE_TESTS="authority::file_log::tests::venue"
ENROLL_TESTS="enrollment::tests::venue"
# The *at forms, and the plain ones glibc issues on architectures that
# have them (x86_64); `?` lets strace skip a name its architecture lacks.
# Every writing call is traced; the checker counts those on the state
# directory's files, not the test harness's own output.
TRACE_SET="openat,write,writev,pwrite64,pwritev,pwritev2,fsync,fdatasync,truncate,ftruncate,renameat,renameat2,linkat,unlinkat,mkdirat,?open,?creat,?rename,?link,?unlink,?mkdir"

die() {
  echo "authority-venue: $*" >&2
  exit 1
}

# A value interpolated into a shell string a container or the VM parses:
# an allowlist, not an escaping trick.
safe_path() {
  case "$2" in
    *[!A-Za-z0-9_./-]*|'') die "$1 ('$2') has a character outside [A-Za-z0-9_./-]" ;;
  esac
}

vm() {
  podman machine ssh -- "$@"
}

# ------------------------------------------------------------- preflight
state="$(podman machine inspect --format '{{.State}}' 2>/dev/null || true)"
[ "$state" = "running" ] || die "the podman machine is not running (state '$state'): podman machine start"
mkdir -p "$TARGET"
TARGET="$(cd "$TARGET" && pwd -P)"
safe_path "the repository root" "$REPO_ROOT"
safe_path "the target directory" "$TARGET"
case "$TARGET" in
  /Users/*) ;;
  *) die "the target directory '$TARGET' must be under /Users, which the VM shares" ;;
esac

set +e
podman run --rm --entrypoint "" "$IMAGE" strace -V >/dev/null 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
  echo "authority-venue: the image '$IMAGE' has no strace; rebuilding it from $CONTAINERFILE"
  podman build -t "$IMAGE" -f "$CONTAINERFILE" "$REPO_ROOT"
fi

if [ "$venue_publish_restart" -eq 0 ]; then
# ---------------------------------------------------------------- build
gran_build=""
if [ "$venue_operator_lifecycle" -eq 0 ]; then
  gran_build='cargo build --locked -p granary-cli --bin gran'
  rm -f "$TARGET/debug/gran"
fi
BUILD_SCRIPT='set -euo pipefail
mkdir -p /tmp/venue-home
'"$gran_build"'
cargo nextest archive -p granary-server --features crash-points,overlay-fault-tests --archive-file "$CARGO_TARGET_DIR/'"$ARCHIVE_NAME"'"
echo "VENUE-BUILD: OK"'
rm -f "$TARGET/$ARCHIVE_NAME"
set +e
build_out="$(podman run --rm --entrypoint "" \
  --user "$(id -u):$(id -g)" \
  --security-opt label=disable \
  -v "$REPO_ROOT:$REPO_ROOT" -v "$TARGET:$TARGET" \
  -e CARGO_TARGET_DIR="$TARGET" -e HOME=/tmp/venue-home \
  -e CARGO_BUILD_JOBS="${GRANARY_VENUE_JOBS:-2}" \
  -e CARGO_PROFILE_DEV_DEBUG=line-tables-only \
  -w "$REPO_ROOT" "$IMAGE" bash -c "$BUILD_SCRIPT" 2>&1)"
rc=$?
set -e
printf '%s\n' "$build_out" | tail -5
if [ "$rc" -ne 0 ]; then
  printf '%s\n' "$build_out" > "$TARGET/venue-build.out"
  die "the build failed (rc=$rc); its whole output is $TARGET/venue-build.out"
fi
grep -qxF "VENUE-BUILD: OK" <<<"$build_out" || die "the build exited 0 without its sentinel"
[ -s "$TARGET/$ARCHIVE_NAME" ] || die "the build left no archive at $TARGET/$ARCHIVE_NAME"
if [ "$venue_operator_lifecycle" -eq 0 ]; then
  [ -x "$TARGET/debug/gran" ] || die "the build left no shipping gran executable at $TARGET/debug/gran"
fi

fi

# ------------------------------------------------------------ provision
WORK="$(vm mktemp -d /var/tmp/granary-venue.XXXXXX)"
case "$WORK" in
  /var/tmp/granary-venue.*) ;;
  *) die "unexpected work directory from the VM: '$WORK'" ;;
esac
safe_path "the VM's work directory" "$WORK"
case "$WORK" in
  *..*) die "the VM's work directory ('$WORK') is not a plain name" ;;
esac
DM="gv-${WORK##*.}"
DM="$(printf '%s' "$DM" | tr -cd 'A-Za-z0-9-')"
# Lane c's container, by name, so teardown can remove it before unmounting.
LANE_C="granary-venue-c-${DM#gv-}"

teardown() {
  local rc=$?
  set +e
  podman rm -f "$LANE_C" >/dev/null 2>&1
  local e_names left_containers
  e_names="$(podman ps -a --filter "name=granary-venue-e-${DM#gv-}-" --format '{{.Names}}' 2>/dev/null)"
  for name in $e_names; do
    podman rm -f "$name" >/dev/null 2>&1
  done
  # Verified, not assumed: a listing that fails, or a container that is
  # still there, is an incomplete teardown.
  if ! left_containers="$(podman ps -a --filter "name=granary-venue-" --format '{{.Names}}' 2>&1)"; then
    echo "authority-venue: TEARDOWN INCOMPLETE: cannot list containers: $left_containers" >&2
    [ "$rc" -eq 0 ] && rc=1
  elif grep -qE "granary-venue-(c|e)-${DM#gv-}" <<<"$left_containers"; then
    echo "authority-venue: TEARDOWN INCOMPLETE: containers left: $left_containers" >&2
    [ "$rc" -eq 0 ] && rc=1
  fi
  # One remote script: undo everything, then print the sentinel only when
  # no mount, table, loop device or directory is left. No sentinel (an ssh
  # that failed, a step that did not finish) is an incomplete teardown.
  local out
  out="$(vm "sudo sh -c '
    if mountpoint -q $WORK/mnt 2>/dev/null; then umount $WORK/mnt; fi
    if dmsetup info $DM >/dev/null 2>&1; then dmsetup remove $DM; fi
    if [ -e $WORK/disk.img ]; then
      for l in \$(losetup -j $WORK/disk.img -O NAME -n); do losetup -d \$l; done
    fi
    left=\"\"
    # Each query fails loudly: a query that cannot answer is not \"absent\".
    mounts=\$(cat /proc/self/mounts) || left=\"\$left mounts?\"
    printf \"%s\\n\" \"\$mounts\" | grep -qF \" $WORK/mnt \" && left=\"\$left mount\"
    tables=\$(dmsetup ls) || left=\"\$left tables?\"
    printf \"%s\\n\" \"\$tables\" | grep -q \"^$DM[[:space:]]\" && left=\"\$left table\"
    if [ -e $WORK/disk.img ]; then
      loops=\$(losetup -j $WORK/disk.img -O NAME -n) || left=\"\$left loops?\"
      [ -n \"\$loops\" ] && left=\"\$left loop\"
    fi
    [ -z \"\$left\" ] && rm -rf $WORK
    [ -e $WORK ] && left=\"\$left dir\"
    [ -z \"\$left\" ] && echo TEARDOWN-CLEAN || echo \"TEARDOWN-LEFT:\$left\"
  '" 2>&1)"
  if ! grep -qxF "TEARDOWN-CLEAN" <<<"$out"; then
    echo "authority-venue: TEARDOWN INCOMPLETE: $WORK, $DM: $out" >&2
    [ "$rc" -eq 0 ] && rc=1
  fi
  exit "$rc"
}
trap teardown EXIT

vm "sudo sh -euc '
  truncate -s 1G $WORK/disk.img
  loop=\$(losetup --find --show $WORK/disk.img)
  sectors=\$(blockdev --getsz \$loop)
  echo \"0 \$sectors linear \$loop 0\" > $WORK/linear.table
  dmsetup create $DM $WORK/linear.table
  mkfs.ext4 -q -F /dev/mapper/$DM
  mkdir $WORK/mnt $WORK/control
  mount /dev/mapper/$DM $WORK/mnt
  chmod 1777 $WORK/mnt $WORK/control
  mkfifo -m 666 $WORK/control/go
'"
# The enrollment lanes' directory, owned by the VM user the rootless
# containers run as (their root): the protection walk refuses an ancestor
# owned by anyone else, and the VM's root is unmapped (uid 65534) inside.
# The mount's root is the authority's state directories' ancestor
# (`/venue`), so it is owned by that user too.
vm_uid="$(vm id -u)"
vm_gid="$(vm id -g)"
case "$vm_uid:$vm_gid" in
  *[!0-9:]*|:*|*:) die "cannot read the VM user's ids: '$vm_uid:$vm_gid'" ;;
esac
vm "sudo sh -euc 'mkdir $WORK/mnt/enroll; chown $vm_uid:$vm_gid $WORK/mnt/enroll; chmod 0755 $WORK/mnt/enroll; chown $vm_uid:$vm_gid $WORK/mnt'"
ENROLL_MOUNT=(-v "$WORK/mnt/enroll:/enroll")
fstype="$(vm findmnt -no FSTYPE "$WORK/mnt")"
[ "$fstype" = "ext4" ] || die "the venue mount is '$fstype', not ext4"
# This ext4 test venue requires a released Linux kernel, version 6.8 or later.
kernel="$(vm uname -r)"
kmajor="${kernel%%.*}"
kminor="${kernel#*.}"
kminor="${kminor%%.*}"
case "$kmajor$kminor" in
  *[!0-9]*|'') die "cannot read the VM's kernel version from '$kernel'" ;;
esac
case "$kernel" in
  *-rc*) die "the VM's kernel $kernel is a release candidate. The ext4 test venue requires a released kernel" ;;
esac
if [ "$kmajor" -lt 6 ] || { [ "$kmajor" -eq 6 ] && [ "$kminor" -lt 8 ]; }; then
  die "the VM's kernel $kernel is too old for the ext4 test venue. Linux 6.8 or later is required"
fi
echo "authority-venue: kernel $(vm uname -r); $WORK/mnt is ext4 ($(vm findmnt -no OPTIONS "$WORK/mnt")) on /dev/mapper/$DM"

in_container() {
  # $1 the lane's script; any further arguments go to podman run.
  local script="$1"
  shift
  podman run --rm --entrypoint "" "$@" \
    --security-opt label=disable --security-opt seccomp=unconfined --cap-add SYS_PTRACE \
    -v "$REPO_ROOT:$REPO_ROOT" -v "$TARGET:$TARGET" \
    -v "$WORK/mnt:/venue" -v "$WORK/control:/control" \
    -e HOME=/tmp/venue-home -w "$REPO_ROOT" "$IMAGE" bash -c "$script"
}

if [ "$venue_publish_restart" -eq 1 ]; then
  # /tmp itself is the supported mount: canonical client/store fixtures and
  # the authority/enrollment directories all remain under the same temp root.
  set +e
  in_container 'set -euo pipefail; mkdir -p "$HOME"; exec scripts/publish-restart.sh' \
    --user "$(id -u):$(id -g)" -v "$WORK/mnt:/tmp" \
    -e TMPDIR=/tmp -e CARGO_TARGET_DIR="$TARGET" \
    -e CARGO_BUILD_JOBS="${GRANARY_VENUE_JOBS:-2}" \
    -e CARGO_PROFILE_DEV_DEBUG=line-tables-only > "$TARGET/venue-publish-restart.out" 2>&1
  rc=$?
  set -e
  cat "$TARGET/venue-publish-restart.out"
  [ "$rc" -eq 0 ] || die "publication restart venue failed (rc=$rc)"
  echo "VENUE publication-restart: OK"
  exit 0
fi

verdict=0

# -------------------------------------------- lane a: the adapter on ext4
rm -rf "$TARGET/venue-extract"
mkdir "$TARGET/venue-extract"
if [ "$venue_operator_lifecycle" -eq 1 ]; then
  set +e
  in_container 'mkdir -p /venue/tmp
TMPDIR=/venue/tmp cargo nextest run --profile ci --archive-file "'"$TARGET/$ARCHIVE_NAME"'" --workspace-remap "'"$REPO_ROOT"'" --extract-to "'"$TARGET"'/venue-extract" --extract-overwrite -E "test(/^lifecycle::tests::/)"' > "$TARGET/venue-lifecycle-tests.out" 2>&1
  lifecycle_rc=$?
  set -e
  cat "$TARGET/venue-lifecycle-tests.out"
  [ "$lifecycle_rc" -eq 0 ] || die "lifecycle ext4 tests failed (rc=$lifecycle_rc)"
  grep -qE 'Summary .* [1-9][0-9]* tests? run: [1-9][0-9]* passed' "$TARGET/venue-lifecycle-tests.out" || die "lifecycle ext4 tests executed no passing case"
else
LANE_A='set -uo pipefail
[ "$(stat -f -c %T /venue)" = "ext2/ext3" ] || { echo "LANE-A: /venue is not ext4"; exit 9; }
mkdir -p /venue/tmp
TMPDIR=/venue/tmp timeout 1800 cargo nextest run --archive-file "'"$TARGET/$ARCHIVE_NAME"'" \
  --workspace-remap "'"$REPO_ROOT"'" --extract-to "'"$TARGET"'/venue-extract" --extract-overwrite \
  -E "test(/^authority::file_log::/) + test(/^authority::tests::intents::/) + test(/^conformance_http::intents::sync_loss::/)" --no-fail-fast 2>&1
echo "LANE-A-RC: $?"'
set +e
out_a="$(in_container "$LANE_A" 2>&1)"
set -e
printf '%s\n' "$out_a" > "$TARGET/venue-lane-a.out"
printf '%s\n' "$out_a" | grep -E "Summary|FAIL|LANE-A|error" || true
passed="$(printf '%s\n' "$out_a" | sed -nE 's/.*Summary .* ([0-9]+) tests? run: ([0-9]+) passed.*/\2/p' | tail -1)"
if grep -qxF "LANE-A-RC: 0" <<<"$out_a" && [ -n "$passed" ] && [ "$passed" -gt 0 ]; then
  echo "VENUE adapter-on-ext4: OK ($passed passed)"
else
  echo "VENUE adapter-on-ext4: FAILED"
  verdict=1
fi

# The composed registration and recovery rows ran in lane a's pass. A total
# count would pass with a row filtered out, so each row named in the source
# must PASS, under its own file's module path: the module file and every
# child module file beside it.
# Every module file at any depth under sync_loss/, so a nested child module
# cannot sit outside the gate.
mapfile -t SYNC_LOSS_CHILDREN < <(find -L crates/granary-server/src/conformance_http/intents/sync_loss -type f -name '*.rs' | LC_ALL=C sort)
SYNC_LOSS_ROWS=(crates/granary-server/src/conformance_http/intents/sync_loss.rs "${SYNC_LOSS_CHILDREN[@]}")
composition_ok=1
grep -qxF "LANE-A-RC: 0" <<<"$out_a" || composition_ok=0
for rows_file in "${SYNC_LOSS_ROWS[@]}"; do
  # An unmatched glob stays literal: a missing file refuses, never a file skipped.
  if [ ! -f "$rows_file" ]; then
    echo "VENUE client-composition-on-ext4: no row file $rows_file"
    composition_ok=0
    continue
  fi
  module="${rows_file#crates/granary-server/src/}"
  module="${module%.rs}"
  module="${module%/mod}"
  module="${module//\//::}"
  # Every test attribute must yield exactly one named row: the attributes are
  # counted by prefix, so one written in a form the extraction does not read
  # (split across lines, or followed by another attribute) is a mismatch
  # that refuses, not a row skipped.
  mapfile -t composition_rows < <(grep -A1 -E '^#\[tokio::test(\(.*\))?\]$' "$rows_file" | sed -nE 's/^async fn ([a-z0-9_]+)\(.*$/\1/p')
  composition_attributes="$(grep -c '^#\[tokio::test' "$rows_file" || true)"
  if [ "${#composition_rows[@]}" -eq 0 ] || [ "${#composition_rows[@]}" -ne "$composition_attributes" ]; then
    echo "VENUE client-composition-on-ext4: $composition_attributes test attribute(s) but ${#composition_rows[@]} named row(s) in $rows_file"
    composition_ok=0
  fi
  for row in "${composition_rows[@]}"; do
    if ! grep -E "PASS .* $module::$row$" <<<"$out_a" >/dev/null; then
      echo "VENUE client-composition-on-ext4: missing PASS for $module::$row"
      composition_ok=0
    fi
  done
done
if [ "$composition_ok" -eq 1 ]; then
  echo "VENUE client-composition-on-ext4: OK"
else
  echo "VENUE client-composition-on-ext4: FAILED"
  verdict=1
fi

# ------------------------------ lane i: the shipped authority binary
# The second mount spelling is a real bind alias, not a symlink. Execute
# ignored tests too: on Linux the only ignored row requires this alias.
SHIPPING_GRAN="$TARGET/debug/gran"
LANE_I='set -uo pipefail
TMPDIR=/venue/tmp GRANARY_HOST_EXT4=1 GRANARY_SHIPPING_GRAN="'"$SHIPPING_GRAN"'" cargo nextest run --archive-file "'"$TARGET/$ARCHIVE_NAME"'" \
  --workspace-remap "'"$REPO_ROOT"'" --extract-to "'"$TARGET"'/venue-extract" --extract-overwrite \
  -E "binary(=authority_host)" --run-ignored all --no-fail-fast 2>&1
echo "LANE-I-RC: $?"'
set +e
out_i="$(in_container "$LANE_I" -v "$WORK/mnt:/alias" 2>&1)"
set -e
printf '%s\n' "$out_i" > "$TARGET/venue-lane-i.out"
printf '%s\n' "$out_i"
lane_i_ok=1
if ! grep -qxF "LANE-I-RC: 0" <<<"$out_i"; then lane_i_ok=0; fi
# Check every test by identity, not merely a nonzero test count.
while IFS= read -r test_name; do
  if ! grep -E "PASS .*authority_host $test_name$" <<<"$out_i" >/dev/null; then
    echo "VENUE authority-binary: missing PASS for $test_name"
    lane_i_ok=0
  fi
done < <(sed -nE 's/^async fn ([a-z_]+)\(.*$/\1/p' crates/granary-server/tests/authority_host.rs)
if [ "$lane_i_ok" -eq 1 ] && grep -q 'async fn ' crates/granary-server/tests/authority_host.rs; then
  echo "VENUE authority-binary: OK"
else
  echo "VENUE authority-binary: FAILED"
  verdict=1
fi

fi

# The archive holds more than one granary_server-* test binary (the lib's
# and the bin's): the one whose listing names the venue's tests is the one.
PICK='for b in "'"$TARGET"'"/venue-extract/target/debug/deps/granary_server-*; do
  [ -f "$b" ] && [ -x "$b" ] || continue
  if "$b" --list 2>/dev/null | grep -qxF "authority::tests::crash::driver: test"; then echo "PICKED $b"; fi
done'
BIN="$(in_container "$PICK" 2>/dev/null | sed -n 's/^PICKED //p' | head -1)"
[ -n "$BIN" ] || die "no extracted granary_server test binary under $TARGET/venue-extract lists the venue's tests"
safe_path "the test binary" "$BIN"

traced() {
  # $1 a name for the trace, $2 the environment, $3 the test, $4 its
  # module (the log adapter's venue tests when absent).
  printf 'set -uo pipefail
%s strace -f -y -qq -e trace=%s -e signal=none -o /control/%s.strace \
  "%s" --exact "%s::%s" --include-ignored --test-threads=1 2>&1
echo "TRACED-RC: $?"' "$2" "$TRACE_SET" "$1" "$BIN" "${4:-$VENUE_TESTS}" "$3"
}

fetch_trace() {
  vm cat "$WORK/control/$1.strace" > "$TARGET/$1.strace"
}

if [ "$venue_operator_lifecycle" -eq 0 ]; then
# ------------------------------------------ lane b: the traced workload
lane_b_ok=1
# The state directory is provisioned, never created by the adapter.
vm "mkdir -p $WORK/mnt/traced/state && chmod 0700 $WORK/mnt/traced/state"
for phase in first restart; do
  set +e
  out_b="$(in_container "$(traced "$phase" \
    "GRANARY_VENUE_STATE=/venue/traced/state GRANARY_VENUE_PHASE=$phase" \
    the_workload_over_the_real_calls)" 2>&1)"
  set -e
  printf '%s\n' "$out_b" > "$TARGET/venue-lane-b-$phase.out"
  printf '%s\n' "$out_b" | grep -E "test result|TRACED-RC|panicked" || true
  fetch_trace "$phase"
  set +e
  python3 "$CHECK" "$phase" /venue/traced/state "$TARGET/$phase.strace"
  rc=$?
  set -e
  if ! grep -qxF "TRACED-RC: 0" <<<"$out_b" || ! grep -qF "1 passed" <<<"$out_b" || [ "$rc" -ne 0 ]; then
    lane_b_ok=0
  fi
done
if [ "$lane_b_ok" -eq 1 ]; then
  echo "VENUE traced-workload: OK"
else
  echo "VENUE traced-workload: FAILED"
  verdict=1
fi

# ------------------------------- lane f: the enrollment verbs, traced
set +e
out_f="$(in_container "$(traced enrollment \
  "GRANARY_VENUE_ENROLL=/enroll/traced/enroll GRANARY_VENUE_CONTROL=/control" \
  the_verbs_over_the_real_calls "$ENROLL_TESTS")" "${ENROLL_MOUNT[@]}" 2>&1)"
set -e
printf '%s\n' "$out_f" > "$TARGET/venue-lane-f.out"
printf '%s\n' "$out_f" | grep -E "test result|TRACED-RC|panicked" || true
fetch_trace enrollment
set +e
python3 "$CHECK" enrollment /enroll/traced/enroll "$TARGET/enrollment.strace"
rc=$?
set -e
if grep -qxF "TRACED-RC: 0" <<<"$out_f" && grep -qF "1 passed" <<<"$out_f" && [ "$rc" -eq 0 ]; then
  echo "VENUE enrollment-traced: OK"
else
  echo "VENUE enrollment-traced: FAILED"
  verdict=1
fi

fi

# ------------------------------------ lane j: local lifecycle on ext4
# The workload reads the clean marker after initialise; it does not launch a server.
vm "mkdir -p $WORK/mnt/lifecycle/state && chmod 0700 $WORK/mnt/lifecycle/state"
set +e
out_j="$(in_container "$(traced lifecycle \
  "GRANARY_VENUE_STATE=/venue/lifecycle/state GRANARY_VENUE_CONTROL=/control GRANARY_VENUE_UNSUPPORTED=/unsupported" \
  lifecycle_workload lifecycle::tests::venue)" --tmpfs /unsupported:rw,mode=1777 2>&1)"
rc=$?
set -e
printf '%s\n' "$out_j" > "$TARGET/venue-lane-j.out"
fetch_trace lifecycle
set +e
python3 "$CHECK" lifecycle /venue/lifecycle/state "$TARGET/lifecycle.strace" > "$TARGET/venue-lane-j-check.out" 2>&1
check_rc=$?
set -e
cat "$TARGET/venue-lane-j-check.out"
set +e
out_j_root="$(in_container 'GRANARY_VENUE_STATE=/venue/lifecycle/root-state "'"$BIN"'" --exact lifecycle::tests::venue::root_verb_preserves_state_owner --include-ignored --test-threads=1' --user 0 2>&1)"
root_rc=$?
set -e
printf '%s\n' "$out_j_root" > "$TARGET/venue-lane-j-root.out"
if [ "$rc" -eq 0 ] && [ "$check_rc" -eq 0 ] && [ "$root_rc" -eq 0 ] && grep -qF "1 passed" <<<"$out_j_root" && grep -qxF "TRACED-RC: 0" <<<"$out_j" && grep -qF "1 passed" <<<"$out_j"; then
  vm test "$(vm cat "$WORK/control/lifecycle-initialise-clean")" = clean || die "initialise did not read back a clean marker"
  echo "VENUE lifecycle-initialise-clean: OK (ext4 marker read; no server launch)"
  echo "VENUE lifecycle: OK"
else
  echo "VENUE lifecycle: FAILED"
  verdict=1
fi

if [ "$venue_operator_lifecycle" -eq 1 ]; then
  if [ "$verdict" -eq 0 ]; then
    echo "authority-venue: OPERATOR LIFECYCLE OK"
  else
    echo "authority-venue: FAILED"
  fi
  exit "$verdict"
fi

# ----------------------------------------------------- lane g: tmpfs
# /tank is a tmpfs in the container; the enrollment directory's ext4 is
# bound below it, so one directory sits on the tmpfs and one under it.
set +e
out_g="$(in_container "GRANARY_VENUE_ON_TMPFS=/tank/on/enroll GRANARY_VENUE_UNDER_TMPFS=/tank/ext/under-tmpfs/enroll \
  \"$BIN\" --exact $ENROLL_TESTS::tmpfs_is_refused_for_the_directory_and_taken_as_an_ancestor \
  --include-ignored --test-threads=1 2>&1; echo LANE-G-RC: \$?" \
  --tmpfs /tank:rw,mode=0755 -v "$WORK/mnt/enroll:/tank/ext" 2>&1)"
set -e
printf '%s\n' "$out_g" > "$TARGET/venue-lane-g.out"
printf '%s\n' "$out_g" | grep -E "test result|LANE-G-RC|panicked" || true
if grep -qxF "LANE-G-RC: 0" <<<"$out_g" && grep -qF "test result: ok. 1 passed" <<<"$out_g"; then
  echo "VENUE enrollment-tmpfs: OK"
else
  echo "VENUE enrollment-tmpfs: FAILED"
  verdict=1
fi

# --------------------------------------------- lane c: a failing device
vm "mkdir -p $WORK/mnt/failing/state && chmod 0700 $WORK/mnt/failing/state"
C_SCRIPT="$(traced failed \
  "GRANARY_VENUE_STATE=/venue/failing/state GRANARY_VENUE_CONTROL=/control" \
  a_sync_the_device_fails_fences_and_is_not_retried)"
out_c_file="$TARGET/venue-lane-c.out"
set +e
in_container "$C_SCRIPT" --name "$LANE_C" >"$out_c_file" 2>&1 &
c_pid=$!
set -e
ready=0
for _ in $(seq 1 600); do
  if vm test -e "$WORK/control/ready"; then
    ready=1
    break
  fi
  sleep 0.5
done
flipped=0
if [ "$ready" -eq 1 ]; then
  # The table: linear everywhere but the log's blocks, which error.
  set +e
  vm "sudo python3 -c '
import subprocess, sys
log = \"$WORK/mnt/failing/state/vol-a.log\"
ext = subprocess.run([\"filefrag\", \"-v\", \"-b4096\", log], capture_output=True, text=True, check=True).stdout
blocks = []
for line in ext.splitlines():
    cols = line.split(\":\")
    if len(cols) < 3 or not cols[0].strip().isdigit():
        continue
    lo, hi = (int(x) for x in cols[1].split(\"..\"))
    p = int(cols[2].split(\"..\")[0])
    blocks.append((p, hi - lo + 1))
if not blocks:
    sys.exit(\"no extent for \" + log + \":\\n\" + ext)
linear = open(\"$WORK/linear.table\").read().split()
sectors, loop = int(linear[1]), linear[3]
rows, at = [], 0
for p, n in sorted(blocks):
    s, k = p * 8, n * 8
    if s > at:
        rows.append(f\"{at} {s - at} linear {loop} {at}\")
    rows.append(f\"{s} {k} error\")
    at = s + k
if at < sectors:
    rows.append(f\"{at} {sectors - at} linear {loop} {at}\")
open(\"$WORK/error.table\", \"w\").write(\"\\n\".join(rows) + \"\\n\")
print(\"the log is at device blocks\", blocks, \"; only they fail\")
'" && vm "sudo sh -euc 'dmsetup suspend $DM; dmsetup load $DM $WORK/error.table; dmsetup resume $DM'"
  rc=$?
  set -e
  [ "$rc" -eq 0 ] && flipped=1
fi
if [ "$flipped" -eq 1 ]; then
  # Opening the FIFO's writing end releases the blocked run.
  vm "sh -c 'echo go > $WORK/control/go'"
else
  # Never ready, or the device was not failed: the run is removed, and
  # the lane fails below. Should the removal fail, the run is released
  # instead (its append then succeeds, and its assertions fail), so the
  # wait below cannot block; the release gives up if nothing reads.
  set +e
  podman rm -f "$LANE_C" >/dev/null 2>&1
  rc=$?
  if [ "$rc" -ne 0 ]; then
    vm "timeout 10 sh -c 'echo go > $WORK/control/go'"
  fi
  set -e
fi
set +e
wait "$c_pid"
set -e
# Restore the device before anything reads the filesystem again.
vm "sudo sh -euc 'dmsetup suspend $DM; dmsetup load $DM $WORK/linear.table; dmsetup resume $DM'"
grep -E "test result|TRACED-RC|panicked" "$out_c_file" || true
fetch_trace failed
set +e
python3 "$CHECK" failed /venue/failing/state "$TARGET/failed.strace"
rc=$?
set -e
if [ "$flipped" -eq 1 ] && grep -qxF "TRACED-RC: 0" "$out_c_file" && grep -qF "1 passed" "$out_c_file" && [ "$rc" -eq 0 ]; then
  echo "VENUE failing-device: OK"
else
  echo "VENUE failing-device: FAILED (ready=$ready, flipped=$flipped)"
  verdict=1
fi

# ------------------------------------ lane d: the SIGKILL crash harness
LANE_D='set -uo pipefail
mkdir -p /venue/crash
TMPDIR=/venue/crash GRANARY_CRASH_COVERAGE="'"$TARGET"'" cargo nextest run \
  --archive-file "'"$TARGET/$ARCHIVE_NAME"'" --workspace-remap "'"$REPO_ROOT"'" \
  -E "test(=authority::tests::crash::the_kill_holds_at_every_point)" 2>&1
echo "LANE-D-RC: $?"'
rm -f "$TARGET/crash-coverage.txt"
set +e
out_d="$(in_container "$LANE_D" 2>&1)"
set -e
printf '%s\n' "$out_d" > "$TARGET/venue-lane-d.out"
printf '%s\n' "$out_d" | grep -E "Summary|FAIL|LANE-D" || true
if grep -qxF "LANE-D-RC: 0" <<<"$out_d" && grep -qE "1 test run: 1 passed" <<<"$out_d" \
  && [ -s "$TARGET/crash-coverage.txt" ]; then
  echo "VENUE crash-harness: OK"
else
  echo "VENUE crash-harness: FAILED"
  verdict=1
fi

# Remove a lane's container and reap its client, both bounded: a container
# that will not go, or a client that will not exit, fails the lane rather
# than hanging it.
stop_container() {
  local name="$1" pid="$2" gone=0
  for _ in 1 2 3; do
    if podman rm -f "$name" >/dev/null 2>&1; then
      gone=1
      break
    fi
    sleep 1
  done
  for _ in $(seq 1 60); do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null
      [ "$gone" -eq 1 ]
      return
    fi
    sleep 0.5
  done
  kill -9 "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  return 1
}

# ------------------------------------------- lane e: the power loss
# The flakey table drops every write while "down"; an up interval of 0
# keeps it down. The switch is --noflush --nolockfs, so the switch itself
# writes nothing back.
# Each after at least one acknowledged record (the check refuses a cut with
# none as vacuous): the first acknowledgement, a mid-run one, a record
# written and not yet synced, a published root, and the final clean marker.
POWER_POINTS=("MarkSynced 1" "MarkSynced 8" "RecordWritten 9" "PutLinked 2" "MarkerRenamed 2")
read -r _ sectors _ loopdev _ <<<"$(vm cat "$WORK/linear.table")"
case "$sectors" in
  *[!0-9]*|'') die "cannot read the linear table's length: '$sectors'" ;;
esac
loopnum="${loopdev#/dev/loop}"
case "$loopdev:$loopnum" in
  /dev/loop*:*[!0-9]*|/dev/loop*:) die "cannot read the linear table's device: '$loopdev'" ;;
  /dev/loop*) ;;
  *) die "cannot read the linear table's device: '$loopdev'" ;;
esac
FLAKEY="0 $sectors flakey $loopdev 0 0 1 1 drop_writes"
power_ok=1
i=0
for point in "${POWER_POINTS[@]}"; do
  i=$((i + 1))
  name="granary-venue-e-${DM#gv-}-$i"
  dir="/venue/power/$i"
  # The state directory provisioned, and every directory the run walks
  # owned by the containers' user (the protection walk's ancestor rule).
  vm "sudo sh -euc 'mkdir -p $WORK/mnt/power/$i/anchor/state $WORK/mnt/power/$i/store; chown -R $vm_uid:$vm_gid $WORK/mnt/power; chmod 0700 $WORK/mnt/power/$i/anchor/state'"
  POWER_ENV="GRANARY_CRASH_STATE=$dir/anchor/state GRANARY_CRASH_STORE=$dir/store GRANARY_CRASH_PIPE=/control/power-$i.pipe GRANARY_CRASH_BOOT=1 GRANARY_CRASH_INCARNATION=1"
  set +e
  in_container "$POWER_ENV GRANARY_CRASH_PLAN='kill $point' \"$BIN\" --exact authority::tests::crash::driver --include-ignored --test-threads=1" \
    --name "$name" >"$TARGET/venue-lane-e-$i.out" 2>&1 &
  e_pid=$!
  set -e
  reached=0
  for _ in $(seq 1 600); do
    if vm "grep -q '^REACHED ' $WORK/control/power-$i.pipe 2>/dev/null"; then
      reached=1
      break
    fi
    sleep 0.5
  done
  canary=unknown
  checked=1
  switched=0
  if [ "$reached" -eq 1 ]; then
    set +e
    vm "sudo sh -euc '
      echo \"$FLAKEY\" > $WORK/flakey.table
      dmsetup suspend --noflush --nolockfs $DM
      dmsetup load $DM $WORK/flakey.table
      dmsetup resume $DM
      echo canary > $WORK/mnt/power/$i/canary
    '"
    rc=$?
    [ "$rc" -eq 0 ] && switched=1
    stop_container "$name" "$e_pid" || checked=0
    vm "sudo sh -euc 'umount $WORK/mnt; dmsetup suspend $DM; dmsetup load $DM $WORK/linear.table; dmsetup resume $DM; mount /dev/mapper/$DM $WORK/mnt'"
    rc=$?
    set -e
    [ "$rc" -eq 0 ] || checked=0
    # Read as a word, so a failed query is neither answer.
    case "$(vm "if test -e $WORK/mnt/power/$i/canary; then echo SURVIVED; else echo GONE; fi" 2>/dev/null)" in
      GONE) canary=gone ;;
      SURVIVED) canary=survived ;;
      *) canary=unknown ;;
    esac
    set +e
    out_e="$(in_container "$POWER_ENV \"$BIN\" --exact authority::tests::crash::every_acknowledged_record_survives_the_power_loss --include-ignored --test-threads=1 2>&1; echo CHECK-RC: \$?" 2>&1)"
    set -e
    printf '%s\n' "$out_e" >> "$TARGET/venue-lane-e-$i.out"
  else
    set +e
    stop_container "$name" "$e_pid"
    set -e
    checked=0
    out_e=""
  fi
  # The check must have run: libtest exits 0 on a name that matches nothing.
  if [ "$checked" -eq 1 ] && [ "$switched" -eq 1 ] && [ "$canary" = gone ] \
    && grep -qxF "CHECK-RC: 0" <<<"$out_e" && grep -qF "test result: ok. 1 passed" <<<"$out_e"; then
    echo "VENUE power-loss $point: OK (canary gone; every acknowledged record committed)"
  elif [ "$canary" = survived ]; then
    echo "VENUE power-loss $point: VOID (the canary survived: the drop did not happen)"
    power_ok=0
  else
    echo "VENUE power-loss $point: FAILED (reached=$reached, switched=$switched, remounted=$checked, canary=$canary)"
    power_ok=0
  fi
done
if [ "$power_ok" -eq 1 ]; then
  echo "VENUE power-loss: OK"
else
  echo "VENUE power-loss: FAILED"
  verdict=1
fi

# ------------------------------------ lane h: the enrollment power loss
# Lane e's machinery: the run holds an attach after its rename, before the
# directory's sync, and marks `enroll-paused`; the device drops every
# write from the switch on; the run is killed, the filesystem remounted
# over the linear table, and a second run reads the set.
name="granary-venue-e-${DM#gv-}-enroll"
vm "rm -f $WORK/control/enroll-paused $WORK/control/enroll-returned-mint $WORK/control/enroll-returned-attach"
H_TEST="\"$BIN\" --exact $ENROLL_TESTS::a_power_loss_before_the_directory_sync --include-ignored --test-threads=1 --nocapture"
H_ENV="GRANARY_VENUE_ENROLL=/enroll/power/enroll GRANARY_VENUE_CONTROL=/control"
set +e
in_container "$H_ENV GRANARY_VENUE_PHASE=cut $H_TEST 2>&1; echo CUT-RC: \$?" \
  --name "$name" "${ENROLL_MOUNT[@]}" >"$TARGET/venue-lane-h.out" 2>&1 &
h_pid=$!
set -e
paused=0
for _ in $(seq 1 600); do
  if vm test -e "$WORK/control/enroll-paused"; then
    paused=1
    break
  fi
  sleep 0.5
done
canary=unknown
remounted=1
switched=0
out_h=""
if [ "$paused" -eq 1 ]; then
  set +e
  vm "sudo sh -euc '
    echo \"$FLAKEY\" > $WORK/flakey.table
    dmsetup suspend --noflush --nolockfs $DM
    dmsetup load $DM $WORK/flakey.table
    dmsetup resume $DM
    echo canary > $WORK/mnt/enroll-canary
  '"
  rc=$?
  [ "$rc" -eq 0 ] && switched=1
  stop_container "$name" "$h_pid" || remounted=0
  vm "sudo sh -euc 'umount $WORK/mnt; dmsetup suspend $DM; dmsetup load $DM $WORK/linear.table; dmsetup resume $DM; mount /dev/mapper/$DM $WORK/mnt'"
  rc=$?
  set -e
  [ "$rc" -eq 0 ] || remounted=0
  case "$(vm "if test -e $WORK/mnt/enroll-canary; then echo SURVIVED; else echo GONE; fi" 2>/dev/null)" in
    GONE) canary=gone ;;
    SURVIVED) canary=survived ;;
    *) canary=unknown ;;
  esac
  set +e
  out_h="$(in_container "$H_ENV GRANARY_VENUE_PHASE=check $H_TEST 2>&1; echo CHECK-RC: \$?" "${ENROLL_MOUNT[@]}" 2>&1)"
  set -e
  printf '%s\n' "$out_h" >> "$TARGET/venue-lane-h.out"
else
  set +e
  stop_container "$name" "$h_pid"
  set -e
  remounted=0
fi
# The verb's return, read as a word, so a failed query is neither answer;
# the mint before it must have returned, or the run never got that far.
returns="$(vm "for v in mint attach; do if test -e $WORK/control/enroll-returned-\$v; then echo \$v=yes; else echo \$v=no; fi; done" 2>/dev/null | tr '\n' ' ')"
# Unanchored at the start: under --nocapture the test's line comes first.
which="$(vm "for s in old new; do if test -e $WORK/control/enroll-check-\$s; then echo the \$s set; fi; done" 2>/dev/null | head -1)"
grep -E "test result|CHECK-RC|panicked" <<<"$out_h" || true
if [ "$remounted" -eq 1 ] && [ "$switched" -eq 1 ] && [ "$canary" = gone ] \
  && [ "$returns" = "mint=yes attach=no " ] && [ -n "$which" ] \
  && grep -qxF "CHECK-RC: 0" <<<"$out_h" && grep -qF "test result: ok. 1 passed" <<<"$out_h"; then
  echo "VENUE enrollment-power-loss: OK (canary gone; the attach never returned; the name holds $which)"
elif [ "$canary" = survived ]; then
  echo "VENUE enrollment-power-loss: VOID (the canary survived: the drop did not happen)"
  verdict=1
else
  echo "VENUE enrollment-power-loss: FAILED (paused=$paused, switched=$switched, remounted=$remounted, canary=$canary, returns=$returns)"
  verdict=1
fi

if [ "$verdict" -eq 0 ]; then
  echo "authority-venue: ALL LANES OK"
else
  echo "authority-venue: FAILED"
fi
exit "$verdict"
