#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# This check requires root on Linux and a real systemd host with a real mount
# namespace and cgroup tree, never a container. Of these venue requirements,
# preflight enforces only root and Linux. `scripts/linux-container.sh` runs it
# in the podman VM under sudo via `vm_run_unit_check`.
#
#   usage: unit-check.sh <stack-env-file> <gran-binary> <expected-sentinel>
#
# <stack-env-file>: the four lines from `stack.sh start` (GRAN_
# ENDPOINT/PIN/ROOT_KEY/VOLUME), reachable from THIS host. GRAN_VOLUME is
# used as the systemd INSTANCE for every real mount in this check
# (the instance IS the volume by construction).
# <gran-binary>: the client binary to install at /usr/local/bin/gran.
# <expected-sentinel>: the EXACT bytes (as a single argv word, charset
# [A-Za-z0-9_./-] so it survives the remote-shell allowlist) that
# sentinel.txt holds in the published tree. Without an
# externally-supplied expectation, a self-comparison such as
# `cmp $MNT/f $MNT/f` would satisfy "cmp the
# published sentinel" while proving nothing about the mount's own bytes.
# The expected sentinel is a required
# third argument. The check refuses to
# start if it is absent or empty; its
# bytes must come from outside the
# mount being checked, so the comparison
# has an independent expectation.
#
# Twelve cases, each printing its own `UNIT: <case> PASS`. Final line
# `UNIT-CHECK: PASS`. Every negative proves the perturbation LANDED
# before scoring the red it causes -- a probe that never applied prints
# exactly like a probe that was survived.
set -euo pipefail

die() {
  echo "unit-check: $*" >&2
  exit 1
}

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
UNIT_FILE="$REPO_ROOT/packaging/gran-mount@.service"

# ---------------------------------------------------------------------------
# Argument parsing -- fixed arity, no trailing argv.
# ---------------------------------------------------------------------------
[ "$#" -eq 3 ] || die "usage: $0 <stack-env-file> <gran-binary> <expected-sentinel> (got $# args)"
STACK_ENV_FILE="$1"
GRAN_BIN="$2"
EXPECTED_SENTINEL="$3"

[ -n "$EXPECTED_SENTINEL" ] \
  || die "refused -- the expected-sentinel argument is empty. Case 1's cmp must be seeded from OUTSIDE the mount; an empty expectation is indistinguishable from 'not supplied'."
case "$EXPECTED_SENTINEL" in
  *[!A-Za-z0-9_./-]*)
    die "refused -- the expected-sentinel argument ('$EXPECTED_SENTINEL') contains a character outside [A-Za-z0-9_./-]. It travels through a remote-shell argv boundary upstream of this script; keep it in the same safe charset that boundary enforces."
    ;;
esac

# ---------------------------------------------------------------------------
# Preflight: uname reports Linux; id -u reports 0; systemctl and the listed
# tools are on PATH; input files and the executable exist; nobody resolves.
# ---------------------------------------------------------------------------
[ "$(uname -s)" = Linux ] || die "refused -- this must run on Linux, not $(uname -s)"
[ "$(id -u)" -eq 0 ] || die "refused -- must run as root (id -u is $(id -u))"
# Preflight every unconditionally used external command, not a sample.
# Include `mountpoint`, which wait_for_row uses for readiness polling.
# Include `rmdir`, `cmp` and `ls`: cleanup_all calls rmdir,
# case 1 compares its sentinel with cmp, and case 12 invokes ls -Z.
# Include `sleep`, an external coreutils command on this host rather
# than a bash builtin; every case's poll loop uses it.
# Keep `chcon` and `getenforce` OUT of this unconditional list.
# They are SELinux-only, and case 12 checks for them conditionally
# when the host is actually SELinux-enforcing.
# Requiring them here would refuse the whole check on non-SELinux
# hosts, where it must also run.
for tool in systemctl journalctl findmnt mountpoint nsenter python3 \
  sha256sum runuser awk sed grep mktemp mv cp install chmod mkdir rm cat \
  readlink timeout seq id rmdir cmp ls sleep wc dirname; do
  command -v "$tool" >/dev/null 2>&1 || die "refused -- required tool is missing: $tool"
done
[ -f "$UNIT_FILE" ] || die "refused -- unit file not found: $UNIT_FILE"
[ -f "$STACK_ENV_FILE" ] || die "refused -- stack env file not found: $STACK_ENV_FILE"
[ -x "$GRAN_BIN" ] || die "refused -- gran binary is not executable: $GRAN_BIN"
command -v nobody >/dev/null 2>&1 || true
id nobody >/dev/null 2>&1 || die "refused -- no 'nobody' account on this host; case 2's unprivileged-user tests need one"

# ---------------------------------------------------------------------------
# The four-line stack.env contract (the same validator conformance.sh and
# demo.sh each also carry, verbatim -- this is the THIRD copy, discharge
# deferred to a scripts/lib/ helper).
# ---------------------------------------------------------------------------
validate_contract() {
  local text_value="$1" line
  local -a lines names
  mapfile -t lines < <(printf '%s\n' "$text_value")
  if [ "${#lines[@]}" -ne 4 ]; then
    printf '%s\n' 'UNIT-CHECK-CONTRACT: REFUSED line-count'
    return 1
  fi
  for line in "${lines[@]}"; do
    if [[ ! "$line" =~ ^GRAN_(ENDPOINT|PIN|ROOT_KEY|VOLUME)=.+$ ]]; then
      printf '%s\n' 'UNIT-CHECK-CONTRACT: REFUSED assignment-shape'
      return 1
    fi
    if [[ ! "${line#*=}" =~ ^[][A-Za-z0-9._:/+=@%,-]+$ ]]; then
      printf '%s\n' 'UNIT-CHECK-CONTRACT: REFUSED value-charset'
      return 1
    fi
    names+=("${line%%=*}")
  done
  local expected got
  expected=$'GRAN_ENDPOINT\nGRAN_PIN\nGRAN_ROOT_KEY\nGRAN_VOLUME'
  got="$(printf '%s\n' "${names[@]}")"
  if [ "$got" != "$expected" ]; then
    printf '%s\n' 'UNIT-CHECK-CONTRACT: REFUSED name-order'
    return 1
  fi
  printf '%s\n' 'UNIT-CHECK-CONTRACT: PASS'
}

STACK_ENV_TEXT="$(cat "$STACK_ENV_FILE")"
set +e
contract_verdict="$(validate_contract "$STACK_ENV_TEXT")"
contract_rc=$?
set -e
echo "$contract_verdict"
[ "$contract_verdict" = 'UNIT-CHECK-CONTRACT: PASS' ] && [ "$contract_rc" -eq 0 ] \
  || die "refused -- stack-env-file failed the four-line contract"

STACK_ENDPOINT="" STACK_PIN="" STACK_ROOT_KEY="" STACK_VOLUME=""
mapfile -t CONTRACT_LINES < <(printf '%s\n' "$STACK_ENV_TEXT")
STACK_ENDPOINT="${CONTRACT_LINES[0]#*=}"
STACK_PIN="${CONTRACT_LINES[1]#*=}"
STACK_ROOT_KEY="${CONTRACT_LINES[2]#*=}"
STACK_VOLUME="${CONTRACT_LINES[3]#*=}"
[ -n "$STACK_ENDPOINT" ] || die "refused -- validated GRAN_ENDPOINT evaluated empty"
[ -n "$STACK_PIN" ] || die "refused -- validated GRAN_PIN evaluated empty"
[ -n "$STACK_ROOT_KEY" ] || die "refused -- validated GRAN_ROOT_KEY evaluated empty"
[ -n "$STACK_VOLUME" ] || die "refused -- validated GRAN_VOLUME evaluated empty"

# The instance IS the volume. Every REAL mount
# in this check uses this instance name, assigned
# directly from the validated stack volume
# rather than checked separately at runtime.
INSTANCE="$STACK_VOLUME"
case "$INSTANCE" in
  *[!a-z0-9-]* | '' | -* | *-)
    die "refused -- GRAN_VOLUME ('$INSTANCE') is not a safe DNS-1123-shaped instance name; refusing to use it as a systemd template instance."
    ;;
esac

STACK_HOST_ENDPOINT="${STACK_ENDPOINT#https://}"
STACK_HOST_ENDPOINT="${STACK_HOST_ENDPOINT%%/*}"
STACK_PORT="${STACK_HOST_ENDPOINT##*:}"
case "$STACK_PORT" in
  *[!0-9]*) die "refused -- could not parse a numeric port out of GRAN_ENDPOINT ('$STACK_ENDPOINT')" ;;
esac
LOCALHOST_ENDPOINT="https://localhost:${STACK_PORT}"

echo "unit-check: instance=$INSTANCE endpoint=$STACK_ENDPOINT localhost-endpoint=$LOCALHOST_ENDPOINT"

# ---------------------------------------------------------------------------
# Global cleanup state, and the EXIT trap. The trap's first statement
# must capture $? before anything else touches it.
# This script has no separate emit_final, but a clobbered rc would
# still make a red case's exit status silently vanish.
# ---------------------------------------------------------------------------
declare -a INSTANCES_STARTED=()
declare -a ENV_FILES_WRITTEN=()
declare -a DROPIN_DIRS=()
UNIT_INSTALLED=0
BIN_INSTALLED_FRESH=0
BIN_STAMP=/usr/local/bin/.unit-check.stamp
MOUNT_DIR=""
# Case 8's two decoys: PASSWD_ENV is
# not the path a %i-to-%I regression
# reaches; TRAVERSAL_ENV is the path
# %I would actually name for the
# hostile instance. Both are recorded
# as CREATED only once this run has
# written them, and cleanup_all
# removes only what this run created.
PASSWD_ENV="/etc/granary/mounts/passwd.env"
PASSWD_ENV_CREATED=0
TRAVERSAL_ENV="/etc/granary/etc/passwd.env"
TRAVERSAL_ENV_CREATED=0
# Case 12 PARKS the good binary here while it installs a mislabelled copy at
# /usr/local/bin/gran. An abort between the park and the restore left the parked
# copy orphaned while cleanup deleted the mislabelled one -- i.e. the host lost
# its working binary and kept nothing. Tracked like every other path this
# harness creates, so the EXIT trap can put it back.
PARKED_GRAN="/usr/local/bin/.unit-check-good-gran"
PARKED_GRAN_CREATED=0
TRAVERSAL_DIR_PREEXISTED=0
# This lane's host is PERSISTENT and can hold state under the old
# `.m8-unit-check*` spelling. Keep both compatibility paths below:
#
#   The STAMP identifies this harness's binary. Adopt a regular old-spelling
#   stamp when BIN_STAMP is absent, so the install block recognizes the
#   binary instead of refusing it as somebody else's gran.
#
#   The PARKED BINARY is the host's working `gran`. Case 12 checks both
#   spellings and refuses an existing path by name rather than overwrite it.
#
# Stamp adoption runs before `trap cleanup_all EXIT` below.
LEGACY_BIN_STAMP=/usr/local/bin/.m8-unit-check.stamp
LEGACY_PARKED_GRAN="/usr/local/bin/.m8-unit-check-good-gran"
if [ -L "$LEGACY_BIN_STAMP" ]; then
  # A SYMLINK is refused, never adopted: `[ -f ]` follows it, so adopting one
  # would carry it to $BIN_STAMP and the `: >"$BIN_STAMP"` below would
  # truncate whatever it points at, as root. This harness refuses a symlink
  # by name everywhere else it touches one; here too.
  die "refused -- '$LEGACY_BIN_STAMP' is a SYMLINK. This harness only ever writes regular files under /usr/local/bin; remove it by hand and re-run."
fi
if [ -f "$LEGACY_BIN_STAMP" ] && [ ! -e "$BIN_STAMP" ] && [ ! -L "$BIN_STAMP" ]; then
  mv -f -- "$LEGACY_BIN_STAMP" "$BIN_STAMP" \
    || die "refused -- could not adopt the pre-rename stamp $LEGACY_BIN_STAMP"
  echo "unit-check: adopted a pre-rename stamp ($LEGACY_BIN_STAMP -> $BIN_STAMP)"
fi

cleanup_all() {
  local rc0=$? failure=0 inst d f rows units
  set +e
  for inst in "${INSTANCES_STARTED[@]:-}"; do
    [ -n "$inst" ] || continue
    systemctl stop "gran-mount@${inst}.service" >/dev/null 2>&1
    systemctl reset-failed "gran-mount@${inst}.service" >/dev/null 2>&1
  done
  for d in "${DROPIN_DIRS[@]:-}"; do
    [ -n "$d" ] || continue
    rm -rf -- "$d"
  done
  if [ "$UNIT_INSTALLED" -eq 1 ]; then
    rm -f -- /run/systemd/system/gran-mount@.service
  fi
  systemctl daemon-reload >/dev/null 2>&1
  for f in "${ENV_FILES_WRITTEN[@]:-}"; do
    [ -n "$f" ] || continue
    rm -f -- "$f"
  done
  # never rm -f a path this run did not create. A pre-existing file at
  # either decoy path already made c8_hostile_instance REFUSE by name
  # before writing anything (below), so *_CREATED is only ever 1 when this
  # run's own write actually happened.
  if [ "$PASSWD_ENV_CREATED" -eq 1 ]; then
    rm -f -- "$PASSWD_ENV"
  fi
  # RESTORE before anything else touches /usr/local/bin/gran: if case 12 was
  # interrupted mid-swap, the good binary is at PARKED_GRAN and the thing at
  # /usr/local/bin/gran is the deliberately mislabelled copy.
  if [ "$PARKED_GRAN_CREATED" -eq 1 ] && { [ -e "$PARKED_GRAN" ] || [ -L "$PARKED_GRAN" ]; }; then
    mv -f -- "$PARKED_GRAN" /usr/local/bin/gran || true
    PARKED_GRAN_CREATED=0
  fi
  if [ "$TRAVERSAL_ENV_CREATED" -eq 1 ]; then
    rm -f -- "$TRAVERSAL_ENV"
    if [ "$TRAVERSAL_DIR_PREEXISTED" -eq 0 ]; then
      rmdir -- /etc/granary/etc 2>/dev/null
    fi
  fi
  if [ "$BIN_INSTALLED_FRESH" -eq 1 ] || [ -f "$BIN_STAMP" ]; then
    rm -f -- /usr/local/bin/gran "$BIN_STAMP"
  fi
  if [ -n "$MOUNT_DIR" ]; then
    rmdir -- "$MOUNT_DIR" 2>/dev/null
    rmdir -- "$(dirname "$MOUNT_DIR")" 2>/dev/null
  fi
  rmdir -- /etc/granary/mounts 2>/dev/null
  rmdir -- /etc/granary 2>/dev/null
  # CacheDirectory=granary/%i -- deliberately persistent across an
  # ordinary restart in production, but this is a throwaway check run, and
  # leaving a per-run instance's cache dir behind on the host is clutter
  # this harness caused and should remove.
  if [ -n "$INSTANCE" ]; then
    rm -rf -- "/var/cache/granary/${INSTANCE}"
  fi
  rmdir -- /var/cache/granary 2>/dev/null

  # Postcondition: re-read the mount table and the unit list, and
  # REQUIRE both empty -- never trust that every case above cleaned up after
  # itself; verify it here, once, from outside every case's own logic.
  #
  # A FAILED capture must never be scored the same as a genuinely EMPTY
  # one (the project's own hard-won lesson: an empty snapshot is not "no
  # rows", it can be a capture that never ran at all). findmnt's raw
  # output (before the awk filter) is checked for non-emptiness AND rc==0
  # -- a running system always has at least a root row, so an empty raw
  # capture is definitionally a failure, not a clean table. systemctl
  # list-units legitimately prints NOTHING on a genuine "no gran-mount@*
  # units" success, so that one is distinguished by ITS OWN exit status
  # instead, captured explicitly rather than swallowed via 2>/dev/null.
  local findmnt_raw findmnt_rc units_rc
  findmnt_raw="$(findmnt -rn -o SOURCE,TARGET 2>/dev/null)"
  findmnt_rc=$?
  if [ "$findmnt_rc" -ne 0 ] || [ -z "$findmnt_raw" ]; then
    echo "unit-check: EXIT-CLEANUP FAILED -- could not read the mount table (findmnt rc=$findmnt_rc, output empty); a failed capture must never be scored as 'no rows'." >&2
    failure=1
  else
    rows="$(printf '%s\n' "$findmnt_raw" | awk '$1=="gran"{print}')"
    if [ -n "$rows" ]; then
      echo "unit-check: EXIT-CLEANUP FAILED -- gran mount row(s) survive:" >&2
      printf '%s\n' "$rows" >&2
      failure=1
    fi
  fi
  units="$(systemctl list-units --all --no-legend --plain 'gran-mount@*' 2>&1)"
  units_rc=$?
  if [ "$units_rc" -ne 0 ]; then
    echo "unit-check: EXIT-CLEANUP FAILED -- could not query systemctl list-units (rc=$units_rc): $units" >&2
    failure=1
  elif [ -n "$units" ]; then
    echo "unit-check: EXIT-CLEANUP FAILED -- gran-mount@* unit(s) still listed:" >&2
    printf '%s\n' "$units" >&2
    failure=1
  fi
  if [ "$failure" -eq 0 ]; then
    echo "unit-check: EXIT-CLEANUP OK -- no mount rows, no gran-mount@* units" >&2
  fi
  trap - EXIT
  exit $(( rc0 != 0 ? rc0 : failure ))
}
trap cleanup_all EXIT

# ---------------------------------------------------------------------------
# Shared helpers.
# ---------------------------------------------------------------------------

# Bound execution with `timeout -k 5 30` and diagnose its exit status exactly.
run_bounded() {
  local out="$1"
  shift
  set +e
  timeout -k 5 30 "$@" >"$out" 2>&1
  BOUNDED_RC=$?
  set -e
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

# Writes /etc/granary/mounts/<instance>.env: the four lines
# verbatim, plus GRAN_MOUNTPOINT, plus optional GRAN_MOUNT_EXTRA.
# $4 overrides GRAN_ENDPOINT (case 11's hostname negative).
write_env() {
  local instance="$1" mountpoint="$2" extra="${3:-}" endpoint="${4:-$STACK_ENDPOINT}"
  local path="/etc/granary/mounts/${instance}.env"
  mkdir -p /etc/granary/mounts
  {
    printf 'GRAN_ENDPOINT=%s\n' "$endpoint"
    printf 'GRAN_PIN=%s\n' "$STACK_PIN"
    printf 'GRAN_ROOT_KEY=%s\n' "$STACK_ROOT_KEY"
    printf 'GRAN_VOLUME=%s\n' "$STACK_VOLUME"
    printf 'GRAN_MOUNTPOINT=%s\n' "$mountpoint"
    if [ -n "$extra" ]; then
      printf 'GRAN_MOUNT_EXTRA=%s\n' "$extra"
    fi
  } >"$path"
  chmod 0644 "$path"
  ENV_FILES_WRITTEN+=("$path")
}

remove_env() {
  local instance="$1"
  rm -f -- "/etc/granary/mounts/${instance}.env"
}

wait_for_unit_state() {
  local unit="$1" want="$2" i state
  state=""
  for i in $(seq 1 100); do
    state="$(systemctl show -p ActiveState --value "$unit" 2>/dev/null || true)"
    case " $want " in
      *" $state "*) printf '%s\n' "$state"; return 0 ;;
    esac
    sleep 0.1
  done
  printf '%s\n' "$state"
  return 1
}

wait_for_row() {
  local path="$1" i
  for i in $(seq 1 100); do
    sleep 0.1
    if mountpoint -q "$path" 2>/dev/null && mount_is_ready "$path"; then
      return 0
    fi
  done
  return 1
}

mainpid_of() {
  systemctl show -p MainPID --value "$1"
}

# python3 errno probe: prints "errno=<n>" on stdout ("errno=0" on success).
python3_errno_probe() {
  local path="$1" mode="$2"
  if [ "$mode" = w ]; then
    python3 - "$path" <<'PY'
import sys, os
path = sys.argv[1]
try:
    fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o644)
    os.close(fd)
    print("errno=0")
except OSError as e:
    print("errno=%d" % e.errno)
PY
  else
    python3 - "$path" <<'PY'
import sys, os
path = sys.argv[1]
try:
    with open(path, "rb") as f:
        f.read()
    print("errno=0")
except OSError as e:
    print("errno=%d" % e.errno)
PY
  fi
}

# The exact-errno oracle: "the operation failed" is the
# degenerate this refuses -- ordinary mode bits give EACCES on a write too.
expect_errno() {
  local got_line="$1" want="$2" label="$3" got
  got="$(printf '%s\n' "$got_line" | sed -n 's/^errno=\([0-9-]*\)$/\1/p')"
  [ -n "$got" ] || die "$label: probe produced no parseable errno line: '$got_line'"
  [ "$got" = "$want" ] \
    || die "$label: FAIL got errno=$got want errno=$want -- the operation merely failing is not sufficient; the exact errno must match, or a permissions accident could be scored as the read-only guarantee"
}

# CacheDirectory=granary/%i resolves to /var/cache/granary/<instance>
# and PERSISTS across systemd starts of the same instance by design (that
# is the whole point of CacheDirectory=) -- but this check restarts the
# SAME instance repeatedly with DIFFERENT effective configuration (case 1
# vs case 11's different endpoint host). gran's own cache correctly
# refuses that as "incompatible cache: marker mismatch" (a real safety
# property, not a bug) rather than silently serving stale content, so
# EVERY real start in this check clears the cache dir first -- each case
# gets a cold, compatible cache, matching what a fresh instance would see.
clear_cache_dir() {
  rm -rf -- "/var/cache/granary/${1}"
}

echo "unit-check: preflight OK"

# ===========================================================================
# Install: the binary (idempotent, stamped), the unit (byte-verbatim, hashed).
# ===========================================================================
if [ -e /usr/local/bin/gran ] && [ ! -f "$BIN_STAMP" ]; then
  die "refused -- /usr/local/bin/gran already exists and does not carry this harness's own stamp ($BIN_STAMP). An unstamped existing file is refused by name rather than silently overwritten."
fi
if [ -f "$BIN_STAMP" ]; then
  rm -f -- /usr/local/bin/gran
fi
if [ ! -e /usr/local/bin/gran ]; then
  BIN_INSTALLED_FRESH=1
fi
install -m 0755 -- "$GRAN_BIN" /usr/local/bin/gran
: >"$BIN_STAMP"
echo "unit-check: installed /usr/local/bin/gran via install(1) (never mv from /tmp -- SELinux can refuse execution with 203/EXEC)"

UNIT_SHA_REPO="$(sha256sum "$UNIT_FILE" | awk '{print $1}')"
mkdir -p /run/systemd/system
# refuse rather than clobber. /run/systemd/system is tmpfs, but a
# pre-existing gran-mount@.service there is still real state this harness
# did not put -- a prior real deployment's runtime unit, or a crashed
# earlier run of this very check that never reached its own cleanup trap.
# Overwriting it silently and then deleting it at exit either destroys an
# operator's runtime override or papers over the crashed run rather than
# surfacing it.
if [ -e /run/systemd/system/gran-mount@.service ]; then
  die "refused -- /run/systemd/system/gran-mount@.service already exists and this harness did not just create it. Refusing to overwrite a pre-existing runtime unit; if this is a leftover from a prior run of this check that crashed before its own cleanup, remove it by hand first."
fi
cp -- "$UNIT_FILE" /run/systemd/system/gran-mount@.service
UNIT_INSTALLED=1
UNIT_SHA_INSTALLED="$(sha256sum /run/systemd/system/gran-mount@.service | awk '{print $1}')"
[ "$UNIT_SHA_REPO" = "$UNIT_SHA_INSTALLED" ] \
  || die "refused -- installed unit file sha256 ($UNIT_SHA_INSTALLED) does not match the repo file ($UNIT_SHA_REPO)"
systemctl daemon-reload
echo "unit-check: installed /run/systemd/system/gran-mount@.service, sha256 $UNIT_SHA_REPO verified byte-identical to $UNIT_FILE"

MOUNT_PARENT="$(mktemp -d /run/unit-check.XXXXXX)"
# mktemp -d creates its directory 0700 (owner-only) by design -- left
# alone, that alone blocks an unprivileged user's traversal into
# MOUNT_DIR regardless of whether the MOUNT itself enforces allow_other,
# so case 2's own oracle would measure the wrong mechanism (the parent
# directory's mode, not the mount's). chmod 0755 here so the mount's own
# default_permissions/allow_other enforcement -- not this scratch
# directory's own permissions -- is what actually decides access.
chmod 0755 "$MOUNT_PARENT"
MOUNT_DIR="$MOUNT_PARENT/mnt"
mkdir -p "$MOUNT_DIR"
echo "unit-check: mountpoint dir $MOUNT_DIR"

# ===========================================================================
# Case 1 -- visible-outside.
# ===========================================================================
c1_visible_outside() {
  write_env "$INSTANCE" "$MOUNT_DIR"
  INSTANCES_STARTED+=("$INSTANCE")
  clear_cache_dir "$INSTANCE"
  systemctl start "gran-mount@${INSTANCE}.service" \
    || die "case1: refused -- systemctl start gran-mount@${INSTANCE} failed (rc=$?)"
  wait_for_row "$MOUNT_DIR" \
    || { journalctl -u "gran-mount@${INSTANCE}.service" --no-pager -n 200 >&2; die "case1: refused -- mount did not become ready within 10s"; }

  local pid
  pid="$(mainpid_of "gran-mount@${INSTANCE}.service")"
  [ -n "$pid" ] && [ "$pid" != 0 ] || die "case1: refused -- could not read MainPID"

  local ns_pid ns_self ns_pid1
  ns_pid="$(readlink "/proc/$pid/ns/mnt")" || die "case1: cannot read /proc/$pid/ns/mnt"
  ns_self="$(readlink /proc/self/ns/mnt)" || die "case1: cannot read /proc/self/ns/mnt"
  ns_pid1="$(readlink /proc/1/ns/mnt)" || die "case1: cannot read /proc/1/ns/mnt"
  [ "$ns_pid" = "$ns_self" ] && [ "$ns_self" = "$ns_pid1" ] \
    || die "case1: FAIL -- mount namespace mismatch: MainPID=$ns_pid self=$ns_self pid1=$ns_pid1"
  echo "UNIT: namespace-identity PASS (MainPID/self/pid1 share $ns_self)"

  local cg_pid cg_self
  cg_pid="$(cat "/proc/$pid/cgroup")" || die "case1: cannot read /proc/$pid/cgroup"
  cg_self="$(cat /proc/self/cgroup)" || die "case1: cannot read /proc/self/cgroup"
  [ "$cg_pid" != "$cg_self" ] \
    || die "case1: FAIL -- cgroup did NOT differ between MainPID and this check shell (an additional assertion, not the visibility property itself: namespaces, not cgroups, govern visibility)"
  echo "UNIT: cgroup-differs PASS"

  local expect_file cmp_out
  expect_file="$(mktemp)"
  printf '%s' "$EXPECTED_SENTINEL" >"$expect_file"
  cmp_out="$(mktemp)"
  run_bounded "$cmp_out" cmp "$expect_file" "$MOUNT_DIR/sentinel.txt"
  if [ "$BOUNDED_RC" -ne 0 ]; then
    echo "case1: cmp output:" >&2
    cat "$cmp_out" >&2
    rm -f "$expect_file" "$cmp_out"
    die "case1: FAIL -- cmp of the EXTERNALLY-SUPPLIED expected sentinel against \$MNT/sentinel.txt did not match (rc=$BOUNDED_RC); a mount serving empty or wrong data must not pass here"
  fi
  rm -f "$expect_file" "$cmp_out"
  echo "UNIT: sentinel-cmp PASS"

  local exec_out exec_rc
  exec_out="$(mktemp)"
  run_bounded "$exec_out" "$MOUNT_DIR/bin/hello.sh"
  [ "$BOUNDED_RC" -eq 0 ] || die "case1: FAIL -- exec of the planted binary failed or hung (rc=$BOUNDED_RC)"
  grep -qF "$MOUNT_DIR/bin/hello.sh" "$exec_out" \
    || die "case1: FAIL -- planted binary's \$0 output did not name a path under the mountpoint: $(cat "$exec_out")"
  rm -f "$exec_out"
  echo "UNIT: exec-under-mount PASS"

  echo "UNIT: visible-outside PASS"
}

# ===========================================================================
# Case 3 -- stop. Stops case 1's instance and verifies the stop itself.
# ===========================================================================
c3_stop() {
  systemctl stop "gran-mount@${INSTANCE}.service" \
    || die "case3: refused -- systemctl stop gran-mount@${INSTANCE} failed (rc=$?)"
  local result execstatus
  result="$(systemctl show -p Result --value "gran-mount@${INSTANCE}.service")"
  execstatus="$(systemctl show -p ExecMainStatus --value "gran-mount@${INSTANCE}.service")"
  [ "$result" = success ] || die "case3: FAIL -- Result=$result, want success"
  [ "$execstatus" = 0 ] || die "case3: FAIL -- ExecMainStatus=$execstatus, want 0"
  if read_mount_row "$MOUNT_DIR" >/dev/null 2>&1; then
    die "case3: FAIL -- a mount-table row survives after systemctl stop"
  fi
  local loaded
  loaded="$(systemctl list-units --all --no-legend --plain "gran-mount@${INSTANCE}.service" 2>/dev/null)"
  [ -z "$loaded" ] || die "case3: FAIL -- gran-mount@${INSTANCE}.service is still loaded after stop: $loaded"
  remove_env "$INSTANCE"
  echo "UNIT: stop PASS"
}

# ===========================================================================
# Case 2 -- allow-other. Two fresh starts of the SAME instance: without the
# flag (EACCES for an unprivileged reader), then with it (read+exec succeed,
# write still fails EROFS). "A second instance" = the second gran-mount@
# start this check performs, with one instance name per volume.
# ===========================================================================
c2_allow_other() {
  # Self-check first: expect_errno must REJECT a mismatched errno. This is
  # the check's OWN negative on its own oracle -- "the operation failed" is
  # not enough; the exact errno must be checked, and this proves the checker
  # actually distinguishes 13 from 30 rather than accepting either as "it
  # failed".
  if (expect_errno "errno=13" "30" "case2-self-check") >/dev/null 2>&1; then
    die "case2: refused -- expect_errno WRONGLY ACCEPTED errno=13 when 30 was wanted; the errno oracle itself is not discriminating"
  fi
  echo "UNIT: allow-other errno-oracle-self-check PASS"

  # Sub-run 1: no allow-other. Unprivileged read must get EACCES.
  write_env "$INSTANCE" "$MOUNT_DIR"
  INSTANCES_STARTED+=("$INSTANCE")
  clear_cache_dir "$INSTANCE"
  systemctl start "gran-mount@${INSTANCE}.service" \
    || die "case2: refused -- systemctl start (no allow-other) failed (rc=$?)"
  wait_for_row "$MOUNT_DIR" \
    || { journalctl -u "gran-mount@${INSTANCE}.service" --no-pager -n 200 >&2; die "case2: refused -- mount (no allow-other) did not become ready"; }
  local noao_probe
  noao_probe="$(runuser -u nobody -- python3 -c "
import os
try:
    with open('$MOUNT_DIR/sentinel.txt','rb') as f: f.read()
    print('errno=0')
except OSError as e:
    print('errno=%d' % e.errno)
")"
  expect_errno "$noao_probe" 13 "case2-no-allow-other-read"
  systemctl stop "gran-mount@${INSTANCE}.service" || die "case2: refused -- stop (no allow-other) failed"
  remove_env "$INSTANCE"
  echo "UNIT: allow-other no-flag-eacces PASS"

  # Sub-run 2: --allow-other. Unprivileged read+exec succeed; write is EROFS.
  write_env "$INSTANCE" "$MOUNT_DIR" "--allow-other"
  clear_cache_dir "$INSTANCE"
  systemctl start "gran-mount@${INSTANCE}.service" \
    || die "case2: refused -- systemctl start (allow-other) failed (rc=$?)"
  wait_for_row "$MOUNT_DIR" \
    || { journalctl -u "gran-mount@${INSTANCE}.service" --no-pager -n 200 >&2; die "case2: refused -- mount (allow-other) did not become ready"; }

  local ao_read_out
  ao_read_out="$(runuser -u nobody -- cat "$MOUNT_DIR/sentinel.txt")" \
    || die "case2: FAIL -- unprivileged read under --allow-other failed"
  [ "$ao_read_out" = "$EXPECTED_SENTINEL" ] \
    || die "case2: FAIL -- unprivileged read under --allow-other returned wrong content: '$ao_read_out'"
  local ao_exec_rc
  set +e
  runuser -u nobody -- "$MOUNT_DIR/bin/hello.sh" >/dev/null 2>&1
  ao_exec_rc=$?
  set -e
  [ "$ao_exec_rc" -eq 0 ] || die "case2: FAIL -- unprivileged exec under --allow-other failed (rc=$ao_exec_rc)"

  local ao_write_probe
  ao_write_probe="$(runuser -u nobody -- python3 -c "
import os
try:
    fd = os.open('$MOUNT_DIR/should-not-exist', os.O_CREAT | os.O_WRONLY, 0o644)
    os.close(fd)
    print('errno=0')
except OSError as e:
    print('errno=%d' % e.errno)
")"
  expect_errno "$ao_write_probe" 30 "case2-allow-other-write"

  systemctl stop "gran-mount@${INSTANCE}.service" || die "case2: refused -- stop (allow-other) failed"
  remove_env "$INSTANCE"
  echo "UNIT: allow-other-flag PASS"

  echo "UNIT: allow-other PASS"
}

# ===========================================================================
# Case 4 -- NEGATIVE, namespace (two drop-ins). The mount succeeds INSIDE
# the unit's own namespace; visibility from OUTSIDE is what must fail.
# ===========================================================================
c4_one_namespace_negative() {
  local label="$1" dropin_body="$2"
  local dropin_dir="/run/systemd/system/gran-mount@${INSTANCE}.service.d"
  mkdir -p "$dropin_dir"
  DROPIN_DIRS+=("$dropin_dir")
  printf '%s\n' "$dropin_body" >"$dropin_dir/override.conf"
  systemctl daemon-reload

  write_env "$INSTANCE" "$MOUNT_DIR"
  INSTANCES_STARTED+=("$INSTANCE")
  clear_cache_dir "$INSTANCE"
  systemctl start "gran-mount@${INSTANCE}.service" \
    || die "case4-$label: refused -- systemctl start failed unexpectedly (rc=$?); this drop-in must let the mount SUCCEED, only in its own namespace"

  local pid i state
  pid=""
  for i in $(seq 1 100); do
    pid="$(mainpid_of "gran-mount@${INSTANCE}.service")"
    [ -n "$pid" ] && [ "$pid" != 0 ] && break
    sleep 0.1
  done
  [ -n "$pid" ] && [ "$pid" != 0 ] || die "case4-$label: refused -- could not read a MainPID"

  # bounded poll for the daemon's own steady state, matching the
  # positive case's 10s bound (seq 1 100 * sleep 0.1) instead of a fixed 1s
  # sleep that could under-wait on a loaded host. Polls THROUGH nsenter
  # (the only vantage point that can see the mount at all here -- that is
  # the whole point of the negative) and keeps the result for the
  # mount-visible-inside-unit-ns assertion below, so this is the same
  # nsenter call rather than a second one re-querying the same fact.
  local inside="" i2
  for i2 in $(seq 1 100); do
    inside="$(nsenter -t "$pid" -m findmnt -rn -o SOURCE,FSTYPE --mountpoint "$MOUNT_DIR" 2>/dev/null || true)"
    [ "$inside" = "gran fuse" ] && break
    sleep 0.1
  done

  local ns_pid ns_self
  ns_pid="$(readlink "/proc/$pid/ns/mnt" 2>/dev/null || true)"
  ns_self="$(readlink /proc/self/ns/mnt)"
  [ -n "$ns_pid" ] || die "case4-$label: refused -- MainPID $pid has no /proc/$pid/ns/mnt (already exited?); the perturbation did not land as expected"
  [ "$ns_pid" != "$ns_self" ] \
    || die "case4-$label: DID NOT LAND -- MainPID's mount namespace equals this shell's; the drop-in did not isolate the unit as expected"

  if read_mount_row "$MOUNT_DIR" >/dev/null 2>&1; then
    die "case4-$label: DID NOT LAND -- a mount-table row is visible from OUTSIDE the unit despite the namespacing drop-in"
  fi
  # This IS the expected, deliberately-triggered condition; the
  # dispatcher checks this literal line as evidence the negative fired.
  echo "UNIT: FAIL mount invisible outside the unit"

  case "$inside" in
    "gran fuse") : ;;
    *) die "case4-$label: DID NOT LAND -- nsenter into MainPID's namespace does not show 'gran fuse' at $MOUNT_DIR within the 10s bound (got '$inside'); the mount itself must have happened, only visibility failed" ;;
  esac
  echo "UNIT: mount-visible-inside-unit-ns PASS ($label)"

  # Wait for the SAME instance to become inactive or
  # failed before reusing it for the next namespace
  # negative. A start racing a stop still in flight
  # would test the wrong state. Capture the stop
  # status and poll through wait_for_unit_state under
  # its bound before handing the instance back.
  local stop_rc=0 poststate
  systemctl stop "gran-mount@${INSTANCE}.service" >/dev/null 2>&1 || stop_rc=$?
  poststate="$(wait_for_unit_state "gran-mount@${INSTANCE}.service" "inactive failed" || true)"
  case "$poststate" in
    inactive | failed) : ;;
    *) die "case4-$label: refused -- gran-mount@${INSTANCE} did not reach inactive/failed within the bound after stop (state=$poststate, stop rc=$stop_rc); reusing this instance for the next namespace negative without verifying its inactivity would race the next start" ;;
  esac
  systemctl reset-failed "gran-mount@${INSTANCE}.service" >/dev/null 2>&1 || true
  remove_env "$INSTANCE"
  rm -rf -- "$dropin_dir"
  DROPIN_DIRS=("${DROPIN_DIRS[@]/$dropin_dir}")
  systemctl daemon-reload

  echo "UNIT: namespace-negative-$label PASS"
}

c4_namespace_negatives() {
  c4_one_namespace_negative "privatemounts" $'[Service]\nPrivateMounts=yes\n'
  c4_one_namespace_negative "protectsystem" $'[Service]\nProtectSystem=strict\nPrivateMounts=no\n'
}

# ===========================================================================
# Case 5 -- NEGATIVE, capability.
# ===========================================================================
c5_capability_negative() {
  local dropin_dir="/run/systemd/system/gran-mount@${INSTANCE}.service.d"
  mkdir -p "$dropin_dir"
  DROPIN_DIRS+=("$dropin_dir")
  printf '[Service]\nCapabilityBoundingSet=\n' >"$dropin_dir/override.conf"
  systemctl daemon-reload

  write_env "$INSTANCE" "$MOUNT_DIR"
  INSTANCES_STARTED+=("$INSTANCE")
  clear_cache_dir "$INSTANCE"
  systemctl start "gran-mount@${INSTANCE}.service" >/dev/null 2>&1 || true

  local state
  state="$(wait_for_unit_state "gran-mount@${INSTANCE}.service" "failed" || true)"
  [ "$state" = failed ] \
    || die "case5: DID NOT LAND -- unit did not reach ActiveState=failed with CapabilityBoundingSet= dropped (state=$state)"

  local journal
  journal="$(journalctl -u "gran-mount@${INSTANCE}.service" --no-pager -n 200 2>/dev/null || true)"
  printf '%s\n' "$journal" | grep -qi 'Operation not permitted' \
    || die "case5: DID NOT LAND -- journal does not mention 'Operation not permitted': $journal"

  if read_mount_row "$MOUNT_DIR" >/dev/null 2>&1; then
    die "case5: FAIL -- a mount row exists despite the capability negative"
  fi

  systemctl reset-failed "gran-mount@${INSTANCE}.service" >/dev/null 2>&1 || true
  remove_env "$INSTANCE"
  rm -rf -- "$dropin_dir"
  DROPIN_DIRS=("${DROPIN_DIRS[@]/$dropin_dir}")
  systemctl daemon-reload

  echo "UNIT: capability-negative PASS"
}

# ===========================================================================
# Case 6 -- NEGATIVE, trust downgrade through the env file.
# ===========================================================================
c6_trust_downgrade() {
  write_env "$INSTANCE" "$MOUNT_DIR" "--trust-server"
  INSTANCES_STARTED+=("$INSTANCE")
  clear_cache_dir "$INSTANCE"
  systemctl start "gran-mount@${INSTANCE}.service" >/dev/null 2>&1 || true

  local state
  state="$(wait_for_unit_state "gran-mount@${INSTANCE}.service" "failed" || true)"
  [ "$state" = failed ] \
    || die "case6: DID NOT LAND -- unit did not reach ActiveState=failed with GRAN_MOUNT_EXTRA=--trust-server (state=$state)"

  local execstatus journal
  execstatus="$(systemctl show -p ExecMainStatus --value "gran-mount@${INSTANCE}.service")"
  [ "$execstatus" = 2 ] || die "case6: DID NOT LAND -- ExecMainStatus=$execstatus, want 2"
  journal="$(journalctl -u "gran-mount@${INSTANCE}.service" --no-pager -n 200 2>/dev/null || true)"
  printf '%s\n' "$journal" | grep -qi 'more than one of --root-key' \
    || die "case6: DID NOT LAND -- journal does not name the trust-mode conflict: $journal"

  if read_mount_row "$MOUNT_DIR" >/dev/null 2>&1; then
    die "case6: FAIL -- a mount row exists despite the trust-downgrade negative"
  fi

  systemctl reset-failed "gran-mount@${INSTANCE}.service" >/dev/null 2>&1 || true
  remove_env "$INSTANCE"

  echo "UNIT: trust-downgrade-negative PASS"
}

# ===========================================================================
# Case 7 -- NEGATIVE, missing env file.
# ===========================================================================
c7_missing_env() {
  local noenv_instance="${INSTANCE}x7"
  rm -f -- "/etc/granary/mounts/${noenv_instance}.env"
  INSTANCES_STARTED+=("$noenv_instance")
  set +e
  systemctl start "gran-mount@${noenv_instance}.service" >/dev/null 2>&1
  local rc=$?
  set -e
  [ "$rc" -ne 0 ] || die "case7: DID NOT LAND -- systemctl start succeeded with no env file present"

  local journal
  journal="$(journalctl -u "gran-mount@${noenv_instance}.service" --no-pager -n 200 2>/dev/null || true)"
  printf '%s\n' "$journal" | grep -qi 'Failed to load environment files' \
    || die "case7: DID NOT LAND -- journal does not say 'Failed to load environment files': $journal"

  systemctl reset-failed "gran-mount@${noenv_instance}.service" >/dev/null 2>&1 || true
  echo "UNIT: missing-env-negative PASS"
}

# ===========================================================================
# Case 8 -- NEGATIVE, hostile instance (%i, never %I).
# ===========================================================================
c8_hostile_instance() {
  local hostile='\x2e\x2e\x2fetc\x2fpasswd'

  # never clobber a file this run did not create -- refuse BY NAME
  # rather than overwrite what might be an operator's own configuration.
  # `-e || -L`, never `-e` alone: `-e` FOLLOWS symlinks, so a DANGLING symlink
  # at either path reads as ABSENT — the guard would then clobber it and
  # cleanup would delete it. `-L` is what makes "anything at all is here" true.
  { [ -e "$PASSWD_ENV" ] || [ -L "$PASSWD_ENV" ]; } \
    && die "case8: refused -- $PASSWD_ENV already exists (or is a symlink); this harness will not overwrite a pre-existing path. Remove it by hand first if it is safe to."
  { [ -e "$TRAVERSAL_ENV" ] || [ -L "$TRAVERSAL_ENV" ]; } \
    && die "case8: refused -- $TRAVERSAL_ENV already exists (or is a symlink); this harness will not overwrite a pre-existing path. Remove it by hand first if it is safe to."
  if { [ -e /etc/granary/etc ] || [ -L /etc/granary/etc ]; } && [ ! -d /etc/granary/etc ]; then
    die "case8: refused -- /etc/granary/etc exists and is not a directory"
  fi
  [ -d /etc/granary/etc ] && TRAVERSAL_DIR_PREEXISTED=1

  # The additional decoy path. The shipped %i
  # specifier does not reach this path for the
  # hostile instance, so this decoy alone proves
  # nothing about a %i-to-%I regression. The
  # traversal decoy below is placed at the
  # path that regression would actually read.
  printf 'GRAN_ENDPOINT=%s\nGRAN_PIN=%s\nGRAN_ROOT_KEY=%s\nGRAN_VOLUME=should-never-be-read-by-unit-check\nGRAN_MOUNTPOINT=%s\n' \
    "$STACK_ENDPOINT" "$STACK_PIN" "$STACK_ROOT_KEY" "$MOUNT_DIR" >"$PASSWD_ENV"
  chmod 0644 "$PASSWD_ENV"
  PASSWD_ENV_CREATED=1

  # THE LOAD-BEARING DECOY. EnvironmentFile=
  # in the shipped unit is /etc/granary/mounts/%i.env -- %i is the
  # STILL-ESCAPED instance, so for this hostile instance it is the literal
  # string '\x2e\x2e\x2fetc\x2fpasswd', never unescaped, and the lookup
  # this case actually exercises against the shipped file is a harmless
  # nonexistent filename. But the REGRESSION this case exists to catch is
  # %I (the UNESCAPED specifier) reaching that same position: %I for this
  # instance is '../etc/passwd', so a regressed
  # EnvironmentFile=/etc/granary/mounts/%I.env resolves to
  # /etc/granary/mounts/../etc/passwd.env, i.e. /etc/granary/etc/passwd.env.
  # THAT is the path a %i -> %I regression would actually read -- plant the
  # decoy there, or the negative can never fire under the very regression
  # it claims to detect.
  mkdir -p /etc/granary/etc
  printf 'GRAN_ENDPOINT=%s\nGRAN_PIN=%s\nGRAN_ROOT_KEY=%s\nGRAN_VOLUME=should-never-be-read-by-unit-check-traversal\nGRAN_MOUNTPOINT=%s\n' \
    "$STACK_ENDPOINT" "$STACK_PIN" "$STACK_ROOT_KEY" "$MOUNT_DIR" >"$TRAVERSAL_ENV"
  chmod 0644 "$TRAVERSAL_ENV"
  TRAVERSAL_ENV_CREATED=1

  INSTANCES_STARTED+=("$hostile")
  set +e
  systemctl start "gran-mount@${hostile}.service" >/dev/null 2>&1
  local rc=$?
  set -e
  [ "$rc" -ne 0 ] || die "case8: DID NOT LAND -- systemctl start succeeded for the hostile instance"

  # neither check below reaches `die` through a piped grep's exit
  # status. Under `set -o pipefail`, `grep -q`'s own early exit on a match
  # can SIGPIPE the writer ahead of it in a `printf | grep -q` pipe, and
  # pipefail then reports the PIPELINE's exit status as nonzero even though
  # grep itself matched -- a `|| die` misreads that as "no match" (a noisy
  # false refusal), and the `&&  die` form used for the second check is the
  # DANGEROUS misread: it would SKIP `die` on a genuine match, the exact
  # fail-open this case exists to avoid. The journal is written to a file
  # and grepped directly instead -- no pipe, no ambiguity, the exit status
  # is grep's own.
  local journal journal_file
  journal="$(journalctl -u "gran-mount@${hostile}.service" --no-pager -n 200 2>/dev/null || true)"
  journal_file="$(mktemp)"
  printf '%s\n' "$journal" >"$journal_file"

  if ! grep -qi 'Failed to load environment files' "$journal_file"; then
    rm -f -- "$journal_file"
    die "case8: DID NOT LAND -- journal does not say 'Failed to load environment files': $journal"
  fi
  if grep -qF 'should-never-be-read-by-unit-check-traversal' "$journal_file"; then
    rm -f -- "$journal_file"
    die "case8: FAIL -- the LOAD-BEARING decoy's volume name (planted at $TRAVERSAL_ENV, the path %I would actually resolve to) appears in the journal; a %i -> %I regression would explain this, and %i must never resolve to it"
  fi
  if grep -qF 'should-never-be-read-by-unit-check' "$journal_file"; then
    rm -f -- "$journal_file"
    die "case8: FAIL -- the original decoy's volume name appears in the journal; it was read (an %I-shaped traversal would explain this; %i must never resolve to it)"
  fi
  rm -f -- "$journal_file"

  systemctl reset-failed "gran-mount@${hostile}.service" >/dev/null 2>&1 || true
  rm -f -- "$PASSWD_ENV"
  rm -f -- "$TRAVERSAL_ENV"
  if [ "$TRAVERSAL_DIR_PREEXISTED" -eq 0 ]; then
    rmdir -- /etc/granary/etc 2>/dev/null || true
  fi
  echo "UNIT: hostile-instance-negative PASS"
}

# ===========================================================================
# Case 9 -- the forbidden-directive lint, on the FILE. Active assignments
# only, on non-comment lines -- the unit's forbidden-directive comment necessarily
# contains every string this hunts.
# ===========================================================================
FORBIDDEN_DIRECTIVES=(
  'PrivateMounts=' 'ProtectSystem=' 'ProtectHome=' 'PrivateTmp='
  'ReadOnlyPaths=' 'ReadWritePaths=' 'InaccessiblePaths=' 'ExecPaths='
  'NoExecPaths=' 'BindPaths=' 'BindReadOnlyPaths=' 'TemporaryFileSystem='
  'PrivateDevices=' 'ProtectKernelTunables=' 'ProtectKernelModules='
  'ProtectKernelLogs=' 'ProtectControlGroups=' 'ProtectProc=' 'ProcSubset='
  'MountAPIVFS=' 'RootDirectory=' 'RootImage=' 'DynamicUser=' 'PrivateUsers='
  'PrivateNetwork=' 'MountFlags='
)

lint_forbidden() {
  local file="$1" dirs names d
  # FORBIDDEN_DIRECTIVES entries carry their own trailing '=' (e.g.
  # 'PrivateMounts='), so a literal alternation built directly from them
  # anchors "name immediately followed by =" --
  # systemd itself strips whitespace around '=' before
  # parsing, so 'PrivateMounts = yes' is LEGAL,
  # ACTIVE systemd and this lint must not miss it. Strip the trailing '='
  # off each name here and require it back explicitly as "optional
  # whitespace, then =", rather than baking a zero-whitespace assumption
  # into the alternation.
  names=()
  for d in "${FORBIDDEN_DIRECTIVES[@]}"; do
    names+=("${d%=}")
  done
  dirs="$(printf '%s|' "${names[@]}")"
  dirs="${dirs%|}"
  awk -v dirs="$dirs" '
    {
      line = $0
      stripped = line
      sub(/^[ \t]+/, "", stripped)
      if (stripped ~ /^#/) next
      if (match(line, "^[ \t]*(" dirs ")[ \t]*=")) {
        print NR ": " line
        found = 1
      }
    }
    END { exit(found ? 1 : 0) }
  ' "$file"
}

c9_lint() {
  local out
  # Assert the forbidden-directive floor before running the
  # cases. Mutants cover only part of the list, so they
  # cannot detect every partial shrink: a smaller array can
  # leave directives unchecked while those mutants still
  # fail as expected. The floor makes that shrink visible.
  if [ "${#FORBIDDEN_DIRECTIVES[@]}" -lt 26 ]; then
    die "case9: refused -- FORBIDDEN_DIRECTIVES holds ${#FORBIDDEN_DIRECTIVES[@]} entries, want at least 26; every assertion in this case iterates that array, so a shrunken set would pass while missing the directives it dropped"
  fi
  out="$(mktemp)"
  if lint_forbidden "$UNIT_FILE" >"$out" 2>&1; then
    :
  else
    die "case9: refused -- the SHIPPED unit file trips the forbidden-directive lint (it must be clean): $(cat "$out")"
  fi
  echo "UNIT: lint-clean-on-shipped-file PASS"

  local mutant1
  mutant1="$(mktemp)"
  { cat "$UNIT_FILE"; printf 'ProtectHome=yes\n'; } >"$mutant1"
  if lint_forbidden "$mutant1" >"$out" 2>&1; then
    die "case9: DID NOT LAND -- a bare 'ProtectHome=yes' appended to a copy was not flagged"
  fi
  grep -qF 'ProtectHome=yes' "$out" || die "case9: refused -- lint refusal did not NAME the offending bare line: $(cat "$out")"
  echo "UNIT: lint-negative-bare PASS"

  local mutant2
  mutant2="$(mktemp)"
  { cat "$UNIT_FILE"; printf '  ProtectSystem=strict\n'; } >"$mutant2"
  if lint_forbidden "$mutant2" >"$out" 2>&1; then
    die "case9: DID NOT LAND -- an INDENTED '  ProtectSystem=strict' appended to a copy was not flagged (leading whitespace must not bypass the lint)"
  fi
  grep -qF 'ProtectSystem=strict' "$out" || die "case9: refused -- lint refusal did not NAME the offending indented line: $(cat "$out")"
  echo "UNIT: lint-negative-indented PASS"

  # an INDENTED *and* SPACED-around-'=' variant -- 'PrivateMounts =
  # yes' is legal, active systemd (it strips whitespace around '=' before
  # parsing) and must not slip past a lint anchored on "name immediately
  # followed by =".
  local mutant3
  mutant3="$(mktemp)"
  { cat "$UNIT_FILE"; printf '  PrivateMounts = yes\n'; } >"$mutant3"
  if lint_forbidden "$mutant3" >"$out" 2>&1; then
    die "case9: DID NOT LAND -- an INDENTED-AND-SPACED '  PrivateMounts = yes' appended to a copy was not flagged (whitespace before '=' must not bypass the lint)"
  fi
  grep -qF 'PrivateMounts = yes' "$out" || die "case9: refused -- lint refusal did not NAME the offending indented-and-spaced line: $(cat "$out")"
  echo "UNIT: lint-negative-indented-and-spaced PASS"

  rm -f -- "$out" "$mutant1" "$mutant2" "$mutant3"
  echo "UNIT: forbidden-directive-lint PASS"
}

# ===========================================================================
# Case 10 -- static pins, one per REQUIRED assignment in the unit, each with its
# own deletion mutant. Not a sample.
# ===========================================================================
# REQUIRED_PIN_SECTIONS parallels REQUIRED_PINS
# by index, with its length asserted below. Each
# directive must appear in the specified section:
# finding its exact text under another section
# does not establish that systemd will apply
# it. The [Unit] directives are included
# alongside the service and install directives.
REQUIRED_PINS=(
  'Description=granary read-only mount %i'
  'After=network-online.target'
  'Wants=network-online.target'
  'Type=exec'
  'EnvironmentFile=/etc/granary/mounts/%i.env'
  'CacheDirectory=granary/%i'
  'CacheDirectoryMode=0700'
  'ExecStart=/usr/local/bin/gran mount %i ${GRAN_MOUNTPOINT} --endpoint ${GRAN_ENDPOINT} --pin ${GRAN_PIN} --root-key ${GRAN_ROOT_KEY} --cache-dir ${CACHE_DIRECTORY} --foreground $GRAN_MOUNT_EXTRA'
  'Restart=no'
  'NoNewPrivileges=yes'
  'CapabilityBoundingSet=CAP_SYS_ADMIN'
  'RestrictNamespaces=yes'
  'RestrictRealtime=yes'
  'RestrictSUIDSGID=yes'
  'LockPersonality=yes'
  'MemoryDenyWriteExecute=yes'
  'ProtectClock=yes'
  'ProtectHostname=yes'
  'SystemCallArchitectures=native'
  'SystemCallFilter=@system-service @mount'
  'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX'
  'DevicePolicy=closed'
  'DeviceAllow=/dev/fuse rw'
  'UMask=0077'
  'WantedBy=multi-user.target'
)
REQUIRED_PIN_SECTIONS=(
  '[Unit]' '[Unit]' '[Unit]'
  '[Service]' '[Service]' '[Service]' '[Service]' '[Service]' '[Service]'
  '[Service]' '[Service]' '[Service]' '[Service]' '[Service]' '[Service]'
  '[Service]' '[Service]' '[Service]' '[Service]' '[Service]' '[Service]'
  '[Service]' '[Service]' '[Service]'
  '[Install]'
)

# is $2 present, as an exact line, WITHIN the block headed by $3 (a
# literal "[Section]" header) in $1 -- not merely present anywhere in the
# file. A directive that is syntactically correct but sits under the wrong
# systemd section is inert (systemd ignores it there) yet a plain
# grep -qxF over the whole file would still call it "pinned".
line_in_section() {
  local file="$1" line="$2" section="$3"
  awk -v want_line="$line" -v want_section="$section" '
    /^\[[A-Za-z]+\]/ { cursec = $0; next }
    { if (cursec == want_section && $0 == want_line) { found = 1 } }
    END { exit(found ? 0 : 1) }
  ' "$file"
}

# Returns 0 (clean) or 1 with the first missing/misplaced pin (or the %I
# violation) printed by name -- the "named by the check" requirement.
find_missing_pin() {
  local file="$1" i n pin section
  n="${#REQUIRED_PINS[@]}"
  for ((i = 0; i < n; i++)); do
    pin="${REQUIRED_PINS[$i]}"
    section="${REQUIRED_PIN_SECTIONS[$i]}"
    if ! line_in_section "$file" "$pin" "$section"; then
      printf 'MISSING PIN: %s (section %s)\n' "$pin" "$section"
      return 1
    fi
  done
  if grep -q '%I' "$file"; then
    printf 'FORBIDDEN: %%%%I present\n'
    return 1
  fi
  return 0
}

c10_static_pins() {
  local out
  out="$(mktemp)"
  # A GATE WHOSE SET THE CALLER PICKS IS NOT A GATE. Everything below iterates
  # REQUIRED_PINS: emptied by a future edit, `find_missing_pin` reports every
  # file clean, the mutant loop runs zero times, and this case still prints its
  # PASS having checked nothing. The floor is asserted BEFORE the set is used,
  # and it is a floor rather than an equality so adding a pin stays cheap while
  # losing one is loud; the floor includes the [Unit] pins.
  if [ "${#REQUIRED_PINS[@]}" -lt 25 ]; then
    echo "unit-check: refused -- REQUIRED_PINS holds ${#REQUIRED_PINS[@]} entries, want at least 25; every assertion in this case iterates that array, so a shrunken set would pass vacuously" >&2
    return 1
  fi
  # The two arrays must stay in exact lockstep by index, or a pin gets
  # checked against the wrong section rather than its own.
  if [ "${#REQUIRED_PINS[@]}" -ne "${#REQUIRED_PIN_SECTIONS[@]}" ]; then
    echo "unit-check: refused -- REQUIRED_PINS has ${#REQUIRED_PINS[@]} entries but REQUIRED_PIN_SECTIONS has ${#REQUIRED_PIN_SECTIONS[@]}; these must stay the same length and in the same order" >&2
    return 1
  fi
  if ! find_missing_pin "$UNIT_FILE" >"$out" 2>&1; then
    die "case10: refused -- the SHIPPED unit file is missing a required pin: $(cat "$out")"
  fi
  echo "UNIT: static-pins-present PASS (${#REQUIRED_PINS[@]} pins, no %I)"

  local pin mutant orig_count orig_lines mutant_lines
  for pin in "${REQUIRED_PINS[@]}"; do
    mutant="$(mktemp)"
    orig_count="$(grep -cxF -- "$pin" "$UNIT_FILE" || true)"
    [ "${orig_count:-0}" -ge 1 ] || die "case10: internal -- pin not present exactly as expected in the repo file: $pin"
    orig_lines="$(wc -l <"$UNIT_FILE")"
    grep -vxF -- "$pin" "$UNIT_FILE" >"$mutant"
    mutant_lines="$(wc -l <"$mutant")"
    # PROVE THE DELETION LANDED, by LINE-COUNT DELTA -- never by
    # re-grepping the deleted string IN THE MUTANT. That count is 0 BY
    # CONSTRUCTION (the mutant is built via `grep -vxF -- "$pin"`, which by
    # definition excludes every line equal to $pin from its own output), so
    # a check that re-counts $pin in the mutant can never see anything but
    # 0 and the "deletion did not land" guard could never fire. The mutant
    # must be exactly $orig_count lines shorter than the
    # original. linux-container.sh's S18-witness and
    # S18-selfcheck-witness use the same line-count check
    # for a deletion: the control must establish that its
    # perturbation landed before scoring the refusal.
    if [ "$mutant_lines" -ne "$((orig_lines - orig_count))" ]; then
      die "case10: the deletion mutant DID NOT LAND for pin: $pin (original $orig_lines line(s), mutant $mutant_lines line(s), want exactly $orig_count fewer)"
    fi
    if find_missing_pin "$mutant" >"$out" 2>&1; then
      die "case10: DID NOT REFUSE -- a copy with '$pin' deleted was still scored clean"
    fi
    grep -qF -- "$pin" "$out" \
      || die "case10: refusal did not NAME the deleted pin '$pin' (got: $(cat "$out"))"
    rm -f -- "$mutant"
  done
  rm -f -- "$out"
  echo "UNIT: static-pins-deletion-mutants PASS (${#REQUIRED_PINS[@]} mutants, each named)"

  # a pin present as an exact line but under the WRONG SECTION is
  # inert in systemd yet a section-blind grep would still call it
  # "pinned". Prove find_missing_pin actually checks placement: relocate
  # Restart=no from [Service] to immediately after [Unit], in a copy, and
  # require the check to still report it MISSING.
  local wrongsec
  wrongsec="$(mktemp)"
  awk '
    /^\[Unit\]/ { print; print "Restart=no"; next }
    /^Restart=no$/ { next }
    { print }
  ' "$UNIT_FILE" >"$wrongsec"
  # PROVE THE PERTURBATION LANDED: Restart=no must appear exactly once in
  # the mutant (relocated, not duplicated or dropped), and it must be the
  # line immediately after [Unit] rather than still under [Service].
  if [ "$(grep -cxF -- 'Restart=no' "$wrongsec")" -ne 1 ]; then
    die "case10: internal -- the wrong-section perturbation for Restart=no did not land as a clean relocation (want exactly 1 occurrence in the mutant, got $(grep -cxF -- 'Restart=no' "$wrongsec"))"
  fi
  if ! awk '/^\[Unit\]/{getline; if ($0=="Restart=no") f=1} END{exit(f?0:1)}' "$wrongsec"; then
    die "case10: internal -- Restart=no is not the line immediately after [Unit] in the wrong-section mutant; the perturbation did not land as constructed"
  fi
  if find_missing_pin "$wrongsec" >"$out" 2>&1; then
    die "case10: DID NOT REFUSE -- a copy with Restart=no moved from [Service] to [Unit] was still scored clean (section placement is not being checked)"
  fi
  grep -qF -- 'Restart=no' "$out" \
    || die "case10: wrong-section refusal did not NAME the misplaced pin (got: $(cat "$out"))"
  rm -f -- "$wrongsec"
  echo "UNIT: static-pins-section-check PASS (Restart=no relocated to [Unit] is correctly refused)"

  echo "UNIT: static-pins PASS"
}

# ===========================================================================
# Case 11 -- NEGATIVE-turned-positive: a HOSTNAME endpoint. Every prior
# executed run used a bare IP, which bypasses getaddrinfo entirely.
# ===========================================================================
c11_hostname_endpoint() {
  write_env "$INSTANCE" "$MOUNT_DIR" "" "$LOCALHOST_ENDPOINT"
  INSTANCES_STARTED+=("$INSTANCE")
  clear_cache_dir "$INSTANCE"
  systemctl start "gran-mount@${INSTANCE}.service" \
    || die "case11: refused -- systemctl start against $LOCALHOST_ENDPOINT failed (rc=$?)"
  wait_for_row "$MOUNT_DIR" \
    || { journalctl -u "gran-mount@${INSTANCE}.service" --no-pager -n 200 >&2; die "case11: refused -- mount against $LOCALHOST_ENDPOINT did not become ready"; }

  local out
  out="$(cat "$MOUNT_DIR/sentinel.txt")" \
    || die "case11: FAIL -- could not read sentinel.txt through the mount against $LOCALHOST_ENDPOINT"
  [ "$out" = "$EXPECTED_SENTINEL" ] \
    || die "case11: FAIL -- content mismatch reading through $LOCALHOST_ENDPOINT: '$out'"

  systemctl stop "gran-mount@${INSTANCE}.service" || die "case11: refused -- stop failed"
  remove_env "$INSTANCE"
  echo "UNIT: hostname-endpoint PASS"
}

# ===========================================================================
# Case 12 -- the binary's SELinux label, only where the host is enforcing.
# ===========================================================================
c12_selinux_label() {
  if ! command -v getenforce >/dev/null 2>&1; then
    echo "UNIT: selinux-label SKIPPED (getenforce not present; not an SELinux host)"
    return 0
  fi
  local mode
  mode="$(getenforce)"
  if [ "$mode" != "Enforcing" ]; then
    echo "UNIT: selinux-label SKIPPED (host SELinux mode is '$mode', not Enforcing)"
    return 0
  fi
  command -v chcon >/dev/null 2>&1 || die "case12: chcon required on an SELinux-enforcing host"

  local label
  label="$(ls -Z /usr/local/bin/gran | awk '{print $1}')"
  case "$label" in
    *:bin_t:*) : ;;
    *) die "case12: refused -- /usr/local/bin/gran is not labelled bin_t before starting the unit: $label" ;;
  esac
  echo "UNIT: selinux-label-positive PASS ($label)"

  local tmp_copy tmp_label parked_candidate
  tmp_copy="/tmp/unit-check-gran.$$"
  cp -- "$GRAN_BIN" "$tmp_copy"
  chmod 0755 "$tmp_copy"
  tmp_label="$(ls -Z "$tmp_copy" | awk '{print $1}')"
  case "$tmp_label" in
    *:user_tmp_t:*) : ;;
    *) rm -f -- "$tmp_copy"; die "case12: internal -- /tmp copy is not labelled user_tmp_t ($tmp_label); cannot construct the negative on this host" ;;
  esac

  # Both spellings: an orphan here is the host's own working `gran`, left by a
  # run that died between the park and the restore, and refusing BY NAME is how
  # an operator finds out. Both park paths are checked so neither can be
  # overwritten by a second park.
  for parked_candidate in "$PARKED_GRAN" "$LEGACY_PARKED_GRAN"; do
    { [ -e "$parked_candidate" ] || [ -L "$parked_candidate" ]; } \
      && die "case12: refused -- $parked_candidate already exists; this harness will not overwrite it"
  done
  mv -- /usr/local/bin/gran "$PARKED_GRAN"
  PARKED_GRAN_CREATED=1
  mv -- "$tmp_copy" /usr/local/bin/gran
  local swapped_label
  swapped_label="$(ls -Z /usr/local/bin/gran | awk '{print $1}')"
  case "$swapped_label" in
    *:user_tmp_t:*) : ;;
    *)
      mv -f -- "$PARKED_GRAN" /usr/local/bin/gran
      PARKED_GRAN_CREATED=0
      die "case12: DID NOT LAND -- the mv-from-/tmp perturbation did not preserve user_tmp_t (got '$swapped_label')"
      ;;
  esac
  echo "UNIT: selinux-label-mutant-landed PASS (mv from /tmp preserved $swapped_label)"

  write_env "$INSTANCE" "$MOUNT_DIR"
  INSTANCES_STARTED+=("$INSTANCE")
  set +e
  clear_cache_dir "$INSTANCE"
  systemctl start "gran-mount@${INSTANCE}.service" >/dev/null 2>&1
  set -e
  local state execstatus
  state="$(wait_for_unit_state "gran-mount@${INSTANCE}.service" "failed" || true)"
  execstatus="$(systemctl show -p ExecMainStatus --value "gran-mount@${INSTANCE}.service")"
  systemctl stop "gran-mount@${INSTANCE}.service" >/dev/null 2>&1 || true
  systemctl reset-failed "gran-mount@${INSTANCE}.service" >/dev/null 2>&1 || true
  remove_env "$INSTANCE"

  mv -f -- "$PARKED_GRAN" /usr/local/bin/gran
  PARKED_GRAN_CREATED=0

  [ "$state" = failed ] \
    || die "case12: DID NOT REFUSE -- unit did not reach ActiveState=failed with the mislabeled binary (state=$state)"
  [ "$execstatus" = 203 ] \
    || die "case12: DID NOT REFUSE with 203/EXEC -- ExecMainStatus=$execstatus"
  echo "UNIT: selinux-label-negative PASS (ExecMainStatus=203)"

  echo "UNIT: selinux-label PASS"
}

# ===========================================================================
# Run every case in order. Static cases (9, 10) do not touch the unit at
# all and can run any time; they run early since they are cheap and fast to
# fail on.
# ===========================================================================
c9_lint
c10_static_pins
c1_visible_outside
c3_stop
c2_allow_other
c4_namespace_negatives
c5_capability_negative
c6_trust_downgrade
c7_missing_env
c8_hostile_instance
c11_hostname_endpoint
c12_selinux_label

echo "UNIT-CHECK: PASS"
exit 0
