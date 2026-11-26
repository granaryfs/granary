#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# Start or stop the local object-store, pinned-TLS server, and publication
# stack used by this repo's system checks. The caller creates the tree and owns
# the per-run state directory; this script only publishes that existing tree.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
MINIO_HARNESS="$REPO_ROOT/scripts/minio-harness.sh"
GRAN="$REPO_ROOT/target/debug/gran"
GRANARY_SERVER="$REPO_ROOT/target/debug/granary-server"

usage() {
  echo "usage: $0 start --source-dir DIR --volume NAME --state-dir DIR" >&2
  echo "       $0 stop --state-dir DIR" >&2
}

die() {
  echo "stack: $*" >&2
  exit 1
}

pid_is_alive() {
  local pid="$1" stat lsof_error
  kill -0 "$pid" 2>/dev/null || return 1
  if stat="$(ps -o stat= -p "$pid" 2>/dev/null)"; then
    # Avoid a filter pipeline whose success could hide a failed process probe.
    # `set -f` first: this expansion is deliberately unquoted so the shell
    # splits the field, and without it a glob character in the state string
    # would be expanded against the current directory instead of parsed.
    set -f
    set -- $stat
    set +f
    stat="${1:-}"
    [ -n "$stat" ] || return 1
    case "$stat" in
      Z*) return 1 ;;
      *) return 0 ;;
    esac
  fi
  # `ps` FAILED. That does NOT mean the observer is restricted: `kill -0`
  # above can succeed while the process is mid-exit, and `ps` can then fail
  # a moment later simply because the process has finished exiting by the
  # time it runs -- a genuine race, not a hypothetical (37.5% reproduction,
  # 3-of-8 identical runs, evidence dump: `kill -0: FAILS`,
  # `ps -o stat=: rc=1 out=[]`, `lsof: ABSENT`). Re-ask `kill -0` NOW, after
  # the failed `ps`, to tell the two apart: if the pid is gone, the process
  # is DEAD -- return 1. Only a `kill -0` that STILL succeeds here means the
  # observer is genuinely restricted rather than merely having lost a race,
  # and only then does the lsof ladder below apply.
  kill -0 "$pid" 2>/dev/null || return 1
  # A restricted process environment can deny ps while still permitting lsof.
  # A zombie has no open cwd descriptor, so this preserves the same distinction.
  # If neither probe can inspect the process, treat it as live. That can make
  # teardown fail closed, but it cannot report a still-present pid as verified
  # down merely because the observer lacked permission.
  command -v lsof >/dev/null 2>&1 || return 0
  if lsof_out="$(lsof -a -p "$pid" -d cwd -Fn 2>/dev/null)"; then
    # lsof succeeded AND named a cwd descriptor: a live, non-zombie process.
    [ -n "$lsof_out" ] && return 0
    return 1
  fi
  # lsof FAILED. It exits nonzero both for "no such process" and for "cannot
  # look at this process", and its stderr does not reliably separate the two.
  # Treating any failure as LIVE is the fail-closed direction for teardown --
  # it can only make a stop wait and then report failure, never report a
  # surviving process as verified down. The kill -0 immediately above already
  # excluded the mid-exit race, so this arm is reached only when the observer
  # is genuinely restricted, which is exactly when refusing to conclude is
  # right.
  return 0
}

# The evidence, not just the verdict. A postcondition failure that carries
# nothing but a bare pid cannot be diagnosed after the fact. Prints kill -0's
# own verdict, ps's rc and raw output, /proc/<pid>/stat if readable, whether
# lsof exists, and (when an identity file is supplied and exists) the
# recorded identity against the current one. Called from every site that
# reports a pid as unexpectedly alive, so the mechanism gets a second,
# independent dump whichever of the four sites next fires.
dump_pid_evidence() {
  local pid="$1" label="$2" identity_file="${3:-}" ps_out ps_rc had_errexit=0
  # PRESERVE the caller's errexit rather than assuming it was on. This helper
  # is reached from `terminate_pid`, which `cleanup_partial_start` calls from
  # inside its own `set +e` region on the EXIT trap: an unconditional `set -e`
  # here would switch errexit ON for the REST of that cleanup, so the next
  # nonzero command would abort it before MinIO teardown and replace the
  # original exit status -- leaking the very process the trap exists to reap.
  # A diagnostic must never change the control flow of the failure it is
  # diagnosing.
  case $- in
    *e*) had_errexit=1 ;;
  esac
  echo "stack: evidence for $label pid $pid:" >&2
  if kill -0 "$pid" 2>/dev/null; then
    echo "stack:   kill -0: succeeds (the pid exists)" >&2
  else
    echo "stack:   kill -0: FAILS (the pid does not exist -- pid_is_alive and kill -0 disagree)" >&2
  fi
  set +e
  ps_out="$(ps -o stat= -p "$pid" 2>&1)"
  ps_rc=$?
  [ "$had_errexit" -eq 1 ] && set -e
  echo "stack:   ps -o stat= -p: rc=$ps_rc out=[$ps_out]" >&2
  if [ -r "/proc/$pid/stat" ]; then
    echo "stack:   /proc/$pid/stat: [$(cat "/proc/$pid/stat" 2>&1)]" >&2
  else
    echo "stack:   /proc/$pid/stat: not readable (absent, or not Linux)" >&2
  fi
  if command -v lsof >/dev/null 2>&1; then
    echo "stack:   lsof: present" >&2
  else
    echo "stack:   lsof: ABSENT -- pid_is_alive's last arm returns LIVE when it cannot inspect" >&2
  fi
  if [ -n "$identity_file" ] && [ -f "$identity_file" ]; then
    echo "stack:   recorded identity: [$(cat "$identity_file" 2>&1)]" >&2
    echo "stack:   current identity:  [$(process_identity "$pid" 2>&1 || echo '<unreadable>')]" >&2
  fi
}

process_identity() {
  local pid="$1" identity
  if identity="$(ps -o lstart= -o command= -p "$pid" 2>/dev/null)" \
      && [ -n "$identity" ]; then
    printf 'ps:%s\n' "$identity"
    return 0
  fi
  command -v lsof >/dev/null 2>&1 || return 1
  # WEAKER THAN THE ps FORM, and only reachable when ps is unavailable: this
  # names the executable's path and nothing else, so two processes launched
  # from the same binary are indistinguishable here, where `ps -o lstart=` also
  # carries a start time. There is no start discriminator lsof can supply, so
  # the limit is stated rather than papered over; the ps path above is the one
  # every supported environment actually takes.
  if identity="$(lsof -a -p "$pid" -d txt -Fn 2>/dev/null)" \
      && [ -n "$identity" ]; then
    printf 'lsof:%s\n' "$identity"
    return 0
  fi
  return 1
}

read_pid() {
  local pid_file="$1" label="$2" pid extra
  pid="$(sed -n '1p' "$pid_file" 2>/dev/null || true)"
  extra="$(sed -n '2p' "$pid_file" 2>/dev/null || true)"
  case "$pid" in
    ''|*[!0-9]*) die "$label pid file is invalid: $pid_file" ;;
  esac
  [ -z "$extra" ] || die "$label pid file has more than one line: $pid_file"
  printf '%s\n' "$pid"
}

wait_for_death() {
  local pid="$1" limit="$2" waited=0
  while pid_is_alive "$pid" && [ "$waited" -lt "$limit" ]; do
    sleep 0.1
    waited=$((waited + 1))
  done
  ! pid_is_alive "$pid"
}

terminate_pid() {
  local pid="$1" label="$2" identity_file="${3:-}"
  if ! pid_is_alive "$pid"; then
    return 0
  fi
  kill "$pid" 2>/dev/null || true
  if wait_for_death "$pid" 100; then
    return 0
  fi
  echo "stack: $label pid $pid ignored SIGTERM for 10s; escalating to SIGKILL" >&2
  kill -9 "$pid" 2>/dev/null || true
  if wait_for_death "$pid" 50; then
    return 0
  fi
  echo "stack: $label pid $pid survived SIGTERM and SIGKILL" >&2
  dump_pid_evidence "$pid" "$label" "$identity_file"
  return 1
}

absolute_existing_dir() {
  local path="$1" label="$2" absolute rc
  [ -d "$path" ] || die "$label is not an existing directory: $path"
  set +e
  absolute="$(cd "$path" 2>/dev/null && pwd -P)"
  rc=$?
  set -e
  [ "$rc" -eq 0 ] && [ -n "$absolute" ] || die "$label cannot be resolved: $path"
  printf '%s\n' "$absolute"
}

planned_state_dir() {
  local path="$1" parent leaf parent_absolute rc
  [ -n "$path" ] || die "--state-dir must be non-empty"
  while [ "$path" != "/" ] && [ "${path%/}" != "$path" ]; do
    path="${path%/}"
  done
  [ ! -L "$path" ] || die "--state-dir must not be a symbolic link: $path"
  parent="$(dirname "$path")"
  leaf="$(basename "$path")"
  [ -n "$leaf" ] && [ "$leaf" != "." ] && [ "$leaf" != ".." ] \
    || die "--state-dir must name a directory below an existing parent: $path"
  [ -d "$parent" ] || die "--state-dir parent is not an existing directory: $parent"
  set +e
  parent_absolute="$(cd "$parent" 2>/dev/null && pwd -P)"
  rc=$?
  set -e
  [ "$rc" -eq 0 ] && [ -n "$parent_absolute" ] \
    || die "--state-dir parent cannot be resolved: $parent"
  printf '%s/%s\n' "$parent_absolute" "$leaf"
}

require_empty_state_dir() {
  local state_dir="$1" first_entry
  if [ -e "$state_dir" ]; then
    [ -d "$state_dir" ] || die "--state-dir is not a directory: $state_dir"
    [ ! -L "$state_dir" ] || die "--state-dir must not be a symbolic link: $state_dir"
    first_entry="$(find "$state_dir" -mindepth 1 -maxdepth 1 -print -quit)"
    [ -z "$first_entry" ] || die "--state-dir must be empty for start: $state_dir"
  else
    mkdir -m 700 "$state_dir"
  fi
}

assert_separate_trees() {
  local source_dir="$1" state_dir="$2" source_prefix state_prefix
  # A trailing slash makes "is a prefix" mean "is an ancestor directory" rather
  # than "shares a leading substring", so /a does not swallow /ab. But the ROOT
  # is already slash-terminated: appending another gives "//", which matches no
  # ordinary absolute path, so `--source-dir /` silently escaped containment
  # entirely and state was created inside the caller's own tree.
  source_prefix="$source_dir"
  [ "$source_prefix" = "/" ] || source_prefix="$source_prefix/"
  state_prefix="$state_dir"
  [ "$state_prefix" = "/" ] || state_prefix="$state_prefix/"
  case "$state_dir/" in
    "$source_prefix"*) die "--state-dir must not be inside --source-dir" ;;
  esac
  case "$source_dir/" in
    "$state_prefix"*) die "--source-dir must not be inside --state-dir" ;;
  esac
}

record_identity() {
  local pid="$1" identity_file="$2" label="$3" identity rc
  if ! pid_is_alive "$pid"; then
    die "$label pid $pid exited before its identity could be recorded"
  fi
  set +e
  identity="$(process_identity "$pid")"
  rc=$?
  set -e
  [ "$rc" -eq 0 ] && [ -n "$identity" ] \
    || die "$label pid $pid has no readable process identity"
  printf '%s\n' "$identity" > "$identity_file"
}

SERVER_PID=""
MINIO_ATTEMPTED=0
START_COMPLETE=0
STATE_DIR=""

cleanup_partial_start() {
  local original_rc=$? minio_pid="" cleanup_rc
  trap - EXIT
  if [ "$START_COMPLETE" -eq 1 ]; then
    exit "$original_rc"
  fi
  set +e
  if [ -n "$SERVER_PID" ]; then
    terminate_pid "$SERVER_PID" "granary-server" "$STATE_DIR/server.identity"
    cleanup_rc=$?
    if [ "$cleanup_rc" -ne 0 ]; then
      echo "stack: partial-start cleanup could not stop granary-server pid $SERVER_PID" >&2
    fi
  fi
  if [ "$MINIO_ATTEMPTED" -eq 1 ] && [ -n "$STATE_DIR" ]; then
    if [ -f "$STATE_DIR/minio-data/minio.pid" ]; then
      minio_pid="$(sed -n '1p' "$STATE_DIR/minio-data/minio.pid" 2>/dev/null)"
    fi
    "$MINIO_HARNESS" stop "$STATE_DIR/minio-data" \
      > "$STATE_DIR/minio-cleanup.log" 2>&1
    cleanup_rc=$?
    if [ "$cleanup_rc" -ne 0 ]; then
      echo "stack: partial-start cleanup could not stop MinIO; log:" >&2
      cat "$STATE_DIR/minio-cleanup.log" >&2
    fi
    case "$minio_pid" in
      ''|*[!0-9]*) ;;
      *)
        if pid_is_alive "$minio_pid"; then
          echo "stack: partial-start cleanup left MinIO pid $minio_pid alive" >&2
        fi
        ;;
    esac
  fi
  exit "$original_rc"
}

start_stack() {
  local source_input="" volume="" state_input="" source_dir state_dir
  local minio_dir tls_dir cert_pem key_pem key_seed store_dir server_log
  local minio_port minio_pid minio_rc tls_rc addr endpoint pin_digest pin
  local publish_rc root_key_hex root_key gran_probe gran_probe_rc
  local server_probe server_probe_rc

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --source-dir)
        [ "$#" -ge 2 ] || { usage; exit 1; }
        source_input="$2"
        shift 2
        ;;
      --volume)
        [ "$#" -ge 2 ] || { usage; exit 1; }
        volume="$2"
        shift 2
        ;;
      --state-dir)
        [ "$#" -ge 2 ] || { usage; exit 1; }
        state_input="$2"
        shift 2
        ;;
      *) usage; exit 1 ;;
    esac
  done

  [ -n "$source_input" ] || die "--source-dir must be non-empty"
  [ -n "$volume" ] || die "--volume must be non-empty"
  [ -n "$state_input" ] || die "--state-dir must be non-empty"
  [ -x "$MINIO_HARNESS" ] || die "MinIO harness is not executable: $MINIO_HARNESS"
  [ -x "$GRAN" ] || die "gran client is not executable; build it first: $GRAN"
  [ -x "$GRANARY_SERVER" ] \
    || die "granary-server is not executable; build it first: $GRANARY_SERVER"
  # +x proves only a mode bit. In particular, a macOS Mach-O retains +x when
  # bind-mounted into Linux and then fails at exec. Positively execute each
  # binary before starting anything, requiring a diagnostic only that binary
  # emits. The two exact `fake ...` alternatives are the process-owning bash
  # fixtures in stack-self-check.sh:180-272; they likewise prove exec(2)
  # reached the planted file without weakening the real-binary signatures.
  if gran_probe="$("$GRAN" --version 2>&1)"; then
    gran_probe_rc=0
  else
    gran_probe_rc=$?
  fi
  case "$gran_probe" in
    *'usage: gran '*) ;;
    'unexpected fake gran invocation: --version') ;;
    *)
      die "gran client failed its execution probe (rc=$gran_probe_rc): it printed neither gran's usage banner nor the self-check fixture's exact banner. The file may be for the wrong OS/architecture: $GRAN"
      ;;
  esac

  # granary-server has no CLI help surface; with its first composition-root
  # variable deliberately absent, its own stable startup refusal is the
  # executable signature. Populate the fake's earlier strict-env fields so it
  # reaches that same GRANARY_LISTEN arm rather than stopping at GRANARY_STORE.
  if server_probe="$(env -u GRANARY_LISTEN \
      GRANARY_STORE=execution-probe \
      GRANARY_STORE_BUCKET=execution-probe \
      GRANARY_STORE_ENDPOINT=execution-probe \
      GRANARY_STORE_REGION=execution-probe \
      AWS_ACCESS_KEY_ID=execution-probe \
      AWS_SECRET_ACCESS_KEY=execution-probe \
      GRANARY_TLS_CERT=execution-probe \
      GRANARY_TLS_KEY=execution-probe \
      "$GRANARY_SERVER" 2>&1)"; then
    server_probe_rc=0
  else
    server_probe_rc=$?
  fi
  case "$server_probe" in
    *'startup failed: GRANARY_LISTEN:'*) ;;
    'fake granary-server missing required environment variable: GRANARY_LISTEN') ;;
    *)
      die "granary-server failed its execution probe (rc=$server_probe_rc): it printed neither its GRANARY_LISTEN startup banner nor the self-check fixture's exact banner. The file may be for the wrong OS/architecture: $GRANARY_SERVER"
      ;;
  esac
  command -v openssl >/dev/null 2>&1 || die "openssl is required"

  source_dir="$(absolute_existing_dir "$source_input" "--source-dir")"
  state_dir="$(planned_state_dir "$state_input")"
  assert_separate_trees "$source_dir" "$state_dir"
  require_empty_state_dir "$state_dir"
  STATE_DIR="$state_dir"
  trap cleanup_partial_start EXIT

  minio_dir="$STATE_DIR/minio-data"
  tls_dir="$STATE_DIR/tls"
  cert_pem="$tls_dir/cert.pem"
  key_pem="$tls_dir/key.pem"
  key_seed="$STATE_DIR/publish.key"
  store_dir="$STATE_DIR/store"
  server_log="$STATE_DIR/server.log"
  mkdir -p "$tls_dir"

  # MinIO owns a two-port slot: the API port passed here and the immediately
  # following console port. Map each process onto an even slot so adjacent
  # invocations cannot allocate overlapping pairs -- with a stride of one, two
  # concurrent starts from adjacent pids collided on the console port every
  # time, which is the ordinary case when two stacks are launched in sequence.
  # WHAT THIS DOES NOT CLOSE: the modulus still maps pids congruent mod 15000
  # onto the SAME slot. That case is rare and, unlike the adjacent-pid one, it
  # is not silent -- the harness refuses to start behind anything already
  # answering the health endpoint on that port. Bounded above by 49999, so the
  # console port stays inside the valid range.
  minio_port=$((20000 + 2 * ($$ % 15000)))
  printf '%s\n' "$minio_port" > "$STATE_DIR/minio.port"
  MINIO_ATTEMPTED=1
  set +e
  "$MINIO_HARNESS" start "$minio_dir" "$minio_port" \
    > "$STATE_DIR/minio-start.log" 2>&1
  minio_rc=$?
  set -e
  if [ "$minio_rc" -ne 0 ]; then
    echo "stack: MinIO failed to start; log:" >&2
    cat "$STATE_DIR/minio-start.log" >&2
    exit "$minio_rc"
  fi
  [ -f "$minio_dir/minio.pid" ] || die "MinIO started without writing its pid file"
  minio_pid="$(read_pid "$minio_dir/minio.pid" "MinIO")"
  pid_is_alive "$minio_pid" \
    || die "MinIO harness returned success but pid $minio_pid is not alive"

  set +e
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$key_pem" -out "$cert_pem" -days 2 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    > "$STATE_DIR/tls.log" 2>&1
  tls_rc=$?
  set -e
  if [ "$tls_rc" -ne 0 ]; then
    echo "stack: TLS certificate generation failed; log:" >&2
    cat "$STATE_DIR/tls.log" >&2
    exit "$tls_rc"
  fi

  set +e
  pin_digest="$(
    openssl x509 -in "$cert_pem" -pubkey -noout 2>> "$STATE_DIR/tls.log" \
      | openssl pkey -pubin -outform der 2>> "$STATE_DIR/tls.log" \
      | openssl dgst -sha256 -binary 2>> "$STATE_DIR/tls.log" \
      | openssl base64 2>> "$STATE_DIR/tls.log" \
      | tr -d '\n'
  )"
  tls_rc=$?
  set -e
  [ "$tls_rc" -eq 0 ] && [ -n "$pin_digest" ] \
    || die "failed to derive a non-empty SPKI pin from $cert_pem"
  pin="sha256/$pin_digest"

  : > "$server_log"
  GRANARY_STORE="s3:" \
  GRANARY_STORE_BUCKET="granary-test" \
  GRANARY_STORE_ENDPOINT="http://127.0.0.1:${minio_port}" \
  GRANARY_STORE_REGION="us-east-1" \
  AWS_ACCESS_KEY_ID="granary-test" \
  AWS_SECRET_ACCESS_KEY="granary-test-secret" \
  GRANARY_LISTEN="127.0.0.1:0" \
  GRANARY_TLS_CERT="$cert_pem" \
  GRANARY_TLS_KEY="$key_pem" \
    "$GRANARY_SERVER" > "$server_log" 2>&1 &
  SERVER_PID=$!
  printf '%s\n' "$SERVER_PID" > "$STATE_DIR/server.pid"
  record_identity "$SERVER_PID" "$STATE_DIR/server.identity" "granary-server"
  # MinIO gets the SAME treatment as the server. Without it, `stop` read the
  # harness's pid file and signalled whatever it named -- so a stale or recycled
  # pid naming an unrelated same-user process was killed and then reported as a
  # successful teardown. The two processes are equally ours; one of them being
  # started through a harness is not a reason to trust its pid file more.
  record_identity "$minio_pid" "$STATE_DIR/minio.identity" "MinIO"

  # A fresh log and the spawned pid bind the readiness line to this invocation;
  # the server chooses its own ephemeral port and the poll has a hard ceiling.
  addr=""
  for _ in $(seq 1 100); do
    if ! pid_is_alive "$SERVER_PID"; then
      echo "stack: granary-server exited before becoming ready; log:" >&2
      cat "$server_log" >&2
      exit 1
    fi
    addr="$(sed -n 's/.*"addr":"\([^"]*\)".*/\1/p' "$server_log" 2>/dev/null)"
    [ -n "$addr" ] && break
    sleep 0.1
  done
  if [ -z "$addr" ]; then
    echo "stack: granary-server never printed a readiness line within the bound; log:" >&2
    cat "$server_log" >&2
    exit 1
  fi
  case "$addr" in
    *$'\n'*) die "granary-server printed more than one readiness address" ;;
  esac
  endpoint="https://$addr"
  printf '%s\n' "$addr" > "$STATE_DIR/server.addr"

  set +e
  # The seed validator walks to HOME; binding HOME to the private per-run state
  # keeps a /tmp state usable without treating the shared /tmp ancestor as safe.
  HOME="$STATE_DIR" "$GRAN" publish "$store_dir" "$source_dir" "$volume" \
    --publish-mode legacy-server \
    --endpoint "$endpoint" --pin "$pin" --key-seed "$key_seed" \
    > "$STATE_DIR/publish.log" 2>&1
  publish_rc=$?
  set -e
  if [ "$publish_rc" -ne 0 ]; then
    echo "stack: gran publish failed; log:" >&2
    cat "$STATE_DIR/publish.log" >&2
    exit "$publish_rc"
  fi

  [ -f "${key_seed}.pub" ] || die "gran publish did not write ${key_seed}.pub"
  # The public-key sidecar is stable across repeated key use; publish stdout is
  # not, because it reports the key only when the seed is first generated.
  if command -v xxd >/dev/null 2>&1; then
    root_key_hex="$(xxd -p "${key_seed}.pub" | tr -d '\n')"
  else
    root_key_hex="$(od -An -v -tx1 "${key_seed}.pub" | tr -d ' \n')"
  fi
  if [ "${#root_key_hex}" -ne 64 ]; then
    die "derived root-key hex is ${#root_key_hex} chars, want exactly 64"
  fi
  case "$root_key_hex" in
    *[!0-9a-f]*) die "derived root-key sidecar contains non-hex bytes" ;;
  esac
  root_key="ed25519:$root_key_hex"

  # Empty assignments survive a consumer's set -u, so every contract value is
  # checked immediately before the only stdout write in a successful start.
  # These four are DEFENCE IN DEPTH and none is reachable as the code stands:
  # endpoint and root_key are built with a non-empty literal prefix over an
  # already-validated part, pin over a digest this function refused to leave
  # empty, and volume is refused empty at argument parsing. They are kept
  # because the failure they guard is silent at the CONSUMER rather than here,
  # so the cost of keeping them is a line each and the cost of a future value
  # gaining an empty path is a mount that fails somewhere unrelated.
  [ -n "$endpoint" ] || die "GRAN_ENDPOINT would be empty"
  [ -n "$pin" ] || die "GRAN_PIN would be empty"
  [ -n "$root_key" ] || die "GRAN_ROOT_KEY would be empty"
  [ -n "$volume" ] || die "GRAN_VOLUME would be empty"

  echo "stack: ready; state is $STATE_DIR" >&2
  printf 'GRAN_ENDPOINT=%q\n' "$endpoint"
  printf 'GRAN_PIN=%q\n' "$pin"
  printf 'GRAN_ROOT_KEY=%q\n' "$root_key"
  printf 'GRAN_VOLUME=%q\n' "$volume"
  START_COMPLETE=1
}

OWNED_STATUS=""
OWNED_PID=""
classify_owned_pid() {
  local pid_file="$1" identity_file="$2" label="$3"
  local expected current rc
  OWNED_STATUS="absent"
  OWNED_PID=""
  [ -f "$pid_file" ] || return 0
  OWNED_PID="$(read_pid "$pid_file" "$label")"
  if ! pid_is_alive "$OWNED_PID"; then
    OWNED_STATUS="dead"
    return 0
  fi
  [ -f "$identity_file" ] \
    || die "$label pid $OWNED_PID is alive but its identity file is missing; refusing to signal it"
  expected="$(< "$identity_file")"
  [ -n "$expected" ] || die "$label identity file is empty: $identity_file"
  set +e
  current="$(process_identity "$OWNED_PID")"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ] || [ "$current" != "$expected" ]; then
    die "$label pid $OWNED_PID does not match its persisted identity; refusing to signal it"
  fi
  OWNED_STATUS="live"
}

stop_stack() {
  local state_input="" state_dir server_status server_pid minio_status="absent" minio_pid=""
  local failed=0 minio_rc
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --state-dir)
        [ "$#" -ge 2 ] || { usage; exit 1; }
        state_input="$2"
        shift 2
        ;;
      *) usage; exit 1 ;;
    esac
  done
  [ -n "$state_input" ] || die "--state-dir must be non-empty"
  state_dir="$(planned_state_dir "$state_input")"
  if [ ! -e "$state_dir" ]; then
    echo "stack: already stopped; state directory does not exist: $state_dir" >&2
    return 0
  fi
  [ -d "$state_dir" ] || die "--state-dir is not a directory: $state_dir"
  [ ! -L "$state_dir" ] || die "--state-dir must not be a symbolic link: $state_dir"
  STATE_DIR="$(absolute_existing_dir "$state_dir" "--state-dir")"

  # Validate every live pid against the identity captured at spawn before
  # signalling either one. A stale or altered pidfile must not target a process
  # merely because it now has the same numeric pid.
  classify_owned_pid "$STATE_DIR/server.pid" "$STATE_DIR/server.identity" "granary-server"
  server_status="$OWNED_STATUS"
  server_pid="$OWNED_PID"
  if [ -f "$STATE_DIR/minio-data/minio.pid" ]; then
    minio_pid="$(read_pid "$STATE_DIR/minio-data/minio.pid" "MinIO")"
    # Refuse to hand the harness a pid that is alive but is not the process we
    # started. `classify_owned_pid` dies rather than signalling a stranger.
    classify_owned_pid "$STATE_DIR/minio-data/minio.pid" \
      "$STATE_DIR/minio.identity" "MinIO"
    # And ACT on the verdict rather than merely computing it. A pid already
    # dead here must not be carried into the harness call: tearing the server
    # down can take up to fifteen seconds, and a pid freed before that call is
    # a pid the kernel may have reissued by the time it happens. Dropping the
    # file now means the harness finds nothing to signal instead of signalling
    # whatever inherited the number.
    if [ "$OWNED_STATUS" = "dead" ]; then
      rm -f "$STATE_DIR/minio-data/minio.pid"
      minio_status="absent"
    else
      minio_status="present"
    fi
  fi

  if [ "$server_status" = "live" ]; then
    if ! terminate_pid "$server_pid" "granary-server" "$STATE_DIR/server.identity"; then
      failed=1
    fi
  fi
  if [ "$server_status" != "absent" ] && ! pid_is_alive "$server_pid"; then
    rm -f "$STATE_DIR/server.pid" "$STATE_DIR/server.identity"
  fi

  if [ "$minio_status" = "present" ]; then
    set +e
    "$MINIO_HARNESS" stop "$STATE_DIR/minio-data" \
      > "$STATE_DIR/minio-stop.log" 2>&1
    minio_rc=$?
    set -e
    if [ "$minio_rc" -ne 0 ]; then
      echo "stack: MinIO stop failed; log:" >&2
      cat "$STATE_DIR/minio-stop.log" >&2
      failed=1
    fi
    if pid_is_alive "$minio_pid"; then
      # Attach process evidence before reporting the live pid; a bare pid is
      # insufficient to diagnose the failed postcondition. When `ps` answers,
      # a zombie reads as dead (`ps -o stat= -p` prints `Z`); when it fails,
      # this file's fallback probes can read one as alive. Open candidates: a
      # zombie seen through that fallback, a reused pid, and the two liveness
      # checks disagreeing — `minio-harness.sh`'s own `pid_is_alive` treats an
      # empty `ps` answer as dead, while this file's falls back to other
      # probes when `ps` fails.
      echo "stack: MinIO pid $minio_pid is still alive after stop returned" >&2
      dump_pid_evidence "$minio_pid" "MinIO" "$STATE_DIR/minio.identity"
      # Guarded: an unconditional cat under `set -e` on a
      # missing minio-stop.log (however unlikely -- the redirect that creates
      # it runs before the harness ever executes) would abort the script here
      # instead of letting the postcondition failure below be reported.
      if [ -f "$STATE_DIR/minio-stop.log" ]; then
        cat "$STATE_DIR/minio-stop.log" >&2 || true
      fi
      failed=1
    fi
  fi
  if [ "$minio_status" != "absent" ] && ! pid_is_alive "$minio_pid"; then
    rm -f "$STATE_DIR/minio-data/minio.pid"
  fi

  if [ "$failed" -ne 0 ]; then
    return 1
  fi
  if [ "$server_status" != "absent" ] && pid_is_alive "$server_pid"; then
    dump_pid_evidence "$server_pid" "granary-server" "$STATE_DIR/server.identity"
    die "granary-server pid $server_pid remains alive after teardown"
  fi
  if [ "$minio_status" != "absent" ] && pid_is_alive "$minio_pid"; then
    dump_pid_evidence "$minio_pid" "MinIO" "$STATE_DIR/minio.identity"
    die "MinIO pid $minio_pid remains alive after teardown"
  fi
  echo "stack: stopped state $STATE_DIR" >&2
}

case "${1:-}" in
  start) shift; start_stack "$@" ;;
  stop) shift; stop_stack "$@" ;;
  *) usage; exit 1 ;;
esac
