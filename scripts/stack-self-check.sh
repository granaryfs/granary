#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# Deterministic contract checks for stack.sh. The fixture repository uses
# process-owning fakes so failures exercise argument forwarding, stdout purity,
# persisted ownership, partial-start cleanup, and verified teardown without
# requiring a second real object-store download for every mutation.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
STACK_SCRIPT="$REPO_ROOT/scripts/stack.sh"
CHECKS=0

pass() {
  CHECKS=$((CHECKS + 1))
  echo "ok $CHECKS - $1"
}

fail() {
  CHECKS=$((CHECKS + 1))
  echo "not ok $CHECKS - $1" >&2
  echo "stack self-check: FAIL" >&2
  exit 1
}

assert() {
  local description="$1"
  shift
  if "$@"; then
    pass "$description"
  else
    fail "$description"
  fi
}

pid_is_alive() {
  local pid="$1" stat rc
  kill -0 "$pid" 2>/dev/null || return 1
  # Fixture processes mark exit from their signal trap before they can become
  # an unreaped zombie. A dead marker is conclusive; an alive marker is not,
  # because an abrupt exit could leave it stale. The host may restrict ps even
  # though kill -0 is permitted, so an uninspectable process stays "alive" in
  # the fail-closed direction and can never satisfy a death assertion.
  if [ -n "${TRACE:-}" ]; then
    [ ! -f "$TRACE/dead-$pid" ] || return 1
  fi
  set +e
  stat="$(ps -o stat= -p "$pid" 2>/dev/null)"
  rc=$?
  set -e
  [ "$rc" -eq 0 ] || return 0
  set -f
  set -- $stat
  set +f
  stat="${1:-}"
  [ -n "$stat" ] || return 1
  case "$stat" in
    Z*) return 1 ;;
    *) return 0 ;;
  esac
}

pid_is_dead() {
  ! pid_is_alive "$1"
}

assert "implementation exists and is executable" test -x "$STACK_SCRIPT"

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/stack-self-check.XXXXXX")"
SCRATCH="$(cd "$SCRATCH" && pwd -P)"
FIXTURE_REPO="$SCRATCH/repo"
TRACE="$SCRATCH/trace"
mkdir -p "$FIXTURE_REPO/scripts" "$FIXTURE_REPO/target/debug" "$TRACE"
cp "$STACK_SCRIPT" "$FIXTURE_REPO/scripts/stack.sh"

mkdir -p "$FIXTURE_REPO/fake-bin"
cat > "$FIXTURE_REPO/fake-bin/ps" <<'FAKE_PS'
#!/usr/bin/env bash
set -euo pipefail
if [ "${GRANARY_SELFTEST_PS_FAIL:-0}" = "1" ]; then
  printf '%s\n' "$*" >> "$GRANARY_SELFTEST_TRACE_DIR/ps-refusals"
  exit 1
fi
pid="${!#}"
[ ! -f "$GRANARY_SELFTEST_TRACE_DIR/dead-$pid" ] || exit 1
kill -0 "$pid" 2>/dev/null || exit 1
case " $* " in
  *' stat= '*) echo "S" ;;
  *) echo "fixture-identity-$pid" ;;
esac
FAKE_PS
chmod +x "$FIXTURE_REPO/fake-bin/ps"

cat > "$FIXTURE_REPO/fake-bin/lsof" <<'FAKE_LSOF'
#!/usr/bin/env bash
set -euo pipefail
pid=""
descriptor=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -p) pid="$2"; shift 2 ;;
    -d) descriptor="$2"; shift 2 ;;
    *) shift ;;
  esac
done
case "$pid" in
  ''|*[!0-9]*) exit 2 ;;
esac
[ ! -f "$GRANARY_SELFTEST_TRACE_DIR/dead-$pid" ] || exit 1
kill -0 "$pid" 2>/dev/null || exit 1
printf '%s\t%s\n' "$pid" "$descriptor" >> "$GRANARY_SELFTEST_TRACE_DIR/lsof-calls"
case "$descriptor" in
  cwd|txt)
    printf 'p%s\nf%s\nnfixture-%s-%s\n' "$pid" "$descriptor" "$descriptor" "$pid"
    ;;
  *) exit 2 ;;
esac
FAKE_LSOF
chmod +x "$FIXTURE_REPO/fake-bin/lsof"

cat > "$FIXTURE_REPO/scripts/minio-harness.sh" <<'FAKE_MINIO'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  start)
    dir="$2"
    port="$3"
    mkdir -p "$dir"
    nohup bash -c '
      marker="$1/alive-$$"
      : > "$marker"
      trap '\''rm -f "$marker"; : > "$1/dead-$$"; exit 0'\'' TERM INT
      while :; do sleep 1; done
    ' fake-minio "$GRANARY_SELFTEST_TRACE_DIR" >/dev/null 2>&1 &
    pid=$!
    waited=0
    while [ ! -f "$GRANARY_SELFTEST_TRACE_DIR/alive-$pid" ] && [ "$waited" -lt 100 ]; do
      sleep 0.01
      waited=$((waited + 1))
    done
    [ -f "$GRANARY_SELFTEST_TRACE_DIR/alive-$pid" ] || { echo "fake MinIO did not start" >&2; exit 1; }
    printf '%s\n' "$pid" > "$dir/minio.pid"
    printf '%s\t%s\t%s\t%s\n' "$dir" "$port" "$pid" "$PPID" >> "$GRANARY_SELFTEST_TRACE_DIR/minio-starts"
    echo "fake minio diagnostic"
    ;;
  stop)
    dir="$2"
    if [ "${GRANARY_SELFTEST_MINIO_STOP_LIES:-0}" = "1" ]; then
      echo "fake minio stopped"
      exit 0
    fi
    [ -f "$dir/minio.pid" ] || exit 0
    pid="$(sed -n '1p' "$dir/minio.pid")"
    # Record WHICH pid the harness was asked to signal. The end state after a
    # stop is identical whether or not the caller handed over a stale pid file
    # -- this harness removes the file on its own already-stopped path -- so the
    # only way to observe that hand-over is to record the request itself.
    printf '%s\n' "$pid" >> "$GRANARY_SELFTEST_TRACE_DIR/minio-stop-signals"
    kill "$pid" 2>/dev/null || true
    waited=0
    while [ -f "$GRANARY_SELFTEST_TRACE_DIR/alive-$pid" ] && [ "$waited" -lt 100 ]; do
      sleep 0.01
      waited=$((waited + 1))
    done
    if [ -f "$GRANARY_SELFTEST_TRACE_DIR/alive-$pid" ]; then
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$dir/minio.pid"
    echo "fake minio stopped"
    ;;
  *)
    echo "unexpected fake minio invocation: $*" >&2
    exit 2
    ;;
esac
FAKE_MINIO
chmod +x "$FIXTURE_REPO/scripts/minio-harness.sh"

cat > "$FIXTURE_REPO/target/debug/granary-server" <<'FAKE_SERVER'
#!/usr/bin/env bash
set -euo pipefail
for name in \
  GRANARY_STORE \
  GRANARY_STORE_BUCKET \
  GRANARY_STORE_ENDPOINT \
  GRANARY_STORE_REGION \
  AWS_ACCESS_KEY_ID \
  AWS_SECRET_ACCESS_KEY \
  GRANARY_LISTEN \
  GRANARY_TLS_CERT \
  GRANARY_TLS_KEY
do
  if [ -z "${!name-}" ]; then
    echo "fake granary-server missing required environment variable: $name" >&2
    exit 2
  fi
done
trap 'exit 0' TERM INT
printf '%s\n' "$$" >> "$GRANARY_SELFTEST_TRACE_DIR/server-pids"
: > "$GRANARY_SELFTEST_TRACE_DIR/alive-$$"
trap 'rm -f "$GRANARY_SELFTEST_TRACE_DIR/alive-$$"; : > "$GRANARY_SELFTEST_TRACE_DIR/dead-$$"; exit 0' TERM INT
echo "{\"addr\":\"127.0.0.1:$((40000 + ($$ % 20000)))\"}" >&2
while :; do
  sleep 1
done
FAKE_SERVER
chmod +x "$FIXTURE_REPO/target/debug/granary-server"

cat > "$FIXTURE_REPO/target/debug/gran" <<'FAKE_GRAN'
#!/usr/bin/env bash
set -euo pipefail
[ "${1:-}" = "publish" ] || { echo "unexpected fake gran invocation: $*" >&2; exit 2; }
store="$2"
source_dir="$3"
volume="$4"
shift 4
key_seed=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --key-seed) key_seed="$2"; shift 2 ;;
    --endpoint) endpoint="$2"; shift 2 ;;
    --pin) pin="$2"; shift 2 ;;
    *) shift ;;
  esac
done
# The fake REFUSES an invocation missing a required option, exactly as the real
# `gran publish` parser does. A fake that silently ignores the options it is
# handed cannot observe them going missing -- and then removing --endpoint or
# --pin from the implementation leaves this gate green while every real stack
# start fails at the argument parser.
[ -n "$key_seed" ] || { echo "fake gran received no key seed" >&2; exit 2; }
[ -n "${endpoint:-}" ] || { echo "fake gran received no --endpoint" >&2; exit 2; }
[ -n "${pin:-}" ] || { echo "fake gran received no --pin" >&2; exit 2; }
state_dir="$(dirname "$key_seed")"
server_addr="$(sed -n 's/.*"addr":"\([^"]*\)".*/\1/p' "$state_dir/server.log")"
[ -n "$server_addr" ] || { echo "fake gran found no server address in this run's log" >&2; exit 2; }
[ "$endpoint" = "https://$server_addr" ] \
  || { echo "fake gran endpoint does not name this run's server" >&2; exit 2; }
expected_pin="sha256/$(openssl x509 -in "$state_dir/tls/cert.pem" -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl base64 \
  | tr -d '\n')"
[ "$pin" = "$expected_pin" ] \
  || { echo "fake gran pin does not match this run's certificate" >&2; exit 2; }
[ "$source_dir" != "/" ] \
  || { echo "fake gran safety stop: source root reached the publisher" >&2; exit 97; }
mkdir -p "$store" "$(dirname "$key_seed")"
: > "$key_seed"
i=0
while [ "$i" -lt 32 ]; do
  octal="$(printf '%03o' "$i")"
  printf "\\$octal" >> "${key_seed}.pub"
  i=$((i + 1))
done
run=1
if [ -f "$GRANARY_SELFTEST_TRACE_DIR/publish-count" ]; then
  run=$(( $(sed -n '1p' "$GRANARY_SELFTEST_TRACE_DIR/publish-count") + 1 ))
fi
printf '%s\n' "$run" > "$GRANARY_SELFTEST_TRACE_DIR/publish-count"
published="$GRANARY_SELFTEST_TRACE_DIR/published-$run"
mkdir -p "$published"
cp -R "$source_dir"/. "$published"/
printf '%s\t%s\t%s\n' "$source_dir" "$volume" "$published" >> "$GRANARY_SELFTEST_TRACE_DIR/publishes"
printf '%064d\n' 0 | tr '0' 'f'
echo "fake publish diagnostic" >&2
if [ "${GRANARY_SELFTEST_PUBLISH_FAIL:-0}" -eq 1 ]; then
  exit 42
fi
FAKE_GRAN
chmod +x "$FIXTURE_REPO/target/debug/gran"

cleanup() {
  set +e
  if [ -d "$SCRATCH" ]; then
    while IFS= read -r pid; do
      case "$pid" in
        ''|*[!0-9]*) ;;
        *) kill "$pid" 2>/dev/null || true ;;
      esac
    done < <(find "$SCRATCH" -name '*.pid' -type f -exec sed -n '1p' {} \; 2>/dev/null)
    while IFS= read -r pid; do
      case "$pid" in
        ''|*[!0-9]*) ;;
        *) kill "$pid" 2>/dev/null || true ;;
      esac
    done < <(find "$SCRATCH" -name server-pids -type f -exec sed -n '1,$p' {} \; 2>/dev/null)
    while IFS= read -r pid; do
      case "$pid" in
        ''|*[!0-9]*) ;;
        *) kill "$pid" 2>/dev/null || true ;;
      esac
    done < <(find "$SCRATCH" -name minio-starts -type f -exec awk -F '\t' '{print $3}' {} \; 2>/dev/null)
    rm -rf "$SCRATCH"
  fi
}
trap cleanup EXIT

mkdir -p "$SCRATCH/source-a" "$SCRATCH/source-b" "$SCRATCH/source-fail"
printf 'alpha tree\n' > "$SCRATCH/source-a/payload"
printf 'beta tree\n' > "$SCRATCH/source-b/payload"
printf 'partial tree\n' > "$SCRATCH/source-fail/payload"
chmod 0644 "$SCRATCH/source-a/payload"
chmod 0755 "$SCRATCH/source-b/payload"

fixture_stack() {
  local run_trace="${RUN_TRACE:-$TRACE}"
  mkdir -p "$run_trace"
  env \
    PATH="$FIXTURE_REPO/fake-bin:$PATH" \
    GRANARY_SELFTEST_TRACE_DIR="$run_trace" \
    GRANARY_SELFTEST_PUBLISH_FAIL="${GRANARY_SELFTEST_PUBLISH_FAIL:-0}" \
    GRANARY_SELFTEST_MINIO_STOP_LIES="${GRANARY_SELFTEST_MINIO_STOP_LIES:-0}" \
    GRANARY_SELFTEST_PS_FAIL="${GRANARY_SELFTEST_PS_FAIL:-0}" \
    GRANARY_STORE= \
    GRANARY_STORE_BUCKET= \
    GRANARY_STORE_ENDPOINT= \
    GRANARY_STORE_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    GRANARY_LISTEN= \
    GRANARY_TLS_CERT= \
    GRANARY_TLS_KEY= \
    "$@"
}

run_start() {
  local source_dir="$1" volume="$2" state_dir="$3" env_file="$4" err_file="$5"
  set +e
  fixture_stack \
    "$FIXTURE_REPO/scripts/stack.sh" start \
    --source-dir "$source_dir" --volume "$volume" --state-dir "$state_dir" \
    > "$env_file" 2> "$err_file"
  RUN_RC=$?
  set -e
}

run_stop() {
  local state_dir="$1" out_file="$2" err_file="$3"
  set +e
  fixture_stack \
    "$FIXTURE_REPO/scripts/stack.sh" stop \
    --state-dir "$state_dir" > "$out_file" 2> "$err_file"
  RUN_RC=$?
  set -e
}

# Same as fixture_stack, but with an EXTRA directory prepended ahead of
# fake-bin -- used only by the A1 race case below, whose fake ps must
# shadow the ordinary fixture ps.
fixture_stack_extra_path() {
  local extra_path="$1"
  shift
  local run_trace="${RUN_TRACE:-$TRACE}"
  mkdir -p "$run_trace"
  env \
    PATH="$extra_path:$FIXTURE_REPO/fake-bin:$PATH" \
    GRANARY_SELFTEST_TRACE_DIR="$run_trace" \
    GRANARY_SELFTEST_PUBLISH_FAIL="${GRANARY_SELFTEST_PUBLISH_FAIL:-0}" \
    GRANARY_SELFTEST_MINIO_STOP_LIES="${GRANARY_SELFTEST_MINIO_STOP_LIES:-0}" \
    GRANARY_SELFTEST_PS_FAIL="${GRANARY_SELFTEST_PS_FAIL:-0}" \
    GRANARY_STORE= \
    GRANARY_STORE_BUCKET= \
    GRANARY_STORE_ENDPOINT= \
    GRANARY_STORE_REGION= \
    AWS_ACCESS_KEY_ID= \
    AWS_SECRET_ACCESS_KEY= \
    GRANARY_LISTEN= \
    GRANARY_TLS_CERT= \
    GRANARY_TLS_KEY= \
    "$@"
}

run_start_extra_path() {
  local extra_path="$1" source_dir="$2" volume="$3" state_dir="$4" env_file="$5" err_file="$6"
  set +e
  fixture_stack_extra_path "$extra_path" \
    "$FIXTURE_REPO/scripts/stack.sh" start \
    --source-dir "$source_dir" --volume "$volume" --state-dir "$state_dir" \
    > "$env_file" 2> "$err_file"
  RUN_RC=$?
  set -e
}

run_stop_extra_path() {
  local extra_path="$1" state_dir="$2" out_file="$3" err_file="$4"
  set +e
  fixture_stack_extra_path "$extra_path" \
    "$FIXTURE_REPO/scripts/stack.sh" stop \
    --state-dir "$state_dir" > "$out_file" 2> "$err_file"
  RUN_RC=$?
  set -e
}

expect_dropped_server_env_refused() {
  local name="$1" before after state env_file err_file server_log
  before="$(awk -v name="$name" '$0 ~ "^  " name "=" { count++ } END { print count + 0 }' "$STACK_SCRIPT")"
  [ "$before" -eq 1 ] \
    || fail "the $name mutation anchor occurs exactly once"
  awk -v name="$name" '$0 !~ "^  " name "=" { print }' "$STACK_SCRIPT" \
    > "$FIXTURE_REPO/scripts/stack.sh.mutant"
  after="$(awk -v name="$name" '$0 ~ "^  " name "=" { count++ } END { print count + 0 }' \
    "$FIXTURE_REPO/scripts/stack.sh.mutant")"
  [ "$after" -eq 0 ] \
    || fail "the $name mutation lands before its verdict is read"
  mv "$FIXTURE_REPO/scripts/stack.sh.mutant" "$FIXTURE_REPO/scripts/stack.sh"
  chmod +x "$FIXTURE_REPO/scripts/stack.sh"

  state="$SCRATCH/state-env-$name"
  env_file="$SCRATCH/env-$name.env"
  err_file="$SCRATCH/env-$name.err"
  run_start "$SCRATCH/source-a" "volume-env-$name" "$state" "$env_file" "$err_file"
  server_log="$state/server.log"
  cp "$STACK_SCRIPT" "$FIXTURE_REPO/scripts/stack.sh"

  if [ "$RUN_RC" -eq 0 ]; then
    fail "dropping $name makes the strict fake server reject start"
  fi
  if [ ! -f "$server_log" ] \
      || ! grep -Fqx "fake granary-server missing required environment variable: $name" "$server_log"; then
    echo "drop-$name stderr:" >&2
    cat "$err_file" >&2
    [ ! -f "$server_log" ] || cat "$server_log" >&2
    fail "dropping $name is refused by name at the fake server"
  fi
  pass "dropping $name is refused by name at the fake server"
}

for server_env in \
  GRANARY_STORE \
  GRANARY_STORE_BUCKET \
  GRANARY_STORE_ENDPOINT \
  GRANARY_STORE_REGION \
  AWS_ACCESS_KEY_ID \
  AWS_SECRET_ACCESS_KEY \
  GRANARY_LISTEN \
  GRANARY_TLS_CERT \
  GRANARY_TLS_KEY
do
  expect_dropped_server_env_refused "$server_env"
done

ENV_A="$SCRATCH/a.env"
ERR_A="$SCRATCH/a.err"
STATE_A="$SCRATCH/state-a"
run_start "$SCRATCH/source-a" "volume-a" "$STATE_A" "$ENV_A" "$ERR_A"
if [ "$RUN_RC" -ne 0 ]; then
  echo "first start stderr:" >&2
  cat "$ERR_A" >&2
fi
# `printf %q ""` renders an empty value as two single-quote characters, which
# satisfies any `.+` shape check -- so no per-line regex can tell an empty
# assignment from a present one. Match that rendering literally. Written as a
# function, not an inline `sh -c`, because the escape needed to smuggle a quote
# through nested quoting is NOT portable: `\x27` is honoured by BSD grep and
# ignored by GNU grep, so an inline form fires on macOS and is silently blind
# on Linux -- the platform this repo's CI actually runs.
no_empty_q_rendering() {
  ! grep -Eq "^GRAN_[A-Z_]+=(''|\"\")$" "$1"
}

# The implementation must contain no mount or unmount COMMAND. Comments are
# stripped first: a whole-file grep cannot tell a comment from a command, so it
# both produced false failures and forbade the script from documenting the very
# property this enforces. `sed`'s status is captured on its OWN LINE rather than
# read through the pipeline -- under `set -o pipefail` a failing `sed` makes the
# pipeline nonzero, which an `if` would read as "grep matched nothing", i.e. a
# PASS produced by a broken scanner.
# The alternation covers shell terminators, redirections, quoting, command
# substitution, paths, and utility names that contain mount or umount. This is
# still a TEXT oracle: it cannot see a command reached through a variable, an
# alias, or an `eval`, nor can it parse every shell quoting construct. The
# assertion is therefore named for the literal text it reads.
# NOT SELF-APPLICABLE: the alternation below contains `(mount|`, and its own
# prefix and suffix classes include `(` and `|`, so the pattern matches its own
# text. Pointing this scanner at THIS file would therefore fire on the regex
# rather than on a command. It is only ever aimed at the implementation and at
# single-line fixtures, and it must stay that way.
scan_for_mount_command() {
  local file="$1" stripped rc pattern
  # WHOLE-LINE comments only. Stripping from every `#` cannot respect shell
  # quoting, so `printf '#'; mount /a /b` reduces to `printf '` and the mount
  # becomes invisible to the scan -- a detector silently losing the thing it
  # detects. Removing only lines that BEGIN with `#` can never hide code: it
  # strips strictly less, so the scan can only fire more often, which is the
  # safe direction for a detector. The cost is that a TRAILING comment
  # mentioning mount would fire; put such prose on its own comment line.
  stripped="$(sed -e '/^[[:space:]]*#/d' "$file")"
  rc=$?
  [ "$rc" -eq 0 ] || return 2
  pattern="(^|[[:space:]]|[;|&(\`/\\\\\"'])[A-Za-z0-9_.]*(mount|umount)[A-Za-z0-9_.]*([[:space:]]|[;|&)\`<>\"']|\$)|gran[[:space:]]+(mount|umount)"
  grep -Eq "$pattern" <<< "$stripped"
}

assert "start accepts the first caller-owned source tree" test "$RUN_RC" -eq 0
assert "start stdout contains exactly four assignments" test "$(wc -l < "$ENV_A" | tr -d ' ')" -eq 4
ADDR_A="$(sed -n 's/.*"addr":"\([^"]*\)".*/\1/p' "$STATE_A/server.log")"
assert "the run's own server log names one readiness address" test -n "$ADDR_A"
assert "endpoint is first and names this run's server" test "$(sed -n '1p' "$ENV_A")" = "GRAN_ENDPOINT=https://$ADDR_A"
# By POSITION, not by presence anywhere in the file: the assertion's name
# claims an order, so it must read line two. A whole-file grep leaves the
# declared order unverified and stays green when two lines are swapped.
assert "pin is the second assignment, by position" sh -c 'case "$(sed -n 2p "$1")" in GRAN_PIN=?*) exit 0 ;; *) exit 1 ;; esac' sh "$ENV_A"
assert "root key comes from the raw sidecar bytes" grep -qx 'GRAN_ROOT_KEY=ed25519:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' "$ENV_A"
assert "root key is the third assignment, by position" sh -c 'case "$(sed -n 3p "$1")" in GRAN_ROOT_KEY=?*) exit 0 ;; *) exit 1 ;; esac' sh "$ENV_A"
assert "volume is the fourth caller-selected assignment" test "$(sed -n '4p' "$ENV_A")" = 'GRAN_VOLUME=volume-a'
assert "publisher diagnostics do not enter the env file" sh -c '! grep -q "fake .* diagnostic" "$1"' sh "$ENV_A"
assert "the first published file has caller bytes" cmp -s "$SCRATCH/source-a/payload" "$TRACE/published-1/payload"
assert "the first published file remains non-executable" test ! -x "$TRACE/published-1/payload"
assert "start did not modify the first source file" grep -qx 'alpha tree' "$SCRATCH/source-a/payload"

set +u
. "$ENV_A"
set -u
# One assertion PER VARIABLE, never the concatenation. `test -n "$A$B$C$D"`
# passes whenever ANY one of the four is non-empty, so it cannot observe a
# single empty value -- which is the only shape this contract is about.
assert "sourced GRAN_ENDPOINT is non-empty" test -n "$GRAN_ENDPOINT"
assert "sourced GRAN_PIN is non-empty" test -n "$GRAN_PIN"
assert "sourced GRAN_ROOT_KEY is non-empty" test -n "$GRAN_ROOT_KEY"
assert "sourced GRAN_VOLUME is non-empty" test -n "$GRAN_VOLUME"
# `printf %q ""` renders an empty value as the two characters '' -- which
# satisfies a `.+` shape check, so no per-line regex above can distinguish an
# empty assignment from a present one. Reject that rendering by name.
assert "no assignment carries the empty %q rendering" no_empty_q_rendering "$ENV_A"

set +e
EXPECT_PIN_DIGEST="$(
  openssl x509 -in "$STATE_A/tls/cert.pem" -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary \
    | openssl base64 \
    | tr -d '\n'
)"
EXPECT_PIN_RC=$?
set -e
assert "the fixture independently derives a non-empty SPKI digest" \
  test "$EXPECT_PIN_RC" -eq 0 -a -n "$EXPECT_PIN_DIGEST"
EXPECT_PIN="sha256/$EXPECT_PIN_DIGEST"
assert "the emitted pin is the SPKI pin of this run's certificate" \
  grep -qxF "GRAN_PIN=$EXPECT_PIN" "$ENV_A"

assert "the first caller-selected state dir receives the server pid" test -f "$STATE_A/server.pid"
assert "the first caller-selected state dir receives the MinIO pid" test -f "$STATE_A/minio-data/minio.pid"
SERVER_A="$(sed -n '1p' "$STATE_A/server.pid")"
MINIO_A="$(sed -n '1p' "$STATE_A/minio-data/minio.pid")"
assert "first state dir owns a live granary-server pid" pid_is_alive "$SERVER_A"
assert "first state dir owns a live MinIO pid" pid_is_alive "$MINIO_A"

assert_start_refused_by() {
  local description="$1" expected="$2" err_file="$3"
  if [ "$RUN_RC" -eq 0 ]; then
    fail "$description"
  fi
  if grep -Fq -- "$expected" "$err_file"; then
    pass "$description"
  else
    echo "unexpected refusal for: $description" >&2
    cat "$err_file" >&2
    fail "$description"
  fi
}

run_start "$SCRATCH/source-a" "volume-repeat" "$STATE_A" \
  "$SCRATCH/repeat.env" "$SCRATCH/repeat.err"
assert_start_refused_by "a second start into the same state dir is refused" \
  "--state-dir must be empty for start" "$SCRATCH/repeat.err"

STATE_INSIDE_SOURCE="$SCRATCH/source-a/nested-state"
run_start "$SCRATCH/source-a" "volume-state-inside" "$STATE_INSIDE_SOURCE" \
  "$SCRATCH/state-inside.env" "$SCRATCH/state-inside.err"
assert_start_refused_by "state dir inside source dir is refused" \
  "--state-dir must not be inside --source-dir" "$SCRATCH/state-inside.err"

STATE_AROUND_SOURCE="$SCRATCH/state-around-source"
SOURCE_INSIDE_STATE="$STATE_AROUND_SOURCE/source"
mkdir -p "$SOURCE_INSIDE_STATE"
printf 'nested source\n' > "$SOURCE_INSIDE_STATE/payload"
run_start "$SOURCE_INSIDE_STATE" "volume-source-inside" "$STATE_AROUND_SOURCE" \
  "$SCRATCH/source-inside.env" "$SCRATCH/source-inside.err"
assert_start_refused_by "source dir inside state dir is refused" \
  "--source-dir must not be inside --state-dir" "$SCRATCH/source-inside.err"

run_start / "volume-root-source" "$SCRATCH/state-under-root" \
  "$SCRATCH/root-source.env" "$SCRATCH/root-source.err"
assert_start_refused_by "the filesystem root cannot be the source dir" \
  "--state-dir must not be inside --source-dir" "$SCRATCH/root-source.err"

mkdir -p "$SCRATCH/state-link-target"
ln -s "$SCRATCH/state-link-target" "$SCRATCH/state-link"
run_start "$SCRATCH/source-a" "volume-state-link" "$SCRATCH/state-link" \
  "$SCRATCH/state-link.env" "$SCRATCH/state-link.err"
assert_start_refused_by "a symlinked state dir is refused" \
  "--state-dir must not be a symbolic link" "$SCRATCH/state-link.err"

ENV_B="$SCRATCH/b.env"
ERR_B="$SCRATCH/b.err"
STATE_B="$SCRATCH/state-b"
run_start "$SCRATCH/source-b" "volume-b" "$STATE_B" "$ENV_B" "$ERR_B"
assert "start accepts a second, different state dir" test "$RUN_RC" -eq 0
ADDR_B="$(sed -n 's/.*"addr":"\([^"]*\)".*/\1/p' "$STATE_B/server.log")"
assert "the second run's server log names one readiness address" test -n "$ADDR_B"
assert "the second endpoint names its own server" \
  test "$(sed -n '1p' "$ENV_B")" = "GRAN_ENDPOINT=https://$ADDR_B"
assert "separate fake-server runs emit separate addresses" test "$ADDR_A" != "$ADDR_B"
assert "the second published file has different caller bytes" cmp -s "$SCRATCH/source-b/payload" "$TRACE/published-2/payload"
assert "the second published file preserves the executable bit" test -x "$TRACE/published-2/payload"
assert "the two publications are byte-distinct" sh -c '! cmp -s "$1" "$2"' sh "$TRACE/published-1/payload" "$TRACE/published-2/payload"
assert "the second publish uses its caller-selected source and volume" grep -Fqx "$SCRATCH/source-b"$'\t'"volume-b"$'\t'"$TRACE/published-2" "$TRACE/publishes"

SERVER_B="$(sed -n '1p' "$STATE_B/server.pid")"
MINIO_B="$(sed -n '1p' "$STATE_B/minio-data/minio.pid")"
run_stop "$STATE_A" "$SCRATCH/stop-a.out" "$SCRATCH/stop-a.err"
assert "stop succeeds for the first state dir" test "$RUN_RC" -eq 0
assert "stop sends diagnostics only to stderr" test ! -s "$SCRATCH/stop-a.out"
assert "stop verifies its granary-server is gone" pid_is_dead "$SERVER_A"
assert "stop verifies its MinIO is gone" pid_is_dead "$MINIO_A"
assert "stopping one state dir leaves the other server alive" pid_is_alive "$SERVER_B"
assert "stopping one state dir leaves the other MinIO alive" pid_is_alive "$MINIO_B"
run_stop "$STATE_A" "$SCRATCH/stop-a2.out" "$SCRATCH/stop-a2.err"
assert "stop is idempotent" test "$RUN_RC" -eq 0
# A MinIO that is ALREADY DEAD when `stop` runs must have its pid file dropped
# before the harness is ever invoked, not carried into it. Tearing the server
# down can take fifteen seconds, and a pid released before that call is a pid
# the kernel may have reissued by the time it happens -- at which point handing
# the harness the stale file makes it signal whatever inherited the number.
DEAD_STATE="$SCRATCH/state-deadminio"
run_start "$SCRATCH/source-a" "volume-dead" "$DEAD_STATE" \
  "$SCRATCH/dead.env" "$SCRATCH/dead.err"
assert "dead-MinIO probe stack starts" test "$RUN_RC" -eq 0
DEAD_MINIO="$(sed -n '1p' "$DEAD_STATE/minio-data/minio.pid")"
kill -9 "$DEAD_MINIO" 2>/dev/null || true
DEAD_WAITED=0
while pid_is_alive "$DEAD_MINIO" && [ "$DEAD_WAITED" -lt 100 ]; do
  sleep 0.1
  DEAD_WAITED=$((DEAD_WAITED + 1))
done
assert "the probe's MinIO really is dead before stop runs" pid_is_dead "$DEAD_MINIO"
run_stop "$DEAD_STATE" "$SCRATCH/dead-stop.out" "$SCRATCH/dead-stop.err"
assert "stop succeeds when its MinIO died first" test "$RUN_RC" -eq 0
assert "stop drops the dead MinIO pid file rather than passing it on" \
  test ! -f "$DEAD_STATE/minio-data/minio.pid"
assert "the harness is never asked to signal a MinIO that was already dead" \
  sh -c '! grep -qxF "$2" "$1"' sh \
  "$TRACE/minio-stop-signals" "$DEAD_MINIO"

run_stop "$STATE_B" "$SCRATCH/stop-b.out" "$SCRATCH/stop-b.err"
assert "stop succeeds for the second state dir" test "$RUN_RC" -eq 0
assert "second granary-server is gone" pid_is_dead "$SERVER_B"
assert "second MinIO is gone" pid_is_dead "$MINIO_B"

# The execution probes had no red of their own: deleting the whole probe block
# from stack.sh left this suite at PASS. These two cases are that red. A
# binary that is present and +x but cannot produce its own diagnostic is exactly
# the macOS-Mach-O-under-Linux case the probes exist for, and `[ -x ]` passes it.
PROBE_REPO="$SCRATCH/probe-repo"
mkdir -p "$PROBE_REPO/scripts" "$PROBE_REPO/target/debug"
cp "$STACK_SCRIPT" "$PROBE_REPO/scripts/stack.sh"
cp "$FIXTURE_REPO/scripts/minio-harness.sh" "$PROBE_REPO/scripts/minio-harness.sh"
cp "$FIXTURE_REPO/target/debug/granary-server" "$PROBE_REPO/target/debug/granary-server"
printf '#!/usr/bin/env bash\nexit 0\n' > "$PROBE_REPO/target/debug/gran"
chmod +x "$PROBE_REPO/target/debug/gran"
set +e
env PATH="$FIXTURE_REPO/fake-bin:$PATH" GRANARY_SELFTEST_TRACE_DIR="$TRACE" \
  "$PROBE_REPO/scripts/stack.sh" start \
  --source-dir "$SCRATCH/source-a" --volume "volume-probe-gran" \
  --state-dir "$SCRATCH/state-probe-gran" \
  > "$SCRATCH/probe-gran.env" 2> "$SCRATCH/probe-gran.err"
PROBE_GRAN_RC=$?
set -e
assert "start refuses a +x gran that cannot produce its own banner" \
  test "$PROBE_GRAN_RC" -ne 0
assert "the gran execution probe names the failure" \
  grep -q "gran client failed its execution probe" "$SCRATCH/probe-gran.err"
assert "a failed gran probe emits no partial env contract" \
  test ! -s "$SCRATCH/probe-gran.env"

cp "$FIXTURE_REPO/target/debug/gran" "$PROBE_REPO/target/debug/gran"
printf '#!/usr/bin/env bash\nexit 0\n' > "$PROBE_REPO/target/debug/granary-server"
chmod +x "$PROBE_REPO/target/debug/granary-server"
set +e
env PATH="$FIXTURE_REPO/fake-bin:$PATH" GRANARY_SELFTEST_TRACE_DIR="$TRACE" \
  "$PROBE_REPO/scripts/stack.sh" start \
  --source-dir "$SCRATCH/source-a" --volume "volume-probe-server" \
  --state-dir "$SCRATCH/state-probe-server" \
  > "$SCRATCH/probe-server.env" 2> "$SCRATCH/probe-server.err"
PROBE_SERVER_RC=$?
set -e
assert "start refuses a +x granary-server that cannot produce its own banner" \
  test "$PROBE_SERVER_RC" -ne 0
assert "the granary-server execution probe names the failure" \
  grep -q "granary-server failed its execution probe" "$SCRATCH/probe-server.err"
assert "a failed granary-server probe emits no partial env contract" \
  test ! -s "$SCRATCH/probe-server.env"

MISSING="$SCRATCH/does-not-exist"
run_start "$MISSING" "missing-volume" "$SCRATCH/state-missing" "$SCRATCH/missing.env" "$SCRATCH/missing.err"
assert "start refuses a source tree that does not already exist" test "$RUN_RC" -ne 0
assert "start never creates a missing source tree" test ! -e "$MISSING"
assert "a failed start emits no partial env contract" test ! -s "$SCRATCH/missing.env"

run_start "$SCRATCH/source-a" "" "$SCRATCH/state-empty" "$SCRATCH/empty.env" "$SCRATCH/empty.err"
assert "start refuses an empty contract value" test "$RUN_RC" -ne 0
assert "empty-value refusal emits no env assignments" test ! -s "$SCRATCH/empty.env"

set +e
GRANARY_SELFTEST_PUBLISH_FAIL=1 fixture_stack \
  "$FIXTURE_REPO/scripts/stack.sh" start \
  --source-dir "$SCRATCH/source-fail" --volume "volume-fail" \
  --state-dir "$SCRATCH/state-fail" > "$SCRATCH/fail.env" 2> "$SCRATCH/fail.err"
RUN_RC=$?
set -e
assert "a publisher failure makes start fail" test "$RUN_RC" -ne 0
assert "a partial start emits no env assignments" test ! -s "$SCRATCH/fail.env"
FAILED_SERVER="$(tail -n 1 "$TRACE/server-pids")"
FAILED_MINIO="$(tail -n 1 "$TRACE/minio-starts" | awk -F '\t' '{print $3}')"
assert "partial-start cleanup kills its granary-server" pid_is_dead "$FAILED_SERVER"
assert "partial-start cleanup kills its MinIO" pid_is_dead "$FAILED_MINIO"

ENV_OWNER="$SCRATCH/owner.env"
STATE_OWNER="$SCRATCH/state-owner"
run_start "$SCRATCH/source-a" "volume-owner" "$STATE_OWNER" "$ENV_OWNER" "$SCRATCH/owner.err"
assert "ownership probe stack starts" test "$RUN_RC" -eq 0
OWN_SERVER="$(sed -n '1p' "$STATE_OWNER/server.pid")"
sleep 300 &
FOREIGN_PID=$!
: > "$TRACE/alive-$FOREIGN_PID"
printf '%s\n' "$FOREIGN_PID" > "$STATE_OWNER/server.pid"
run_stop "$STATE_OWNER" "$SCRATCH/owner-stop.out" "$SCRATCH/owner-stop.err"
assert "stop refuses a pid whose persisted identity does not match" test "$RUN_RC" -ne 0
assert "identity mismatch never kills the foreign process" pid_is_alive "$FOREIGN_PID"
kill "$FOREIGN_PID" 2>/dev/null || true
rm -f "$TRACE/alive-$FOREIGN_PID"
printf '%s\n' "$OWN_SERVER" > "$STATE_OWNER/server.pid"
run_stop "$STATE_OWNER" "$SCRATCH/owner-stop2.out" "$SCRATCH/owner-stop2.err"
assert "ownership probe cleans up after restoring its pid" test "$RUN_RC" -eq 0

ENV_LIE="$SCRATCH/lie.env"
STATE_LIE="$SCRATCH/state-lie"
run_start "$SCRATCH/source-a" "volume-lie" "$STATE_LIE" "$ENV_LIE" "$SCRATCH/lie.err"
assert "stubborn-MinIO probe stack starts" test "$RUN_RC" -eq 0
LIE_MINIO="$(sed -n '1p' "$STATE_LIE/minio-data/minio.pid")"
GRANARY_SELFTEST_MINIO_STOP_LIES=1 run_stop "$STATE_LIE" "$SCRATCH/lie-stop.out" "$SCRATCH/lie-stop.err"
assert "the MinIO process survives the lying harness" pid_is_alive "$LIE_MINIO"
assert "stop fails when the harness returns success but leaves MinIO alive" test "$RUN_RC" -ne 0
kill "$LIE_MINIO" 2>/dev/null || true
rm -f "$STATE_LIE/minio-data/minio.pid"
run_stop "$STATE_LIE" "$SCRATCH/lie-stop2.out" "$SCRATCH/lie-stop2.err"

STATE_LSOF="$SCRATCH/state-lsof"
GRANARY_SELFTEST_PS_FAIL=1 run_start "$SCRATCH/source-a" "volume-lsof" "$STATE_LSOF" \
  "$SCRATCH/lsof.env" "$SCRATCH/lsof.err"
assert "start succeeds when ps is unavailable and lsof is the fallback" test "$RUN_RC" -eq 0
assert "the ps fixture actually refuses the fallback stanza" test -s "$TRACE/ps-refusals"
assert "pid_is_alive reaches lsof's cwd probe" grep -q $'\tcwd$' "$TRACE/lsof-calls"
assert "process identity reaches lsof's txt probe" grep -q $'\ttxt$' "$TRACE/lsof-calls"
LSOF_SERVER="$(sed -n '1p' "$STATE_LSOF/server.pid")"
LSOF_MINIO="$(sed -n '1p' "$STATE_LSOF/minio-data/minio.pid")"
GRANARY_SELFTEST_PS_FAIL=1 run_stop "$STATE_LSOF" "$SCRATCH/lsof-stop.out" "$SCRATCH/lsof-stop.err"
assert "stop succeeds through the lsof fallback" test "$RUN_RC" -eq 0
assert "lsof-fallback stop verifies its server is gone" pid_is_dead "$LSOF_SERVER"
assert "lsof-fallback stop verifies its MinIO is gone" pid_is_dead "$LSOF_MINIO"

# ---------------------------------------------------------------------------
# A1 (evidence-backed, 37.5% reproduction): a ps
# that ALWAYS FAILS for the MinIO pid, with that pid made GENUINELY dead
# by the time pid_is_alive re-asks kill -0. A pid_is_alive that fell
# straight from a failed ps to the lsof ladder without re-asking kill -0
# would, when lsof ALSO cannot conclude (exactly the "lsof: ABSENT" shape,
# where lsof correctly determines death via its own kill -0 but reports
# that as an ordinary FAILURE,
# indistinguishable at the exit-code level from "cannot inspect"), return
# ALIVE regardless of whether the process was actually gone. pid_is_alive
# re-asks kill -0 immediately after a failed ps, before ever falling to the
# lsof ladder.
#
# A plain "ps always fails" is not enough to construct this deterministically:
# empirically, by the time stack.sh's own postcondition check runs (after
# the real MinIO harness's stop has already signalled and confirmed the
# process via its own file marker), the fixture process is reliably ALREADY
# fully reaped on this host -- so pid_is_alive's FIRST kill -0 already
# correctly reports it dead, and the ps/lsof ladder that follows it is
# never even reached. The case
# below therefore builds the exact race directly: a special `ps`, invoked
# for the MinIO pid ONLY (every other pid is delegated to the ordinary
# fixture ps unchanged), itself SIGKILLs the target and polls kill -0 until
# it is confirmed fully gone, THEN fails -- so pid_is_alive's own FIRST
# kill -0 (before ps runs) still sees a genuinely live process, and only
# the RE-ASKED kill -0 (or, without it, the lsof ladder) sees it gone. This
# fires inside classify_owned_pid's own pid_is_alive call (the earliest of
# pid_is_alive's four call sites reached for a MinIO that stop must decide
# is present or absent) rather than the later "still alive after stop
# returned" postcondition -- both read the SAME pid_is_alive, so the
# re-asked kill -0 is exercised identically either way. Because the kill is a
# SIGKILL (bypassing the fixture's own TERM/INT trap, which is what would
# otherwise write its dead-marker file), lsof's dead-marker fast path never
# fires either, so this also is not a "lsof absent" construction: it is the
# same "any lsof failure reads as ambiguous" defect described above.
# ---------------------------------------------------------------------------
mkdir -p "$FIXTURE_REPO/fake-bin-a1race"
cat > "$FIXTURE_REPO/fake-bin-a1race/ps" <<'FAKE_PS_A1RACE'
#!/usr/bin/env bash
set -euo pipefail
pid="${!#}"
if [ -n "${GRANARY_SELFTEST_PS_RACE_KILL_PID:-}" ] && [ "$pid" = "$GRANARY_SELFTEST_PS_RACE_KILL_PID" ]; then
  # Force the target GENUINELY dead before failing, bounded so this can
  # never hang the suite. SIGKILL deliberately bypasses the fixture
  # process's own TERM/INT trap, so its dead-marker file is never written --
  # only a re-asked kill -0 (A1's fix) or a permission-restricted lsof can
  # tell this case apart from "cannot inspect".
  kill -9 "$pid" 2>/dev/null || true
  # THE INJECTION MUST LEAVE A MARK. `RUN_RC -eq 0` also holds for an
  # ordinary stop, so it cannot prove that this race injection fired.
  # A variable the fake does not read or a pid that does not match must
  # not produce a passing injection check.
  # GRANARY_SELFTEST_PS_RACE_MARKER exists only to prove that the fault
  # was applied; nothing outside the self-test reads it.
  # `if`, NOT `[ … ] && …`: as a trailing && list this returns 1 whenever
  # the marker is unset, and under `set -euo pipefail` that ABORTS the fake
  # before the bounded wait below — which would put back the very race the
  # A1 case exists to exclude, in the control added to prove it fired.
  if [ -n "${GRANARY_SELFTEST_PS_RACE_MARKER:-}" ]; then
    : > "$GRANARY_SELFTEST_PS_RACE_MARKER"
  fi
  waited=0
  while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 300 ]; do
    sleep 0.01
    waited=$((waited + 1))
  done
  exit 1
fi
exec "$GRANARY_SELFTEST_PS_RACE_DELEGATE" "$@"
FAKE_PS_A1RACE
chmod +x "$FIXTURE_REPO/fake-bin-a1race/ps"

STATE_A1RACE="$SCRATCH/state-a1-ps-race"
run_start "$SCRATCH/source-a" "volume-a1-ps-race" "$STATE_A1RACE" \
  "$SCRATCH/a1-race.env" "$SCRATCH/a1-race.err"
if [ "$RUN_RC" -ne 0 ]; then
  echo "A1-race setup start stderr:" >&2
  cat "$SCRATCH/a1-race.err" >&2
fi
assert "A1 race setup: the probe stack starts normally" test "$RUN_RC" -eq 0
A1RACE_MINIO="$(sed -n '1p' "$STATE_A1RACE/minio-data/minio.pid")"
assert "A1 race setup: its MinIO is alive before the race begins" pid_is_alive "$A1RACE_MINIO"

A1RACE_MARKER="$SCRATCH/a1-race-fired"
rm -f "$A1RACE_MARKER"
GRANARY_SELFTEST_PS_RACE_KILL_PID="$A1RACE_MINIO" GRANARY_SELFTEST_PS_RACE_DELEGATE="$FIXTURE_REPO/fake-bin/ps" \
  GRANARY_SELFTEST_PS_RACE_MARKER="$A1RACE_MARKER" \
  run_stop_extra_path "$FIXTURE_REPO/fake-bin-a1race" "$STATE_A1RACE" \
  "$SCRATCH/a1-race-stop.out" "$SCRATCH/a1-race-stop.err"
if [ "$RUN_RC" -ne 0 ]; then
  echo "A1 race stop stderr:" >&2
  cat "$SCRATCH/a1-race-stop.err" >&2
fi
assert "A1: the race was actually injected (the fake ps killed the pid and said so)" \
  test -e "$A1RACE_MARKER"
assert "A1: stop succeeds when ps fails for a MinIO pid that is genuinely dead by the re-asked kill -0" \
  test "$RUN_RC" -eq 0

port_matches_two_port_slot() {
  local trace_file="$1" dir port minio_pid stack_pid expected
  IFS=$'\t' read -r dir port minio_pid stack_pid < "$trace_file"
  case "$port" in ''|*[!0-9]*) return 1 ;; esac
  case "$stack_pid" in ''|*[!0-9]*) return 1 ;; esac
  expected=$((20000 + 2 * (stack_pid % 15000)))
  [ "$port" -eq "$expected" ]
}

port_pairs_are_disjoint() {
  local trace_a="$1" trace_b="$2" dir_a port_a minio_a stack_a
  local dir_b port_b minio_b stack_b
  IFS=$'\t' read -r dir_a port_a minio_a stack_a < "$trace_a"
  IFS=$'\t' read -r dir_b port_b minio_b stack_b < "$trace_b"
  [ "$stack_a" != "$stack_b" ] || return 1
  [ "$port_a" -ne "$port_b" ] \
    && [ "$((port_a + 1))" -ne "$port_b" ] \
    && [ "$port_a" -ne "$((port_b + 1))" ]
}

CONCURRENT_TRACE_A="$TRACE/concurrent-a"
CONCURRENT_TRACE_B="$TRACE/concurrent-b"
CONCURRENT_STATE_A="$SCRATCH/state-concurrent-a"
CONCURRENT_STATE_B="$SCRATCH/state-concurrent-b"
mkdir -p "$CONCURRENT_TRACE_A" "$CONCURRENT_TRACE_B"
set +e
RUN_TRACE="$CONCURRENT_TRACE_A" fixture_stack \
  "$FIXTURE_REPO/scripts/stack.sh" start \
  --source-dir "$SCRATCH/source-a" --volume volume-concurrent-a \
  --state-dir "$CONCURRENT_STATE_A" \
  > "$SCRATCH/concurrent-a.env" 2> "$SCRATCH/concurrent-a.err" &
CONCURRENT_JOB_A=$!
RUN_TRACE="$CONCURRENT_TRACE_B" fixture_stack \
  "$FIXTURE_REPO/scripts/stack.sh" start \
  --source-dir "$SCRATCH/source-b" --volume volume-concurrent-b \
  --state-dir "$CONCURRENT_STATE_B" \
  > "$SCRATCH/concurrent-b.env" 2> "$SCRATCH/concurrent-b.err" &
CONCURRENT_JOB_B=$!
wait "$CONCURRENT_JOB_A"
CONCURRENT_RC_A=$?
wait "$CONCURRENT_JOB_B"
CONCURRENT_RC_B=$?
set -e
assert "the first concurrent stack starts" test "$CONCURRENT_RC_A" -eq 0
assert "the second concurrent stack starts" test "$CONCURRENT_RC_B" -eq 0
assert "the first concurrent stack receives a two-port slot" \
  port_matches_two_port_slot "$CONCURRENT_TRACE_A/minio-starts"
assert "the second concurrent stack receives a two-port slot" \
  port_matches_two_port_slot "$CONCURRENT_TRACE_B/minio-starts"
assert "the concurrent MinIO API/console port pairs are disjoint" \
  port_pairs_are_disjoint "$CONCURRENT_TRACE_A/minio-starts" "$CONCURRENT_TRACE_B/minio-starts"
RUN_TRACE="$CONCURRENT_TRACE_A" run_stop "$CONCURRENT_STATE_A" \
  "$SCRATCH/concurrent-stop-a.out" "$SCRATCH/concurrent-stop-a.err"
assert "the first concurrent stack stops" test "$RUN_RC" -eq 0
RUN_TRACE="$CONCURRENT_TRACE_B" run_stop "$CONCURRENT_STATE_B" \
  "$SCRATCH/concurrent-stop-b.out" "$SCRATCH/concurrent-stop-b.err"
assert "the second concurrent stack stops" test "$RUN_RC" -eq 0

# POSITIVE CONTROL FIRST: a scanner that has never detected anything is not a
# detector. Each fixture below is a spelling a real implementation could use,
# and the scanner must fire on every one of them before its silence on the real
# file is allowed to mean anything.
for spelling in \
  'mount /a /b' \
  'umount /a' \
  'mount;' \
  'mount|tee x' \
  'mount&' \
  'x=$(mount)' \
  '/usr/bin/mount /a /b' \
  '/usr/sbin/umount /a' \
  'gran mount v /m' \
  'fusermount -u /mnt/x' \
  'diskutil unmount /mnt/x' \
  'umount2 /mnt/x' \
  'mount_nfs server:/ /mnt/x' \
  'mount.fuse3 volume /mnt/x' \
  '"mount" /a /b' \
  "'umount' /a" \
  '\mount /a /b' \
  'mount>/dev/null' \
  'umount</dev/null' \
  "printf '#'; mount /a /b" \
  'x=1 # note
mount /a /b'
do
  printf '%s\n' "$spelling" > "$SCRATCH/mount-fixture"
  if scan_for_mount_command "$SCRATCH/mount-fixture"; then
    pass "mount scanner fires on: $spelling"
  else
    fail "mount scanner fires on: $spelling"
  fi
done
# And it must NOT fire on prose, or the implementation cannot document itself.
printf '%s\n' '# this script mounts nothing and unmounts nothing' > "$SCRATCH/mount-fixture"
if scan_for_mount_command "$SCRATCH/mount-fixture"; then
  fail "mount scanner ignores a comment that says mount"
else
  pass "mount scanner ignores a comment that says mount"
fi

if scan_for_mount_command "$STACK_SCRIPT"; then
  fail "no mount or unmount command appears in the implementation's non-comment lines"
else
  pass "no mount or unmount command appears in the implementation's non-comment lines"
fi

echo "stack self-check: PASS ($CHECKS checks)"
