#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# Demonstrates the "server down, cached reads keep working" claim
# against the REAL surfaces — a real `granary-server` behind
# real pinned TLS, a real MinIO bucket, and the compiled `gran` binary.
#
#   scripts/m7-demo.sh               # expect final line DEGRADED-READ-OK
#   scripts/m7-demo.sh --wipe-cache  # expect final line DEGRADED-READ-REFUSED
#
# Each invocation is a COMPLETE, independent run: build, start MinIO,
# mint TLS material, start a granary-server, publish a small volume, a
# WARM `gran cat` (populates the cache), kill the granary-server (never
# MinIO — the object store outlives the grain server, which is the
# demo's point), then the SAME `gran cat` again in a FRESH PROCESS. Only
# the `--wipe-cache` variant additionally wipes the cache dir between the
# warm read and the post-kill read, which is what turns
# DEGRADED-READ-OK into the negative proof DEGRADED-READ-REFUSED:
# same dead server, cache wiped, the read now genuinely has nothing to
# fall back to.
#
# The cache dir (and everything else except the publishing key) is wiped
# at the START of every invocation too — never reused across runs — for
# a structural reason, not tidiness: `GRANARY_LISTEN=127.0.0.1:0` binds a
# NEW ephemeral port each run, so a cache dir surviving from
# a PRIOR run would carry a different `--endpoint` in its origin marker
# and every read would fail closed on `CacheError::Incompatible` before
# ever reaching the degraded path this script exists to demonstrate.
#
# The publishing key-seed DOES persist across runs, deliberately: `gran
# publish`'s `load_or_create_key` prints the raw public key hex to STDOUT
# only on first generation, so a second run against an existing seed
# file would have nothing to scrape even if this script still tried —
# which is exactly why the `--root-key` hex below is read back off the
# `.pub` sidecar's raw bytes, never off `gran publish`'s stdout — see
# the note at the read site below.
set -euo pipefail
cd "$(dirname "$0")/.."

WIPE_CACHE=0
case "${1:-}" in
  --wipe-cache) WIPE_CACHE=1 ;;
  "") ;;
  *) echo "usage: $0 [--wipe-cache]" >&2; exit 1 ;;
esac

DEMO_DIR="target/m7-demo"
MINIO_DIR="$DEMO_DIR/minio-data"
MINIO_PORT=19277
TLS_DIR="$DEMO_DIR/tls"
CERT_PEM="$TLS_DIR/cert.pem"
KEY_PEM="$TLS_DIR/key.pem"
KEY_SEED="$DEMO_DIR/publish.key"
STORE_DIR="$DEMO_DIR/store"
SOURCE_DIR="$DEMO_DIR/source"
CACHE_DIR="$DEMO_DIR/cache"
SERVER_LOG="$DEMO_DIR/server.log"
VOLUME="m7-demo-vol"
FILE_NAME="hello.txt"
WARM_OUT="$DEMO_DIR/warm-output.bin"
DEGRADED_OUT="$DEMO_DIR/degraded-output.bin"
DEGRADED_ERR="$DEMO_DIR/degraded-stderr.log"

SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$SERVER_PID" 2>/dev/null || break
      sleep 0.1
    done
    kill -9 "$SERVER_PID" 2>/dev/null || true
  fi
  ./scripts/minio-harness.sh stop "$MINIO_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$DEMO_DIR"

# Fresh every run — see the header note on WHY (a stale origin marker
# would refuse on Incompatible before ever reaching degraded mode).
rm -rf "$MINIO_DIR" "$TLS_DIR" "$STORE_DIR" "$SOURCE_DIR" "$CACHE_DIR" "$SERVER_LOG" \
       "$WARM_OUT" "$DEGRADED_OUT" "$DEGRADED_ERR"

echo "== building binaries =="
cargo build -p granary-cli -p granary-client -p granary-server

echo "== starting minio =="
./scripts/minio-harness.sh start "$MINIO_DIR" "$MINIO_PORT"
# Fixed test-only credentials (`scripts/minio-harness.sh`'s own comment:
# "every consumer reads these same names") — `start` exports them into
# ITS OWN process only, so this script (a separate process) names the
# same fixed values directly rather than trying to inherit an export
# that never crosses the process boundary.
GRANARY_MINIO_USER="granary-test"
GRANARY_MINIO_PASS="granary-test-secret"

echo "== minting TLS material (measured against both openssls on this machine) =="
mkdir -p "$TLS_DIR"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$KEY_PEM" -out "$CERT_PEM" -days 2 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
PIN_DIGEST="$(
  openssl x509 -in "$CERT_PEM" -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary \
    | openssl base64 \
    | tr -d '\n'
)"
if [ -z "$PIN_DIGEST" ]; then
  echo "failed to derive the SPKI pin from $CERT_PEM" >&2
  exit 1
fi
PIN="sha256/${PIN_DIGEST}"
echo "pin: $PIN"

echo "== starting granary-server =="
GRANARY_STORE="s3:" \
GRANARY_STORE_BUCKET="granary-test" \
GRANARY_STORE_ENDPOINT="http://127.0.0.1:${MINIO_PORT}" \
GRANARY_STORE_REGION="us-east-1" \
AWS_ACCESS_KEY_ID="$GRANARY_MINIO_USER" \
AWS_SECRET_ACCESS_KEY="$GRANARY_MINIO_PASS" \
GRANARY_LISTEN="127.0.0.1:0" \
GRANARY_TLS_CERT="$CERT_PEM" \
GRANARY_TLS_KEY="$KEY_PEM" \
  target/debug/granary-server >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# The bound address comes from the readiness line, never a
# fixed port — `GRANARY_LISTEN=127.0.0.1:0` picks an ephemeral one, and
# the server logs it as JSON on stderr (`"addr":"..."`,
# `binary_signals.rs`'s own READY_KEY). Bounded poll, never a blind
# sleep; fail loudly with the captured log if it never appears (a server
# that failed to start prints its refusal there instead).
ADDR=""
for _ in $(seq 1 100); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "granary-server exited before becoming ready. log:" >&2
    cat "$SERVER_LOG" >&2
    exit 1
  fi
  ADDR="$(sed -n 's/.*"addr":"\([^"]*\)".*/\1/p' "$SERVER_LOG" 2>/dev/null | head -1)"
  [ -n "$ADDR" ] && break
  sleep 0.1
done
if [ -z "$ADDR" ]; then
  echo "granary-server never printed a readiness line within the bound. log:" >&2
  cat "$SERVER_LOG" >&2
  exit 1
fi
echo "granary-server ready at $ADDR"
ENDPOINT="https://${ADDR}"

echo "== harvest + publish =="
mkdir -p "$SOURCE_DIR"
printf 'hello from the m7 degraded-mode demo\n' > "$SOURCE_DIR/$FILE_NAME"
target/debug/gran publish "$STORE_DIR" "$SOURCE_DIR" "$VOLUME" \
  --publish-mode legacy-server \
  --endpoint "$ENDPOINT" --pin "$PIN" --key-seed "$KEY_SEED"

if [ ! -f "${KEY_SEED}.pub" ]; then
  echo "publish did not write ${KEY_SEED}.pub" >&2
  exit 1
fi
# The raw 32 public-key bytes come off the `.pub` sidecar, hex
# encoded — NEVER scraped from `gran publish`'s stdout (which prints the
# hex only on FIRST key generation, so a re-run against an existing
# key-seed file would scrape nothing).
# `command -v` gates the choice, so `set -e` never aborts on a missing
# `xxd` before the POSIX `od` fallback is even reached —
# the fallback was unreachable when it hung off a post-hoc length check
# of a failed `xxd` substitution.
if command -v xxd >/dev/null 2>&1; then
  ROOT_KEY_HEX="$(xxd -p "${KEY_SEED}.pub" | tr -d '\n')"
else
  ROOT_KEY_HEX="$(od -An -v -tx1 "${KEY_SEED}.pub" | tr -d ' \n')"
fi
if [ "${#ROOT_KEY_HEX}" -ne 64 ]; then
  echo "derived root-key hex is ${#ROOT_KEY_HEX} chars, want exactly 64: $ROOT_KEY_HEX" >&2
  exit 1
fi
ROOT_KEY="ed25519:${ROOT_KEY_HEX}"

echo "== warm gran cat (--root-key REQUIRED — a cat verifies against a signed root) =="
target/debug/gran cat "$VOLUME" "$FILE_NAME" \
  --endpoint "$ENDPOINT" --pin "$PIN" --root-key "$ROOT_KEY" --cache-dir "$CACHE_DIR" \
  > "$WARM_OUT"
echo "warm read: $(wc -c < "$WARM_OUT" | tr -d ' ') bytes"

echo "== killing granary-server (NOT minio) =="
kill "$SERVER_PID"
for _ in $(seq 1 50); do
  kill -0 "$SERVER_PID" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "granary-server ignored SIGTERM; escalating to SIGKILL" >&2
  kill -9 "$SERVER_PID" 2>/dev/null || true
fi
SERVER_PID=""

if [ "$WIPE_CACHE" -eq 1 ]; then
  echo "== --wipe-cache: removing $CACHE_DIR =="
  rm -rf "$CACHE_DIR"
fi

echo "== gran cat again, fresh process, server dead =="
set +e
target/debug/gran cat "$VOLUME" "$FILE_NAME" \
  --endpoint "$ENDPOINT" --pin "$PIN" --root-key "$ROOT_KEY" --cache-dir "$CACHE_DIR" \
  > "$DEGRADED_OUT" 2> "$DEGRADED_ERR"
DEGRADED_STATUS=$?
set -e

if [ "$WIPE_CACHE" -eq 1 ]; then
  if [ "$DEGRADED_STATUS" -eq 0 ]; then
    echo "the --wipe-cache read SUCCEEDED with the server dead and the cache wiped — this \
disproves the negative proof it exists to give. stderr:" >&2
    cat "$DEGRADED_ERR" >&2
    exit 1
  fi
  echo "read failed as expected (cache wiped, server dead, nothing to fall back to):"
  cat "$DEGRADED_ERR"
  echo "DEGRADED-READ-REFUSED"
else
  if [ "$DEGRADED_STATUS" -ne 0 ]; then
    echo "the degraded read FAILED with the cache still warm — expected DEGRADED-READ-OK. \
stderr:" >&2
    cat "$DEGRADED_ERR" >&2
    exit 1
  fi
  if ! cmp -s "$WARM_OUT" "$DEGRADED_OUT"; then
    echo "the degraded read succeeded but its bytes differ from the warm read — that is a \
correctness defect, not a demo artifact." >&2
    exit 1
  fi
  echo "degraded read byte-identical to the warm read ($(wc -c < "$DEGRADED_OUT" | tr -d ' ') \
bytes), server dead throughout:"
  cat "$DEGRADED_ERR"
  echo "DEGRADED-READ-OK"
fi
