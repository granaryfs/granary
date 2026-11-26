#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# Local MinIO for the K2 conditional-write lane.
# MinIO OSS is ARCHIVED upstream (2026-04-25); this pins the
# last PORTABLE community release on every channel — darwin-arm64 for
# the dev Mac, linux-amd64 for CI, linux-arm64 for the local Linux loop
# (scripts/linux-container.sh: the podman machine is native aarch64, and the
# FUSE mount only works there) — each verified by SHA256. The darwin and
# amd64 hashes were taken 2026-08-13 from dl.min.io; the darwin binary's
# hash also matched an earlier independent fetch. The arm64 hash was taken
# 2026-09-01, as its own note below records.
#
# THE DISTRIBUTION CHANNEL IS GONE, THE ARTEFACT IS NOT. On 2026-09-14,
# `dl.min.io` answered **410 Gone** for every community release on
# every channel — not a stale pin, a site-wide withdrawal, and its own
# body said: "These files are no longer served from this site. This
# applies to all community releases and to all hotfix builds for them."
# Re-pinning to a newer release cannot recover that distribution channel.
# The GitHub release tag carries artefacts matching the SHA256 constants
# taken from dl.min.io in 2026-08/09:
#
#   channel       size (bytes)  two fetches  vs the hash pinned here
#   darwin-arm64   108,218,434  cmp-identical  MATCHES
#   linux-amd64    110,989,496  cmp-identical  MATCHES
#   linux-arm64    105,251,000  cmp-identical  MATCHES
#
# plus upstream's own published `.sha256sum` sidecar asset for each of
# the three, which agrees with all three constants. So this is a
# STRONGER record than the two-fetch rule below asks for: the same bytes
# came from two INDEPENDENT DISTRIBUTION CHANNELS months apart and hash the
# same. The per-channel K2 audit recorded below is evidence for these exact
# binaries. CI's two `minio-RELEASE.*` cache keys use the same release string.
#
# A GitHub release asset CAN be replaced or deleted by the upstream
# repo, exactly as dl.min.io's were. That is not a new exposure: the
# SHA256 gate below is what makes either channel acceptable, and it
# fails CLOSED on substituted bytes. If GitHub goes the way of
# dl.min.io, set GRANARY_MINIO_BINARY to a copy of the artefact (see
# `ensure` below) — it takes the same hash check and no other path.
#
# EVIDENCE IS PER CHANNEL, not per release. The conditional-write surface
# granary needs (If-None-Match:*, If-Match, 304 revalidation,
# single-drive) was executed against exactly this release with server-side
# audit confirmation for darwin-arm64 and linux-amd64. That run is evidence
# for THOSE TWO BINARIES and not for a third. The linux-arm64 evidence is:
# `minio-harness.sh test` inside the linux-container container, 7 of 7
# granary-store::minio_cas tests passed (2026-09-01), against a MinIO
# freshly FETCHED through this channel rather than a cached one. The
# reason that is not pedantry: modern single-drive MinIO is a zero-parity
# ERASURE backend that still computes HighwayHash bitrot checksums, so it
# carries arch-specific code paths this lane can actually reach.
#
# CI NEVER EXERCISES THE linux-arm64 CHANNEL — CI's own lane is
# linux/x64. An arm64-only divergence in MinIO's behaviour therefore
# passes CI green and shows up only on a developer's machine, which is
# the opposite of the usual direction. Re-run the audit above (not just
# the checksum) whenever RELEASE is bumped.
#
#   scripts/minio-harness.sh ensure          # download+verify the binary
#   scripts/minio-harness.sh path            # report the platform's binary path
#   scripts/minio-harness.sh start DIR PORT  # serve DIR on 127.0.0.1:PORT
#   scripts/minio-harness.sh check-port      # refuse an occupied test port
#   scripts/minio-harness.sh stop DIR        # stop the server for DIR
#   scripts/minio-harness.sh test            # ensure + start + run the
#                                            # #[ignore]d store lane + stop
#
# The binary is cached under the repository's target/minio/, data
# in the caller's DIR, credentials fixed test-only values. Poll the
# health endpoint, never sleep blind — ready in ~0.8 s on the dev Mac,
# which includes a fixed 0.5 s settle before the first poll is
# trusted, sized off a measured ~110 ms same-port bind-conflict failure.
set -euo pipefail
# Captured BEFORE the cd, and the only thing that needs it: every path this
# script computes is repo-relative, but GRANARY_MINIO_BINARY comes from the
# CALLER and is theirs to write relative to where they are standing. Without
# this, `cd /tmp && GRANARY_MINIO_BINARY=minio-copy …/minio-harness.sh ensure`
# refuses a file that is right there — which is precisely the fresh-clone,
# binary-carried-by-hand case the hatch exists for.
INVOCATION_PWD="$PWD"
cd "$(dirname "$0")/.."

TEST_PORT=19187

RELEASE="RELEASE.2025-09-07T16-13-09Z"
SHA_DARWIN_ARM64="7c3b3039b76e55a1b80935848ed83998d5e8d317374f87851f46a019ff5c0aa4"
SHA_LINUX_AMD64="7c5bd8512c6e966455b1d198209358b2d191c77a83ab377c4073281065fb855f"
# Hashed 2026-09-01 from dl.min.io, from TWO independent fetches whose bytes
# were byte-identical (`cmp`), so this is the artefact's hash and not one
# download's corruption. 105,251,000 bytes; `file` reports "ELF 64-bit LSB
# executable, ARM aarch64, statically linked".
SHA_LINUX_ARM64="5c83cd2cf151717ba0243f73e1c7802ff36e272b67144bdd7f1f7d684fd6f03d"

# The base URL is separate from the release pin. A re-pin moves RELEASE and
# voids the per-channel audit; a re-host moves this constant and does not.
BASE_URL="https://github.com/minio/minio/releases/download/${RELEASE}"

# Fixed test-only credentials; every consumer reads these same names.
export GRANARY_MINIO_USER="granary-test"
export GRANARY_MINIO_PASS="granary-test-secret"

# `exit 1` here must never be reached through a `$(...)` command
# substitution, which runs in a SUBSHELL — the exit would kill that
# subshell, not the script, so an unsupported platform would fall through
# with an empty $plat/$sha, fetch a 404 into a junk `.tmp`, and fail later
# with a confusing shasum error instead of failing here. Every
# caller below calls `detect_platform` directly (never inside `$(...)`)
# before it is first needed, so this exit is the script's real, once-only,
# exit — and because the download path is never reached, no `.tmp` is ever
# created for an unsupported platform.
PLATFORM=""
PLATFORM_SHA=""
detect_platform() {
  [ -n "$PLATFORM" ] && return 0
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) PLATFORM="darwin-arm64"; PLATFORM_SHA="${SHA_DARWIN_ARM64}" ;;
    Linux-x86_64) PLATFORM="linux-amd64"; PLATFORM_SHA="${SHA_LINUX_AMD64}" ;;
    # `Linux-aarch64`, NEVER `Linux-arm64`. `uname -m` on Linux ARM is
    # `aarch64` (executed 2026-09-01 in both the podman VM and a container
    # from it: `uname -m = aarch64`), while MinIO's DOWNLOAD path segment is
    # `linux-arm64` — the two spellings differ, and a case label copied from
    # the artefact name would silently never match and fall through to the
    # unsupported-platform exit below. Support-shaped non-support.
    Linux-aarch64) PLATFORM="linux-arm64"; PLATFORM_SHA="${SHA_LINUX_ARM64}" ;;
    *) echo "unsupported platform for the pinned MinIO: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
  esac
}

bin_path() {
  echo "target/minio/minio-${RELEASE}-${PLATFORM}"
}

# `kill -0 PID` succeeds for a ZOMBIE too — the process table entry
# persists until the parent calls wait(2) on it. start()'s spawned minio
# is a DIRECT child of this script, backgrounded and never explicitly
# waited on, so a child that dies right after we record its pid stays
# kill-0-"alive" for the rest of this script's run, silently defeating
# both Fix A1 (start()'s post-check) and Fix A2 (stop()'s death wait) —
# caught by execution: with lsof made unavailable to isolate the kill -0
# path, a fresh minio that lost the port race still reported "ready"
# because its own exited (zombie) pid passed `kill -0`. `ps -o stat=`
# distinguishes a genuine zombie ('Z...') from a live process; both
# BSD ps (macOS) and GNU ps (Linux/CI) support it.
pid_is_alive() {
  local pid="$1" stat
  kill -0 "$pid" 2>/dev/null || return 1
  stat="$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
  [ -n "$stat" ] || return 1
  case "$stat" in
    Z*) return 1 ;;
    *) return 0 ;;
  esac
}

ensure() {
  detect_platform
  local bin; bin="$(bin_path)"
  if [ -x "$bin" ] && echo "${PLATFORM_SHA}  ${bin}" | shasum -a 256 -c - >/dev/null 2>&1; then
    echo "minio ok: ${bin}"
    return 0
  fi
  mkdir -p "$(dirname "$bin")"
  # A `.tmp` never survives this function (see the refusal path below), but a
  # run KILLED mid-download leaves one, and CI's cache glob is
  # `target/minio/minio-*` under an immutable release-keyed name — so a
  # half-file can be cached for the life of the pin. Clear it before writing.
  rm -f "${bin}.tmp"

  # THE ESCAPE HATCH, and why it cannot weaken the gate. dl.min.io's
  # withdrawal (header) proved a distribution channel can vanish while the
  # artefact is still correct, and a fresh clone with no served channel
  # cannot run this lane AT ALL. GRANARY_MINIO_BINARY names a local copy
  # of the artefact — and takes the IDENTICAL shasum gate three lines
  # below, on the same constant, with no branch that skips it. So the most
  # it can do is supply bytes that are already the pinned bytes; it is a
  # second way to obtain the SAME artefact, never a way to admit another
  # one. It is copied rather than symlinked so that the cached file this
  # script re-verifies before every later use is the file it checked.
  if [ -n "${GRANARY_MINIO_BINARY:-}" ]; then
    # Resolved against the CALLER's directory, not the repo root this script
    # cd'd to — an absolute path is unaffected, a relative one now means what
    # the caller meant.
    local supplied="$GRANARY_MINIO_BINARY"
    case "$supplied" in
      /*) ;;
      *) supplied="${INVOCATION_PWD}/${supplied}" ;;
    esac
    echo "using GRANARY_MINIO_BINARY=${supplied} (hash-checked below)"
    [ -f "$supplied" ] \
      || { echo "GRANARY_MINIO_BINARY is not a file: ${supplied}" >&2; exit 1; }
    cp "$supplied" "${bin}.tmp"
  else
    echo "fetching minio ${RELEASE} (${PLATFORM})..."
    # Fix A4: -f so an HTTP error page doesn't get written to .tmp and exit 0
    # (the checksum gate still catches that, but with a confusing "no
    # properly formatted SHA checksum lines found" instead of a fetch
    # failure); --connect-timeout/--max-time so a hung download doesn't hang
    # forever (CI already bounds this by the job timeout, the
    # local lane bounded it at nothing).
    #
    # --max-time was 120: the GitHub asset is ~108 MB and the dev Mac
    # fetches it in ~3 s, but 120 s is a ~0.9 MB/s floor and this runs on
    # CI runners and in a podman VM. Raised to 300 to bound a slow link
    # rather than a hung one — the value is still a BOUND, which is the
    # property Fix A4 wanted.
    curl -fsSL --connect-timeout 10 --max-time 300 -o "${bin}.tmp" \
      "${BASE_URL}/minio.${PLATFORM}.${RELEASE}"
  fi

  # The single gate BOTH paths above reach, and the only way to `$bin`.
  # On refusal the rejected bytes are DELETED rather than left behind:
  # a bare `set -e` abort here would leave a ~108 MB `${bin}.tmp` of refused
  # bytes beside the binary, which CI's default `target/minio/minio-*` cache
  # glob matches — and that key is the immutable release string, so one bad
  # run could carry the junk for the life of the pin. It is not a correctness
  # hole (`bin_path()` has no `.tmp` in
  # it, so a refused file is never run), which is why it is easy to miss.
  if ! echo "${PLATFORM_SHA}  ${bin}.tmp" | shasum -a 256 -c -; then
    rm -f "${bin}.tmp"
    echo "minio: refused — the bytes do not match the pinned SHA-256 for ${PLATFORM}." >&2
    echo "       Nothing was installed and the rejected file was deleted." >&2
    exit 1
  fi
  chmod +x "${bin}.tmp"
  mv "${bin}.tmp" "$bin"
  echo "minio ok: ${bin}"
}

check_port() {
  local port="$1"
  # Fix A3 (pre-flight): if anything is already answering the health
  # endpoint on this port before we have spawned anything, a fresh MinIO
  # behind it would be indistinguishable from the impostor once BOTH are
  # answering — refuse up front rather than relying only on the post-check
  # below. This is the cheap guard that makes that post-check nearly
  # unreachable.
  if curl -sf "http://127.0.0.1:${port}/minio/health/ready" >/dev/null 2>&1; then
    cat >&2 <<EOF
minio start: something is ALREADY answering the MinIO health endpoint on
127.0.0.1:${port} — a foreign or leaked server holds this port. Refusing to
start a second server behind it (its answers would be indistinguishable
from ours once both exist).
  find it:  lsof -iTCP:${port} -sTCP:LISTEN   (or: ps aux | grep minio)
  clear it: kill the pid lsof reports, or '$0 stop DIR' if DIR's own
            pidfile still names it — then retry.
EOF
    exit 1
  fi
}

start() {
  local dir="$1" port="$2"
  detect_platform
  local bin; bin="$(bin_path)"
  [ -x "$bin" ] || { echo "run 'ensure' first (no ${bin})" >&2; exit 1; }

  check_port "$port"

  # Pre-create the test bucket: on single-drive MinIO a bucket IS a
  # top-level directory in the data dir (no mc/admin API needed —
  # verified empirically; the store client cannot create buckets).
  mkdir -p "$dir/granary-test"
  MINIO_ROOT_USER="$GRANARY_MINIO_USER" MINIO_ROOT_PASSWORD="$GRANARY_MINIO_PASS" \
    "$bin" server --address "127.0.0.1:${port}" \
    --console-address "127.0.0.1:$((port + 1))" "$dir" \
    >"${dir}/minio.log" 2>&1 &
  echo $! > "${dir}/minio.pid"
  # Fix A1's settle: give a fresh process time to fail fast (e.g. lose a
  # same-port bind conflict) BEFORE trusting the first health-ready
  # result. A warm foreign server can answer a health probe issued the
  # INSTANT after backgrounding, before our own process has even reached
  # its bind() call, so checking with zero settle can win the race
  # against our own not-yet-failed process — caught by execution, twice:
  # a `stat=R` trace showed our own doomed process still genuinely
  # RUNNING (not a zombie, not yet crashed) when checked with no delay at
  # all, and measured directly (a standalone same-port launch) at ~110ms
  # from spawn to FATAL exit on this machine. 0.5s is ~4.5x that measured
  # figure — this is polling with a delayed start, not a blind sleep: the
  # loop below still polls up to 30s past this point.
  sleep 0.5
  # Poll ready; 30 s ceiling (plus the settle above) is ~150x the
  # measured single-drive startup.
  for _ in $(seq 1 300); do
    if curl -sf "http://127.0.0.1:${port}/minio/health/ready" >/dev/null 2>&1; then
      local pid; pid="$(cat "${dir}/minio.pid")"
      # Fix A1: the health probe alone cannot tell "our server is ready"
      # from "a foreign server already owned this port and ours died on
      # startup" (executed: a stale MinIO on the port makes the fresh spawn
      # exit immediately with "Specified port is already in use", the
      # STALE server answers this same probe, and the untamed code above
      # returned 0 here anyway). Verify before trusting the probe.
      if ! pid_is_alive "$pid"; then
        echo "minio: health probe on 127.0.0.1:${port} succeeded but the pid we spawned (${pid}) is not alive — our process must have exited (most likely: the port was already taken and a FOREIGN server is answering the health probe instead of ours). refusing to report ready." >&2
        echo "minio.log tail:" >&2
        tail -20 "${dir}/minio.log" >&2
        rm -f "${dir}/minio.pid"
        exit 1
      fi
      # Belt-and-suspenders: confirm the port is actually held by OUR pid,
      # where a portable tool allows checking. A MISSING lsof only skips
      # this sub-check — the pid_is_alive check above is unconditional
      # and alone catches the stale-server case, since the new process
      # exits when the port is taken. A PRESENT lsof reporting a
      # different pid is a hard failure, never silently ignored.
      if command -v lsof >/dev/null 2>&1; then
        local owners
        owners="$(lsof -t -iTCP:"${port}" -sTCP:LISTEN 2>/dev/null || true)"
        if [ -n "$owners" ] && ! printf '%s\n' "$owners" | grep -qx "$pid"; then
          echo "minio: health probe on 127.0.0.1:${port} succeeded and pid ${pid} is alive, but lsof reports the port is held by pid(s) [${owners}], not ${pid} — a FOREIGN server is answering the health probe. refusing to report ready." >&2
          echo "minio.log tail:" >&2
          tail -20 "${dir}/minio.log" >&2
          kill "$pid" 2>/dev/null || true
          rm -f "${dir}/minio.pid"
          exit 1
        fi
      fi
      echo "minio ready on 127.0.0.1:${port} (pid ${pid})"
      return 0
    fi
    sleep 0.1
  done
  echo "minio failed to become ready; log tail:" >&2
  tail -20 "${dir}/minio.log" >&2
  kill "$(cat "${dir}/minio.pid")" 2>/dev/null || true
  exit 1
}

stop() {
  local dir="$1"
  [ -f "${dir}/minio.pid" ] || return 0
  local pid; pid="$(cat "${dir}/minio.pid")"
  if ! pid_is_alive "$pid"; then
    rm -f "${dir}/minio.pid"
    echo "minio already stopped (pid ${pid} was not running)"
    return 0
  fi
  # Fix A2: SIGTERM alone (the untamed code's `kill ... || true`, pidfile
  # removed and "minio stopped" printed unconditionally, no wait, no
  # verification) reports success whether or not the process actually
  # died. A TERM-ignoring or slow process was reported stopped with its
  # handle discarded; a run that needed SIGKILL leaked a server holding
  # the port (executed: SIGKILL leaves the server listening and
  # target/minio/test-data-* behind), which arms the A1 false-ready path
  # for the next run. Wait for real death, escalate, verify, and only
  # drop the pidfile once the process is actually gone. `pid_is_alive`
  # throughout, not bare `kill -0` — this pid is our own direct child
  # when stop() runs inside run_tests()'s EXIT trap, so a dead-but-
  # unreaped zombie must not read as still running.
  kill "$pid" 2>/dev/null || true
  local waited=0
  while pid_is_alive "$pid" && [ "$waited" -lt 100 ]; do
    sleep 0.1
    waited=$((waited + 1))
  done
  if pid_is_alive "$pid"; then
    echo "minio pid ${pid} ignored SIGTERM for 10s; escalating to SIGKILL" >&2
    kill -9 "$pid" 2>/dev/null || true
    waited=0
    while pid_is_alive "$pid" && [ "$waited" -lt 50 ]; do
      sleep 0.1
      waited=$((waited + 1))
    done
  fi
  if pid_is_alive "$pid"; then
    echo "minio pid ${pid} did NOT die (survived SIGTERM and SIGKILL) — leaving ${dir}/minio.pid in place, it still likely holds the port; investigate by hand" >&2
    return 1
  fi
  rm -f "${dir}/minio.pid"
  echo "minio stopped"
}

run_tests() {
  ensure
  local dir="target/minio/test-data-$$" port="$TEST_PORT"
  # `stop` can now legitimately return 1 (Fix A2: a process that survived
  # SIGKILL); `|| true` keeps the trap's `rm -rf` reachable under `set -e`
  # regardless — cleanup of our own scratch dir must not depend on stop's
  # verdict.
  trap 'stop "'"$dir"'" || true; rm -rf "'"$dir"'"' EXIT
  start "$dir" "$port"
  # The store's MinIO lane is #[ignore]d so `cargo nextest run` stays
  # hermetic; this harness IS how the lane runs (locally and in CI).
  GRANARY_MINIO_ENDPOINT="http://127.0.0.1:${port}" \
    cargo nextest run -p granary-store --run-ignored=only
}

case "${1:-}" in
  path) detect_platform; bin_path ;;
  ensure) ensure ;;
  start)  [ $# -eq 3 ] || { echo "usage: $0 start DIR PORT" >&2; exit 1; }; ensure; start "$2" "$3" ;;
  stop)   [ $# -eq 2 ] || { echo "usage: $0 stop DIR" >&2; exit 1; }; stop "$2" ;;
  check-port) [ $# -eq 1 ] || { echo "usage: $0 check-port" >&2; exit 1; }; check_port "$TEST_PORT" ;;
  test)   run_tests ;;
  *) echo "usage: $0 {path|ensure|start DIR PORT|stop DIR|check-port|test}" >&2; exit 1 ;;
esac
