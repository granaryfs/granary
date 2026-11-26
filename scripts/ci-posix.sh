#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

venue="$GRAN_CI_RUN/posix"
evidence="$RUNNER_TEMP/fuse-posix-$GRAN_CI_ID"
mkdir -m 0700 "$evidence"

# The sentinel service belongs to the earlier FUSE step. If it failed
# before stopping its mount, leave recovery to the job teardown.
if ! { sudo timeout --kill-after=5 10 ./scripts/ci-mounts.sh check --under "$GRAN_CI_MOUNT"; } \
    > "$evidence/sentinel-mount.log" 2>&1; then
  cat "$evidence/sentinel-mount.log" >&2
  echo "POSIX refused: could not verify that the earlier FUSE step unmounted $GRAN_CI_MOUNT" >&2
  exit 1
fi

if ! { sudo timeout --kill-after=5 10 ./scripts/ci-mounts.sh check --gran; } \
    > "$evidence/gran-mount.log" 2>&1; then
  cat "$evidence/gran-mount.log" >&2
  echo "Pre-pass mount check failed for a leaked gran mount from an earlier step or an unreadable mount table" >&2
  exit 1
fi

# The fuse job has a tmpfs for nextest. The authority needs supported disk
# storage. The host bind makes that storage available to both passes.
sudo install -d -m 0700 /var/tmp/gran-ci-posix
sudo mkdir -m 0755 "$GRAN_CI_POSIX"
sudo mkdir -p "$venue"
sudo mount --bind "$GRAN_CI_POSIX" "$venue"
sudo mount --make-private "$venue"
findmnt -T "$venue" -o TARGET,FSTYPE,OPTIONS,PROPAGATION > "$evidence/storage.log"

(
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends \
    git autoconf automake libtool make gcc pkg-config python3 openssl \
    perl libtest-harness-perl bc gawk attr acl xfsprogs xfslibs-dev libcap-dev e2fsprogs \
    libacl1-dev libattr1-dev libaio-dev liburing-dev uuid-dev \
    libgdbm-dev libssl-dev libuuid1 libtool-bin util-linux kmod procps
) > "$evidence/prerequisites.log" 2>&1
sudo install -d -m 0755 -o "$(id -u)" -g "$(id -g)" "$venue/build"
bash scripts/posix-tools.sh "$venue/build/tools" > "$evidence/suite-build.log" 2>&1
sudo chown -R root:root "$venue/build"

run_pass() {
  local pass="$1"
  shift
  # Mounts created by a pass stay in its namespace, even when another host
  # process clones the host mount namespace during the pass.
  sudo systemd-run --scope --quiet --collect --unit="gran-ci-$GRAN_CI_ID-posix-$pass" \
    timeout --kill-after=15 1200 unshare --mount --propagation private \
    python3 -B scripts/posix-conformance.py \
      --tools "$venue/build/tools" --work "$venue/$pass" --revision "$GITHUB_SHA" \
      --gran "$GITHUB_WORKSPACE/target/debug/gran" \
      --server "$GITHUB_WORKSPACE/target/debug/granary-server" "$@"
}

baseline_rc=0
control_rc=0
# The runner user opens the logs so the artifact action can upload them.
run_pass baseline --ci-exit > "$evidence/baseline.jsonl" 2>&1 || baseline_rc=$?
run_pass unlink-control --unlink-noop --baseline "$venue/baseline" > "$evidence/unlink-control.jsonl" 2>&1 || control_rc=$?
printf 'baseline=%s\nunlink-control=%s\n' "$baseline_rc" "$control_rc" > "$evidence/exit-status.txt"

# Copy only test evidence. The work directories also contain private keys
# and authority state that must stay out of the artifact. The artifact is
# owned by the runner user.
(
  sudo bash -s -- "$venue" <<'BASH'
set -euo pipefail
cd "$1"
shopt -s nullglob
files=()
for pass in baseline unlink-control; do
  files+=("$pass"/{pjdfstest,xfstests}/*.{log,rc,source,out}
          "$pass"/xfs-generic-001/generic/*.full
          "$pass"/xfs-generic-*/generic/*.out.bad "$pass"/mount*.log)
  for name in server.log refusals.json device-node-probe.json provenance.json unlink-witness.jsonl; do
    if [[ -f "$pass/$name" ]]; then
      files+=("$pass/$name")
    fi
  done
done
tar -czf - -T /dev/null -- "${files[@]}"
BASH
) > "$evidence/raw-logs.tar.gz"

if [[ "$baseline_rc" != 0 || "$control_rc" != 1 ]] ||
   ! grep -Fxq '{"event": "unlink-control-complete", "assertion": 5}' "$evidence/unlink-control.jsonl"; then
  echo "POSIX exit check failed (baseline=$baseline_rc, unlink control=$control_rc). See the fuse-posix artifact." >&2
  exit 1
fi
echo 'POSIX exit comparison passed and the unlink control caught assertion 5'
