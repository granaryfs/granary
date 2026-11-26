#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
# Stubbed runner-check acceptance controls; all artifacts stay in the checkout.
set -euo pipefail

checker=$1
fixture=$(mktemp -d "${checker%/*}/.runner-check-test.XXXXXX")
trap 'rm -rf "$fixture"' EXIT
real_python=$(command -v python3)
real_cat=$(command -v cat)
real_rmdir=$(command -v rmdir)
mkdir -p "$fixture/scripts/infra" "$fixture/bin" "$fixture/service-bin" "$fixture/actions-runner" "$fixture/home" "$fixture/tmp=service" "$fixture/proc/123"
# Only fixed platform paths are redirected; the check functions stay intact.
original=$(cat "$checker")
original=${original//\/etc\/os-release/$fixture/os-release}
original=${original//\/proc\/meminfo/$fixture/meminfo}
original=${original//\/dev\/fuse/\/dev\/null}
original=${original//\/proc\/\$pid/$fixture/proc/\$pid}
printf '%s\n' "$original" > "$fixture/scripts/infra/runner-check.sh"
printf 'ID=ubuntu\nVERSION_ID=24.04\nPRETTY_NAME="Ubuntu 24.04"\n' > "$fixture/os-release"
printf 'MemTotal: 33554432 kB\n' > "$fixture/meminfo"
printf '8\n' > "$fixture/cpus"
printf '100\n' > "$fixture/free-disk"
printf '6.8.0-60-generic\n' > "$fixture/kernel"
printf '0\n' > "$fixture/umask-status"
printf '0\n' > "$fixture/apt-status"
printf '0\n' > "$fixture/venue-status"
printf '0\n' > "$fixture/ensurepip-status"
printf '0\n' > "$fixture/root-uid"
printf '0\n' > "$fixture/unit-status"
printf 'running\n' > "$fixture/listener"
printf '1000 999\n' > "$fixture/held-groups"
printf '%s/service-bin:/usr/bin:/bin\n' "$fixture" > "$fixture/actions-runner/.path"
printf 'TMPDIR=%s/tmp=service\nFIXTURE_ROOT=%s\n' "$fixture" "$fixture" > "$fixture/actions-runner/.env"
printf 'echo login-profile-was-read > "%s/profile-read"\nexport PATH=/usr/bin:/bin\n' "$fixture" > "$fixture/home/.bash_profile"
printf 'VENUE_SOURCE = "checkout-specific venue"\n' > "$fixture/scripts/check-publish-restart.py"

cat > "$fixture/scripts/infra/runner-umask.sh" <<'STUB'
#!/bin/bash
fixture=${BASH_SOURCE[0]%/scripts/infra/runner-umask.sh}
[ "$1" = --check ] || exit 90
if [ "$(cat "$fixture/umask-status")" != 0 ]; then printf 'umask context\numask drift fixture\n' >&2; fi
exit "$(cat "$fixture/umask-status")"
STUB
chmod +x "$fixture/scripts/infra/runner-umask.sh"

# The launcher executes the real Python implementation with only identity
# syscalls replaced. Its execve still supplies the actual service environment.
cat > "$fixture/python-stub.py" <<'PY'
import os
from pathlib import Path
import pwd
import sys
from types import SimpleNamespace

root = Path(__file__).parent
if sys.argv[1] == "-c":
    code = sys.argv[2]
    sys.argv = sys.argv[2:]
    pwd.getpwnam = lambda name: SimpleNamespace(pw_name=name, pw_dir=str(root / "home"), pw_gid=1000, pw_uid=1000)
    def setgroups(groups):
        (root / "launched-groups").write_text(",".join(map(str, groups)))
    os.setgroups = setgroups
    os.setgid = lambda gid: None
    os.setuid = lambda uid: None
    exec(compile(code, "runner-launcher", "exec"))
elif sys.argv[1:] in (["-", "venue"], [str(root / "scripts/check-publish-restart.py"), "venue"]):
    if sys.argv[1] != "-" and not (root / "scripts/check-publish-restart.py").stat().st_mode & 0o004:
        print("python3: checkout checker: Permission denied", file=sys.stderr)
        sys.exit(13)
    source = sys.stdin.read() if sys.argv[1] == "-" else (root / "scripts/check-publish-restart.py").read_text()
    if source != 'VENUE_SOURCE = "checkout-specific venue"\n':
        print("venue source missing or changed", file=sys.stderr)
        sys.exit(94)
    if os.getcwd() != "/" or os.environ.get("TMPDIR") != str(root / "tmp=service"):
        sys.exit(91)
    (root / "venue-called").write_text("checkout venue in service TMPDIR")
    if int((root / "venue-status").read_text()):
        print("venue context", file=sys.stderr)
        print("PUBLISH-RESTART REFUSED: injected venue failure", file=sys.stderr)
    sys.exit(int((root / "venue-status").read_text()))
elif sys.argv[1:] == ["--version"]:
    sys.exit(0 if os.environ.get("FIXTURE_ROOT") == str(root) else 92)
elif sys.argv[1:] == ["-m", "ensurepip", "--version"]:
    if os.environ.get("FIXTURE_ROOT") != str(root):
        sys.exit(92)
    if int((root / "ensurepip-status").read_text()):
        print("No module named ensurepip", file=sys.stderr)
    sys.exit(int((root / "ensurepip-status").read_text()))
else:
    sys.exit(93)
PY
# Absolute interpreter paths keep the stubs independent of the tested PATH.
printf '#!/bin/bash\nexec "%s" "%s/python-stub.py" "$@"\n' "$real_python" "$fixture" > "$fixture/bin/python3"
cp "$fixture/bin/python3" "$fixture/service-bin/python3"

cat > "$fixture/bin/stub" <<'STUB'
#!/bin/bash
fixture=${BASH_SOURCE[0]%/bin/*}
case "${0##*/}" in
  systemctl)
    printf '%s\n' "$*" >> "$fixture/systemctl-calls"
    case "$1" in
      list-unit-files)
        [ "$*" = 'list-unit-files actions.runner.* --type=service --no-legend --plain' ] || exit 80
        if [ "$(cat "$fixture/unit-status")" != 0 ]; then printf 'unit context\nsystemctl: unit discovery failed\n' >&2; exit 1; fi
        printf 'actions.runner.fixture.service disabled\n' ;;
      list-units) printf '● actions.runner.fixture.service loaded failed failed Runner\n' ;;
      show)
        [ "${!#}" = actions.runner.fixture.service ] || exit 81
        case "$3" in WorkingDirectory) printf '%s/actions-runner\n' "$fixture" ;; User) echo fixture-runner ;; UMask) echo 'UMask=0022' ;; *) exit 82 ;; esac ;;
      is-system-running) echo running ;;
      *) exit 83 ;;
    esac ;;
  id)
    case "$1" in -u) cat "$fixture/root-uid" ;; -G) echo '1000 999' ;; *) exit 84 ;; esac ;;
  pgrep)
    printf 'lookup\n' >> "$fixture/listener-lookups"
    case "$(cat "$fixture/listener")" in
      running|unreadable-status) echo 123 ;;
      vanish-*) [ "$(wc -l < "$fixture/listener-lookups" | tr -d ' ')" = 1 ] && echo 123 ;;
      stopped) exit 1 ;;
      *) exit 2 ;;
    esac ;;
  cat)
    case "$1" in
      "$fixture/proc/123/cgroup")
        if [ "$(cat "$fixture/listener")" = vanish-cgroup ]; then
          "$REAL_RMDIR" "$fixture/proc/123"
          echo 'listener pid 123 vanished at cgroup read' >&2; exit 1
        fi
        echo '0::/system.slice/actions.runner.fixture.service' ;;
      "$fixture/proc/123/status")
        if [ "$(cat "$fixture/listener")" = unreadable-status ]; then echo 'listener status: Permission denied' >&2; exit 1; fi
        if [ "$(cat "$fixture/listener")" = vanish-status ]; then
          "$REAL_RMDIR" "$fixture/proc/123"
          echo 'listener pid 123 vanished at status read' >&2; exit 1
        fi
        printf 'Name:\tRunner.Listener\nGroups:\t%s\n' "$(cat "$fixture/held-groups")" ;;
      *) exec "$REAL_CAT" "$@" ;;
    esac ;;
  uname) case "$1" in -m) echo x86_64 ;; -r) cat "$fixture/kernel" ;; esac ;;
  apt-get)
    printf '%s\n' "$*" >> "$fixture/apt-calls"
    if [ "$*" = update ]; then
      case "$(cat "$fixture/apt-status")" in
        0) echo 'Hit:1 fixture InRelease' ;;
        err) echo 'Err:1 fixture InRelease' ;;
        fetch) echo 'W: Failed to fetch fixture' >&2 ;;
        *) exit 100 ;;
      esac
    elif [ "$*" != '-s install -y musl-tools fuse3' ]; then exit 85; fi ;;
  curl)
    [ "$1" = -q ] || exit 89
    printf '%s\n' "${!#}" >> "$fixture/curl-calls"
    case "$*" in *dl.min.io*|*' -f'*|'-f'*) exit 22 ;; esac ;;
  nproc) cat "$fixture/cpus" ;;
  df) printf 'Avail\n%sG\n' "$(cat "$fixture/free-disk")" ;;
  mktemp)
    if [ "${1:-}" = -d ]; then mkdir -p "$fixture/mount"; echo "$fixture/mount"
    else : > "$fixture/check-stderr"; echo "$fixture/check-stderr"; fi ;;
  mount|umount|rmdir) : ;;
  *) exit 86 ;;
esac
STUB
for command in systemctl id pgrep cat uname apt-get curl nproc df mktemp mount umount rmdir; do
  cp "$fixture/bin/stub" "$fixture/bin/$command"
done
cat > "$fixture/service-bin/tool" <<'STUB'
#!/bin/bash
[ "$PWD" = / ] && [ "${TMPDIR:-}" = "$FIXTURE_ROOT/tmp=service" ] && [ -z "${ROOT_ONLY_ENV:-}" ] || exit 87
printf '%s\n' "${0##*/}" >> "$FIXTURE_ROOT/tool-calls"
if [ "${0##*/}" = docker ]; then
  [ "$(/bin/cat "$FIXTURE_ROOT/launched-groups")" = '1000,999' ] || { printf 'docker context\ndocker: held groups lack access\n' >&2; exit 88; }
fi
STUB
for command in rustup cargo cmake go perl git sudo docker; do
  cp "$fixture/service-bin/tool" "$fixture/service-bin/$command"
done
chmod +x "$fixture/bin/"* "$fixture/service-bin/"*

cases=0
run_case() {
  : > "$fixture/curl-calls"
  : > "$fixture/apt-calls"
  : > "$fixture/systemctl-calls"
  : > "$fixture/listener-lookups"
  mkdir -p "$fixture/proc/123"
  rc=0
  PATH="$fixture/bin:$PATH" REAL_CAT="$real_cat" REAL_RMDIR="$real_rmdir" ROOT_ONLY_ENV=must-not-inherit \
    bash "$fixture/scripts/infra/runner-check.sh" "$@" > "$fixture/output" 2>&1 || rc=$?
}
expect_row() { # label status row-name detail expected-exit
  local label=$1 status=$2 name=$3 detail=$4 expected_rc=$5 line count=0
  while IFS= read -r line; do
    if [[ "$line" == "$status "* ]] && [[ "${line:5}" == "$name "* ]] && [[ "$line" == *"$detail"* ]]; then
      count=$((count + 1))
    fi
  done < "$fixture/output"
  if [ "$rc:$count" != "$expected_rc:1" ]; then
    echo "self-test FAILED $label: expected rc=$expected_rc and one $status $name ($detail); got rc=$rc count=$count" >&2
    cat "$fixture/output" >&2
    exit 1
  fi
  cases=$((cases + 1))
  printf 'self-test %s: %s %s; rc=%s (expected)\n' "$label" "$status" "$name" "$rc"
}
reset_checker() {
  printf '%s\n' "$original" > "$fixture/scripts/infra/runner-check.sh"
  cmp -s <(printf '%s\n' "$original") "$fixture/scripts/infra/runner-check.sh"
}
inject_checker() { # literal old/new: display and verify the injected guard fault
  local old=$1 new=$2 changed
  changed=${original/"$old"/"$new"}
  [ "$changed" != "$original" ] || { echo 'self-test mutation did not land' >&2; exit 1; }
  printf '%s\n' "$changed" > "$fixture/scripts/infra/runner-check.sh"
  diff -u <(printf '%s\n' "$original") "$fixture/scripts/infra/runner-check.sh" || [ "$?" = 1 ]
}

# Capacity boundaries apply only to the selected profile.
printf '2\n' > "$fixture/cpus"
printf 'MemTotal: 5242880 kB\n' > "$fixture/meminfo"
printf '40\n' > "$fixture/free-disk"
run_case --light runner
expect_row 'light CPU boundary' PASS 'cpus >= 2' 'found 2' 0
expect_row 'light memory boundary' PASS 'memory >= 5 GiB' 'found 5 GiB' 0
expect_row 'light disk boundary' PASS 'free disk >= 40 GiB at the runner' 'found 40 GiB' 0
expect_row 'light profile identified' PASS 'runner profile' 'light' 0
expect_row 'light explicit runner user' PASS 'runner user' "user 'runner'" 0

printf '1\n' > "$fixture/cpus"
run_case --light runner
expect_row 'light refuses 1 CPU' FAIL 'cpus >= 2' 'found 1' 1
printf '2\n' > "$fixture/cpus"
printf 'MemTotal: 4194304 kB\n' > "$fixture/meminfo"
run_case --light runner
expect_row 'light refuses 4 GiB memory' FAIL 'memory >= 5 GiB' 'found 4 GiB' 1
printf 'MemTotal: 5242880 kB\n' > "$fixture/meminfo"
printf '39\n' > "$fixture/free-disk"
run_case --light runner
expect_row 'light refuses 39 GiB disk' FAIL 'free disk >= 40 GiB at the runner' 'found 39 GiB' 1

printf 'MemTotal: 6291456 kB\n' > "$fixture/meminfo"
printf '60\n' > "$fixture/free-disk"
run_case runner
expect_row 'full refuses light CPU capacity' FAIL 'cpus >= 4' 'found 2' 1
expect_row 'full refuses light memory capacity' FAIL 'memory >= 15 GiB' 'found 6 GiB' 1
printf '4\n' > "$fixture/cpus"
printf 'MemTotal: 15728640 kB\n' > "$fixture/meminfo"
run_case runner
expect_row 'full CPU boundary' PASS 'cpus >= 4' 'found 4' 0
expect_row 'full memory boundary' PASS 'memory >= 15 GiB' 'found 15 GiB' 0
expect_row 'full disk boundary' PASS 'free disk >= 60 GiB at the runner' 'found 60 GiB' 0
printf '59\n' > "$fixture/free-disk"
run_case runner
expect_row 'full refuses 59 GiB disk' FAIL 'free disk >= 60 GiB at the runner' 'found 59 GiB' 1

printf '2\n' > "$fixture/cpus"
printf 'MemTotal: 5242880 kB\n' > "$fixture/meminfo"
printf '40\n' > "$fixture/free-disk"
inject_checker "if [ \"\$profile\" = light ]; then" 'if false; then'
run_case --light runner
expect_row 'disabled light CPU floor control' FAIL 'cpus >= 4' 'found 2' 1
expect_row 'disabled light memory floor control' FAIL 'memory >= 15 GiB' 'found 5 GiB' 1
expect_row 'disabled light disk floor control' FAIL 'free disk >= 60 GiB at the runner' 'found 40 GiB' 1
reset_checker
run_case --light runner
expect_row 'light floors restored' PASS 'runner profile' 'light' 0
printf '8\n' > "$fixture/cpus"
printf 'MemTotal: 33554432 kB\n' > "$fixture/meminfo"
printf '100\n' > "$fixture/free-disk"

# A status glyph must fail the unit lookup; an installed failed unit succeeds.
inject_checker "list-unit-files 'actions.runner.*' --type=service --no-legend --plain" "list-units --type=service --all --no-legend 'actions.runner.*'"
run_case
expect_row 'glyph control' FAIL 'runner user' "user 'none'" 1
reset_checker
run_case
expect_row 'failed unit file by name' PASS 'exactly one runner service' 'found 1' 0
grep -Fx 'show -p User --value actions.runner.fixture.service' "$fixture/systemctl-calls" >/dev/null
printf '1\n' > "$fixture/unit-status"
run_case
expect_row 'unit discovery failure stderr' FAIL 'exactly one runner service' 'stderr: systemctl: unit discovery failed' 1
printf '0\n' > "$fixture/unit-status"
run_case
expect_row 'unit discovery restored' PASS 'exactly one runner service' 'found 1' 0

mv "$fixture/scripts/infra/runner-umask.sh" "$fixture/umask-saved"
run_case
expect_row 'missing umask helper' FAIL 'runner umask 0022' 'script missing' 1
expect_row 'absent _work needs umask' FAIL '_work not group/other-writable' 'runner umask 0022 row failed' 1
if grep -F 'show -p UMask' "$fixture/systemctl-calls" >/dev/null; then echo 'self-test FAILED: default systemd UMask was read' >&2; exit 1; fi
mv "$fixture/umask-saved" "$fixture/scripts/infra/runner-umask.sh"
run_case
expect_row 'present umask helper' PASS 'runner umask 0022' '--check' 0
expect_row 'absent _work with umask' PASS '_work not group/other-writable' 'runner umask 0022 passed' 0
printf '2\n' > "$fixture/umask-status"
run_case
expect_row 'umask drift stderr' FAIL 'runner umask 0022' 'stderr: umask drift fixture' 1
expect_row 'absent _work with drift' FAIL '_work not group/other-writable' 'runner umask 0022 row failed' 1
printf '0\n' > "$fixture/umask-status"

# With no PATH in .env, .path is the job PATH and must carry the toolchain.
printf '/usr/bin:/bin\n' > "$fixture/actions-runner/.path"
run_case
expect_row 'login PATH lacks toolchain' FAIL 'rustup and cargo on runner PATH' 'rustup --version' 1
printf '%s/service-bin:/usr/bin:/bin\n' "$fixture" > "$fixture/actions-runner/.path"
run_case
for name in 'rustup and cargo on runner PATH' 'cmake (fips.yml)' 'go (fips.yml)' 'perl (fips.yml)' git python3 'ensurepip for Python virtual environments' 'docker usable by runner user (container actions)'; do
  expect_row 'service .path and .env' PASS "$name" '' 0
done
# A python3 without ensurepip (no python3-venv) fails the venv row.
printf '1\n' > "$fixture/ensurepip-status"
run_case
expect_row 'python3 without ensurepip' FAIL 'ensurepip for Python virtual environments' 'python3-venv' 1
printf '0\n' > "$fixture/ensurepip-status"
# The fleet's shape: .path lacks the toolchain and .env's PATH carries it;
# jobs see .env's PATH, so the row passes.
printf '/usr/bin:/bin\n' > "$fixture/actions-runner/.path"
printf 'PATH=%s/service-bin:/usr/bin:/bin\n' "$fixture" >> "$fixture/actions-runner/.env"
run_case
expect_row '.env PATH carries the toolchain' PASS 'rustup and cargo on runner PATH' '' 0
# .env's PATH wins even over a .path that would pass.
printf '%s/service-bin:/usr/bin:/bin\n' "$fixture" > "$fixture/actions-runner/.path"
printf 'TMPDIR=%s/tmp=service\nFIXTURE_ROOT=%s\nPATH=/usr/bin:/bin\n' "$fixture" "$fixture" > "$fixture/actions-runner/.env"
run_case
expect_row '.env PATH wins over .path' FAIL 'rustup and cargo on runner PATH' 'rustup --version' 1
# With .env setting PATH, .path need not exist.
printf 'TMPDIR=%s/tmp=service\nFIXTURE_ROOT=%s\nPATH=%s/service-bin:/usr/bin:/bin\n' "$fixture" "$fixture" "$fixture" > "$fixture/actions-runner/.env"
mv "$fixture/actions-runner/.path" "$fixture/path-saved"
run_case
expect_row 'no .path when .env sets PATH' PASS 'runner service environment' 'job PATH from .env' 0
# A bare PATH= unsets PATH, as the runner does, so the toolchain is not found.
printf 'TMPDIR=%s/tmp=service\nFIXTURE_ROOT=%s\nPATH=\n' "$fixture" "$fixture" > "$fixture/actions-runner/.env"
run_case
expect_row 'bare PATH= unsets PATH' FAIL 'rustup and cargo on runner PATH' 'rustup --version' 1
mv "$fixture/path-saved" "$fixture/actions-runner/.path"
printf '%s/service-bin:/usr/bin:/bin\n' "$fixture" > "$fixture/actions-runner/.path"
printf 'TMPDIR=%s/tmp=service\nFIXTURE_ROOT=%s\n' "$fixture" "$fixture" > "$fixture/actions-runner/.env"
[ ! -e "$fixture/profile-read" ]

printf '1000 998\n' > "$fixture/held-groups"
run_case
expect_row 'listener lacks docker group despite user membership' FAIL 'docker usable by runner user (container actions)' 'pid 123 held groups' 1
expect_row 'tool failure stderr' FAIL 'docker usable by runner user (container actions)' 'stderr: docker: held groups lack access' 1
printf '1000 999\n' > "$fixture/held-groups"
printf 'error\n' > "$fixture/listener"
run_case
expect_row 'listener lookup error cannot establish absence' FAIL 'runner service environment' 'listener groups unavailable' 1
printf 'running\n' > "$fixture/listener"

printf 'unreadable-status\n' > "$fixture/listener"
run_case
expect_row 'existing listener read failure stderr' FAIL 'runner service environment' 'stderr: listener status: Permission denied' 1
[ "$(wc -l < "$fixture/listener-lookups" | tr -d ' ')" = 1 ]
printf 'running\n' > "$fixture/listener"

# Refusing a disappeared PID confuses exit with unreadable status. First prove
# that refusal, then the bounded retry and explicit fallback at both read sites.
for read_site in cgroup status; do
  printf 'vanish-%s\n' "$read_site" > "$fixture/listener"
  inject_checker "if [ \"\$attempt\" = 0 ]; then continue; fi" 'if false; then continue; fi'
  run_case
  expect_row "vanished $read_site without retry" FAIL 'runner service environment' 'stderr: Runner.Listener pid 123 vanished during retry' 1
  reset_checker
  run_case
  expect_row "vanished $read_site retries to no listener" PASS 'runner service environment' 'no Runner.Listener runs; using user groups; pid 123 vanished; retried pgrep once' 0
  expect_row "vanished $read_site uses user groups" PASS 'docker usable by runner user (container actions)' 'no Runner.Listener runs; using user groups' 0
  [ "$(wc -l < "$fixture/listener-lookups" | tr -d ' ')" = 2 ]
done
printf 'running\n' > "$fixture/listener"
run_case
expect_row 'listener has docker group' PASS 'docker usable by runner user (container actions)' 'pid 123 held groups' 0
printf 'stopped\n' > "$fixture/listener"
run_case
expect_row 'no listener is explicit' PASS 'docker usable by runner user (container actions)' 'no Runner.Listener runs; using user groups' 0
printf 'running\n' > "$fixture/listener"

inject_checker 'results-receiver.actions.githubusercontent.com static.rust-lang.org' 'dl.min.io static.rust-lang.org'
run_case
expect_row 'dead MinIO host control' FAIL 'egress https://dl.min.io' 'any HTTP response' 1
reset_checker
run_case
hosts=(github.com api.github.com codeload.github.com objects.githubusercontent.com release-assets.githubusercontent.com pipelines.actions.githubusercontent.com results-receiver.actions.githubusercontent.com static.rust-lang.org index.crates.io static.crates.io registry-1.docker.io ghcr.io)
[ "$(wc -l < "$fixture/curl-calls" | tr -d ' ')" = "${#hosts[@]}" ]
for host in "${hosts[@]}"; do
  expect_row 'HTTP authentication response reaches host' PASS "egress https://$host" 'any HTTP response' 0
  grep -Fx "https://$host" "$fixture/curl-calls" >/dev/null
done
if grep -F 'dl.min.io' "$fixture/curl-calls" >/dev/null; then echo 'self-test FAILED: dl.min.io was probed' >&2; exit 1; fi

for fault in err fetch nonzero; do
  printf '%s\n' "$fault" > "$fixture/apt-status"
  run_case
  expect_row "apt $fault" FAIL 'apt usable' 'no Err:/Failed to fetch' 1
  case "$fault" in
    err) expect_row 'apt Err diagnostic' FAIL 'apt usable' 'stderr: Err:1 fixture InRelease' 1 ;;
    fetch) expect_row 'apt fetch diagnostic' FAIL 'apt usable' 'stderr: W: Failed to fetch fixture' 1 ;;
  esac
  [ "$(wc -l < "$fixture/apt-calls" | tr -d ' ')" = 1 ]
done
printf '0\n' > "$fixture/apt-status"
run_case
expect_row 'apt update and simulation' PASS 'apt usable' 'apt-get -s install -y musl-tools fuse3' 0
[ "$(cat "$fixture/apt-calls")" = $'update\n-s install -y musl-tools fuse3' ]

for kernel in 6.8.0-rc1 6.7.12-generic unreadable; do
  printf '%s\n' "$kernel" > "$fixture/kernel"
  run_case
  expect_row "kernel $kernel" FAIL 'kernel >= 6.8' "found $kernel" 1
done
for kernel in 6.8.0 6.8.0-60-generic 6.10.1-generic; do
  printf '%s\n' "$kernel" > "$fixture/kernel"
  run_case
  expect_row "kernel $kernel" PASS 'kernel >= 6.8' "found $kernel" 0
done

# Mode 0600 models a root-readable checker that the runner cannot open; the
# Python stub refuses path access but accepts the identical bytes on stdin.
chmod 600 "$fixture/scripts/check-publish-restart.py"
inject_checker "as_runner 'python3 - venue' < \"\$checkout/scripts/check-publish-restart.py\"" "as_runner \"python3 '\$checkout/scripts/check-publish-restart.py' venue\""
run_case
expect_row 'unreadable checkout path control' FAIL 'publish-restart temp storage/kernel' 'stderr: python3: checkout checker: Permission denied' 1
reset_checker
run_case
expect_row 'unreadable checkout source on stdin' PASS 'publish-restart temp storage/kernel' 'source on stdin' 0
[ "$(cat "$fixture/venue-called")" = 'checkout venue in service TMPDIR' ]
[ ! -e "$fixture/check-stderr" ]
chmod 644 "$fixture/scripts/check-publish-restart.py"
mv "$fixture/scripts/check-publish-restart.py" "$fixture/checker-saved"
run_case
expect_row 'root cannot open checker source' FAIL 'publish-restart temp storage/kernel' 'No such file or directory' 1
mv "$fixture/checker-saved" "$fixture/scripts/check-publish-restart.py"
run_case
expect_row 'root-readable checker source restored' PASS 'publish-restart temp storage/kernel' 'source on stdin' 0

printf '1\n' > "$fixture/venue-status"
inject_checker "row FAIL \"\$name\" \"\$detail\" \"\$(tail -n 1 \"\$stderr_file\")\"" "row FAIL \"\$name\" \"\$detail\""
run_case
expect_row 'hidden stderr control' FAIL 'publish-restart temp storage/kernel' 'check-publish-restart.py venue' 1
if grep -F 'PUBLISH-RESTART REFUSED' "$fixture/output" >/dev/null; then echo 'self-test FAILED: hidden-stderr control still displayed stderr' >&2; exit 1; fi
reset_checker
run_case
expect_row 'publish-restart venue refusal stderr' FAIL 'publish-restart temp storage/kernel' 'stderr: PUBLISH-RESTART REFUSED: injected venue failure' 1
if grep -F 'venue context' "$fixture/output" >/dev/null; then echo 'self-test FAILED: more than last stderr line displayed' >&2; exit 1; fi
printf '0\n' > "$fixture/venue-status"
run_case
expect_row 'checkout venue in service TMPDIR' PASS 'publish-restart temp storage/kernel' 'check-publish-restart.py venue' 0
[ "$(cat "$fixture/venue-called")" = 'checkout venue in service TMPDIR' ]

# Missing runner files and unreadable process status must not silently fall back.
mv "$fixture/actions-runner/.env" "$fixture/env-saved"
run_case
expect_row 'missing service .env' FAIL 'runner service environment' 'variables from .env' 1
mv "$fixture/env-saved" "$fixture/actions-runner/.env"
printf 'malformed\n' > "$fixture/held-groups"
run_case
expect_row 'unreadable listener groups' FAIL 'runner service environment' 'listener groups unavailable' 1
expect_row 'unreadable listener groups stderr' FAIL 'runner service environment' "stderr: invalid Groups in $fixture/proc/123/status" 1
printf '1000 999\n' > "$fixture/held-groups"
run_case
expect_row 'readable environment and held groups' PASS 'runner service environment' 'pid 123 held groups' 0

printf '1000\n' > "$fixture/root-uid"
run_case
[ "$rc" = 2 ] && [ "$(cat "$fixture/output")" = 'run as root' ]
cases=$((cases + 1))
echo 'self-test non-root: refused; rc=2 (expected)'
printf '0\n' > "$fixture/root-uid"
reset_checker
cmp -s <(printf '%s\n' "$original") "$fixture/scripts/infra/runner-check.sh"
run_case
expect_row 'all requirements clean after fault removal' PASS 'runner service environment' 'variables from .env' 0
[ "$cases" -gt 0 ]
echo "runner-check self-test: $cases assertions passed (failing controls before passing fixtures)"
