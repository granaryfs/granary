#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
#
# Check that a VM meets what granary's CI jobs assume of a self-hosted runner.
# Run INSIDE the guest as root, after the runner is registered:
#   runner-check.sh [RUNNER_USER]      (default: the runner unit's User=)
#   runner-check.sh --light [RUNNER_USER] (light profile; all other checks kept)
#   runner-check.sh --self-test        (stubbed checks; no root needed)
# Full capacity floors: 4 CPUs, 15 GiB memory, 60 GiB free disk.
# Light capacity floors: 2 CPUs, 5 GiB memory, 40 GiB free disk; labelled in output.
# One PASS/FAIL row per requirement; exits 1 on any FAIL. Reads no credential.
set -uo pipefail

script_dir=$(cd -- "${BASH_SOURCE[0]%/*}" && pwd) || exit 2
checkout=$(cd -- "$script_dir/../.." && pwd) || exit 2
if [ "${1:-}" = --self-test ]; then
  bash "$script_dir/runner-check-self-test.sh" "$script_dir/runner-check.sh"
  exit $?
fi
profile=full
if [ "${1:-}" = --light ]; then
  profile=light
  shift
fi

fail=0
row() { # status name detail [last stderr line]
  local detail=$3
  if [ "$1" = FAIL ] && [ -n "${4:-}" ]; then detail+="; stderr: $4"; fi
  printf '%-4s %-34s %s\n' "$1" "$2" "$detail"
  [ "$1" = PASS ] || fail=1
}
check() { # name detail command...
  local name=$1 detail=$2; shift 2
  if "$@" >/dev/null 2>"$stderr_file"; then
    row PASS "$name" "$detail"
  else
    row FAIL "$name" "$detail" "$(tail -n 1 "$stderr_file")"
    return 1
  fi
}

kernel_supported() { # full uname release, including prerelease suffix
  [[ "$1" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)([-.][a-zA-Z0-9_.+-]+)?$ ]] || return 1
  local major=${BASH_REMATCH[1]} minor=${BASH_REMATCH[2]}
  [[ "$1" != *-rc* ]] || return 1
  (( 10#$major > 6 || (10#$major == 6 && 10#$minor >= 8) ))
}

# Match the service, not an unrelated runner elsewhere on the VM. Reading the
# listener's held groups detects a missing docker group until a service restart.
listener_groups() {
  local pid pids lookup_rc cgroup groups found vanished attempt vanished_pid=""
  for attempt in 0 1; do
    pids=$(pgrep -x Runner.Listener)
    lookup_rc=$?
    # pgrep returns 1 for no match; lookup errors cannot establish absence.
    [ "$lookup_rc" -le 1 ] || { echo 'Runner.Listener lookup failed' >&2; return 1; }
    found=0; vanished=0
    while IFS= read -r pid; do
      [ -n "$pid" ] || continue
      if ! cgroup=$(cat "/proc/$pid/cgroup"); then
        if [ ! -d "/proc/$pid" ]; then vanished=1; vanished_pid=$pid; break; fi
        return 1
      fi
      case "$cgroup" in *"/$unit"|*"/$unit/"*) ;; *) continue ;; esac
      if ! groups=$(cat "/proc/$pid/status" | awk '$1 == "Groups:" { for (i=2; i<=NF; i++) printf "%s%s", (i==2 ? "" : ","), $i; print ""; found=1 } END { if (!found) exit 1 }'); then
        if [ ! -d "/proc/$pid" ]; then vanished=1; vanished_pid=$pid; break; fi
        return 1
      fi
      [[ "$groups" =~ ^[0-9]+(,[0-9]+)*$ ]] || { echo "invalid Groups in /proc/$pid/status" >&2; return 1; }
      if [ "$found" = 1 ] && [ "$runner_groups" != "$groups" ]; then echo 'listener groups disagree' >&2; return 1; fi
      runner_groups=$groups
      group_detail="Runner.Listener pid $pid held groups"
      found=1
    done <<< "$pids"
    if [ "$vanished" = 1 ]; then
      if [ "$attempt" = 0 ]; then continue; fi
      echo "Runner.Listener pid $vanished_pid vanished during retry" >&2
      return 1
    fi
    if [ "$found" = 0 ]; then
      groups=$(id -G "$user") || return 1
      runner_groups=${groups// /,}
      group_detail="no Runner.Listener runs; using user groups"
    fi
    if [ -n "$vanished_pid" ]; then group_detail+="; pid $vanished_pid vanished; retried pgrep once"; fi
    return 0
  done
}

load_service_environment() {
  local line env_path="" env_sets_path=0 runner_path
  [ -n "$user" ] && [ -n "$runner_dir" ] || { echo 'runner user/directory unavailable' >&2; return 1; }
  [ -r "$runner_dir/.env" ] || { echo 'runner .env unreadable' >&2; return 1; }
  # The runner saves literal NAME=value lines, not shell code. Do not source
  # them as root or inherit the caller's environment or a login profile.
  while IFS= read -r line || [ -n "$line" ]; do
    [[ "$line" == *=* ]] || continue
    [[ "${line%%=*}" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || return 1
    if [[ "$line" == PATH=* ]]; then env_sets_path=1; env_path=${line#PATH=}; continue; fi
    service_environment+=("$line")
  done < "$runner_dir/.env" || return 1
  # The runner applies .env to jobs, so a PATH there is what a job's steps
  # see (a bare PATH= unsets it, as the runner does); .path is the job PATH
  # only when .env sets none.
  if [ "$env_sets_path" = 1 ]; then
    path_source=".env"
    if [ -n "$env_path" ]; then service_environment+=("PATH=$env_path"); fi
  else
    runner_path=$(cat "$runner_dir/.path" 2>/dev/null) || { echo 'no PATH in .env and .path unreadable' >&2; return 1; }
    [ -n "$runner_path" ] || { echo 'no PATH in .env and .path empty' >&2; return 1; }
    path_source=".path"
    service_environment+=("PATH=$runner_path")
  fi
  listener_groups
}

as_runner() { # command in the service environment and held supplementary groups
  [ "$service_environment_ok" = 1 ] || { echo 'runner service environment row failed' >&2; return 1; }
  # -c leaves stdin available for the venue checker, opened by root before
  # dropping privileges; the runner need not traverse the checkout directory.
  python3 -c '
import os
import pwd
import sys

account = pwd.getpwnam(sys.argv[1])
environment = {"HOME": account.pw_dir, "USER": account.pw_name,
               "LOGNAME": account.pw_name, "SHELL": "/bin/bash"}
for assignment in sys.argv[4:]:
    name, value = assignment.split("=", 1)
    environment[name] = value
os.setgroups([int(group) for group in sys.argv[2].split(",")])
os.setgid(account.pw_gid)
os.setuid(account.pw_uid)
os.chdir("/")
os.execve("/bin/bash", ["/bin/bash", "--noprofile", "--norc", "-c", sys.argv[3]], environment)
' "$user" "$runner_groups" "$1" "${service_environment[@]}"
}

publish_restart_venue() {
  as_runner 'python3 - venue' < "$checkout/scripts/check-publish-restart.py"
}

apt_usable() {
  local output
  output=$(apt-get update 2>&1) || { printf '%s\n' "$output" >&2; return 1; }
  if [[ "$output" == *'Failed to fetch'* ]] || [[ "$output" =~ (^|$'\n')Err: ]]; then printf '%s\n' "$output" >&2; return 1; fi
  apt-get -s install -y musl-tools fuse3
}

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
# Rows run as the runner user, who may not be able to read the caller's directory.
cd / || exit 2
stderr_file=$(mktemp) || exit 2
trap 'rm -f "$stderr_file"' EXIT

# Discover installed unit files as runner-umask.sh does: failed/unloaded
# services still have names here, and list-units' status glyphs never appear.
units=()
discovery_ok=1
unit_names=$(systemctl list-unit-files 'actions.runner.*' --type=service --no-legend --plain 2>"$stderr_file" | awk '{print $1}') || discovery_ok=0
discovery_error=$(tail -n 1 "$stderr_file")
while IFS= read -r unit; do
  [ -n "$unit" ] && units+=("$unit")
done <<< "$unit_names"
count=${#units[@]}
unit=""; runner_dir=""; service_user=""; directory_error=""; user_error=""
if [ "$discovery_ok" = 1 ] && [ "$count" = 1 ]; then
  unit=${units[0]}
  runner_dir=$(systemctl show -p WorkingDirectory --value "$unit" 2>"$stderr_file")
  directory_error=$(tail -n 1 "$stderr_file")
  service_user=$(systemctl show -p User --value "$unit" 2>"$stderr_file")
  user_error=$(tail -n 1 "$stderr_file")
fi
user=${1:-$service_user}
runner_groups=""; group_detail="listener groups unavailable"
service_environment=()
service_environment_ok=0
if load_service_environment 2>"$stderr_file"; then service_environment_ok=1; fi
service_environment_error=$(tail -n 1 "$stderr_file")

# Platform
# Read the fields, never source the guest's file.
: >"$stderr_file"
os_field() { sed -n "s/^$1=//p" /etc/os-release 2>>"$stderr_file" | head -1 | tr -d '"'; }
ID=$(os_field ID); VERSION_ID=$(os_field VERSION_ID); PRETTY_NAME=$(os_field PRETTY_NAME)
os_error=$(tail -n 1 "$stderr_file")
check "os ubuntu 24.04" "found ${PRETTY_NAME:-unknown}${os_error:+; stderr: $os_error}" test "${ID:-}-${VERSION_ID:-}" = ubuntu-24.04
arch=$(uname -m 2>"$stderr_file")
arch_error=$(tail -n 1 "$stderr_file")
check "arch x86_64" "found $arch${arch_error:+; stderr: $arch_error}" test "$arch" = x86_64
kver=$(uname -r 2>"$stderr_file")
kernel_error=$(tail -n 1 "$stderr_file")
check "kernel >= 6.8" "found $kver (stable release required)${kernel_error:+; stderr: $kernel_error}" kernel_supported "$kver"

# The runner
check "exactly one runner service" "found $count; discovery status $discovery_ok${discovery_error:+; stderr: $discovery_error}" test "$discovery_ok:$count" = 1:1
check "runner user" "user '${user:-none}', dir '${runner_dir:-none}'${user_error:+; stderr: $user_error}" test -n "$user"
if [ "$service_environment_ok" = 1 ]; then
  row PASS "runner service environment" "job PATH from ${path_source:-?}, variables from .env; $group_detail"
else
  row FAIL "runner service environment" "job PATH from ${path_source:-?}, variables from .env; $group_detail" "${directory_error:-$service_environment_error}"
fi
umask_script="$script_dir/runner-umask.sh"
umask_ok=0
if [ -x "$umask_script" ]; then
  if check "runner umask 0022" "$umask_script --check" "$umask_script" --check; then umask_ok=1; fi
else
  row FAIL "runner umask 0022" "$umask_script --check failed or script missing"
fi
if [ -n "$runner_dir" ] && [ -d "$runner_dir/_work" ]; then
  if mode=$(stat -c %a "$runner_dir/_work" 2>"$stderr_file"); then
    check "_work not group/other-writable" "mode $mode" bash -c "(( (8#$mode & 0022) == 0 ))"
  else
    row FAIL "_work not group/other-writable" 'stat failed' "$(tail -n 1 "$stderr_file")"
  fi
elif [ -n "$runner_dir" ] && [ -d "$runner_dir" ]; then
  if [ "$umask_ok" = 1 ]; then
    row PASS "_work not group/other-writable" "absent until the first job; runner umask 0022 passed"
  else
    row FAIL "_work not group/other-writable" "absent; runner umask 0022 row failed"
  fi
else
  row FAIL "_work not group/other-writable" "no runner directory '${runner_dir:-none}'"
fi

# Privilege the jobs use
check "passwordless sudo for runner user" "sudo -n true; $group_detail" as_runner 'sudo -n true'
check "apt usable" "apt-get update (no Err:/Failed to fetch); apt-get -s install -y musl-tools fuse3" apt_usable
check "systemd (systemctl)" "systemctl is-system-running" bash -c 'systemctl is-system-running | grep -Eq "running|degraded"'
check "tmpfs mountable by sudo" "mount -t tmpfs" bash -c 'd=$(mktemp -d) && mount -t tmpfs -o size=1m tmpfs "$d" && umount "$d" && rmdir "$d"'

# FUSE (the fuse job runs its suite as root against /dev/fuse)
check "/dev/fuse present" "character device" test -c /dev/fuse

# Apply this checkout's exact venue rule through an already-open stdin.
check "publish-restart temp storage/kernel" "$checkout/scripts/check-publish-restart.py venue (source on stdin); $group_detail" publish_restart_venue

# Toolchains the jobs assume are preinstalled (rust-toolchain.toml pins the version; rustup fetches it)
check "rustup and cargo on runner PATH" "rustup --version; cargo --version; $group_detail" as_runner 'rustup --version && cargo --version'
check "cmake (fips.yml)" "apt install cmake; template 9000 predates it; $group_detail" as_runner 'cmake --version'
check "go (fips.yml)" "apt install golang-go; template 9000 predates it; $group_detail" as_runner 'go version'
check "perl (fips.yml)" "perl -v; $group_detail" as_runner 'perl -v'
check "git" "git --version; $group_detail" as_runner 'git --version'
check "python3" "python3 --version; $group_detail" as_runner 'python3 --version'
check "ensurepip for Python virtual environments" "apt install python3-venv: python3 -m venv needs ensurepip; $group_detail" as_runner 'python3 -m ensurepip --version'
check "docker usable by runner user (container actions)" "docker info; $group_detail" as_runner 'docker info'

# Any HTTP answer demonstrates HTTPS reachability; authentication/404 responses
# are useful evidence too. MinIO binaries come from GitHub release assets.
for host in github.com api.github.com codeload.github.com objects.githubusercontent.com \
            release-assets.githubusercontent.com pipelines.actions.githubusercontent.com \
            results-receiver.actions.githubusercontent.com static.rust-lang.org \
            index.crates.io static.crates.io registry-1.docker.io ghcr.io; do
  check "egress https://$host" "any HTTP response" curl -q -sS -o /dev/null --max-time 10 "https://$host"
done

# Resources
min_cpus=4; min_memory_gb=15; min_free_gb=60
if [ "$profile" = light ]; then
  min_cpus=2; min_memory_gb=5; min_free_gb=40
  row PASS "runner profile" "light"
fi
cpus=$(nproc 2>"$stderr_file")
cpu_error=$(tail -n 1 "$stderr_file")
mem_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>"$stderr_file")
memory_error=$(tail -n 1 "$stderr_file")
mem_gb=$(( ${mem_kb:-0} / 1024 / 1024 ))
free_gb=$(df -BG --output=avail "${runner_dir:-/}" 2>"$stderr_file" | tail -1 | tr -dc 0-9)
disk_error=$(tail -n 1 "$stderr_file")
check "cpus >= $min_cpus" "found $cpus${cpu_error:+; stderr: $cpu_error}" test "$cpus" -ge "$min_cpus"
check "memory >= $min_memory_gb GiB" "found ${mem_gb} GiB${memory_error:+; stderr: $memory_error}" test "$mem_gb" -ge "$min_memory_gb"
check "free disk >= $min_free_gb GiB at the runner" "found ${free_gb} GiB${disk_error:+; stderr: $disk_error}" test "${free_gb:-0}" -ge "$min_free_gb"

exit "$fail"
