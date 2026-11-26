#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
# Apply or check the runner service umask and workspace permissions.
set -euo pipefail

DROPIN_CONTENT=$'[Service]\nUMask=0022\n'

extract_working_directory() { # unit text -> WorkingDirectory value
  awk -F= '$1 == "WorkingDirectory" { value = substr($0, index($0, "=") + 1) } END { print value }'
}

dropin_matches() { # file -> whether its complete content is the required drop-in
  [ -f "$1" ] && [ "$(cat "$1")" = "${DROPIN_CONTENT%$'\n'}" ]
}

mode_needs_go_w_removed() { # octal mode -> whether group/other write bits are set
  local mode=${1#0}
  (( (8#$mode & 0022) != 0 ))
}

extract_status_umask() { # /proc/PID/status text -> four-digit umask or empty
  awk '$1 == "Umask:" { print $2; found = 1; exit } END { if (!found) exit 1 }'
}

service_listener_umask() { # service -> print every matching listener as pid:umask
  local unit=$1 pid cgroup umask
  while IFS= read -r pid; do
    [ -n "$pid" ] || continue
    cgroup="$(cat "/proc/$pid/cgroup" 2>/dev/null || true)"
    [[ "$cgroup" == *"/$unit"* ]] || continue
    umask="$(extract_status_umask <"/proc/$pid/status" 2>/dev/null || true)"
    printf '%s:%s\n' "$pid" "$umask"
  done < <(pgrep -x Runner.Listener 2>/dev/null || true)
}

listener_is_clean() { # listener list -> true only when at least one is present and all are 0022
  local listeners=$1 row seen=0
  while IFS= read -r row; do
    [ -n "$row" ] || continue
    seen=1
    [ "${row#*:}" = 0022 ] || return 1
  done <<<"$listeners"
  [ "$seen" -eq 1 ]
}

wait_for_service_listener() { # service -> wait up to 30 seconds for a listener, then print its rows
  local unit=$1 current='' attempt
  for ((attempt = 0; attempt <= 30; attempt++)); do
    current="$(service_listener_umask "$unit")"
    if [ -n "$current" ]; then printf '%s\n' "$current"; return 0; fi
    [ "$attempt" -lt 30 ] || break
    sleep 1
  done
  printf '%s\n' "$current"
  return 1
}

report_missing_work() { # work directory -> print informational missing-work message
  echo "runner-umask: no _work yet (it is created by the first job under the new umask): $1"
}

exit_for_drift() { # drift flag -> the command's documented 0/2 status
  [ "$1" -eq 0 ] && return 0
  return 2
}

usage() {
  cat >&2 <<EOF
usage: $0 [--check|--restart-when-idle|--self-test]
  --restart-when-idle restarts only when no Runner.Worker is found. A job can
  still be picked up between that check and the restart (a small race), so use
  this option only when the runner is quiet.
EOF
}

check_only=0
restart_when_idle=0
self_test=0
case "${1:-}" in
  "") ;;
  --check) check_only=1 ;;
  --restart-when-idle) restart_when_idle=1 ;;
  --self-test) self_test=1 ;;
  *) usage; exit 2 ;;
esac

if [ "$self_test" -eq 1 ]; then
  failures=0
  fixture_unit=$'Description=fake runner\nWorkingDirectory=/srv/gha/actions-runner\nExecStart=/bin/true'
  got="$(printf '%s\n' "$fixture_unit" | extract_working_directory)"
  [ "$got" = /srv/gha/actions-runner ] || failures=$((failures + 1))
  printf '%s\n' "runner-umask self-test: unit WorkingDirectory fixture -> $([ "$got" = /srv/gha/actions-runner ] && echo ok || echo FAILED)"
  for expected in 0002 0022; do
    fixture_status="Name:\tRunner.Listener\nUmask:\t$expected\nState:\tS (sleeping)"
    got="$(printf '%b\n' "$fixture_status" | extract_status_umask)"
    if [ "$got" = "$expected" ]; then echo "runner-umask self-test: proc status umask $expected -> ok"; else failures=$((failures + 1)); echo "runner-umask self-test: proc status umask $expected -> FAILED ($got)" >&2; fi
  done
  if mode_needs_go_w_removed 775; then echo 'runner-umask self-test: mode 775 detects write bits -> ok'; else failures=$((failures + 1)); echo 'runner-umask self-test: mode 775 -> FAILED' >&2; fi
  if mode_needs_go_w_removed 755; then failures=$((failures + 1)); echo 'runner-umask self-test: mode 755 -> FAILED' >&2; else echo 'runner-umask self-test: mode 755 is clean -> ok'; fi
  fixture="$(mktemp)"
  printf '%s' "$DROPIN_CONTENT" >"$fixture"
  if dropin_matches "$fixture"; then echo 'runner-umask self-test: exact drop-in fixture -> ok'; else failures=$((failures + 1)); echo 'runner-umask self-test: exact drop-in fixture -> FAILED' >&2; fi
  printf '[Service]\nUMask=0002\n' >"$fixture"
  if dropin_matches "$fixture"; then failures=$((failures + 1)); echo 'runner-umask self-test: differing drop-in fixture -> FAILED' >&2; else echo 'runner-umask self-test: differing drop-in fixture -> ok'; fi
  if listener_is_clean '123:0022' && ! listener_is_clean '123:0002' && ! listener_is_clean ''; then
    echo 'runner-umask self-test: running listener state -> ok'
  else failures=$((failures + 1)); echo 'runner-umask self-test: running listener state -> FAILED' >&2; fi
  lookup_count_file="$(mktemp)"
  printf '0\n' >"$lookup_count_file"
  service_listener_umask() {
    local count
    count="$(cat "$lookup_count_file")"
    count=$((count + 1))
    printf '%s\n' "$count" >"$lookup_count_file"
    if [ "$count" -lt 3 ]; then return 0; fi
    printf '123:0022\n'
  }
  sleep() { :; }
  if got="$(wait_for_service_listener fixture.service)" && [ "$got" = '123:0022' ] && [ "$(cat "$lookup_count_file")" -eq 3 ]; then
    echo 'runner-umask self-test: delayed listener after restart -> ok'
  else failures=$((failures + 1)); echo 'runner-umask self-test: delayed listener after restart -> FAILED' >&2; fi
  rm -f "$lookup_count_file"
  fixture_work="$(mktemp -d)"
  if [ ! -d "$fixture_work/_work" ]; then
    got="$(report_missing_work "$fixture_work/_work")"
    if [[ "$got" == *'no _work yet (it is created by the first job under the new umask)'* ]]; then
      echo 'runner-umask self-test: absent _work fixture -> ok'
    else failures=$((failures + 1)); echo 'runner-umask self-test: absent _work fixture -> FAILED' >&2; fi
  else failures=$((failures + 1)); echo 'runner-umask self-test: absent _work fixture -> FAILED' >&2; fi
  rm -rf "$fixture_work"
  if exit_for_drift 0; then echo 'runner-umask self-test: clean exit code 0 -> ok'; else failures=$((failures + 1)); echo 'runner-umask self-test: clean exit code -> FAILED' >&2; fi
  if exit_for_drift 1; then failures=$((failures + 1)); echo 'runner-umask self-test: drift exit code -> FAILED' >&2; else rc=$?; if [ "$rc" -eq 2 ]; then echo 'runner-umask self-test: drift exit code 2 -> ok'; else failures=$((failures + 1)); echo "runner-umask self-test: drift exit code -> FAILED ($rc)" >&2; fi; fi
  rm -f "$fixture"
  echo "runner-umask self-test: $((12 - failures))/12 passed"
  [ "$failures" -eq 0 ]
  exit
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "runner-umask: run as root" >&2
  exit 2
fi

units=()
while IFS= read -r unit; do
  [ -n "$unit" ] && units+=("$unit")
done < <(systemctl list-unit-files --type=service --no-legend 'actions.runner.*.service' | awk '{print $1}')
if [ "${#units[@]}" -eq 0 ]; then
  echo 'runner-umask: no actions.runner.*.service unit files found' >&2
  exit 2
fi

drift=0
changed=0
restart_units=()
declare -A unit_problem=() unit_dropin_ok=() unit_listener=()
for unit in "${units[@]}"; do
  unit_text="$(systemctl cat "$unit")"
  working_directory="$(printf '%s\n' "$unit_text" | extract_working_directory)"
  case "$working_directory" in
    */actions-runner) ;;
    *) echo "runner-umask: $unit has unexpected WorkingDirectory [$working_directory]" >&2; drift=1; unit_problem[$unit]=1; continue ;;
  esac
  work="$working_directory/_work"
  dropin="/etc/systemd/system/$unit.d/umask.conf"
  unit_listener[$unit]="$(service_listener_umask "$unit")"
  if dropin_matches "$dropin"; then unit_dropin_ok[$unit]=1; else unit_dropin_ok[$unit]=0; fi
  if [ "$check_only" -eq 1 ]; then
    if [ "${unit_dropin_ok[$unit]}" -ne 1 ]; then echo "runner-umask: $unit drop-in drift: $dropin" >&2; drift=1; fi
    if [ ! -d "$work" ]; then report_missing_work "$work"
    else
      mode="$(stat -c '%a' "$work")"
      if mode_needs_go_w_removed "$mode"; then echo "runner-umask: $unit workspace mode drift: $work (mode $mode)" >&2; drift=1; fi
    fi
    if ! listener_is_clean "${unit_listener[$unit]}"; then
      echo "runner-umask: $unit running listener umask drift: ${unit_listener[$unit]:-no Runner.Listener found}" >&2
      drift=1
    fi
    continue
  fi
  if [ "${unit_dropin_ok[$unit]}" -ne 1 ]; then
    install -d -m 0755 "${dropin%/*}"
    printf '%s' "$DROPIN_CONTENT" >"$dropin"
    chmod 0644 "$dropin"
    changed=1
    echo "runner-umask: installed $dropin"
  fi
  if [ -d "$work" ]; then
    mode="$(stat -c '%a' "$work")"
    if mode_needs_go_w_removed "$mode"; then chmod go-w "$work"; echo "runner-umask: removed group/other write from $work (mode $mode)"; fi
  else
    report_missing_work "$work"
  fi
  if [ "${unit_dropin_ok[$unit]}" -ne 1 ] || ! listener_is_clean "${unit_listener[$unit]}"; then
    restart_units+=("$unit")
  fi
done

if [ "$check_only" -eq 1 ]; then
  exit_for_drift "$drift"
  exit $?
fi
if [ "$changed" -eq 1 ]; then systemctl daemon-reload; fi

for unit in "${units[@]}"; do
  if [ "${unit_problem[$unit]:-0}" -eq 1 ]; then
    echo "runner-umask: $unit: problem found"
    continue
  fi
  needs_restart=0
  for candidate in "${restart_units[@]}"; do [ "$candidate" != "$unit" ] || needs_restart=1; done
  if [ "$needs_restart" -eq 0 ]; then
    echo "runner-umask: $unit: ok (running listener umask ${unit_listener[$unit]#*:})"
    continue
  fi
  if [ "$restart_when_idle" -eq 1 ] && ! pgrep -x Runner.Worker >/dev/null; then
    systemctl restart "$unit"
    current="$(wait_for_service_listener "$unit")" || true
    if listener_is_clean "$current"; then
      echo "runner-umask: $unit: restarted; running listener umask ${current#*:}"
    else
      echo "runner-umask: $unit: restart completed; running listener umask ${current:-not found or unreadable} (restart needed)" >&2
      drift=1
    fi
  else
    drift=1
    echo "runner-umask: $unit: restart needed: run \`systemctl restart $unit\` when the runner is idle"
  fi
done

exit_for_drift "$drift"
exit $?
