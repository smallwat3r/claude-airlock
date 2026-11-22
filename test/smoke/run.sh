#!/usr/bin/env bash
# End-to-end check of the launcher against a real Docker daemon. Run it on the
# host (not inside the sandbox) after changing the launcher, the Dockerfile
# parts or the layout of the checkout:
#
#   test/smoke/run.sh
#
# It runs the unit tests, replaces the sidecars (they bind-mount their config
# from the checkout, so a moved checkout leaves them pointing at stale paths),
# then starts real sessions in a throwaway project and checks the sandbox from
# the inside: open, filtered and, when the docker feature is built, with the
# socket proxy. The first session builds the image if it is missing, which
# takes a while.
#
# The files next to this one:
#   inside/   the scripts that run inside a session, one per kind of session.
#             inside/lib.sh has their helpers.
#   checks/   the Python checks of what a session left on the host, such as
#             its capture and its records.

set -euo pipefail

SMOKE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SMOKE}/../.." && pwd)"
LAUNCHER="${ROOT}/bin/claude-airlock"
SIDECARS=(claude-egress-proxy claude-airlock-ps-proxy claude-airlock-proxy)
STATE="${XDG_STATE_HOME:-${HOME}/.local/state}/claude-airlock"
FAILED=0
# Set by prepare: the throwaway project, the name of its session container,
# the launcher's stderr of the last session, and the files planted on the host
PROJECT=""
CONTAINER=""
SESSION_ERR=""
OTHER_PROJECT="${HOME}/.claude/projects/-claude-smoke-another-project"
HOST_SESSION="${HOME}/.claude/sessions/smoke-host-session"
HOST_PLUGIN="${HOME}/.claude/plugins/smoke-host-plugin"

section() {
  echo
  echo "$1"
}
ok() { echo "ok   $1"; }
fail() {
  echo "FAIL $1"
  FAILED=1
}
# A failing check prints the end of what its command wrote, to say why
check() { # description, command...
  local description="$1" said
  shift
  if said="$("$@" 2>&1)"; then
    ok "${description}"
  else
    fail "${description}"
    tail -n 5 <<<"${said}" | cut -c 1-400 | sed 's/^/     /'
  fi
}
# Run one of the Python checks, which can import the launcher's package
python_check() { # name, arguments...
  local name="$1"
  shift
  PYTHONPATH="${ROOT}" python3 "${SMOKE}/checks/${name}.py" "$@"
}

# Run scripts of inside/ with bash in a sandbox session started in the
# throwaway project. The first argument names the scripts, separated by
# spaces. The other arguments are VAR=value settings for the launcher. They
# come on top of the defaults the checks assume, so a setting exported in the
# shell or kept in the config file does not skew the checks. The scripts
# report with "ok" and "FAIL" lines. The launcher's stderr is kept in
# ${SESSION_ERR} for the checks made from outside.
session() { # "script..." [VAR=value]...
  local name script output
  script="$(cat "${SMOKE}/inside/lib.sh")"
  for name in $1; do
    script+=$'\n'"$(cat "${SMOKE}/inside/${name}.sh")"
  done
  shift
  output="$(cd "${PROJECT}" && env CLAUDE_AIRLOCK_NET_FILTER=0 \
    CLAUDE_AIRLOCK_NET_LOG=0 CLAUDE_AIRLOCK_PROC_LOG=0 \
    CLAUDE_AIRLOCK_SSH_AGENT=0 CLAUDE_AIRLOCK_SHARED_HISTORY=0 \
    CLAUDE_AIRLOCK_DOCKER_SOCKET=0 CLAUDE_AIRLOCK_RW_CONFIG=0 \
    CLAUDE_AIRLOCK_CACHE=1 \
    "$@" "${LAUNCHER}" --shell -c "${script}" 2>"${SESSION_ERR}" </dev/null)" || {
    fail "session exited with an error, see below"
    cat "${SESSION_ERR}" >&2
  }
  printf '%s\n' "${output}"
  if grep -q '^FAIL' <<<"${output}"; then FAILED=1; fi
}

preflight() {
  echo "Preflight"
  if [ -n "${CLAUDE_AIRLOCK_SANDBOX:-}" ]; then
    echo "This runs on the host, not inside the sandbox." >&2
    exit 1
  fi
  check "python3 is 3.9 or later" \
    python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))'
  check "docker daemon is reachable" docker info
  [ "${FAILED}" = 0 ] || exit 1
}

unit_tests() {
  section "Unit tests"
  if "${ROOT}/test/launcher_test.py" 2>&1 | tail -3; then
    ok "launcher tests pass"
  else
    fail "launcher tests"
  fi
  check "every feature assembles into a Dockerfile" \
    bash -c "'${LAUNCHER}' --dockerfile | grep -q '^ENTRYPOINT'"
}

# Remove the sidecars so the sessions below start them from this checkout.
# Asks first when sessions are running, because they lose their sidecars.
replace_sidecars() {
  local running answer name
  section "Sidecars"
  running="$(docker ps --format '{{.Names}}' | grep '^claude-' |
    grep -vxF -f <(printf '%s\n' "${SIDECARS[@]}") || true)"
  if [ -n "${running}" ]; then
    echo "Sessions still running:"
    echo "  ${running//$'\n'/$'\n'  }"
    echo "Replacing the sidecars cuts the network of the filtered ones and the"
    echo "docker access of those using the socket proxy."
    # No answer (not a terminal) counts as no
    read -r -p "Continue? [y/N] " answer || answer=""
    [ "${answer}" = "y" ] || exit 1
  fi
  for name in "${SIDECARS[@]}"; do
    if docker rm -f "${name}" >/dev/null 2>&1; then
      ok "removed ${name}, the launcher recreates it when needed"
    fi
  done
}

# Remove what prepare and the sessions left: the project, its cache volume
# and its history, and the files planted on the host
# shellcheck disable=SC2317,SC2329 # called by the trap
cleanup() {
  local volume
  for volume in $(docker volume ls -q --filter "name=claude-cache-$(basename "${PROJECT}")"); do
    docker volume rm "${volume}" >/dev/null 2>&1 || true
  done
  rm -rf "${PROJECT}" "${SESSION_ERR}" "${OTHER_PROJECT}"
  rm -f "${HOST_SESSION}" "${HOST_PLUGIN}"
  rm -rf "${STATE}/history/$(basename "${PROJECT}")-"*
}

# Make the throwaway project, and plant on the host what the sessions must
# or must not see
prepare() {
  PROJECT="$(mktemp -d "${TMPDIR:-/tmp}/claude-smoke-XXXXXX")"
  CONTAINER="claude-$(basename "${PROJECT}")"
  SESSION_ERR="$(mktemp)"
  trap cleanup EXIT
  git -C "${PROJECT}" init -q
  echo "SECRET=1" >"${PROJECT}/.env"
  echo "EXAMPLE=1" >"${PROJECT}/.env.example"
  # The transcripts of another project, which a session must not see
  mkdir -p "${OTHER_PROJECT}"
  echo '{"type":"user"}' >"${OTHER_PROJECT}/session.jsonl"
  # A session of the host's own claude, which a session must not see, and a
  # plugin of the host, which it must
  mkdir -p "$(dirname "${HOST_SESSION}")" "$(dirname "${HOST_PLUGIN}")"
  touch "${HOST_SESSION}" "${HOST_PLUGIN}"
  # The checksum of the host's login, for inside/defaults.sh to compare with
  host_login_checksum >"${PROJECT}/.smoke-login"
}

# The checksum of the login of the host's claude, nothing without one: a
# file, on macOS an item of the Keychain
host_login_checksum() {
  local kept
  if kept="$(security find-generic-password -a "${USER:-$(id -un)}" \
    -s "Claude Code-credentials" -w 2>/dev/null)" && [ -n "${kept}" ]; then
    printf '%s' "${kept}" | sha256sum 2>/dev/null || true
  else
    { sha256sum <"${HOME}/.claude/.credentials.json"; } 2>/dev/null || true
  fi
}

defaults() {
  section "Session with the defaults"
  session defaults
  check "the session wrote into the project" [ -f "${PROJECT}/written-by-session" ]
  check "a planted git hook is reported" \
    grep -q "changed files that can run commands on the host" "${SESSION_ERR}"
  rm -f "${PROJECT}/.git/hooks/pre-commit"
  check "what a session leaves in ~/.claude stays with the sandbox" \
    [ -f "${STATE}/home/smoke-probe" ]
  check "and is not in that of the host" bash -c "! ls '${HOME}/.claude/smoke-probe'"
  rm -f "${STATE}/home/smoke-probe"
  check "the history of the session is kept apart, per project" \
    bash -c "ls '${STATE}/history/$(basename "${PROJECT}")-'*/file-history/smoke-probe"
  check "and not with the history of every project" \
    bash -c "! ls '${HOME}/.claude/file-history/smoke-probe'"
}

egress_filter() {
  section "Session with the egress filter"
  session egress-filter CLAUDE_AIRLOCK_NET_FILTER=1
  check "--net-log lists the blocked domain" \
    bash -c "'${LAUNCHER}' --net-log | grep -q example.com"
  check "the proxy log survives a proxy restart" \
    bash -c "'${LAUNCHER}' --net-reload && '${LAUNCHER}' --net-log | grep -q example.com"
  # The proxy handles the signal a moment after the command returns
  check "the proxy log rotates on request" \
    bash -c "docker exec claude-egress-proxy squid -k rotate && sleep 2 &&
      docker exec claude-egress-proxy test -f /var/log/squid/access.log.0"
  check "--net-log also reads the rotated log" \
    bash -c "'${LAUNCHER}' --net-log | grep -q example.com"
  # The proxy --net-reload started is still up, no session ended since
  check "the proxy asks about a host through what the launcher keeps" \
    python_check asked_hosts claude-egress-proxy
}

# The capture and the record of processes. Under a runtime where a watcher
# sidecar cannot see into the session, such as gVisor, no watcher is started
# and the launcher records memory and CPU use from outside instead (see
# claude_airlock/sandbox/runtime.py).
capture_and_processes() {
  local captured="${STATE}/captures/${CONTAINER}.capture-"
  local watched="${STATE}/processes/${CONTAINER}.procs-"
  local watcher=watcher
  section "Session with the network capture and the record of processes"
  if [ "$(python_check watched_inside)" = 0 ]; then watcher=no-watcher; fi
  rm -f "${captured}"* "${watched}"*
  session "${watcher} capture" CLAUDE_AIRLOCK_NET_LOG=1 CLAUDE_AIRLOCK_PROC_LOG=1
  # Without a capture, which the launcher reports, there is nothing to read
  if ! grep -q "network capture" "${SESSION_ERR}"; then
    check "the capture names what the session reached, by UDP too" \
      python_check capture "${captured}"
    check "the capture sidecar is gone" \
      bash -c "! docker inspect '${CONTAINER}.capture'"
    if [ "${watcher}" = watcher ]; then
      check "the connection of curl is tied to curl" \
        python_check processes "${watched}" "${captured}"
    else
      check "memory and CPU use were recorded from outside the session" \
        python_check health "${watched}"
      check "the launcher said what the runtime does not provide" \
        grep -q "processes are not recorded" "${SESSION_ERR}"
    fi
    check "the watcher sidecar is gone" \
      bash -c "! docker inspect '${CONTAINER}.procs'"
  fi
  session filtered-capture CLAUDE_AIRLOCK_NET_FILTER=1 CLAUDE_AIRLOCK_NET_LOG=1
  check "the filtered session was captured too" \
    bash -c "[ \"\$(ls '${captured}'*.pcap | wc -l)\" -eq 2 ]"
}

socket_proxy() {
  section "Session with the socket proxy"
  session socket-proxy CLAUDE_AIRLOCK_DOCKER_SOCKET=1
  # The session leaves this file when the docker feature is in the image
  if [ -f "${PROJECT}/.smoke-docker-used" ]; then
    check "the calls through the socket proxy were noted, the denied one too" \
      python_check door_uses "${STATE}/door-use.jsonl" "${PROJECT}" docker
  fi
}

ssh_agent() {
  [ -S "${SSH_AUTH_SOCK:-}" ] || return 0
  section "Session with the SSH agent"
  session ssh-agent CLAUDE_AIRLOCK_SSH_AGENT=1
  # On macOS the session uses the agent of Docker's machine, which the
  # launcher cannot note
  if [ "$(uname)" != Darwin ]; then
    check "the use of the agent was noted" \
      python_check door_uses "${STATE}/door-use.jsonl" "${PROJECT}" ssh-agent
  fi
}

summary() {
  echo
  if [ "${FAILED}" = 0 ]; then
    echo "All checks passed. Not covered here, try once by hand: an interactive"
    echo "claude-airlock session from your editor, and Ctrl-C during a piped run"
    echo "(claude-airlock -p ... < file)."
  else
    echo "Some checks failed."
  fi
}

main() {
  preflight
  unit_tests
  replace_sidecars
  prepare
  defaults
  egress_filter
  capture_and_processes
  socket_proxy
  ssh_agent
  summary
  exit "${FAILED}"
}

main
