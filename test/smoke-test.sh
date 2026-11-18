#!/usr/bin/env bash
# End-to-end check of the launcher against a real Docker daemon. Run it on the
# host (not inside the sandbox) after changing the launcher, the Dockerfile
# parts or the layout of the checkout:
#
#   test/smoke-test.sh
#
# It runs the unit tests, replaces the sidecars (they bind-mount their config
# from the checkout, so a moved checkout leaves them pointing at stale paths),
# then starts real sessions in a throwaway project and checks the sandbox from
# the inside: open, filtered and, when the docker feature is built, with the
# socket proxy. The first session builds the image if it is missing, which
# takes a while.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAUNCHER="${ROOT}/bin/claude-docker"
SIDECARS=(claude-egress-proxy claude-docker-ps-proxy claude-docker-proxy)
FAILED=0

ok() { echo "ok   $1"; }
fail() {
  echo "FAIL $1"
  FAILED=1
}
check() { # description, command...
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then ok "${description}"; else fail "${description}"; fi
}

# Run a script with bash inside a sandbox session started in the throwaway
# project. Extra arguments are VAR=value settings for the launcher, on top of
# the defaults the checks assume, so a setting exported in the shell or kept
# in the config file does not skew them. The script reports with "ok" and
# "FAIL" lines of its own, the launcher's stderr is kept in ${SESSION_ERR}
# for the checks made from outside.
session() { # script [VAR=value]...
  local script="$1" output
  shift
  output="$(cd "${PROJECT}" && env CLAUDE_DOCKER_NET_FILTER=0 CLAUDE_DOCKER_NET_LOG=0 \
    CLAUDE_DOCKER_PROC_LOG=0 CLAUDE_DOCKER_SSH_AGENT=0 CLAUDE_DOCKER_SHARED_HISTORY=0 \
    CLAUDE_DOCKER_SOCKET=0 CLAUDE_DOCKER_RW_CONFIG=0 CLAUDE_DOCKER_CACHE=1 \
    "$@" "${LAUNCHER}" --shell -c "${script}" 2>"${SESSION_ERR}" </dev/null)" || {
    fail "session exited with an error, see below"
    cat "${SESSION_ERR}" >&2
  }
  printf '%s\n' "${output}"
  if grep -q '^FAIL' <<<"${output}"; then FAILED=1; fi
}

# Helpers for the scripts run inside the container: check expects its command
# to succeed, check_fails expects the sandbox to stop it
# shellcheck disable=SC2016 # expanded by the bash in the container
INSIDE='
ok() { echo "ok   $1"; }
fail() { echo "FAIL $1"; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else fail "$d"; fi; }
check_fails() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then fail "$d"; else ok "$d"; fi; }
'

echo "Preflight"
if [ -n "${CLAUDE_DOCKER_SANDBOX:-}" ]; then
  echo "This runs on the host, not inside the sandbox." >&2
  exit 1
fi
check "python3 is 3.9 or later" \
  python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))'
check "docker daemon is reachable" docker info
[ "${FAILED}" = 0 ] || exit 1

echo
echo "Unit tests"
if "${ROOT}/test/launcher_test.py" 2>&1 | tail -3; then
  ok "launcher tests pass"
else
  fail "launcher tests"
fi
check "every feature assembles into a Dockerfile" \
  bash -c "'${LAUNCHER}' --dockerfile | grep -q '^ENTRYPOINT'"

echo
echo "Sidecars"
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

PROJECT="$(mktemp -d "${TMPDIR:-/tmp}/claude-smoke-XXXXXX")"
SESSION_ERR="$(mktemp)"
STATE="${XDG_STATE_HOME:-${HOME}/.local/state}/claude-sandbox"
# What Claude Code would remember of another project, which a session of
# this one must not get to see
OTHER_PROJECT="${HOME}/.claude/projects/-claude-smoke-another-project"
mkdir -p "${OTHER_PROJECT}"
echo '{"type":"user"}' >"${OTHER_PROJECT}/session.jsonl"
# What the host's claude keeps for itself, which is not a session's to see,
# what comes from the host all the same, and the login as it is now
HOST_SESSION="${HOME}/.claude/sessions/smoke-host-session"
HOST_PLUGIN="${HOME}/.claude/plugins/smoke-host-plugin"
mkdir -p "$(dirname "${HOST_SESSION}")" "$(dirname "${HOST_PLUGIN}")"
touch "${HOST_SESSION}" "${HOST_PLUGIN}"
SMOKE_LOGIN="$(sha256sum <"${HOME}/.claude/.credentials.json" 2>/dev/null || true)"
# The sessions leave a cache volume named after the project behind
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
trap cleanup EXIT
git -C "${PROJECT}" init -q
echo "SECRET=1" >"${PROJECT}/.env"
echo "EXAMPLE=1" >"${PROJECT}/.env.example"

echo
echo "Session with the defaults"
# shellcheck disable=SC2016
session "${INSIDE}"'
check "runs as the host user, the owner of the project" [ "$(id -u)" = "$(stat -c %u .)" ]
check "holds no capabilities" grep -q "^CapEff:.0000000000000000$" /proc/self/status
check_fails "root filesystem is read-only" touch /smoke-probe
check "/tmp is writable" touch /tmp/smoke-probe
check "~/.cache is writable" touch "/home/sandbox/.cache/smoke-probe"
check "project is mounted read-write" touch written-by-session
check_fails ".env is shadowed" [ -s .env ]
check ".env.example stays readable" [ -s .env.example ]
check_fails "settings.json is read-only" [ -w /home/sandbox/.claude/settings.json ]
check_fails "skills are read-only" [ -w /home/sandbox/.claude/skills ]
check "CLAUDE.md lists the installed tools" grep -q "^- Python 3 with uv" /etc/claude-code/CLAUDE.md
check_fails "CLAUDE.md has no template placeholder" grep -q Placeholder /etc/claude-code/CLAUDE.md
check_fails "the transcripts of another project are out of sight" \
  [ -e /home/sandbox/.claude/projects/-claude-smoke-another-project/session.jsonl ]
check "the prompt history is there to add to" [ -w /home/sandbox/.claude/history.jsonl ]
check "the file history is there to add to" touch /home/sandbox/.claude/file-history/smoke-probe
check_fails "the sessions of the host are out of sight" \
  [ -e /home/sandbox/.claude/sessions/smoke-host-session ]
check "~/.claude is writable" touch /home/sandbox/.claude/smoke-probe
check "the plugins of the host are there" [ -e /home/sandbox/.claude/plugins/smoke-host-plugin ]
check "the login is that of the host" \
  [ "$(sha256sum < /home/sandbox/.claude/.credentials.json)" = "'"${SMOKE_LOGIN}"'" ]
check "claude starts" claude --version
check "egress is open" curl -fsS -m 15 -o /dev/null https://example.com
echo planted > .git/hooks/pre-commit
'
check "the session wrote into the project" [ -f "${PROJECT}/written-by-session" ]
check "a planted git hook is reported" \
  grep -q "changed files that can run commands on the host" "${SESSION_ERR}"
rm -f "${PROJECT}/.git/hooks/pre-commit"

echo
echo "Session with the egress filter"
# shellcheck disable=SC2016
session "${INSIDE}"'
check "an allowed domain is reachable" curl -fsS -m 15 -o /dev/null https://api.github.com
# Refused by the proxy itself, a proxy that is down would also fail the request
check "another domain is blocked with a 403" \
  bash -c "curl -sS -m 15 -o /dev/null https://example.com 2>&1 | grep -q 403"
# An address of GitHub, whose reverse DNS names an allowed domain: the
# name the owner of an address gives it is not what the filter goes by
check "an address is blocked whatever its reverse DNS says" \
  bash -c "curl -sS -m 15 -o /dev/null https://140.82.121.4 2>&1 | grep -q 403"
check_fails "direct connections fail" curl -fsS -m 5 --noproxy "*" -o /dev/null https://1.1.1.1
' CLAUDE_DOCKER_NET_FILTER=1
check "the egress proxy is running" \
  bash -c "docker inspect -f '{{.State.Running}}' claude-egress-proxy | grep -q true"
check "--net-log lists the blocked domain" \
  bash -c "'${LAUNCHER}' --net-log | grep -q example.com"
check "the proxy log survives a proxy restart" \
  bash -c "'${LAUNCHER}' --net-reload && '${LAUNCHER}' --net-log | grep -q example.com"
# The signal is handled a moment after the command returns
check "the proxy log rotates on request" \
  bash -c "docker exec claude-egress-proxy squid -k rotate && sleep 2 &&
    docker exec claude-egress-proxy test -f /var/log/squid/access.log.0"
check "--net-log also reads the rotated log" \
  bash -c "'${LAUNCHER}' --net-log | grep -q example.com"

check "what a session leaves in ~/.claude stays with the sandbox" \
  [ -f "${STATE}/home/smoke-probe" ]
check "and is not in that of the host" bash -c "! ls '${HOME}/.claude/smoke-probe'"
rm -f "${STATE}/home/smoke-probe"
check "the history of the session is kept apart, per project" \
  bash -c "ls '${STATE}/history/$(basename "${PROJECT}")-'*/file-history/smoke-probe"
check "and not with the history of every project" \
  bash -c "! ls '${HOME}/.claude/file-history/smoke-probe'"

echo
echo "Session with the network capture and the record of processes"
CAPTURED="${STATE}/captures/claude-$(basename "${PROJECT}").capture-"
WATCHED="${STATE}/processes/claude-$(basename "${PROJECT}").procs-"
rm -f "${CAPTURED}"* "${WATCHED}"*
# shellcheck disable=SC2016
session "${INSIDE}"'
# The watcher of processes joins a moment after the session is up
sleep 3
watcher="$(grep -l "[p]rocwatch" /proc/[0-9]*/cmdline 2>/dev/null | head -1 | cut -d/ -f3)"
check "the watcher of processes is up" [ -n "${watcher}" ]
check_fails "it is not the session to stop" kill "${watcher}"
check_fails "nor its record the session to read" ls "/proc/${watcher}/root/"
check "egress is still open" curl -fsS -m 15 -o /dev/null https://example.com
check "a connection that is not HTTP works" bash -c "exec 3<>/dev/tcp/1.1.1.1/53"
check "a datagram goes out" bash -c "echo probe >/dev/udp/1.1.1.1/9999"
check "holds no capabilities" grep -q "^CapEff:.0000000000000000$" /proc/self/status
' CLAUDE_DOCKER_NET_LOG=1 CLAUDE_DOCKER_PROC_LOG=1
if ! grep -q "network capture" "${SESSION_ERR}"; then
  # shellcheck disable=SC2016 # expanded by the python below
  READ_CAPTURE='
import glob, sys
sys.path.insert(0, sys.argv[1])
from claude_sandbox.pcap import read_capture
(file,) = glob.glob(sys.argv[2] + "*")
found = read_capture(file)
ports = {(c.address, c.port) for c in found.connections}
assert ("1.1.1.1", 53) in ports, ports
assert "example.com" in found.names.values(), found.names
sent = {(f.transport, f.address, f.port) for f in found.flows}
assert ("udp", "1.1.1.1", 9999) in sent, sent
'
  check "the capture names what the session reached, by UDP too" \
    python3 -c "${READ_CAPTURE}" "${ROOT}" "${CAPTURED}"
  check "the capture sidecar is gone" \
    bash -c "! docker inspect 'claude-$(basename "${PROJECT}").capture'"
  # shellcheck disable=SC2016 # expanded by the python below
  READ_PROCESSES='
import glob, sys
sys.path.insert(0, sys.argv[1])
from claude_sandbox.pcap import read_capture
from claude_sandbox.processes import read_record
(file,) = glob.glob(sys.argv[2] + "*")
record = read_record(file)
assert not record.unreadable, "the watcher could not see who holds a socket"
names = {process.name for process in record.processes}
assert "curl" in names, names
(capture,) = glob.glob(sys.argv[3] + "*")
made = [
    record.holder(c.source_port, c.address, c.port, c.when)
    for c in read_capture(capture).connections
    if c.port == 443
]
assert any(line and line[0].name == "curl" for line in made), made
'
  check "the connection of curl is tied to curl" \
    python3 -c "${READ_PROCESSES}" "${ROOT}" "${WATCHED}" "${CAPTURED}"
  check "the watcher sidecar is gone" \
    bash -c "! docker inspect 'claude-$(basename "${PROJECT}").procs'"
fi
# shellcheck disable=SC2016
session "${INSIDE}"'
check "an allowed domain is reachable" curl -fsS -m 15 -o /dev/null https://api.github.com
check_fails "direct connections fail" curl -fsS -m 5 --noproxy "*" -o /dev/null https://1.1.1.1
' CLAUDE_DOCKER_NET_FILTER=1 CLAUDE_DOCKER_NET_LOG=1
check "the filtered session was captured too" bash -c "ls '${CAPTURED}'* | wc -l | grep -q 2"

# What the launcher noted of the use of a door by this project
# shellcheck disable=SC2016 # expanded by the python below
READ_USES='
import json, sys
uses = [json.loads(line) for line in open(sys.argv[1])]
mine = [u for u in uses if u["project"] == sys.argv[2] and u["door"] == sys.argv[3]]
assert mine, uses[-5:]
if sys.argv[3] == "docker":
    assert any(u["status"] == 403 for u in mine), mine
'

echo
echo "Session with the socket proxy"
# shellcheck disable=SC2016
session "${INSIDE}"'
if ! command -v docker >/dev/null; then
  echo "skip the docker feature is not in this image"
  exit 0
fi
check "docker ps works" docker ps
check_fails "other docker calls are denied" docker volume ls
touch .smoke-docker-used
' CLAUDE_DOCKER_SOCKET=1
if [ -f "${PROJECT}/.smoke-docker-used" ]; then
  check "the calls through the socket proxy were noted, the denied one too" \
    python3 -c "${READ_USES}" "${STATE}/door-use.jsonl" "${PROJECT}" docker
fi

if [ -S "${SSH_AUTH_SOCK:-}" ]; then
  echo
  echo "Session with the SSH agent"
  # shellcheck disable=SC2016
  session "${INSIDE}"'
# It lists the keys, or says there are none: either way the agent answered
check "the agent answers through the launcher" bash -c "ssh-add -l; [ \$? -le 1 ]"
' CLAUDE_DOCKER_SSH_AGENT=1
  # On macOS the session has the agent of Docker's machine, not noted
  if [ "$(uname)" != Darwin ]; then
    check "the use of the agent was noted" \
      python3 -c "${READ_USES}" "${STATE}/door-use.jsonl" "${PROJECT}" ssh-agent
  fi
fi

echo
if [ "${FAILED}" = 0 ]; then
  echo "All checks passed. Not covered here, try once by hand: an interactive"
  echo "claude-docker session from your editor, and Ctrl-C during a piped run"
  echo "(claude-docker -p ... < file)."
else
  echo "Some checks failed."
fi
exit "${FAILED}"
