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
  output="$(cd "${PROJECT}" && env CLAUDE_DOCKER_NET_FILTER=0 \
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
# The sessions leave a cache volume named after the project behind
# shellcheck disable=SC2317 # called by the trap
cleanup() {
  local volume
  for volume in $(docker volume ls -q --filter "name=claude-cache-$(basename "${PROJECT}")"); do
    docker volume rm "${volume}" >/dev/null 2>&1 || true
  done
  rm -rf "${PROJECT}" "${SESSION_ERR}"
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
check "~/.cache is writable" touch "/home/node/.cache/smoke-probe"
check "project is mounted read-write" touch written-by-session
check_fails ".env is shadowed" [ -s .env ]
check ".env.example stays readable" [ -s .env.example ]
check_fails "settings.json is read-only" [ -w /home/node/.claude/settings.json ]
check "CLAUDE.md lists the installed tools" grep -q "^- Python 3 with uv" /etc/claude-code/CLAUDE.md
check_fails "CLAUDE.md has no template placeholder" grep -q Placeholder /etc/claude-code/CLAUDE.md
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
check_fails "another domain is blocked" curl -fsS -m 15 -o /dev/null https://example.com
check_fails "direct connections fail" curl -fsS -m 5 --noproxy "*" -o /dev/null https://1.1.1.1
' CLAUDE_DOCKER_NET_FILTER=1
check "the egress proxy is running" \
  bash -c "docker inspect -f '{{.State.Running}}' claude-egress-proxy | grep -q true"
check "--net-log lists the blocked domain" \
  bash -c "'${LAUNCHER}' --net-log | grep -q example.com"

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
' CLAUDE_DOCKER_SOCKET=1

echo
if [ "${FAILED}" = 0 ]; then
  echo "All checks passed. Not covered here, try once by hand: an interactive"
  echo "claude-docker session from your editor, and Ctrl-C during a piped run"
  echo "(claude-docker -p ... < file)."
else
  echo "Some checks failed."
fi
exit "${FAILED}"
