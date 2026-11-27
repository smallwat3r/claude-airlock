# shellcheck shell=bash
# Helpers for the scripts in this directory, which run inside a session.
# run.sh puts this file in front of each of them. check expects its command
# to succeed, check_fails expects the sandbox to stop it.

ok() { echo "ok   $1"; }
fail() { echo "FAIL $1"; }
check() { # description, command...
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then ok "${description}"; else fail "${description}"; fi
}
check_fails() { # description, command...
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then fail "${description}"; else ok "${description}"; fi
}
# Whether a proxy refuses a request itself, with a 403: a request it let
# through is answered by what is behind it, with something else
denied() { # curl arguments...
  [ "$(curl -sS -m 15 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null)" = 403 ]
}

# The containers of the Docker API, straight to the socket proxy as a
# session can go, and one that is not there: should the proxy let a
# request for it through, nothing happens to a container, the daemon
# answers with a 404
SOCKET_API="http://${DOCKER_HOST#tcp://}/containers"
NO_CONTAINER=claude-smoke-no-such-container
# What the socket proxy refuses in either mode: what writes to a container
# or hands out its files, whatever the method it comes by
check_socket_denials() {
  local none="${SOCKET_API}/${NO_CONTAINER}"
  check "a write is denied" denied -X POST "${none}/stop"
  check "the input of a container is out of reach" \
    denied "${none}/attach/ws?stream=1&stdin=1"
  check "the files of a container are out of reach" \
    denied "${none}/archive?path=/etc"
  check "so is the whole of one" denied "${none}/export"
  check "so is what changed in it" denied "${none}/changes"
}
