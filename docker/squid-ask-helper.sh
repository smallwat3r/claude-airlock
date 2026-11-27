#!/bin/bash
# How the egress filter asks the user about a host that is not on its list
# (CLAUDE_AIRLOCK_NET_ASK, see claude_airlock/sandbox/asked_hosts.py).
#
# Squid runs this as the helper of an external ACL (see squid.conf), for a
# request no other rule allowed. Each line it is given is a request:
#
#   CHANNEL ADDRESS HOST PORT ...
#
# the address it came from and the host and port it is for, and the answer
# is the channel, then OK to let it through or ERR to refuse it.
#
# The launcher of a session that asks keeps a directory named after the
# address of the session, in the one mounted here, with a file by-port in
# it and a file for each host at a port:
#
#   ADDRESS/waiting/HOST:PORT   written here, a request for it waits
#   ADDRESS/allowed/HOST:PORT   written by the launcher, the user said yes
#   ADDRESS/refused/HOST:PORT   written by the launcher, the user said no
#
# So a yes is for that port of the host alone: one for its HTTPS lets no
# SSH through to it. A request of a session without such a directory is
# refused at once, as the filter does without this. So is one of a session
# whose directory has no by-port, made by a launcher that kept a host
# without its port: what it was told is not taken for any port. Otherwise
# a request waits until the launcher has written the answer, or has taken
# the waiting file away without one, which refuses this request alone.
#
# What a session chooses is the host, so that is taken for a file name
# only when it is a name of the public DNS: labels of letters, digits and
# dashes with dots between them, the last one starting with a letter.
# Never a path, and never what squid would reach without asking the DNS
# for it, which the user cannot tell from a name: an address, in whatever
# notation, or the bare name of a container on the proxy's networks,
# another session's for one. The port is a number as squid writes one.

set -u
shopt -s nullglob

ROOT="${1:-/var/lib/claude-airlock/asked}"
# Seconds between two looks for an answer, and how many looks a request
# waits for one: ten minutes, by when whatever asked has given up
EVERY="${ASK_EVERY:-0.5}"
LOOKS="${ASK_LOOKS:-1200}"
# How many hosts and ports of one session wait for an answer at most, the
# requests for more are refused: a session cannot fill the user's screen with
# questions, nor the directory with files
MOST_WAITING=8

# The same as HOST_PATTERN, LONGEST_HOST, PORT_PATTERN, HIGHEST_PORT and
# BY_PORT of asked_hosts.py
HOST='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$'
LONGEST_HOST=253
PORT='^[1-9][0-9]{0,4}$'
HIGHEST_PORT=65535
BY_PORT=by-port
ADDRESS='^[0-9]{1,3}(\.[0-9]{1,3}){3}$'

# The answer the launcher has about a host at a port, nothing when it has
# none
answered() { # tree, HOST:PORT
  if [[ -e "$1/allowed/$2" ]]; then
    echo OK
  elif [[ -e "$1/refused/$2" ]]; then
    echo ERR
  fi
}

# Note that a request waits for an answer about a host at a port. Not when
# as many as may wait already do.
wait_for() { # tree, HOST:PORT
  local waiting=("$1"/waiting/*)
  if [[ ! -e "$1/waiting/$2" ]] && ((${#waiting[@]} >= MOST_WAITING)); then
    return 1
  fi
  : 2>/dev/null >"$1/waiting/$2"
}

# Wait for the answer about a host and say it, refused without one. Run in
# the background, the requests of other sessions are not held up
# meanwhile: a short line is written whole, so the answers do not mix.
answer_when_told() { # channel, tree, HOST:PORT
  local channel="$1" tree="$2" asked="$3" looks="${LOOKS}"
  while ((looks-- > 0)) && [[ -e "${tree}/waiting/${asked}" ]]; do
    [[ -z "$(answered "${tree}" "${asked}")" ]] || break
    sleep "${EVERY}"
  done
  rm -f -- "${tree}/waiting/${asked}"
  # Looked for once more: the launcher writes it, then takes the wait away
  local answer
  answer="$(answered "${tree}" "${asked}")"
  echo "${channel} ${answer:-ERR}"
}

while read -r channel address host port _; do
  [[ "${channel}" =~ ^[0-9]+$ ]] || continue
  # Not with ${host,,}: the tests run this with the bash of macOS, 3.2
  host="$(LC_ALL=C tr '[:upper:]' '[:lower:]' <<<"${host}")"
  tree="${ROOT}/${address}"
  answer=ERR
  if [[ "${address}" =~ ${ADDRESS} && "${host}" =~ ${HOST} ]] &&
    ((${#host} <= LONGEST_HOST)) && [[ "${port:-}" =~ ${PORT} ]] &&
    ((port <= HIGHEST_PORT)) && [[ -f "${tree}/${BY_PORT}" ]] &&
    [[ -d "${tree}/waiting" ]]; then
    asked="${host}:${port}"
    answer="$(answered "${tree}" "${asked}")"
    if [[ -z "${answer}" ]] && wait_for "${tree}" "${asked}"; then
      answer_when_told "${channel}" "${tree}" "${asked}" &
      continue
    fi
  fi
  echo "${channel} ${answer:-ERR}"
done

# Squid is done with this helper: nobody reads the answers still waited for
pending="$(jobs -p)"
if [[ -n "${pending}" ]]; then
  # shellcheck disable=SC2086
  kill ${pending} 2>/dev/null
fi
exit 0
