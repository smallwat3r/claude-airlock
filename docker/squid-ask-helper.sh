#!/bin/bash
# How the egress filter asks the user about a host that is not on its list
# (CLAUDE_AIRLOCK_NET_ASK, see claude_airlock/sandbox/asked_hosts.py).
#
# Squid runs this as the helper of an external ACL (see squid.conf), for a
# request no other rule allowed. Each line it is given is a request:
#
#   CHANNEL ADDRESS HOST ...
#
# the address it came from and the host it is for, and the answer is the
# channel, then OK to let it through or ERR to refuse it.
#
# The launcher of a session that asks keeps a directory named after the
# address of the session, in the one mounted here:
#
#   ADDRESS/waiting/HOST   written here, a request for the host waits
#   ADDRESS/allowed/HOST   written by the launcher, the user said yes
#   ADDRESS/refused/HOST   written by the launcher, the user said no
#
# A request of a session without one is refused at once, as the filter
# does without this. Otherwise it waits until the launcher has written the
# answer, or has taken the waiting file away without one, which refuses
# this request alone.
#
# What a session chooses is the host, so that is taken for a file name
# only when it is one of letters, digits, dots and dashes that starts and
# ends with a letter or a digit: never a path.

set -u
shopt -s nullglob

ROOT="${1:-/var/lib/claude-airlock/asked}"
# Seconds between two looks for an answer, and how many looks a request
# waits for one: ten minutes, by when whatever asked has given up
EVERY="${ASK_EVERY:-0.5}"
LOOKS="${ASK_LOOKS:-1200}"
# How many hosts of one session wait for an answer at most, the requests
# for more are refused: a session cannot fill the user's screen with
# questions, nor the directory with files
MOST_WAITING=8

HOST='^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$'
ADDRESS='^[0-9]{1,3}(\.[0-9]{1,3}){3}$'

# The answer the launcher has about a host, nothing when it has none
answered() { # tree, host
  if [[ -e "$1/allowed/$2" ]]; then
    echo OK
  elif [[ -e "$1/refused/$2" ]]; then
    echo ERR
  fi
}

# Note that a request waits for an answer about a host. Not when as many
# hosts as may wait already do.
wait_for() { # tree, host
  local waiting=("$1"/waiting/*)
  if [[ ! -e "$1/waiting/$2" ]] && ((${#waiting[@]} >= MOST_WAITING)); then
    return 1
  fi
  : 2>/dev/null >"$1/waiting/$2"
}

# Wait for the answer about a host and say it, refused without one. Run in
# the background, the requests of other sessions are not held up
# meanwhile: a short line is written whole, so the answers do not mix.
answer_when_told() { # channel, tree, host
  local channel="$1" tree="$2" host="$3" looks="${LOOKS}"
  while ((looks-- > 0)) && [[ -e "${tree}/waiting/${host}" ]]; do
    [[ -z "$(answered "${tree}" "${host}")" ]] || break
    sleep "${EVERY}"
  done
  rm -f -- "${tree}/waiting/${host}"
  # Looked for once more: the launcher writes it, then takes the wait away
  local answer
  answer="$(answered "${tree}" "${host}")"
  echo "${channel} ${answer:-ERR}"
}

while read -r channel address host _; do
  [[ "${channel}" =~ ^[0-9]+$ ]] || continue
  host="${host,,}"
  tree="${ROOT}/${address}"
  answer=ERR
  if [[ "${address}" =~ ${ADDRESS} && "${host}" =~ ${HOST} && -d "${tree}/waiting" ]]; then
    answer="$(answered "${tree}" "${host}")"
    if [[ -z "${answer}" ]] && wait_for "${tree}" "${host}"; then
      answer_when_told "${channel}" "${tree}" "${host}" &
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
