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
