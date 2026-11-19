# shellcheck shell=bash
# The watcher sidecar, under a runtime where it can see into the session.

# The watcher joins a moment after the session is up
sleep 3
watcher="$(grep -l "[p]rocwatch" /proc/[0-9]*/cmdline 2>/dev/null | head -1 | cut -d/ -f3)"
check "the watcher of processes is up" [ -n "${watcher}" ]
check_fails "it is not the session to stop" kill "${watcher}"
check_fails "nor its record the session to read" ls "/proc/${watcher}/root/"
