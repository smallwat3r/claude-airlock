# shellcheck shell=bash
# Under a runtime where a watcher sidecar cannot see into the session, such
# as gVisor, none is started.

# Wait as long as watcher.sh does, so a watcher would have joined by now
sleep 3
check_fails "no watcher is in the session" grep -l "[p]rocwatch" /proc/[0-9]*/cmdline
