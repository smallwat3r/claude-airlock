"""Prints 1 when a watcher sidecar can see into the sessions the launcher
would start now, otherwise 0. This depends on the runtime: the one set in
CLAUDE_AIRLOCK_RUNTIME or the config file, otherwise the daemon's default."""

from __future__ import annotations

import os

from claude_airlock.runtime import session_runtime
from claude_airlock.settings import detect_host, load_settings

config = os.path.join(detect_host(os.environ).user_conf, "config")
print(int(session_runtime(load_settings(os.environ, config)).JOINABLE))
