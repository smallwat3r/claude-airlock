"""Checks that the egress proxy can ask the user about a host
(CLAUDE_AIRLOCK_NET_ASK): its helper, run in the proxy's container as the
user squid runs it as, finds what a launcher keeps for a session, holds a
request for a host nobody answered for yet, and lets it through once the
launcher has a yes. The session is made up, at an address no container
has.

Usage: asked_hosts.py PROXY_CONTAINER"""

from __future__ import annotations

import os
import subprocess
import sys
import time

from records import require

from claude_airlock.sandbox.asked_hosts import AskedHosts
from claude_airlock.settings import detect_host

ADDRESS = "10.255.255.7"
PATIENCE = 20.0

proxy = sys.argv[1]
asked = AskedHosts(detect_host(os.environ), "claude-smoke-asked-hosts")
require(asked.open(ADDRESS), "the directory of the session was not made")
helper = subprocess.Popen(
    ["docker", "exec", "--interactive", "--user=proxy", proxy]
    + ["bash", "/etc/squid/ask-helper"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    text=True,
)
try:
    assert helper.stdin
    assert helper.stdout
    asked.answer("allowed.test", True)
    helper.stdin.write(
        f"0 {ADDRESS} allowed.test -\n"
        "1 10.255.255.8 allowed.test -\n"
        f"2 {ADDRESS} waits.test -\n"
    )
    helper.stdin.flush()
    first = sorted(helper.stdout.readline().strip() for _ in range(2))
    require(first == ["0 OK", "1 ERR"], f"the helper said {first}")
    deadline = time.monotonic() + PATIENCE
    while asked.waiting() != ["waits.test"] and time.monotonic() < deadline:
        time.sleep(0.1)
    require(asked.waiting() == ["waits.test"], f"waiting: {asked.waiting()}")
    asked.answer("waits.test", True)
    held = helper.stdout.readline().strip()
    require(held == "2 OK", f"the helper said {held!r} of the host that waited")
finally:
    helper.kill()
    helper.wait()
    asked.close()
