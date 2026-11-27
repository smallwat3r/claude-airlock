"""Checks that the egress proxy can ask the user about a host
(CLAUDE_AIRLOCK_NET_ASK): its helper, run in the proxy's container as the
user squid runs it as, finds what a launcher keeps for a session, holds a
request for a host nobody answered for yet, and lets it through once the
launcher has a yes, for the port it was given alone. The session is made
up, at an address no container has.

Usage: asked_hosts.py PROXY_CONTAINER"""

from __future__ import annotations

import os
import subprocess
import sys
import time

from records import require

from claude_airlock.sandbox.asked_hosts import AskedHosts, Destination
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
    asked.answer(Destination("allowed.test", 443), True)
    asked.answer(Destination("allowed.test", 22), False)
    helper.stdin.write(
        f"0 {ADDRESS} allowed.test 443\n"
        "1 10.255.255.8 allowed.test 443\n"
        f"2 {ADDRESS} allowed.test 22\n"
        f"3 {ADDRESS} waits.test 443\n"
    )
    helper.stdin.flush()
    first = sorted(helper.stdout.readline().strip() for _ in range(3))
    require(first == ["0 OK", "1 ERR", "2 ERR"], f"the helper said {first}")
    waits = Destination("waits.test", 443)
    deadline = time.monotonic() + PATIENCE
    while asked.waiting() != [waits] and time.monotonic() < deadline:
        time.sleep(0.1)
    require(asked.waiting() == [waits], f"waiting: {asked.waiting()}")
    asked.answer(waits, True)
    held = helper.stdout.readline().strip()
    require(held == "3 OK", f"the helper said {held!r} of the host that waited")
finally:
    helper.kill()
    helper.wait()
    asked.close()
