"""Checks that the watcher of a smoke session recorded curl, and that the
HTTPS connection in the capture is tied to it.

Usage: processes.py RECORD_PREFIX CAPTURE_PREFIX"""

from __future__ import annotations

import sys

from records import only_file, require

from claude_airlock.pcap import read_capture
from claude_airlock.processes import read_record

record = read_record(only_file(sys.argv[1]))
require(not record.unreadable, "the watcher could not see who holds a socket")
names = {process.name for process in record.processes}
require("curl" in names, names)
holders = [
    record.holder(made.source_port, made.address, made.port, made.when)
    for made in read_capture(only_file(sys.argv[2])).connections
    if made.port == 443
]
require(any(line and line[0].name == "curl" for line in holders), holders)
