"""Checks that the launcher recorded the memory and CPU use of a smoke
session from outside it, as it does under gVisor, and finished the record.

Usage: health.py RECORD_PREFIX"""

from __future__ import annotations

import sys

from records import only_file, require

from claude_sandbox.processes import read_record

file = only_file(sys.argv[1])
require(file.endswith(".jsonl"), f"the record was not finished: {file}")
record = read_record(file)
require(record.outside and not record.processes, record)
measured = [s for s in record.samples if s.memory and s.cpu is not None]
require(measured, record)
