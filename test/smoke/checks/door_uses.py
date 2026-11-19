"""Checks that the launcher noted the use of a door (ssh-agent or docker)
by a project. For docker, one of the calls must have been denied.

Usage: door_uses.py RECORD_FILE PROJECT DOOR"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from records import require

record, project, door = sys.argv[1:4]
uses = [json.loads(line) for line in Path(record).read_text().splitlines()]
ours = [use for use in uses if use["project"] == project and use["door"] == door]
require(ours, f"no use of {door} was noted, the last entries are {uses[-5:]}")
if door == "docker":
    require(any(use["status"] == 403 for use in ours), ours)
