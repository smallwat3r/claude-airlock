"""Finding the record that a smoke session left."""

from __future__ import annotations

import glob
import sys
from pathlib import Path


def only_file(prefix: str, ending: str = "") -> Path:
    """The one file whose path starts with the prefix, and ends as told
    when told. Exits with a message when there is none or more than one."""
    found = glob.glob(prefix + "*" + ending)
    if len(found) != 1:
        sys.exit(f"expected one file starting with {prefix}, found {found}")
    return Path(found[0])


def require(holds: object, message: object) -> None:
    """Exit with the message unless the condition holds."""
    if not holds:
        sys.exit(str(message))
