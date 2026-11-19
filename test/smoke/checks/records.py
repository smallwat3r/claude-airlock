"""Finding the record that a smoke session left."""

from __future__ import annotations

import glob
import sys


def only_file(prefix: str) -> str:
    """The one file whose path starts with the prefix. Exits with a message
    when there is none or more than one."""
    found = glob.glob(prefix + "*")
    if len(found) != 1:
        sys.exit(f"expected one file starting with {prefix}, found {found}")
    return found[0]


def require(holds: object, message: object) -> None:
    """Exit with the message unless the condition holds."""
    if not holds:
        sys.exit(str(message))
