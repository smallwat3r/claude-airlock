"""Where a path is, against a directory: as both are written, or by where
they lead. The name of each says which.

  is_under, is_within,     as the paths are written, nothing is resolved:
  overlap, nearest         whoever asks resolves them first where a link
                           counts
  leads_under              as they are written, or by where they lead: a
                           link into a directory is in it
  resolved_within,         by where they lead alone
  resolved_overlap"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable


def is_under(path: str, directory: str) -> bool:
    """Whether a path is under a directory, not the directory itself. By
    both as they are written, neither is resolved: who asks resolves them
    first where a link counts. The root holds every other path."""
    return path.startswith(directory.rstrip(os.sep) + os.sep)


def is_within(path: str, directory: str) -> bool:
    """Whether a path is a directory or under it, see is_under."""
    return path == directory or is_under(path, directory)


def overlap(one: str, other: str) -> bool:
    """Whether one of two directories is the other or is inside it,
    either way round, see is_within."""
    return is_within(one, other) or is_within(other, one)


def nearest(
    path: str,
    roots: Iterable[str],
    within: Callable[[str, str], bool] = is_under,
) -> str | None:
    """Of some directories, the one nearest above a path, by within (under
    it, by default), none when the path is in none of them. As they are
    written, whoever asks resolves them first where a link counts."""
    return max((root for root in roots if within(path, root)), key=len, default=None)


def leads_under(path: str, directory: str) -> bool:
    """Whether a path is under a directory as both are written, or by
    where they lead: a link into it is in it."""
    if is_under(path, directory):
        return True
    return is_under(os.path.realpath(path), os.path.realpath(directory))


def resolved_within(path: str, root: str) -> str | None:
    """Where a path is within a directory as that directory is written,
    none when it is not within it. By where the two lead, either can be
    reached through a link."""
    real_path, real_root = os.path.realpath(path), os.path.realpath(root)
    if not is_within(real_path, real_root):
        return None
    return os.path.normpath(os.path.join(root, os.path.relpath(real_path, real_root)))


def resolved_overlap(one: str, other: str) -> bool:
    """Whether one of two directories is the other or is inside it,
    either way round, by where each leads: a link to a directory is the
    directory."""
    return overlap(os.path.realpath(one), os.path.realpath(other))
