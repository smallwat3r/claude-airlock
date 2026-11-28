"""What the launcher keeps of earlier launches that a session could have
turned to its use since, for later launches to go by:

- The files of secrets that were hidden through a link named as one (see
  hidden_files of hidden.py). A session can remove the link, and with it
  all that said the file holds secrets: they go on being hidden while
  they are there.
- The directories that were a session's to write. A link a session left
  in one is still its doing once the directory is mounted read-only, or
  not at all (see refuse_withheld_dirs of mounts.py).

Of every project at once: a file or a directory is the same whichever
project's session had it. The latest MOST_REMEMBERED of each are kept, and
none that is gone."""

from __future__ import annotations

import dataclasses
import json
import os
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from ..files import (
    GONE,
    NotRead,
    json_object,
    locked,
    private_dir,
    read_plain,
    write_whole,
)
from ..notice import warn
from ..settings import Host

# Of each kind, as many as are kept, and the bytes of the file that are
# read: a path of 4096 bytes, each written as JSON escapes it, six for one
MOST_REMEMBERED = 1000
REMEMBERED_BYTES = 2 * MOST_REMEMBERED * 6 * 4096


def _paths(value: object) -> tuple[str, ...]:
    """The absolute paths of a field of the record, none of what is no
    such path."""
    if not isinstance(value, list):
        return ()
    return tuple(
        path for path in value if isinstance(path, str) and os.path.isabs(path)
    )


def _not_gone(path: str) -> bool:
    """Whether a file can be there: not when nothing is, but when what
    it is in is closed to the launcher, which a session can make it, for
    the file to be forgotten and readable once it is opened again."""
    try:
        os.lstat(path)
    except OSError as problem:
        return problem.errno not in GONE
    return True


def _latest(
    kept: Sequence[str], added: Iterable[str], there: Callable[[str], bool]
) -> tuple[str, ...]:
    """What was kept and what is added, the added last, each once, none
    that is not there any more, no more than MOST_REMEMBERED of the
    latest."""
    new = list(dict.fromkeys(added))
    again = set(new)
    latest = [path for path in kept if path not in again] + new
    return tuple(path for path in latest if there(path))[-MOST_REMEMBERED:]


@dataclass(frozen=True)
class Remembered:
    """What earlier launches left to go by, see the module."""

    hidden_through_links: tuple[str, ...] = ()
    written: tuple[str, ...] = ()

    @classmethod
    def load(cls, host: Host) -> Remembered:
        """What is kept, nothing when nothing is. Said when it cannot be
        read: what it would have kept hidden or refused is not, then."""
        content = read_plain(host.remembered_file, REMEMBERED_BYTES)
        said = None if isinstance(content, NotRead) else json_object(content)
        if said is None:
            if content is not NotRead.ABSENT:
                warn(
                    f"{host.remembered_file} cannot be read, what earlier"
                    " launches left in it is not gone by, and it is written anew"
                )
            return cls()
        return cls(
            _paths(said.get("hidden_through_links")), _paths(said.get("written"))
        )

    def save(self, host: Host) -> None:
        """Write it whole, in the place of what was kept."""
        private_dir(host.state_dir)
        write_whole(host.remembered_file, json.dumps(dataclasses.asdict(self)))

    def adding(
        self, hidden_through_links: Iterable[str], written: Iterable[str]
    ) -> Remembered:
        """What is kept with this added, see _latest: of what was hidden
        through a link what can still be there (see _not_gone), of the
        directories those that still are."""
        return Remembered(
            _latest(self.hidden_through_links, hidden_through_links, _not_gone),
            _latest(self.written, written, os.path.isdir),
        )


def remember(
    host: Host,
    *,
    hidden_through_links: Iterable[str] = (),
    written: Iterable[str] = (),
) -> None:
    """Add to what is kept: files hidden through a link, directories a
    session can write. Under a lock, other launchers add to it too."""
    private_dir(host.state_dir)
    with locked(host.remembered_file + ".lock"):
        kept = Remembered.load(host)
        kept.adding(hidden_through_links, written).save(host)
