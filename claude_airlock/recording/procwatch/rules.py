"""Which files are taken to hold secrets, by the rules the launcher gives
the watcher (see secrets.py), and the files of them noted of each process,
once each. gVisor tells what is opened by the same rules, see gvisor.py,
and a trace holds the paths of Claude Code's own file tools against them."""

from __future__ import annotations

import enum
import fnmatch
import json
import os
from collections.abc import Hashable, Mapping, Sequence

# The files of secrets seen open that are noted, one for each process and
# file: a session can open them in as many processes as it likes, and
# must not fill the part of the record kept for its connections that way
MOST_OPENED = 1000
# What the kernel puts after the path of a file that was removed while
# it was open
DELETED = " (deleted)"


def _kinds(said: object) -> dict[str, str]:
    """Paths or names, each with a kind of secrets, as the launcher
    wrote them: none of what is not."""
    if not isinstance(said, dict):
        return {}
    return {
        str(key): str(kind)
        for key, kind in said.items()
        if isinstance(key, str) and isinstance(kind, str)
    }


def _names(said: object) -> tuple[str, ...]:
    if not isinstance(said, list):
        return ()
    return tuple(name for name in said if isinstance(name, str))


def _under(directories: Sequence[str]) -> tuple[str, ...]:
    """Directories, each as a path in it starts: with a / at its end,
    one alone for the root."""
    return tuple(os.path.join(normal(directory), "") for directory in directories)


def normal(path: str) -> str:
    """A path as the rules hold it, the way Linux takes it: its . and ..
    worked out, and the slashes it starts with as one. normpath keeps
    two of those, as POSIX lets a system read // as it likes, and Linux
    reads them as one: a session that names //home/me/.ssh/id_ed25519
    opens the key all the same."""
    found = os.path.normpath(path)
    return "/" + found.lstrip("/") if found.startswith("/") else found


class Secrets:
    """Which files are taken to hold secrets, by the path a process holds
    one under, each with the kind of secrets it holds: a file by its
    path, a file in a directory but for the names passed over there (a
    public key, the hosts ssh knows), and a file of a name in one of the
    roots, but for the templates of those names. The roots are where
    files of those names are hidden from a session (the project and the
    directories mounted next to it, see hidden_files of hidden.py): one
    made elsewhere, in /tmp say, is no secret kept from it. The launcher
    says which they are (see secrets.py), the watcher is given them as
    JSON."""

    def __init__(
        self,
        files: Mapping[str, str] | None = None,
        dirs: Mapping[str, str] | None = None,
        passed: Sequence[str] = (),
        names: Mapping[str, str] | None = None,
        exempt: Sequence[str] = (),
        roots: Sequence[str] = (),
    ) -> None:
        self._files = {normal(path): kind for path, kind in (files or {}).items()}
        self._dirs = {
            normal(directory) + "/": kind for directory, kind in (dirs or {}).items()
        }
        self._passed = tuple(passed)
        self._names = dict(names or {})
        self._exempt = frozenset(exempt)
        self._roots = _under(roots)

    @classmethod
    def read(cls, said: str) -> Secrets:
        """The rules as as_json wrote them. Raises ValueError for what is
        not JSON, and passes over what is not one of them."""
        rules = json.loads(said)
        if not isinstance(rules, dict):
            rules = {}
        return cls(
            _kinds(rules.get("files")),
            _kinds(rules.get("dirs")),
            _names(rules.get("passed")),
            _kinds(rules.get("names")),
            _names(rules.get("exempt")),
            _names(rules.get("roots")),
        )

    def as_json(self) -> str:
        """The rules, for the watcher to be given on its command line."""
        return json.dumps(
            {
                "files": self._files,
                "dirs": {
                    directory.rstrip("/"): kind
                    for directory, kind in self._dirs.items()
                },
                "passed": list(self._passed),
                "names": self._names,
                "exempt": sorted(self._exempt),
                "roots": [normal(root) for root in self._roots],
            },
            separators=(",", ":"),
        )

    def places(self) -> tuple[Mapping[str, str], Mapping[str, str]]:
        """The files of secrets by their paths, and the directories every
        file below which is one but for the names passed over, each with
        its kind: those of the rules that are not names."""
        dirs = {directory.rstrip("/"): kind for directory, kind in self._dirs.items()}
        return self._files, dirs

    def markers(self) -> tuple[bytes, ...] | None:
        """Bytes of which a path taken to hold secrets has one at least,
        for what tells of paths to be passed over unread when it has none
        of them (see gvisor.py): the name of each file and directory, and
        the longest run of letters of each pattern. None when a pattern
        has no run that has to be there, or a class of letters ([ab]),
        whose letters need not be."""
        found = [os.path.basename(path) for path in self._files]
        found += [os.path.basename(directory.rstrip("/")) for directory in self._dirs]
        for pattern in self._names:
            if "[" in pattern:
                return None
            longest = max(pattern.replace("?", "*").split("*"), key=len)
            if not longest:
                return None
            found.append(longest)
        return tuple(dict.fromkeys(marker.encode() for marker in found if marker))

    def of(self, path: str) -> str | None:
        """The kind of secrets a file holds, none for one that is not
        taken to hold any. Of an absolute path only: what a descriptor
        links to otherwise (a socket, a pipe) is no file. The names are
        the session's to choose, each pattern is the launcher's, and a
        pattern of fnmatch takes no more than a pass over a name."""
        if not path.startswith("/"):
            return None
        path = normal(path.removesuffix(DELETED))
        kind = self._files.get(path)
        if kind:
            return kind
        name = os.path.basename(path)
        for directory, kind in self._dirs.items():
            if path.startswith(directory):
                passed = any(fnmatch.fnmatchcase(name, one) for one in self._passed)
                return None if passed else kind
        if name in self._exempt or not path.startswith(self._roots):
            return None
        for pattern, kind in self._names.items():
            if fnmatch.fnmatchcase(name, pattern):
                return kind
        return None


class Telling(enum.Enum):
    """What to do of a file of secrets a process was seen to open, see
    OpenedOnce."""

    # Note it
    NEW = enum.auto()
    # Nothing: it was noted already, or there were too many
    KNOWN = enum.auto()
    # Note that there were more than are noted, this once
    TOO_MANY = enum.auto()


class OpenedOnce:
    """The files of secrets noted of each process, for one to be noted
    once for each process and file, and no more than MOST_OPENED in all:
    a session can open them in as many processes as it likes. A process
    is known by what the caller gives, its id and when it started say."""

    def __init__(self) -> None:
        self._noted: dict[Hashable, set[str]] = {}
        self._count = 0
        self.too_many = False

    def take(self, process: Hashable, path: str) -> Telling:
        if self.too_many or path in self._noted.get(process, ()):
            return Telling.KNOWN
        if self._count >= MOST_OPENED:
            self.too_many = True
            return Telling.TOO_MANY
        self._count += 1
        self._noted.setdefault(process, set()).add(path)
        return Telling.NEW

    def forget(self, process: Hashable) -> None:
        """A process that is another now: its files are noted again, and
        counted again."""
        self._noted.pop(process, None)
