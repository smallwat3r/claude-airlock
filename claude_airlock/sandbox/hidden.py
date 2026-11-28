"""The files of secrets in what a session is given, hidden from it: each
read as empty, and a directory that could not be looked into for them
covered whole. Which names say secrets, see names_secrets, is a rule of
withheld.py too, for what of the host is mounted on its own."""

from __future__ import annotations

import errno
import fnmatch
import os
import stat
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field

from ..docker import covered_arg, hidden_arg, refuse_past_most
from ..errors import Fatal
from ..events import flat
from ..files import CLOSED, GONE, private_dir
from ..notice import warn
from ..paths import is_within, resolved_within
from ..settings import Host, Settings

SHADOWED_NAMES = (".env", ".env.*", ".envrc", ".netrc", ".pypirc")

SHADOW_EXEMPT = (".env.example", ".env.sample", ".env.template")

SHADOW_PRUNED_DIRS = ("node_modules", ".git")
# No more files are hidden than this, with the directories covered,
# see refuse_past_most: a session can make any number of files of
# secrets
MOST_HIDDEN = 1000
# The errors of where a link named as a file of secrets leads, when it
# leads nowhere: to what is gone (GONE of files.py, nothing is there to
# hide) or closed to the launcher (CLOSED, see openable), or round in a
# loop
LEADS_NOWHERE = GONE | CLOSED | {errno.ELOOP}


@dataclass(frozen=True)
class Hidden:
    """What a session is kept from of what it has mounted: the files of
    secrets, which read as empty, and the directories that could not be
    looked into for any, which hold nothing for it. With the files of
    secrets found through a link that leads to them, see _led_to, which a
    session can remove: hidden_files is told them again at the next
    launch, see remembered.py. Those in a directory that is covered too,
    which is no longer once it is opened again."""

    files: list[str] = field(default_factory=list)
    covered: list[str] = field(default_factory=list)
    linked: list[str] = field(default_factory=list)

    def hides(self, path: str) -> bool:
        """Whether a path is hidden, or in a directory that is covered:
        nothing else can be mounted there, docker takes one mount at a
        place, and none in what is covered, which is read-only."""
        return path in self.files or _in_covered(path, self.covered)

    def args(self, host: Host) -> list[str]:
        """The mounts that hide them."""
        hidden = [hidden_arg(path) for path in self.files]
        if not self.covered:
            return hidden
        empty = empty_dir(host)
        return hidden + [covered_arg(empty, path) for path in self.covered]


# What hides nothing, for what is asked with nothing hidden
NO_SECRETS = Hidden()


def _in_covered(path: str, covered: Sequence[str]) -> bool:
    """Whether a path is one of the directories covered, or in one."""
    return any(is_within(path, directory) for directory in covered)


def empty_dir(host: Host) -> str:
    """A directory of the launcher's with nothing in it, to mount
    read-only over one that a session is not to see into."""
    return private_dir(os.path.join(host.history_dir, "empty"))


def openable(directory: str) -> bool:
    """Whether a directory the launcher cannot look into is one a session
    could: the user's own, whose mode a session can change as the user
    can. Not another user's, which stays closed to both."""
    try:
        about = os.lstat(directory)
    except OSError:
        return False
    return stat.S_ISDIR(about.st_mode) and about.st_uid == os.getuid()


def names_secrets(name: str, patterns: Sequence[str]) -> bool:
    """Whether a file of that name is taken to hold secrets, by the name
    globs that are hidden. Not a template (see SHADOW_EXEMPT)."""
    if name in SHADOW_EXEMPT:
        return False
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def _led_to(link: str, roots: Sequence[str]) -> list[str]:
    """Where a link that is named as a file of secrets leads, as a
    session has it: the secrets are in the file it points to, which is
    readable under a name of its own that says nothing, and is hidden in
    its place. By each mounted directory it is in. None for what is no
    plain file, and for what is in no mounted directory, which a session
    does not have. Fatal for what cannot be told to be either, see
    _not_looked_into."""
    real = os.path.realpath(link)
    found = [each for root in roots if (each := resolved_within(real, root))]
    if not found:
        return []
    try:
        plain = stat.S_ISREG(os.lstat(real).st_mode)
    except OSError as problem:
        if problem.errno in LEADS_NOWHERE:
            return []
        raise _not_looked_into(problem) from None
    return found if plain else []


def _not_looked_into(problem: OSError) -> Fatal:
    """What is said of a path that cannot be looked at for files of
    secrets, for another reason than that it is gone or closed: a path
    deeper than the system takes, for one, which a session can make, and
    which docker could not mount anything at either. Neither hidden nor
    covered, it would be the session's to read."""
    return Fatal(
        f"cannot tell what to hide in {flat(problem.filename)}"
        f" ({problem.strerror}), a session may have made it so: move or remove"
        " it for a session to start"
    )


def _secrets_in(
    root: str, roots: Sequence[str], patterns: Sequence[str], closed: dict[str, None]
) -> Iterator[tuple[str, bool]]:
    """The files of secrets in a mounted directory, as hidden_files has
    them, one at a time, and those links named as one lead to in any of
    the roots, each with whether it was found through a link. What
    cannot be looked into is added to closed. Fatal for a directory that
    cannot be listed for another reason than that it is closed or gone,
    see _not_looked_into."""

    def not_listed(problem: OSError) -> None:
        if problem.errno in GONE:
            return
        if problem.errno not in CLOSED or not isinstance(problem.filename, str):
            raise _not_looked_into(problem)
        closed[problem.filename] = None

    for directory, subdirs, files in os.walk(root, onerror=not_listed):
        if not os.access(directory, os.X_OK):
            # Listed, and not to be entered: neither what its files are
            # nor what is below it can be told
            closed[directory] = None
            subdirs[:] = []
            continue
        subdirs[:] = sorted(d for d in subdirs if d not in SHADOW_PRUNED_DIRS)
        for name in sorted(files):
            if not names_secrets(name, patterns):
                continue
            path = os.path.join(directory, name)
            try:
                found, through_a_link = _to_hide(path, roots)
            except OSError as problem:
                if problem.errno not in CLOSED:
                    raise _not_looked_into(problem) from None
                # Closed since it was listed, as above
                closed[directory] = None
                subdirs[:] = []
                break
            yield from ((each, through_a_link) for each in found)


def _to_hide(path: str, roots: Sequence[str]) -> tuple[list[str], bool]:
    """What hiding the secrets at a path takes, and whether they are
    reached through a link: the file itself, or what a link there leads
    to, see _led_to. Nothing for what is neither, or gone since it was
    listed, by a build or another session. OSError for what cannot be
    told, whoever asks says what that makes of it."""
    try:
        mode = os.lstat(path).st_mode
    except OSError as problem:
        if problem.errno in GONE:
            return [], False
        raise
    if stat.S_ISREG(mode):
        return [path], False
    if stat.S_ISLNK(mode):
        return _led_to(path, roots), True
    return [], False


def _hidden_again(path: str, roots: Sequence[str]) -> list[str]:
    """Where a file that was hidden through a link at an earlier launch
    is in the roots, as long as it is there, see _to_hide: it can be in
    none of them at this launch. One in a directory closed to the
    launcher is hidden where it was, it cannot be told to be gone. Fatal
    for one in reach that cannot be looked at otherwise, see
    _not_looked_into."""
    if not any(resolved_within(path, root) for root in roots):
        return []
    try:
        found, _ = _to_hide(path, roots)
    except OSError as problem:
        if problem.errno not in CLOSED:
            raise _not_looked_into(problem) from None
        found = [path]
    return [
        inside
        for each in found
        for root in roots
        if (inside := resolved_within(each, root))
    ]


def _refuse_past_most_hidden(
    hidden: dict[str, None], closed: dict[str, None], root: str = ""
) -> None:
    """Fatal for more files to hide, with the directories that cannot be
    looked into, than MOST_HIDDEN, the last found named, and the mounted
    directory they were found in, when they were found in one."""
    if not hidden and not closed:
        return
    last = next(reversed(closed or hidden))
    where = f" in {flat(root)}," if root else ""
    refuse_past_most(
        len(hidden) + len(closed),
        MOST_HIDDEN,
        "files of secrets to hide and directories that cannot be looked into,"
        f"{where} {flat(last)} among them",
    )


def hidden_files(
    settings: Settings,
    roots: Sequence[str],
    linked_before: Sequence[str] = (),
) -> Hidden:
    """What to shadow in the directories a session is given (roots, see
    mounted_dirs of mounts.py): .env files (and direnv's .envrc, which
    commonly exports secrets, plus .netrc and .pypirc, which hold nothing
    but credentials), so they are never visible inside the container. Template
    files (.env.example and friends) stay readable, they exist to be read
    and hold no secrets. Regular files only: a .env directory (some
    virtualenvs) cannot take a /dev/null bind mount and would abort the
    run. Of a link under such a name, the file it leads to, see _led_to,
    and of those hidden through a link at an earlier launch (linked_before)
    those that are still there: a session can remove the link, the file
    is no less one of secrets for it.
    CLAUDE_AIRLOCK_SHADOW adds name globs, e.g. "*.pem:.npmrc". The
    whole tree is walked on purpose, pruning more directories would be
    faster but could leave a real secret visible.

    A directory that cannot be looked into is not passed over: a session
    can take the right to list one away, for the file in it to go
    unhidden at the next launch, and give it back then. One a session
    could open is hidden whole instead, and said. One that cannot be
    looked into for another reason ends the launch, a path deeper than
    the system takes for one, see _not_looked_into.

    Fatal past MOST_HIDDEN of them, files and directories together: they
    could not all be hidden, and a session started with them in reach
    would read them."""
    patterns = SHADOWED_NAMES + settings.shadow
    # By path, in the order found: a directory mounted next to the project
    # can be inside it, and docker refuses to mount twice at one place
    hidden: dict[str, None] = {}
    linked: dict[str, None] = {}
    closed: dict[str, None] = {}
    for root in roots:
        for path, through_a_link in _secrets_in(root, roots, patterns, closed):
            hidden[path] = None
            if through_a_link:
                linked[path] = None
            _refuse_past_most_hidden(hidden, closed, root)
        _refuse_past_most_hidden(hidden, closed, root)
    for before in linked_before:
        again = dict.fromkeys(_hidden_again(before, roots))
        hidden.update(again)
        linked.update(again)
    # Those hidden again are each a mount too, with all found before them
    _refuse_past_most_hidden(hidden, closed)
    covered = [directory for directory in closed if openable(directory)]
    if covered:
        warn(
            "these directories cannot be looked into for files of secrets to"
            " hide, which a session can have made so: they hold nothing for"
            " this session",
            *(f"  {directory}" for directory in covered),
            "Make them yours to read again (chmod u+rx) for a session to see"
            " into them.",
        )
    # Nothing is mounted in what is covered, see Hidden.hides
    files = [path for path in hidden if not _in_covered(path, covered)]
    return Hidden(files, covered, list(linked))
