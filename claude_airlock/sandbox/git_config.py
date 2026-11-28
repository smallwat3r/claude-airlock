"""Reading a git config as git does: what git lists of it, given a plain
file alone and not waited on for long, and the files it has git read
with it. For the check of what a session left (fingerprint.py) and for
the git config a session is given (session.py)."""

from __future__ import annotations

import os
import re
import subprocess
import threading
from collections.abc import Callable, Iterator, Sequence

from ..files import expand_home, open_plain
from ..settings import Host
from .bounded import Look

# The seconds git is given to read a config, it takes a moment: a file a
# session swapped for a pipe must not have the check wait on it
GIT_SECONDS = 10.0
# No larger config is given to git, and no more of what git says of one
# is read: both are a session's to make large, and a config of a few
# kilobytes can be written to list as gigabytes
GIT_CONFIG_BYTES = 1024 * 1024
GIT_SAID_BYTES = 4 * 1024 * 1024
# Nor is what git said of a config kept for the next time it is asked
# about when it is larger than this, see git_listing: a session can have
# each of the configs git is run for list as GIT_SAID_BYTES
KEPT_SAID_BYTES = 64 * 1024
# The entries of a config that have git read another file with it, at all
# times or on a condition, as git lists them
_INCLUDES = re.compile(rb"include(if\..*)?\.path", re.DOTALL)
# No more configs are followed from one config than this, a session can
# have each include the next
MOST_INCLUDED = 100


# What has git read a repository or a config besides the file it is
# asked about, which the launcher may have been started with
GIT_READ_ELSEWHERE = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
)


def _git_environment() -> dict[str, str]:
    """What git is run with for a config: nothing of a repository, nor
    the user's own config and the system's. Git reads those as it starts
    whatever it is asked, and the files they include, and the user's own
    can be a link into a directory a session was given: a pipe it named
    there would hold every look for GIT_SECONDS, and a file that is no
    config would have git list none. From the root, for the same reason:
    from the project, git would take the repository there for its own,
    and read the config a session can leave in its place."""
    environment = {
        name: value
        for name, value in os.environ.items()
        if name not in GIT_READ_ELSEWHERE
        and not name.startswith("GIT_CONFIG_KEY_")
        and not name.startswith("GIT_CONFIG_VALUE_")
    }
    unread = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    return {**environment, **unread}


def _git_says(*args: str) -> bytes | None:
    """What git says when it is asked about a config, none when that
    cannot be had: no git, a config it cannot read, one it was not done
    with within GIT_SECONDS, and one it says more of than GIT_SAID_BYTES.
    No more than that is read, and git is ended there: a config is the
    session's to write, and one of a few kilobytes can be made to list
    as gigabytes, which would all be held here."""
    try:
        git = subprocess.Popen(
            ["git", *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd="/",
            env=_git_environment(),
        )
    except OSError:
        return None
    # Ended when its time is up, which the read below then sees as the end
    late = threading.Timer(GIT_SECONDS, git.kill)
    late.start()
    try:
        with git:
            said = git.stdout.read(GIT_SAID_BYTES + 1) if git.stdout else b""
            if len(said) > GIT_SAID_BYTES:
                git.kill()
    finally:
        late.cancel()
    if git.returncode != 0 or len(said) > GIT_SAID_BYTES:
        return None
    return said


def git_listing(file: str, look: Look | None = None) -> bytes | None:
    """The entries of a git config as git lists them with -z, none for
    one that git is not asked about or has no answer for (see _git_says).
    Git is not given what is no plain file, a pipe a session of this
    project that still runs can put there, nor a file past
    GIT_CONFIG_BYTES, which no config a user keeps comes near. Nor any
    once the look has no runs of git left, which it then says, see
    Look.into. What git said is kept in the look, no more of it than
    KEPT_SAID_BYTES: a config is asked about for its hash and for its
    hooksPath, and in every working tree that reads it."""
    look = look or Look()
    if file in look.said:
        return look.said[file]
    said = _listing(file, look)
    if said is None or len(said) <= KEPT_SAID_BYTES:
        look.said[file] = said
    return said


def _listing(file: str, look: Look) -> bytes | None:
    """What git lists of a config, see git_listing."""
    probe = open_plain(file, links=True)
    if probe is None:
        return None
    with probe:
        try:
            large = os.fstat(probe.fileno()).st_size > GIT_CONFIG_BYTES
        except OSError:
            return None
    if large or not look.run():
        return None
    return _git_says("config", "--file", file, "--list", "-z")


def _included_configs(listing: bytes, config: str, home: str = "") -> list[str]:
    """The files a git config has git read with it, by its listing:
    those of include.path, and of includeIf whatever its condition, which
    holds in one place and not in another. A relative one is taken from
    where the config is, as git takes it, and ~ is the home given, else
    the one of this process."""
    home = home or os.path.expanduser("~")
    found = []
    for entry in listing.split(b"\0"):
        name, _, value = entry.partition(b"\n")
        if value and _INCLUDES.fullmatch(name):
            path = expand_home(os.fsdecode(value), home)
            found.append(os.path.normpath(os.path.join(os.path.dirname(config), path)))
    return found


def included_configs(
    configs: Sequence[str],
    home: str,
    taken: Callable[[str, str], bool] = lambda _path, _by: True,
) -> list[str]:
    """The files that some git configs have git read with them, and
    those that these do, each once and as git takes it (see
    _included_configs): those that are there, no more than MOST_INCLUDED.
    Not one that taken says no to, asked with the config that names it,
    nor what that one includes."""
    seen = set(configs)
    pending = list(reversed(configs))
    found: list[str] = []
    look = Look()
    while pending and len(found) < MOST_INCLUDED:
        config = pending.pop()
        listing = git_listing(config, look)
        if listing is None:
            continue
        for path in _included_configs(listing, config, home):
            if path in seen or not os.path.isfile(path):
                continue
            seen.add(path)
            if taken(path, config):
                found.append(path)
                pending.append(path)
    return found[:MOST_INCLUDED]


class ConfigRead:
    """A git config and the files it includes, and those include, as git
    reads them, whatever their condition: each once, in the order git
    reads them, with its listing (see git_listing), none for one git has
    no listing of. Each file by its own listing, which git is given a
    plain file for alone: asked with --includes, git would open what is
    included itself, a pipe a session left there too, and wait on it. No
    more of them than MOST_INCLUDED, more says whether there were more
    once they are gone through: a session can have each include the
    next. What git says of each is had from the look, see git_listing."""

    def __init__(self, config: str, look: Look, home: str = "") -> None:
        self._config = config
        self._home = home
        self._look = look
        # How many are gone through at most, and whether there were more
        self.most = MOST_INCLUDED
        self.more = False

    def __iter__(self) -> Iterator[tuple[str, bytes | None]]:
        pending = [self._config]
        seen: set[str] = set()
        while pending:
            file = pending.pop()
            if file in seen:
                continue
            if len(seen) >= self.most:
                self.more = True
                return
            seen.add(file)
            listing = git_listing(file, self._look)
            yield file, listing
            if listing is not None:
                included = _included_configs(listing, file, self._home)
                pending += [
                    path for path in reversed(included) if os.path.lexists(path)
                ]


def home_git_configs(host: Host) -> list[str]:
    """The user's own git configs, which git reads wherever it is run:
    ~/.gitconfig and the one of ~/.config/git."""
    return [
        os.path.join(host.home, ".gitconfig"),
        os.path.join(host.config_home, "git", "config"),
    ]
