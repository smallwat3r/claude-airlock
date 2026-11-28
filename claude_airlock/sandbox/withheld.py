"""What of the host is never a session's to have, the rules every path of
the host is asked by before it is mounted (see withheld), and the one way
a path of the host is mounted that is no directory a session is given
(see HostMounts)."""

from __future__ import annotations

import enum
import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from ..docker import NO_COLON, mount_arg, refuse_past_most, volume_takes
from ..errors import Fatal
from ..events import flat
from ..notice import warn
from ..paths import (
    is_under,
    is_within,
    leads_under,
    overlap,
    resolved_overlap,
    resolved_within,
)
from ..settings import CONTAINER_CLAUDE, Host
from .hidden import MOST_HIDDEN, NO_SECRETS, SHADOWED_NAMES, Hidden, names_secrets


def _kept_out(host: Host) -> list[str]:
    """The directories of the home that are never a session's to have,
    nor anything in them or around them: the user's keys, and what
    decides how the next session is sandboxed and what it is told, the
    launcher's settings and records and Claude's own directory. What a
    session needs of the last is mounted by the launcher, see home.py."""
    return [
        os.path.join(host.home, ".ssh"),
        os.path.join(host.home, ".gnupg"),
        host.claude_dir,
        host.user_conf,
        host.state_dir,
    ]


def kept_out(path: str, host: Host, but: Sequence[str] = ()) -> str:
    """The directory that is never a session's to have which a file is
    in, see _kept_out, empty when it is in none. By the path as it is
    written and by where it leads: a link to a key is the key. But for
    the directories given, which whoever asks handles itself."""
    for kept in _kept_out(host):
        if kept not in but and leads_under(path, kept):
            return kept
    return ""


def _unsafe_dir(path: str, host: Host, but: Sequence[str] = ()) -> str:
    """Why a directory is never to be mounted, empty when it may be: the
    filesystem root, the home directory or any of its parents, mounting
    one would expose the whole home and defeat the sandbox. And what is
    kept out of every session, see _kept_out, with the directories around
    it, but for the directories given, which whoever asks handles itself.
    By the path as it is written and by where it leads, a link to the
    home directory is the home directory."""
    real = os.path.realpath(path)
    for home, directory in ((host.home, path), (os.path.realpath(host.home), real)):
        if is_within(os.path.normpath(home), os.path.normpath(directory)):
            return "it would defeat the sandbox"
    for kept in _kept_out(host):
        if kept in but:
            continue
        # Mounting the one brings in the other, or a part of it
        if overlap(path, kept) or overlap(real, os.path.realpath(kept)):
            return f"{kept} is not a session's to have, it would defeat the sandbox"
    return ""


def refuse_unsafe_dir(path: str, host: Host) -> None:
    """Refuse a directory that is never to be mounted, see _unsafe_dir."""
    unsafe = _unsafe_dir(path, host)
    if unsafe:
        raise Fatal(f"refusing to mount {path}: {unsafe}")


# No more links are followed on the way to a path than this, as the
# system has it: past it the path leads nowhere, a loop
MOST_LINKS = 40


def links_on_the_way(path: str) -> tuple[list[str], str]:
    """The links an absolute path is resolved through, each where it is,
    with what is above it resolved, and where the path leads: as realpath
    has it, with the links it passed on the way. Past MOST_LINKS links,
    those found so far and where realpath says it leads."""
    links: list[str] = []
    resolved = os.sep
    parts = path.split(os.sep)
    while parts:
        name = parts.pop(0)
        if name in ("", os.curdir):
            continue
        if name == os.pardir:
            resolved = os.path.dirname(resolved)
            continue
        here = os.path.join(resolved, name)
        try:
            target = os.readlink(here)
        except OSError:
            # No link, or nothing there: what is below it is as written
            resolved = here
            continue
        if len(links) >= MOST_LINKS:
            return links, os.path.realpath(path)
        links.append(here)
        if os.path.isabs(target):
            resolved = os.sep
        parts[:0] = target.split(os.sep)
    return links, resolved


def _through_link_in(links: Sequence[str], root: str) -> bool:
    """Whether a path goes through a link in a directory, by the links
    it was resolved through (see links_on_the_way) and where the
    directory leads (root): a session that can write the directory could
    have made the link, or put another in its place."""
    return any(is_under(link, root) for link in links)


@dataclass(frozen=True)
class Written:
    """The directories a session can write, or could at an earlier launch,
    each with where it leads: resolved once for all that a launch asks of
    them, the git config, each file it includes, the statusline, the
    parts of ~/.claude and each directory mounted next to the project."""

    places: tuple[tuple[str, str], ...] = ()

    @classmethod
    def of(cls, directories: Iterable[str]) -> Written:
        """The directories, each once, with where each leads."""
        unique = dict.fromkeys(directories)
        return cls(tuple((each, os.path.realpath(each)) for each in unique))

    def holds(self, path: str) -> bool:
        """Whether a path is in one of them as it is written, or by where
        it leads, as leads_under of paths.py has it with where each of
        them leads resolved once: what is there is a session's to
        write."""
        real = os.path.realpath(path)
        return any(
            is_under(path, directory) or is_under(real, root)
            for directory, root in self.places
        )


# What no session writes, for what is asked with nothing written
NOTHING_WRITTEN = Written()


def link_out(path: str, written: Written) -> str:
    """The directory a session can write, or could at an earlier launch
    (written), that a link on the way to a path is in, when the path
    leads out of all of them, empty when it does not: the session could
    have left that link, to be given what it points to the next time.
    Wherever the path is named from, ~/.gitconfig as a link into a
    repository of dotfiles that has a link of its own to a key. Not by
    the path itself, which is a directory a session writes once it is
    mounted next to the project, and leads where it leads."""
    others = [(each, root) for each, root in written.places if each != path]
    links, real = links_on_the_way(os.path.abspath(path))
    if any(is_within(real, root) for _, root in others):
        return ""
    for directory, root in others:
        if _through_link_in(links, root):
            return directory
    return ""


class Rule(enum.Enum):
    """What withheld keeps a path of the host back by."""

    LINK_OUT = enum.auto()
    COLON = enum.auto()
    UNSAFE = enum.auto()
    SECRETS = enum.auto()
    KEPT_OUT = enum.auto()


@dataclass(frozen=True)
class Refusal:
    """Why withheld keeps a path back: the rule, and what is said of it."""

    rule: Rule
    said: str


def withheld(
    path: str,
    host: Host,
    written: Written,
    shadow: Sequence[str] = (),
    but: Sequence[str] = (),
) -> Refusal | None:
    """Why a file or a directory of the host is not to be mounted into a
    session, none when it may be: the one rule for what the launcher
    mounts of the host besides the project, the directories mounted next
    to it and what goes through HostMounts, the git config and the files
    it includes, the statusline and the parts of ~/.claude. Not one that
    is, or goes through, a link out of a directory a session can write or
    could (written, see link_out), nor one docker cannot take. Nor a
    directory that is never to be mounted, see _unsafe_dir. Nor a file
    whose name says it holds secrets, by its own name and the name of
    what it leads to, see names_secrets, with the globs of shadow, nor
    one in a directory that is never a session's to have, see kept_out.
    Of those two, but for the directories given, which whoever asks
    handles itself. Each rule asked once, the first that refuses says
    why."""
    out = link_out(path, written)
    if out:
        said = f"it is, or goes through, a link out of {out}, which a session"
        return Refusal(Rule.LINK_OUT, said + " could have made")
    if not volume_takes(path):
        return Refusal(Rule.COLON, NO_COLON)
    if os.path.isdir(path):
        unsafe = _unsafe_dir(path, host, but)
        return Refusal(Rule.UNSAFE, unsafe) if unsafe else None
    patterns = (*SHADOWED_NAMES, *shadow)
    names = {os.path.basename(path), os.path.basename(os.path.realpath(path))}
    if any(names_secrets(name, patterns) for name in names):
        return Refusal(Rule.SECRETS, "its name is one of secrets")
    kept = kept_out(path, host, but)
    return (
        Refusal(Rule.KEPT_OUT, f"{kept} is not a session's to have") if kept else None
    )


@dataclass
class HostMounts:
    """The one way a path of the host is mounted into a session, but for
    the directories it is given (roots): the git config and the files it
    includes, the statusline, and the parts of ~/.claude. Each is asked
    of withheld right before it is mounted, by what a session can write
    or could (written) and the globs of secrets (shadow), and kept with
    those mounted before it, with its source in sources for Placed of
    placed.py to look at again right before docker run: one that leads
    into a directory a session can write is the session's to swap for a
    link meanwhile.

    One that leads into a directory a session is given is that
    directory again, under another name. So what is read-only there
    (read_only, the paths protected and the directories mounted
    read-only) is read-only through it too, and what is hidden there
    (hidden) is hidden through it too, see mount.

    What is mounted of the launcher's own (the base, the history it keeps
    of a project, an empty directory) is no session's to point anywhere,
    and does not go through here."""

    host: Host
    written: Written = NOTHING_WRITTEN
    shadow: tuple[str, ...] = ()
    roots: tuple[str, ...] = ()
    read_only: tuple[str, ...] = ()
    hidden: Hidden = NO_SECRETS
    args: list[str] = field(default_factory=list)
    mounted: list[tuple[str, str]] = field(default_factory=list)
    # How many mounts hide what is hidden under another name, see
    # _hidden_below
    _hiding: int = field(default=0, init=False, repr=False)

    @property
    def sources(self) -> list[str]:
        """The paths of the host mounted through here."""
        return [path for path, _ in self.mounted]

    def refused(self, path: str, but: Sequence[str] = ()) -> Refusal | None:
        """Why a path of the host would not be mounted, see withheld,
        without mounting it. Nor one that leads to what is hidden in a
        directory a session is given, a file of secrets hidden there or
        a directory covered there: under another name it would not be."""
        refused = withheld(path, self.host, self.written, self.shadow, but)
        if refused is not None:
            return refused
        hidden = self._hidden_at(path)
        if hidden:
            said = f"it leads to {hidden}, which is hidden from a session"
            return Refusal(Rule.SECRETS, said)
        return None

    def mount(
        self, path: str, target: str, options: str, but: Sequence[str] = ()
    ) -> Refusal | None:
        """Mount a path of the host at target, unless withheld keeps it
        back, asked here whatever was asked before: why it does, none
        when it is mounted. Read-only where it leads to what is read-only
        in the session, read-only wins as it does for a directory asked
        for both ways, and said. With what is hidden in it, see
        _hidden_below."""
        refused = self.refused(path, but)
        if refused is not None:
            return refused
        if "ro" not in options.split(","):
            options = self._read_only_wins(path, options)
        self.args.append(mount_arg(path, target, options))
        self.args += self._hidden_below(path, target)
        self.mounted.append((path, target))
        return None

    def must_mount(
        self, path: str, target: str, options: str, but: Sequence[str] = ()
    ) -> None:
        """Mount a path of the host a session cannot go without, see
        mount. Fatal when withheld keeps it back: what the session
        writes there would go nowhere the host has it, and no stand-in
        would be what it is asked for."""
        refused = self.mount(path, target, options, but)
        if refused is not None:
            raise Fatal(f"refusing to mount {flat(path)}: {refused.said}")

    def claude_part(
        self, name: str, options: str, *, needed: bool = False
    ) -> Refusal | None:
        """Mount a part of the host's ~/.claude, by its name there, over
        its place in the session's. One that is a link is the user's,
        ~/.claude is no session's to write, and may lead anywhere a
        session may be given, elsewhere in ~/.claude too. Not through a
        link a session could have made, out of a directory it can write
        or could, nor to what no session is to have, the user's keys or
        the home: see withheld, which asks the rest as of any path of the
        host. What a session cannot go without (needed) ends the launch
        when it is kept back, see must_mount. Why another is, none when
        it is mounted."""
        path = os.path.join(self.host.claude_dir, name)
        target = f"{CONTAINER_CLAUDE}/{name}"
        but = (self.host.claude_dir,)
        if needed:
            self.must_mount(path, target, options, but)
            return None
        return self.mount(path, target, options, but)

    def _read_only_wins(self, path: str, options: str) -> str:
        """The options of a mount that would be writable, read-only when
        the path is, holds or is in what is read-only in the session, as
        written or by where they lead: writable, it would be written to
        there. Said when it is made so."""
        for kept in self.read_only:
            if overlap(path, kept) or resolved_overlap(path, kept):
                holds = is_within(kept, path) or is_within(
                    os.path.realpath(kept), os.path.realpath(path)
                )
                how = "it holds" if holds else "it leads into"
                warn(
                    f"{path} is mounted read-only: {how} {kept}, which is"
                    " read-only in this session"
                )
                return "ro," + options
        return options

    def _in_roots(self, path: str) -> list[str]:
        """Where a path of the host leads in each directory a session is
        given that it leads into, as the path is there."""
        found = (resolved_within(path, root) for root in self.roots)
        return list(dict.fromkeys(inside for inside in found if inside))

    def _hidden_at(self, path: str) -> str:
        """What is hidden in a directory a session is given that a path
        of the host leads to, or into: a file of secrets, a directory
        covered. Empty when it leads to nothing of that."""
        for inside in self._in_roots(path):
            if inside in self.hidden.files:
                return inside
            for directory in self.hidden.covered:
                if is_within(inside, directory):
                    return directory
        return ""

    def _hidden_below(self, path: str, target: str) -> list[str]:
        """The mounts that hide, under target, what is hidden in a
        directory a session is given that a path of the host leads into:
        the files of secrets and the directories covered below where it
        leads, each where it is under target. The directories above each
        are held in place in the directory it is in, see _held_in_place
        of mounts.py, or are read-only there and here alike. Fatal past
        MOST_HIDDEN of them with those hidden already, see
        refuse_past_most: each is a mount."""
        files: dict[str, None] = {}
        covered: dict[str, None] = {}
        for inside in self._in_roots(path):
            files.update(dict.fromkeys(_moved_under(self.hidden.files, inside, target)))
            covered.update(
                dict.fromkeys(_moved_under(self.hidden.covered, inside, target))
            )
        if not files and not covered:
            return []
        self._hiding += len(files) + len(covered)
        refuse_past_most(
            len(self.hidden.files) + len(self.hidden.covered) + self._hiding,
            MOST_HIDDEN,
            "files of secrets to hide and directories covered, with those under"
            f" {flat(path)}",
        )
        return Hidden(list(files), list(covered)).args(self.host)


def _moved_under(paths: Iterable[str], inside: str, target: str) -> list[str]:
    """Of some paths, those under a directory (inside), each where it is
    under target instead."""
    return [
        os.path.join(target, os.path.relpath(path, inside))
        for path in paths
        if is_under(path, inside)
    ]
