"""What a session is given of the host besides its project: the
directories mounted next to it, what of them it cannot change, and the
files of secrets hidden from it."""

from __future__ import annotations

import enum
import errno
import fnmatch
import os
import stat
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import NamedTuple

from ..docker import (
    NO_COLON,
    covered_arg,
    env_arg,
    held_arg,
    hidden_arg,
    mount_arg,
    volume_takes,
)
from ..errors import Fatal
from ..events import flat
from ..files import (
    CLOSED,
    GONE,
    expand_home,
    file_id,
    is_under,
    is_within,
    leads_under,
    overlap,
    private_dir,
)
from ..notice import warn
from ..settings import SESSION_DIRS, Host, Settings, variable

SHADOWED_NAMES = (".env", ".env.*", ".envrc", ".netrc", ".pypirc")
SHADOW_EXEMPT = (".env.example", ".env.sample", ".env.template")
SHADOW_PRUNED_DIRS = ("node_modules", ".git")
# No more files are hidden than this, nor directories held in place, see
# refuse_past_most: a session can make any number of files of secrets, or
# one as deep as a path goes
MOST_HIDDEN = 1000
MOST_HELD = 2000
# The errors of where a link named as a file of secrets leads, when it
# leads nowhere: to what is gone (GONE of files.py, nothing is there to
# hide) or closed to the launcher (CLOSED, see openable), or round in a
# loop
LEADS_NOWHERE = GONE | CLOSED | {errno.ELOOP}


def refuse_past_most(count: int, most: int, what: str) -> None:
    """Fatal for more of a kind of mount than most: each is an argument
    of docker run, which the system takes only so many of, and what each
    is for is a session's to make any number of. Said with what they are
    for, and where: whoever asks gives the paths in what flat, a session
    names them, and a line break in a name would start a line of its own
    (see flat)."""
    if count > most:
        raise Fatal(
            f"more than {most} {what}: more than can each be mounted, a"
            " session may have made them"
        )


@dataclass(frozen=True)
class ExtraDir:
    """A host directory mounted alongside the project, at its host path."""

    path: str
    read_only: bool = False


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


def _unsafe_dir(path: str, host: Host) -> str:
    """Why a directory is never to be mounted, empty when it may be: the
    filesystem root, the home directory or any of its parents, mounting
    one would expose the whole home and defeat the sandbox. And what is
    kept out of every session, see _kept_out, with the directories around
    it. By the path as it is written and by where it leads, a link to the
    home directory is the home directory."""
    real = os.path.realpath(path)
    for home, directory in ((host.home, path), (os.path.realpath(host.home), real)):
        if is_within(os.path.normpath(home), os.path.normpath(directory)):
            return "it would defeat the sandbox"
    for kept in _kept_out(host):
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


def _links_on_the_way(path: str) -> tuple[list[str], str]:
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
    it was resolved through (see _links_on_the_way) and where the
    directory leads (root): a session that can write the directory could
    have made the link, or put another in its place."""
    return any(is_under(link, root) for link in links)


@dataclass(frozen=True)
class Written:
    """The directories a session can write, or could at an earlier launch,
    each with where it leads: resolved once for all that a launch asks of
    them, the git config, each file it includes, the statusline and each
    directory mounted next to the project."""

    places: tuple[tuple[str, str], ...] = ()

    @classmethod
    def of(cls, directories: Iterable[str]) -> Written:
        """The directories, each once, with where each leads."""
        unique = dict.fromkeys(directories)
        return cls(tuple((each, os.path.realpath(each)) for each in unique))

    def holds(self, path: str) -> bool:
        """Whether a path is in one of them as it is written, or by where
        it leads: what is there is a session's to write."""
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
    links, real = _links_on_the_way(os.path.abspath(path))
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
    mounts of the host besides the project, the git config and the files
    it includes, the statusline and the directories mounted next to the
    project. Not one that is, or goes through, a link out of a directory
    a session can write or could (written, see link_out), nor one docker
    cannot take. Nor a directory that is never to be mounted, see
    _unsafe_dir. Nor a file whose name says it holds secrets, by its own
    name and the name of what it leads to, see names_secrets, with the
    globs of shadow, nor one in a directory that is never a session's to
    have, see kept_out, but for the directories given, which whoever asks
    handles itself. Each rule asked once, the first that refuses says
    why."""
    out = link_out(path, written)
    if out:
        said = f"it is, or goes through, a link out of {out}, which a session"
        return Refusal(Rule.LINK_OUT, said + " could have made")
    if not volume_takes(path):
        return Refusal(Rule.COLON, NO_COLON)
    if os.path.isdir(path):
        unsafe = _unsafe_dir(path, host)
        return Refusal(Rule.UNSAFE, unsafe) if unsafe else None
    patterns = (*SHADOWED_NAMES, *shadow)
    names = {os.path.basename(path), os.path.basename(os.path.realpath(path))}
    if any(names_secrets(name, patterns) for name in names):
        return Refusal(Rule.SECRETS, "its name is one of secrets")
    kept = kept_out(path, host, but)
    return (
        Refusal(Rule.KEPT_OUT, f"{kept} is not a session's to have") if kept else None
    )


def mounted_dirs(dirs: list[ExtraDir], host: Host) -> list[str]:
    """The directories a session is given: the project, and those mounted
    next to it."""
    return [host.project_dir, *(each.path for each in dirs)]


def writable_dirs(dirs: list[ExtraDir], host: Host) -> list[str]:
    """The directories a session is given to write: the project, and those
    mounted next to it that are not read-only."""
    return [host.project_dir, *(each.path for each in dirs if not each.read_only)]


def refuse_withheld_dirs(
    dirs: list[ExtraDir], host: Host, written_before: Sequence[str] = ()
) -> None:
    """Refuse a directory to mount that withheld keeps back: one that is
    never to be mounted, see _unsafe_dir, and one that is, or goes
    through, a link in the project, or in another directory a session can
    write, or could at an earlier launch (written_before), and leads out
    of there. A session could have left the link for this, to be given
    the next time what it points to, named from there or from anywhere
    else. One the user keeps such a link to is named by where it is. The
    project too, started from such a link: a session of the project it is
    in could have left it, for ~/.aws to be the next project mounted."""
    written = Written.of([*writable_dirs(dirs, host), *written_before])
    for path in mounted_dirs(dirs, host):
        refused = withheld(path, host, written)
        if refused is None:
            continue
        said = refused.said
        if refused.rule is Rule.LINK_OUT:
            said += (
                ". Start from the directory it leads to"
                if path == host.project_dir
                else ". Name the directory it leads to"
            )
        raise Fatal(f"refusing to mount {flat(path)}: {said}")


def _absolute_path(raw: str, host: Host) -> str:
    """A path as written by the user made absolute, a leading ~ expanded
    and a relative one taken from the project."""
    expanded = expand_home(raw, host.home)
    return os.path.normpath(os.path.join(host.project_dir, expanded))


def _resolve_dir(raw: str, host: Host) -> str:
    """Absolute path of an existing directory."""
    path = _absolute_path(raw, host)
    if not os.path.isdir(path):
        raise Fatal(f"not a directory: {raw}")
    return path


def add_extra_dir(
    dirs: list[ExtraDir], raw: str, host: Host, read_only: bool = False
) -> None:
    """Add a directory to mount. One that was added before is not added
    again, docker rejects a repeated mount destination, and read-only
    wins whichever way it was asked for first: what one setting keeps a
    session from, another does not give back without a word. The project
    is already mounted, and writable: asked for read-only it is refused,
    there is no session that does not write to it. What is never to be
    mounted is refused with the rest, see refuse_withheld_dirs."""
    path = _resolve_dir(raw, host)
    if path == host.project_dir:
        if read_only:
            raise Fatal(
                f"cannot mount {raw} read-only: it is the project of this"
                " session, which is mounted writable"
            )
        return
    for at, extra in enumerate(dirs):
        if extra.path != path:
            continue
        if read_only:
            dirs[at] = ExtraDir(path, read_only=True)
        elif extra.read_only:
            warn(f"{path} stays read-only: it was asked for read-only as well")
        return
    dirs.append(ExtraDir(path, read_only))


def configured_extra_dirs(settings: Settings, host: Host) -> list[ExtraDir]:
    """The directories asked for by the settings, before the command line."""
    dirs: list[ExtraDir] = []
    # The scratch directory shared between sessions. The default is skipped
    # when missing, one asked for by name must exist.
    default_shared = os.path.join(host.home, "claude-shared")
    if settings.shared_dir is None:
        if os.path.isdir(default_shared):
            add_extra_dir(dirs, default_shared, host)
    elif settings.shared_dir:
        add_extra_dir(dirs, settings.shared_dir, host)
    for raw in settings.extra_dirs:
        add_extra_dir(dirs, raw, host)
    for raw in settings.extra_dirs_ro:
        add_extra_dir(dirs, raw, host, read_only=True)
    return dirs


def _nearest(
    path: str,
    roots: Iterable[str],
    within: Callable[[str, str], bool] = is_under,
) -> str | None:
    """Of some directories, the one nearest above a path, by within (under
    it, by default), none when the path is in none of them. As they are
    written, whoever asks resolves them first where a link counts."""
    return max((root for root in roots if within(path, root)), key=len, default=None)


def _within(path: str, root: str) -> str | None:
    """Where a path is under a directory as that directory is mounted,
    none when it is not under it. By where the two lead, either can be
    reached through a link."""
    real_path, real_root = os.path.realpath(path), os.path.realpath(root)
    if not is_within(real_path, real_root):
        return None
    return os.path.normpath(os.path.join(root, os.path.relpath(real_path, real_root)))


def _refuse_protected_link(
    raw: str, path: str, dirs: list[ExtraDir], host: Host
) -> None:
    """Refuse a path to protect that is, or goes through, a link in what
    a session can write: the read-only mount is where the link leads, and
    nothing holds the link, which no mount can. A session would replace
    it with what it likes, which the host reads at the path protected.
    Each link on the way by the mounted directory it is in, the one
    nearest to it by where they lead, whether the link leads out of it or
    not: wherever the path is named from, ~/kit as a link into the shared
    directory too, which is in none of them as it is written."""
    writable = writable_dirs(dirs, host)
    # Each by where it leads, the first of those that lead to the same
    by_real: dict[str, str] = {}
    for root in mounted_dirs(dirs, host):
        by_real.setdefault(os.path.realpath(root), root)
    links, _ = _links_on_the_way(path)
    for link in links:
        real = _nearest(link, by_real)
        root = by_real[real] if real else ""
        if root in writable:
            raise Fatal(
                f"cannot protect {raw}: it is, or goes through, a link in {root},"
                " which a session could replace. Name the path it leads to"
            )


def protected_dirs(
    dirs: list[ExtraDir], settings: Settings, host: Host
) -> tuple[list[ExtraDir], list[str]]:
    """What CLAUDE_AIRLOCK_PROTECT makes of a session's mounts: the
    directories to mount, those it names read-only, and the paths inside
    one of them (or the project) to mount read-only on top, each as it is
    found there. For what a session must be able to read and must not
    change, wherever it is mounted from: the host's claude may follow
    files that are in a directory every session can write, a kit of
    skills in the shared directory for one. A path that is in no mounted
    directory is not in the session at all, and passed over. A directory
    that is mounted from inside a protected path is a part of it, and is
    read-only with it: mounted writable it would be written to there,
    whatever the path around it is said to be."""
    dirs = list(dirs)
    inside: list[str] = []
    for raw in settings.protect:
        path = _absolute_path(raw, host)
        if _within(host.project_dir, path):
            raise Fatal(
                f"cannot protect {raw}: the project is in it, --add-dir-ro"
                " mounts a directory read-only"
            )
        for at, extra in enumerate(dirs):
            if not extra.read_only and _within(extra.path, path):
                dirs[at] = ExtraDir(extra.path, read_only=True)
                warn(
                    f"{extra.path} is mounted read-only: it is in {raw},"
                    " which CLAUDE_AIRLOCK_PROTECT protects"
                )
        _refuse_protected_link(raw, path, dirs, host)
        roots = mounted_dirs(dirs, host)
        found = [mounted for mounted in (_within(path, r) for r in roots) if mounted]
        if not found:
            continue
        if not os.path.lexists(path):
            # It could be made from inside the session, as anything
            raise Fatal(f"cannot protect {raw}: it does not exist")
        for at, extra in enumerate(dirs):
            if extra.path in found:
                dirs[at] = ExtraDir(extra.path, read_only=True)
        # Each once: a path is found in every mounted directory it is
        # in, the same when one of those is inside another, and docker
        # refuses to mount twice at one place
        for mounted in found:
            if mounted not in roots and mounted not in inside:
                inside.append(mounted)
    return dirs, inside


def _held_in_place(
    inside: list[str], host: Host, dirs: list[ExtraDir], hidden: Hidden = NO_SECRETS
) -> list[str]:
    """The directories between each protected path and what it is mounted
    in, when that is writable. A session cannot write to a read-only
    mount, but it can rename a directory above one and make the path
    again with its own content, which is what the host would then read.
    A directory that is a mount cannot be renamed or removed: each of
    these is mounted on itself, writable as before. None for a path in
    what is read-only anyway, a mounted directory or another protected
    path: there is nothing to rename there, and a writable mount would
    open it.

    The same for a directory mounted inside another, read-only or not,
    the project too, which is no more held by being a mount than what is
    above it. And for each hidden file and covered directory: a session
    cannot read it, but it could move a directory above it to where the
    next launch does not look for files to hide (see SHADOW_PRUNED_DIRS),
    and read it then. Not what is covered, or in it: one mount at a
    place, see Hidden.hides."""
    writable = writable_dirs(dirs, host)
    read_only = [*(d.path for d in dirs if d.read_only), *inside]
    held: dict[str, None] = {}
    for path in (*inside, *hidden.files, *hidden.covered, *mounted_dirs(dirs, host)):
        root = _nearest(path, (*writable, *read_only))
        if root is None or root in read_only:
            continue
        directory = os.path.dirname(path)
        while directory != root:
            held[directory] = None
            directory = os.path.dirname(directory)
        refuse_past_most(
            len(held),
            MOST_HELD,
            "directories to hold in place above the files hidden and the paths"
            f" protected, {flat(path)} among them",
        )
    return sorted(path for path in held if not hidden.hides(path))


class _MountPoints(NamedTuple):
    """Where the mounts of protect_args go: the directories held in place,
    and the protected paths mounted read-only."""

    held: list[str]
    protected: list[str]


def _mount_points(
    inside: list[str], host: Host, dirs: list[ExtraDir], hidden: Hidden
) -> _MountPoints:
    """Where the mounts of protect_args go, for it and for Placed: the
    paths of protected_dirs, but for one that is hidden, or covered,
    which is read-only there already, one mount at a place (see
    Hidden.hides), and the directories that keep them, the directories
    mounted inside another and the hidden files where they are, see
    _held_in_place."""
    protected = [path for path in inside if not hidden.hides(path)]
    return _MountPoints(_held_in_place(protected, host, dirs, hidden), protected)


def protect_args(
    inside: list[str], host: Host, dirs: list[ExtraDir], hidden: Hidden = NO_SECRETS
) -> list[str]:
    """The read-only mounts of protected_dirs, on top of what they are
    in, and the mounts that keep them, see _mount_points."""
    points = _mount_points(inside, host, dirs, hidden)
    held = [held_arg(path) for path in points.held]
    return held + [mount_arg(path, path, "ro,z") for path in points.protected]


# What a file is to the system, whatever it is named and whatever leads to
# it: the device it is on and its number there
type Identity = tuple[int, int]


def _moved(path: str, said: str) -> Fatal:
    """What is said of a path a mount goes from or to that is not as it
    has to be to be mounted: gone, a link, or another than was planned."""
    return Fatal(
        f"cannot mount at {flat(path)}: {said}, a session that runs meanwhile"
        " may have made it so. Launch again once it is as it was"
    )


def _about(path: str, *, links: bool = False) -> os.stat_result | None:
    """What lstat says of a path, or stat through the links on the way
    when told. None for one in a directory closed to the launcher. Fatal
    for one that is not there, see _moved."""
    try:
        return os.stat(path) if links else os.lstat(path)
    except OSError as problem:
        if problem.errno in CLOSED:
            return None
        raise _moved(path, f"{problem.strerror}") from None


def _identity(about: os.stat_result | None) -> Identity:
    """What a path is by what lstat or stat says of it, and what no file
    is for one in a directory closed to the launcher, see _about."""
    return file_id(about) if about else (-1, -1)


def _root_identity(root: str) -> Identity:
    """What a mounted directory leads to, through the links on the way."""
    return _identity(_about(root, links=True))


def _parts_below(root: str, path: str) -> tuple[tuple[Identity, ...], str]:
    """What each part of a path below a mounted directory is, from the
    one under it down to the path, none for the directory itself. With
    the first that is a link, empty when none is, after which no part is
    looked at: a mount at the path would go where the link leads, which
    a session that can write there could have pointed anywhere. Nor any
    after one in a directory closed to the launcher, which cannot be
    told: a file hidden there as it was, see _hidden_again. That
    directory is held in place where a session can write, as every one
    above a hidden file, see _held_in_place."""
    if path == root:
        return (), ""
    parts: list[Identity] = []
    here = root
    for name in os.path.relpath(path, root).split(os.sep):
        here = os.path.join(here, name)
        about = _about(here)
        if about and stat.S_ISLNK(about.st_mode):
            return tuple(parts), here
        parts.append(_identity(about))
        if about is None:
            break
    return tuple(parts), ""


class _Below(NamedTuple):
    """A path below a directory a mount goes from or to, by what each
    part of it is from the one under the directory down, see
    _parts_below."""

    root: str
    path: str
    parts: tuple[Identity, ...]

    @classmethod
    def of(cls, root: str, path: str) -> _Below:
        """The path as it is now. Fatal for one that goes through a link:
        the walk for files to hide follows none, a session can have made
        one since, or the user named a directory to mount inside another
        through one."""
        parts, link = _parts_below(root, path)
        if link:
            raise Fatal(
                f"cannot mount at {flat(path)}: it goes through {flat(link)},"
                " a link, which a session that can write there could point"
                " anywhere. Name the path it leads to"
            )
        return cls(root, path, parts)

    def refuse_moved(self) -> None:
        """Fatal when a part of the path is a link now, or another than
        it was."""
        parts, link = _parts_below(self.root, self.path)
        if link:
            raise _moved(self.path, f"it goes through {flat(link)}, a link now")
        if parts != self.parts:
            raise _moved(self.path, "it is another than was planned")


class _Led(NamedTuple):
    """A file of the host that is mounted alone, by where it leads, which
    is below a directory a session can write, or could at an earlier
    launch (see _led_into)."""

    path: str
    below: _Below


def _led_into(files: Iterable[str], written: Written) -> list[_Led]:
    """Of the files of the host mounted alone, those that lead into a
    directory a session can write, or could at an earlier launch
    (written), each by where it leads in the one nearest above that:
    ~/.gitconfig kept as a link into a repository of dotfiles that a
    session of its own has. Not those that lead elsewhere, which are out
    of a session's reach. Fatal for one that goes through a link below
    there, see _Below.of."""
    roots = [root for _, root in written.places]
    led = []
    for path in dict.fromkeys(files):
        real = os.path.realpath(path)
        root = _nearest(real, roots)
        if root is not None:
            led.append(_Led(path, _Below.of(root, real)))
    return led


@dataclass(frozen=True)
class Placed:
    """What a session's mounts go from and to of the directories it is
    given, as it was when they were planned, for refuse_moved: each of
    those directories by what it leads to, and each path below one, the
    directories held in place, the paths protected, the files hidden and
    the directories covered (see _Below). The files of the host mounted
    alone that lead into a directory a session can write, by where they
    lead (see _led_into). With what refuse_withheld_dirs asks of the
    directories again."""

    host: Host
    dirs: tuple[ExtraDir, ...]
    written_before: tuple[str, ...]
    roots: tuple[tuple[str, Identity], ...]
    below: tuple[_Below, ...]
    led: tuple[_Led, ...]

    @classmethod
    def of(
        cls,
        inside: list[str],
        host: Host,
        dirs: list[ExtraDir],
        hidden: Hidden = NO_SECRETS,
        written_before: Sequence[str] = (),
        files: Sequence[str] = (),
    ) -> Placed:
        """Where the mounts of protect_args and hidden.args go, and the
        directories they are in, as they are now, and where the files of
        the host mounted alone (files) lead. Fatal for a path below one
        of those directories that goes through a link, see _Below.of."""
        roots = mounted_dirs(dirs, host)
        points = _mount_points(inside, host, dirs, hidden)
        paths = (*points.held, *points.protected, *hidden.files, *hidden.covered)
        below = [
            _Below.of(root, path)
            for path in dict.fromkeys(paths)
            if (root := _nearest(path, roots, within=is_within)) is not None
        ]
        written = Written.of([*writable_dirs(dirs, host), *written_before])
        return cls(
            host,
            tuple(dirs),
            tuple(written_before),
            tuple((root, _root_identity(root)) for root in roots),
            tuple(below),
            tuple(_led_into(files, written)),
        )

    def refuse_moved(self) -> None:
        """Fatal when what the mounts go from or to is not as it was
        planned. The directories they are in, and those mounted inside
        them, are what a session that runs meanwhile can write, and what
        was planned to be held in place there it can swap for a link to
        the home, for docker to mount that, writable, where the
        directory was. So each directory mounted is asked again what
        refuse_withheld_dirs asks of it, and has to lead to what it did,
        and no part of a path below one may be a link now, or another
        than it was. The same of a file of the host that leads into such
        a directory, which has to lead where it did: a session can swap
        it there for a link to a key, for docker to mount that in its
        place. For right before docker run: docker resolves each path
        itself once it has them, so a moment is left in which one can
        still be moved, this keeps it to that."""
        refuse_withheld_dirs(list(self.dirs), self.host, self.written_before)
        for root, was in self.roots:
            if _root_identity(root) != was:
                raise _moved(root, "it is another directory than was checked")
        for led in self.led:
            if os.path.realpath(led.path) != led.below.path:
                raise _moved(led.path, "it leads elsewhere than was planned")
        for below in (*self.below, *(led.below for led in self.led)):
            below.refuse_moved()


def extra_dir_args(dirs: list[ExtraDir]) -> list[str]:
    args = [
        mount_arg(extra.path, extra.path, "ro,z" if extra.read_only else "z")
        for extra in dirs
    ]
    if dirs:
        # The mounted extra directories, said in docker/CLAUDE-airlock.md
        shown = ":".join(d.path + ("(ro)" if d.read_only else "") for d in dirs)
        args.append(env_arg(SESSION_DIRS, shown))
    return args


def protect_env_args(inside: list[str]) -> list[str]:
    """The session is told what it cannot change of what it has mounted,
    see docker/CLAUDE-airlock.md."""
    return [env_arg(variable("protect"), ":".join(inside))] if inside else []


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
    found = [each for root in roots if (each := _within(real, root))]
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
    if not any(_within(path, root) for root in roots):
        return []
    try:
        found, _ = _to_hide(path, roots)
    except OSError as problem:
        if problem.errno not in CLOSED:
            raise _not_looked_into(problem) from None
        found = [path]
    return [
        inside for each in found for root in roots if (inside := _within(each, root))
    ]


def _refuse_past_most_hidden(
    root: str, hidden: dict[str, None], closed: dict[str, None]
) -> None:
    """Fatal for more files to hide, with the directories that cannot be
    looked into, than MOST_HIDDEN, the last found named."""
    if not hidden and not closed:
        return
    last = next(reversed(closed or hidden))
    refuse_past_most(
        len(hidden) + len(closed),
        MOST_HIDDEN,
        "files of secrets to hide and directories that cannot be looked into,"
        f" in {flat(root)}, {flat(last)} among them",
    )


def hidden_files(
    settings: Settings,
    host: Host,
    dirs: list[ExtraDir],
    linked_before: Sequence[str] = (),
) -> Hidden:
    """What to shadow: .env files (and direnv's .envrc, which commonly
    exports secrets, plus .netrc and .pypirc, which hold nothing but
    credentials), so they are never visible inside the container. Template
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
    roots = mounted_dirs(dirs, host)
    for root in roots:
        for path, through_a_link in _secrets_in(root, roots, patterns, closed):
            hidden[path] = None
            if through_a_link:
                linked[path] = None
            _refuse_past_most_hidden(root, hidden, closed)
        _refuse_past_most_hidden(root, hidden, closed)
    for before in linked_before:
        again = dict.fromkeys(_hidden_again(before, roots))
        hidden.update(again)
        linked.update(again)
    refuse_past_most(len(hidden), MOST_HIDDEN, "files of secrets to hide")
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
