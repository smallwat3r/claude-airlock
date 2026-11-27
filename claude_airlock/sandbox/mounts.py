"""What a session is given of the host besides its project: the
directories mounted next to it, what of them it cannot change, and the
files of secrets hidden from it."""

from __future__ import annotations

import fnmatch
import os
import stat
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field

from ..docker import covered_arg, env_arg, held_arg, hidden_arg, mount_arg
from ..errors import Fatal
from ..files import (
    expand_home,
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


def refuse_past_most(count: int, most: int, what: str) -> None:
    """Fatal for more of a kind of mount than most: each is an argument
    of docker run, which the system takes only so many of, and what each
    is for is a session's to make any number of. Said with what they are
    for, and where."""
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


def refuse_unsafe_dir(path: str, host: Host) -> None:
    """Refuse the filesystem root, the home directory or any of its parents:
    mounting one read-write would expose the whole home and defeat the
    sandbox. And what is kept out of every session, see _kept_out, with
    the directories around it. By the path as it is written and by where
    it leads, a link to the home directory is the home directory."""
    real = os.path.realpath(path)
    for home, directory in ((host.home, path), (os.path.realpath(host.home), real)):
        if is_within(os.path.normpath(home), os.path.normpath(directory)):
            raise Fatal(f"refusing to mount {path}: it would defeat the sandbox")
    for kept in _kept_out(host):
        # Mounting the one brings in the other, or a part of it
        if overlap(path, kept) or overlap(real, os.path.realpath(kept)):
            raise Fatal(
                f"refusing to mount {path}: {kept} is not a session's to have,"
                " it would defeat the sandbox"
            )


def mounted_dirs(dirs: list[ExtraDir], host: Host) -> list[str]:
    """The directories a session is given: the project, and those mounted
    next to it."""
    return [host.project_dir, *(each.path for each in dirs)]


def writable_dirs(dirs: list[ExtraDir], host: Host) -> list[str]:
    """The directories a session is given to write: the project, and those
    mounted next to it that are not read-only."""
    return [host.project_dir, *(each.path for each in dirs if not each.read_only)]


def refuse_links_out(
    dirs: list[ExtraDir], host: Host, written_before: Sequence[str] = ()
) -> None:
    """Refuse a directory to mount that is named by a path in the project,
    or in another directory a session can write, or could at an earlier
    launch (written_before), and is not in there: it is reached through a
    link, which a session could have left for this, to be given the next
    time what it points to. One the user keeps such a link to is named by
    where it is."""
    writable = [*writable_dirs(dirs, host), *written_before]
    for extra in dirs:
        for root in writable:
            inside = is_under(extra.path, root)
            if inside and _within(extra.path, root) is None:
                raise Fatal(
                    f"refusing to mount {extra.path}: it is a link out of {root},"
                    " which a session could have made. Name the directory it"
                    " leads to"
                )


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
    there is no session that does not write to it."""
    path = _resolve_dir(raw, host)
    refuse_unsafe_dir(path, host)
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
    By the mounted directory the path is in as it is written, the one
    nearest to it."""
    roots = mounted_dirs(dirs, host)
    root = max((r for r in roots if is_under(path, r)), key=len, default=None)
    if root is None or root not in writable_dirs(dirs, host):
        return
    if _within(path, root) != path:
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
        above = [root for root in (*writable, *read_only) if is_under(path, root)]
        root = max(above, key=len, default=None)
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
            f" protected, {path} among them",
        )
    return sorted(path for path in held if not hidden.hides(path))


def protect_args(
    inside: list[str], host: Host, dirs: list[ExtraDir], hidden: Hidden = NO_SECRETS
) -> list[str]:
    """The read-only mounts of protected_dirs, on top of what they are
    in, and the mounts that keep them, the directories mounted inside
    another and the hidden files where they are, see _held_in_place. Not
    of a protected path that is hidden, or covered: it is read-only
    there already, and one mount at a place, see Hidden.hides."""
    inside = [path for path in inside if not hidden.hides(path)]
    held = [held_arg(path) for path in _held_in_place(inside, host, dirs, hidden)]
    return held + [mount_arg(path, path, "ro,z") for path in inside]


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
    does not have."""
    real = os.path.realpath(link)
    try:
        plain = stat.S_ISREG(os.lstat(real).st_mode)
    except OSError:
        return []
    if not plain:
        return []
    return [found for root in roots if (found := _within(real, root))]


def _secrets_in(
    root: str, roots: Sequence[str], patterns: Sequence[str], closed: dict[str, None]
) -> Iterator[tuple[str, bool]]:
    """The files of secrets in a mounted directory, as hidden_files has
    them, one at a time, and those links named as one lead to in any of
    the roots, each with whether it was found through a link. What
    cannot be looked into is added to closed."""

    def not_listed(problem: OSError) -> None:
        if isinstance(problem.filename, str):
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
            found, through_a_link = _to_hide(path, roots)
            yield from ((each, through_a_link) for each in found)


def _to_hide(path: str, roots: Sequence[str]) -> tuple[list[str], bool]:
    """What hiding the secrets at a path takes, and whether they are
    reached through a link: the file itself, or what a link there leads
    to, see _led_to. Nothing for what is neither, or gone since it was
    listed, by a build or another session."""
    try:
        mode = os.lstat(path).st_mode
    except OSError:
        return [], False
    if stat.S_ISREG(mode):
        return [path], False
    if stat.S_ISLNK(mode):
        return _led_to(path, roots), True
    return [], False


def _hidden_again(path: str, roots: Sequence[str]) -> list[str]:
    """Where a file that was hidden through a link at an earlier launch
    is in the roots, as long as it is there, see _to_hide: it can be in
    none of them at this launch."""
    found, _ = _to_hide(path, roots)
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
        f" in {root}, {last} among them",
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
    could open is hidden whole instead, and said.

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
