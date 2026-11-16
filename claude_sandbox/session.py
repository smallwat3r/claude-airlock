"""The session container: the directories mounted into it, its docker run
options and the run itself."""

from __future__ import annotations

import fcntl
import fnmatch
import json
import os
import shlex
import signal
import stat
import subprocess
import sys
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .docker import (
    docker,
    docker_ok,
    docker_safe_name,
    env_arg,
    mount_arg,
    project_slug,
)
from .home import CLAUDE, home_args, session_state_args
from .image import Image
from .settings import BIN_DIR, CONTAINER_HOME, Fatal, Host, Settings, private_dir

SHADOWED_NAMES = (".env", ".env.*", ".envrc", ".netrc", ".pypirc")
SHADOW_EXEMPT = (".env.example", ".env.sample", ".env.template")
SHADOW_PRUNED_DIRS = ("node_modules", ".git")
# What tells the launcher to end: a kill, and a terminal that is gone (a
# closed window, a killed Emacs buffer)
END_SIGNALS = (signal.SIGTERM, signal.SIGHUP)
# Seconds between two tries to stop a session the launcher was told to end
STOP_EVERY = 0.5


@dataclass(frozen=True)
class ExtraDir:
    """A host directory mounted alongside the project, at its host path."""

    path: str
    read_only: bool = False


def refuse_unsafe_dir(path: str, host: Host) -> None:
    """Refuse the filesystem root, the home directory or any of its parents:
    mounting one read-write would expose the whole home and defeat the
    sandbox. By the path as it is written and by where it leads, a link
    to the home directory is the home directory."""
    for home, directory in (
        (host.home, path),
        (os.path.realpath(host.home), os.path.realpath(path)),
    ):
        if (home.rstrip("/") + "/").startswith(directory.rstrip("/") + "/"):
            raise Fatal(f"refusing to mount {path}: it would defeat the sandbox")


def absolute_path(raw: str, host: Host) -> str:
    """A path as written by the user made absolute, expanding a leading ~
    (the shell does not expand it in the --add-dir=~/x form, nor is it
    expanded in the config file)."""
    expanded = raw
    if raw == "~":
        expanded = host.home
    elif raw.startswith("~/"):
        expanded = host.home + raw[1:]
    return os.path.normpath(os.path.join(host.project_dir, expanded))


def resolve_dir(raw: str, host: Host) -> str:
    """Absolute path of an existing directory."""
    path = absolute_path(raw, host)
    if not os.path.isdir(path):
        raise Fatal(f"not a directory: {raw}")
    return path


def add_extra_dir(
    dirs: list[ExtraDir], raw: str, host: Host, read_only: bool = False
) -> None:
    """Add a directory to mount. Duplicates and the project itself are
    skipped: docker rejects a repeated mount destination, and the project is
    already mounted. A directory already added read-write stays so."""
    path = resolve_dir(raw, host)
    refuse_unsafe_dir(path, host)
    if path == host.project_dir or any(extra.path == path for extra in dirs):
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


def claim_name(directory: str, name: str) -> int | None:
    """Claim a name among the launchers, none when another has it: the
    lock held on a file of that name, which is let go of with the launcher
    however it ends. The file stays, one that is removed could be locked
    by two."""
    descriptor = os.open(os.path.join(directory, name), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(descriptor)
        return None
    return descriptor


def within(path: str, root: str) -> str | None:
    """Where a path is under a directory as that directory is mounted,
    none when it is not under it. By where the two lead, either can be
    reached through a link."""
    real_path, real_root = os.path.realpath(path), os.path.realpath(root)
    if real_path != real_root and not real_path.startswith(real_root + os.sep):
        return None
    return os.path.normpath(os.path.join(root, os.path.relpath(real_path, real_root)))


def protected_dirs(
    dirs: list[ExtraDir], settings: Settings, host: Host
) -> tuple[list[ExtraDir], list[str]]:
    """What CLAUDE_DOCKER_PROTECT makes of a session's mounts: the
    directories to mount, those it names read-only, and the paths inside
    one of them (or the project) to mount read-only on top, each as it is
    found there. For what a session must be able to read and must not
    change, wherever it is mounted from: the host's claude may follow
    files that are in a directory every session can write, a kit of
    skills in the shared directory for one. A path that is in no mounted
    directory is not in the session at all, and passed over."""
    dirs = list(dirs)
    inside: list[str] = []
    for raw in settings.protect:
        path = absolute_path(raw, host)
        if within(host.project_dir, path):
            raise Fatal(
                f"cannot protect {raw}: the project is in it, --add-dir-ro"
                " mounts a directory read-only"
            )
        roots = [host.project_dir, *(extra.path for extra in dirs)]
        found = [mounted for mounted in (within(path, r) for r in roots) if mounted]
        if not found:
            continue
        if not os.path.lexists(path):
            # It could be made from inside the session, as anything
            raise Fatal(f"cannot protect {raw}: it does not exist")
        for at, extra in enumerate(dirs):
            if extra.path in found:
                dirs[at] = ExtraDir(extra.path, read_only=True)
        inside += [m for m in found if m not in roots and m not in inside]
    return dirs, inside


def protect_args(inside: list[str]) -> list[str]:
    """The read-only mounts of protected_dirs, on top of what they are
    in."""
    return [mount_arg(path, path, "ro,z") for path in inside]


@contextmanager
def container_name(host: Host, env: Mapping[str, str]) -> Iterator[str]:
    """claude-{project}[-{instance}], the instance taken from the Emacs
    buffer name (*claude:dir:instance*) so parallel sessions never clash.
    Claimed for as long as the block lasts: a container only takes its
    name when it starts, and two launchers started together would both
    find the same one free."""
    name = "claude-" + os.path.basename(host.project_dir)
    buffer_name = env.get("CLAUDE_BUFFER_NAME")
    if buffer_name:
        instance = buffer_name.rsplit(":", 1)[-1]
        name += "-" + instance.removesuffix("*")
    name = docker_safe_name(name)
    # Buffer names are only unique within one Emacs, so a second Emacs (or a
    # plain shell) on the same project asks for a name that is already
    # taken. Step past it rather than fail, the other session is still live.
    base = name.removesuffix("-")
    directory = private_dir(host.names_dir)
    candidate, number = base, 2
    while True:
        claim = claim_name(directory, candidate)
        if claim is not None:
            if not docker_ok("container", "inspect", candidate):
                break
            os.close(claim)
        candidate = f"{base}-{number}"
        number += 1
    try:
        yield candidate
    finally:
        os.close(claim)


def telemetry_args(settings: Settings) -> list[str]:
    """Unless CLAUDE_DOCKER_TELEMETRY=1, Claude Code is told to keep its
    usage events and crash reports to itself. They go to third parties
    (Datadog for one) outside of any tool call, with what they hold not
    the user's to see. Nothing a session does depends on them."""
    if settings.telemetry:
        return []
    return [env_arg("DISABLE_TELEMETRY", 1), env_arg("DISABLE_ERROR_REPORTING", 1)]


def base_args(settings: Settings, host: Host, name: str) -> list[str]:
    """What every session gets: identity, the core mounts, the hardening and
    the resource limits."""
    return [
        "--rm",
        "--interactive",
        # Claude runs as PID 1 and does not reap orphaned children, without
        # an init, zombies accumulate and count toward --pids-limit
        "--init",
        f"--name={name}",
        f"--user={os.getuid()}:{os.getgid()}",
        f"--workdir={host.project_dir}",
        # Run under the host home path (symlinked to /home/node in the image)
        # so absolute paths in the config of ~/.claude resolve consistently
        env_arg("HOME", host.home),
        env_arg("TERM", "xterm-256color"),
        env_arg("INSIDE_EMACS", ""),
        # Claude's TUI defaults to the alternate screen, which has no
        # scrollback of its own (e.g. inside Emacs eat): everything above the
        # current viewport is gone. Render inline instead so old output stays
        # in the terminal's scrollback.
        env_arg("CLAUDE_CODE_DISABLE_ALTERNATE_SCREEN", 1),
        env_arg("CLAUDE_CONFIG_DIR", CLAUDE),
        *telemetry_args(settings),
        # Read by bin/claude-statusline to show a sandbox badge and the
        # network mode in the Claude UI
        env_arg("CLAUDE_DOCKER_SANDBOX", name),
        env_arg("CLAUDE_DOCKER_NET_FILTER", int(settings.net_filter)),
        # The session is told its settings, so that Claude can name the one
        # behind something it could not do (see docker/CLAUDE-sandbox.md).
        # The other switches are only set when they are on, by the code
        # that acts on them.
        env_arg("CLAUDE_DOCKER_NET_LOG", int(settings.net_log)),
        env_arg("CLAUDE_DOCKER_PROC_LOG", int(settings.proc_log)),
        env_arg("CLAUDE_DOCKER_CACHE", int(settings.cache)),
        env_arg("CLAUDE_DOCKER_MEMORY", settings.memory),
        env_arg("CLAUDE_DOCKER_PIDS", settings.pids),
        # No gpg binary (or key) in the image, so a host gitconfig with
        # commit.gpgsign=true would make every commit fail. Sign the
        # sandbox's commits at review time, before pushing.
        env_arg("GIT_CONFIG_COUNT", 2),
        env_arg("GIT_CONFIG_KEY_0", "commit.gpgsign"),
        env_arg("GIT_CONFIG_VALUE_0", "false"),
        env_arg("GIT_CONFIG_KEY_1", "tag.gpgsign"),
        env_arg("GIT_CONFIG_VALUE_1", "false"),
        mount_arg(host.project_dir, host.project_dir, "z"),
        *home_args(host),
        # ~/.local/share/claude is NOT mounted. It holds the versioned claude
        # binary the launcher symlinks to, mounting the host's copy shadows
        # the image's baked-in version, dangling the symlink (exit 127). The
        # image owns the version (auto-updater is off, update = rebuild), so
        # keep it self-contained.
        mount_arg(host.claude_state_dir, f"{CONTAINER_HOME}/.local/state/claude", "z"),
        *statusline_args(host),
        *session_state_args(),
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        # exec where builds and test binaries run, sized so a runaway process
        # cannot eat host RAM through an unbounded tmpfs (default: half of RAM)
        "--tmpfs=/tmp:exec,size=4g",
        f"--tmpfs={CONTAINER_HOME}/.config:size=64m",
        f"--tmpfs={CONTAINER_HOME}/.npm:exec,size=1g",
        f"--pids-limit={settings.pids}",
        # Same value for swap, otherwise docker allows as much swap again on top
        f"--memory={settings.memory}",
        f"--memory-swap={settings.memory}",
        cache_arg(settings, host),
        # A stronger runtime when asked for, e.g. runsc (gVisor), which keeps
        # the container off the host kernel. It must be installed in the daemon.
        *([f"--runtime={settings.runtime}"] if settings.runtime else []),
    ]


def configured_statusline(host: Host) -> str | None:
    """The program ~/.claude/settings.json runs as its statusline, if any."""
    try:
        text = Path(host.claude_dir, "settings.json").read_text(encoding="utf-8")
        words = shlex.split(json.loads(text)["statusLine"]["command"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    program = words[0] if words else ""
    if program.startswith("~/"):
        program = host.home + program[1:]
    return os.path.normpath(program) if os.path.isabs(program) else None


def statusline_args(host: Host) -> list[str]:
    """~/.claude/settings.json runs the statusline from this checkout, which
    is neither in the image nor (usually) the mounted project, so mount the
    script alone at its host path. Also at the path settings.json names when
    that is another way to the same file (a symlink to the script, or a
    checkout reached through one): the container has nothing else to follow
    the link with."""
    script = os.path.join(BIN_DIR, "claude-statusline")
    targets = [script]
    configured = configured_statusline(host)
    try:
        if configured and configured != script and os.path.samefile(configured, script):
            targets.append(configured)
    except OSError:
        pass
    return [mount_arg(script, target, "ro,z") for target in targets]


def cache_arg(settings: Settings, host: Host) -> str:
    """~/.cache holds the Go module, uv and npm caches. By default it is a
    named volume per project, so sessions do not download everything again.
    Per project on purpose: a shared cache would let a compromised session
    poison the dependencies of every other project. Unlike the tmpfs it has
    no size cap, remove the claude-cache-* volumes to reclaim the space."""
    target = f"{CONTAINER_HOME}/.cache"
    if not settings.cache:
        return f"--tmpfs={target}:exec,size=2g"
    return mount_arg(f"claude-cache-{project_slug(host.project_dir)}", target)


def session_args(action: str, env: Mapping[str, str]) -> list[str]:
    """What depends on how this one session was started."""
    args = []
    if action == "shell":
        args.append("--entrypoint=bash")
    # A TTY only when there is one, so piped and scripted runs (claude -p)
    # work instead of failing with "the input device is not a TTY"
    if sys.stdin.isatty() and sys.stdout.isatty():
        args.append("--tty")
    # Passed through when set. GH_TOKEN is how gh authenticates in here, its
    # config directory is a tmpfs.
    for name in ("ANTHROPIC_API_KEY", "GH_TOKEN", "CLAUDE_BUFFER_NAME"):
        if name in env:
            args.append(env_arg(name))
    return args


def extra_dir_args(dirs: list[ExtraDir]) -> list[str]:
    args = [
        mount_arg(extra.path, extra.path, "ro,z" if extra.read_only else "z")
        for extra in dirs
    ]
    if dirs:
        # Read by bin/claude-statusline to list the mounted extra directories
        shown = ":".join(d.path + ("(ro)" if d.read_only else "") for d in dirs)
        args.append(env_arg("CLAUDE_DOCKER_DIRS", shown))
    return args


def protect_env_args(inside: list[str]) -> list[str]:
    """The session is told what it cannot change of what it has mounted,
    see docker/CLAUDE-sandbox.md."""
    return [env_arg("CLAUDE_DOCKER_PROTECT", ":".join(inside))] if inside else []


def git_include_paths() -> list[str]:
    """The files the global git config pulls in with include or includeIf."""
    try:
        result = subprocess.run(
            ["git", "config", "--global", "--get-regexp", r"^include(if\..*)?\.path$"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="replace",
            check=False,
        )
    except FileNotFoundError:
        return []
    # One "key value" pair per line
    return [line.split(" ", 1)[1] for line in result.stdout.splitlines() if " " in line]


def git_config_args(host: Host) -> list[str]:
    """Forward the git config, read-only."""
    args = []
    gitconfig = os.path.join(host.home, ".gitconfig")
    if os.path.isfile(gitconfig):
        args.append(mount_arg(gitconfig, f"{CONTAINER_HOME}/.gitconfig", "ro,z"))
    xdg_git = os.path.join(host.config_home, "git")
    if os.path.isdir(xdg_git):
        args.append(mount_arg(xdg_git, f"{CONTAINER_HOME}/.config/git", "ro,z"))
    # Files pulled in with include/includeIf (e.g. a work identity under
    # "gitdir:~/work/") live outside the mounts, so without this they
    # silently never apply. Mounted at their host path, the one the config
    # refers to. Relative paths are taken from the home directory, where
    # ~/.gitconfig is.
    for path in git_include_paths():
        if path.startswith("~/"):
            path = host.home + path[1:]
        elif not path.startswith("/"):
            path = os.path.join(host.home, path)
        if path == gitconfig or path.startswith(xdg_git + "/"):
            continue
        if os.path.isfile(path):
            args.append(mount_arg(path, path, "ro,z"))
    return args


def shadow_args(settings: Settings, host: Host, dirs: list[ExtraDir]) -> list[str]:
    """Shadow .env files (and direnv's .envrc, which commonly exports
    secrets, plus .netrc and .pypirc, which hold nothing but credentials) so
    they are never visible inside the container. Template files (.env.example
    and friends) stay readable, they exist to be read and hold no secrets.
    Regular files only: a .env directory (some virtualenvs) cannot take a
    /dev/null bind mount and would abort the run. CLAUDE_DOCKER_SHADOW adds
    name globs, e.g. "*.pem:.npmrc". The whole tree is walked on purpose,
    pruning more directories would be faster but could leave a real secret
    visible."""
    patterns = SHADOWED_NAMES + settings.shadow
    # By path, in the order found: a directory mounted next to the project
    # can be inside it, and docker refuses to mount twice at one place
    hidden: dict[str, None] = {}
    for root in [host.project_dir] + [extra.path for extra in dirs]:
        for directory, subdirs, files in os.walk(root):
            subdirs[:] = sorted(d for d in subdirs if d not in SHADOW_PRUNED_DIRS)
            for name in sorted(files):
                if name in SHADOW_EXEMPT:
                    continue
                if not any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns):
                    continue
                path = os.path.join(directory, name)
                if stat.S_ISREG(os.lstat(path).st_mode):
                    hidden[path] = None
    for path in hidden:
        if ":" in path:
            # Not left visible, and not for docker to trip over
            raise Fatal(
                f"cannot hide {path}: docker takes no path with a colon,"
                " rename or remove the file"
            )
    return [mount_arg("/dev/null", path, "ro") for path in hidden]


@contextmanager
def interrupts_held() -> Iterator[None]:
    """Keep Ctrl-C from ending the launcher for as long as the block
    lasts: it has to outlive the session to collect what its sidecars
    recorded and to check what it left behind, and Ctrl-C twice is how
    Claude Code is left. Ctrl-C still reaches docker (same foreground
    process group) and ends the session there. Held with a handler, one
    that is ignored would be ignored by docker too."""
    previous = signal.signal(signal.SIGINT, lambda *_: None)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)


class Ending:
    """The launcher being told to end while it has a session, see
    ending_passed_on."""

    def __init__(self, name: str) -> None:
        self._name = name
        # The signal that told it, none while none did
        self.signal: int | None = None
        self._over = threading.Event()

    def told(self, number: int, _frame: object) -> None:
        """The handler of the signals: the first one counts."""
        if self.signal is None:
            self.signal = number
            threading.Thread(target=self._stop_session, daemon=True).start()

    def _stop_session(self) -> None:
        # Until the session is over, not once: its container may not be
        # there yet, and is then started a moment later
        while not self._over.is_set():
            try:
                docker_ok("stop", self._name)
            except Fatal:
                return
            self._over.wait(STOP_EVERY)

    def session_over(self) -> None:
        self._over.set()

    def status(self, status: int) -> int:
        """What the launcher ends with: the session's status, or the way
        a shell reports the signal that ended it."""
        return status if self.signal is None else 128 + self.signal


@contextmanager
def ending_passed_on(name: str) -> Iterator[Ending]:
    """For as long as the block lasts, a signal that would end the
    launcher (see END_SIGNALS) ends the session of that name instead, and
    the launcher then ends as it does after any session: it collects what
    the sidecars recorded, checks what the session left behind and removes
    the proxies no session uses any more. Ended on the spot it would leave
    all of that for the next launch, the socket proxy and the host's
    Docker socket it holds included. A kill that cannot be handled still
    does, see report_unchecked_sessions and Sidecar.left_behind."""
    ending = Ending(name)
    previous = {number: signal.signal(number, ending.told) for number in END_SIGNALS}
    try:
        yield ending
    finally:
        ending.session_over()
        for number, handler in previous.items():
            signal.signal(number, handler)


def run_session(
    run_args: list[str], image: Image, command_args: list[str], ending: Ending
) -> int:
    """Run the container and wait for it. Not an exec: the launcher has to
    outlive the session to check what it left behind, see interrupts_held
    and ending_passed_on. Not at all when the launcher was told to end
    before it got here."""
    try:
        if ending.signal is not None:
            return 0
        status = docker("run", *run_args, image.tag, *command_args).returncode
    finally:
        ending.session_over()
    # Killed by a signal: report it the way a shell would
    return status if status >= 0 else 128 - status
