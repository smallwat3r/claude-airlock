"""The session container: its name, its docker run options and the run
itself. What of the host is mounted into it is in mounts.py, how the
launcher ends while it runs in ending.py."""

from __future__ import annotations

import os
import re
import shlex
import sys
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path

from ..action import Action
from ..docker import (
    DROP_CAPABILITIES,
    NO_NEW_PRIVILEGES,
    Tmpfs,
    docker,
    docker_ok,
    docker_safe_name,
    env_arg,
    mount_arg,
    project_slug,
)
from ..files import (
    expand_home,
    is_under,
    private_dir,
    settings_object,
    try_lock_file,
    write_whole,
)
from ..notice import warn
from ..settings import (
    CONTAINER_CLAUDE,
    CONTAINER_HOME,
    SESSION_KERNEL,
    SESSION_SANDBOX,
    Host,
    Settings,
    variable,
)
from .claude_args import is_a_command, says_permissions
from .ending import Ending
from .fingerprint import home_git_configs, included_configs
from .home import home_args, place_in_base, session_state, statusline_of
from .image import Image
from .mounts import SHADOWED_NAMES, kept_out, names_secrets
from .networks import PROXY_NETWORKS
from .runtime import DOCKERS_OWN, Runtime

# Of the name of a session, as much as is kept: a file takes no more than
# 255 bytes for a name, and the launcher names files after a session with
# more put after (its sidecars, its records)
SESSION_NAME_WIDTH = 128


def _claim_name(directory: str, name: str) -> int | None:
    """Claim a name among the launchers, none when another has it: the
    lock held on a file of that name, see lock_file."""
    return try_lock_file(os.path.join(directory, name))


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
    # No longer than files named after it can take, see SESSION_NAME_WIDTH
    name = docker_safe_name(name)[:SESSION_NAME_WIDTH]
    # Buffer names are only unique within one Emacs, so a second Emacs (or a
    # plain shell) on the same project asks for a name that is already
    # taken. Step past it rather than fail, the other session is still live.
    base = name.removesuffix("-")
    directory = private_dir(host.names_dir)
    candidate, number = base, 2
    while True:
        # Never the name of a proxy, running or not: a session of that
        # name would be taken for it, and removed as one that is idle
        reserved = candidate in PROXY_NETWORKS
        claim = None if reserved else _claim_name(directory, candidate)
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


def _telemetry_args(settings: Settings) -> list[str]:
    """Unless CLAUDE_AIRLOCK_TELEMETRY=1, Claude Code is told to keep its
    usage events and crash reports to itself. They go to third parties
    (Datadog for one) outside of any tool call, with what they hold not
    the user's to see. Nothing a session does depends on them. DO_NOT_TRACK
    says the same to the tools a session runs that go by it, on top of
    those the image names (see base.Dockerfile)."""
    if settings.telemetry:
        return []
    return [
        env_arg("DISABLE_TELEMETRY", 1),
        env_arg("DISABLE_ERROR_REPORTING", 1),
        env_arg("DO_NOT_TRACK", 1),
    ]


def _connector_args(settings: Settings) -> list[str]:
    """Unless CLAUDE_AIRLOCK_CONNECTORS=1, Claude Code is told not to load
    the connectors of the claude.ai account (Gmail, Google Drive and the
    like). They are a way out of the sandbox with the user's own access,
    which no other setting closes, and each brings its tools and its
    instructions into every request of a session that has no use for
    them."""
    if settings.connectors:
        return []
    return [env_arg("ENABLE_CLAUDEAI_MCP_SERVERS", "false")]


def permission_args(settings: Settings, claude_args: list[str]) -> list[str]:
    """Unless CLAUDE_AIRLOCK_ASK=1, claude is told not to ask before it
    uses a tool: the container is what keeps a session from the host, and
    a question for every command is no safeguard on top of it that anyone
    reads for long. Not when its arguments say how to go about permissions
    themselves, and not for a command of claude's that is no session. What
    this leaves open is said in the README (Known limits): the project and
    the network, which a session can reach without being asked."""
    if settings.ask or is_a_command(claude_args) or says_permissions(claude_args):
        return []
    return ["--dangerously-skip-permissions"]


# The number of the one user the image has besides root, sandbox, which
# its base image gave it
IMAGE_UID = 1000
# What a session whose user has another number is given as /etc/passwd:
# root, the user of the session under the image's name and with its home,
# and nobody
KNOWN_USERS = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "sandbox:x:{uid}:{gid}::{home}:/bin/bash\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
)


def _users_file(host: Host, uid: int, gid: int) -> str:
    """The passwd of a session whose user is not the image's, see
    user_args: a file of the launcher's, made when it is not there or
    says something else."""
    path = os.path.join(private_dir(host.state_dir), "passwd")
    content = KNOWN_USERS.format(uid=uid, gid=gid, home=CONTAINER_HOME)
    try:
        kept = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        kept = ""
    if kept != content:
        write_whole(path, content)
    return path


def user_args(host: Host) -> list[str]:
    """Who a session runs as: the user of the launcher, so that what it
    writes in the project is theirs. The image knows one user, by the
    number IMAGE_UID. A session of a user with another number (501 on
    macOS, a second account on Linux) would run as nobody the image has
    heard of, and what asks who it is fails for it: ssh above all ("No
    user exists for uid 501"), and with it git over SSH and the door of
    the SSH agent. So such a session is given a passwd in which that
    number is the image's user. Not root, which the image knows."""
    uid, gid = os.getuid(), os.getgid()
    args = [f"--user={uid}:{gid}"]
    if uid not in (0, IMAGE_UID):
        args.append(mount_arg(_users_file(host, uid, gid), "/etc/passwd", "ro,z"))
    return args


def base_args(
    settings: Settings, host: Host, name: str, runtime: Runtime = DOCKERS_OWN
) -> list[str]:
    """What every session gets: identity, the core mounts, the hardening and
    the resource limits, adjusted for its runtime."""
    return [
        "--rm",
        "--interactive",
        # Docker keeps nothing of what the session writes: kept, it would
        # be read by docker logs, which the Docker socket allows a session
        # of another project (CLAUDE_AIRLOCK_DOCKER_SOCKET), a chat whole
        "--log-driver=none",
        # Claude runs as PID 1 and does not reap orphaned children, without
        # an init, zombies accumulate and count toward --pids-limit
        "--init",
        f"--name={name}",
        *user_args(host),
        f"--workdir={host.project_dir}",
        # Run under the host home path (symlinked to /home/sandbox in the image)
        # so absolute paths in the config of ~/.claude resolve consistently
        env_arg("HOME", host.home),
        env_arg("TERM", "xterm-256color"),
        env_arg("INSIDE_EMACS", ""),
        # Claude's TUI defaults to the alternate screen, which has no
        # scrollback of its own (e.g. inside Emacs eat): everything above the
        # current viewport is gone. Render inline instead so old output stays
        # in the terminal's scrollback.
        env_arg("CLAUDE_CODE_DISABLE_ALTERNATE_SCREEN", 1),
        env_arg("CLAUDE_CONFIG_DIR", CONTAINER_CLAUDE),
        *_telemetry_args(settings),
        *_connector_args(settings),
        # For a statusline of the user's own to show the sandbox and the
        # network mode in the Claude UI
        env_arg(SESSION_SANDBOX, name),
        env_arg(variable("net_filter"), int(settings.net_filter)),
        # The session is told its settings, so that Claude can name the one
        # behind something it could not do (see docker/CLAUDE-airlock.md).
        # The other switches are only set when they are on, by the code
        # that acts on them.
        env_arg(variable("net_log"), int(settings.net_log)),
        env_arg(variable("proc_log"), int(settings.proc_log)),
        env_arg(variable("cache"), int(settings.cache)),
        env_arg(variable("memory"), settings.memory),
        env_arg(variable("pids"), settings.pids),
        *([env_arg(variable("cpus"), settings.cpus)] if settings.cpus else []),
        # And of a kernel of its own, under which it is ended as a whole
        # at a limit and has to keep well below it, see runtime.py
        *([env_arg(SESSION_KERNEL, runtime.KIND)] if runtime.KIND else []),
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
        # keep it self-contained. Nor is ~/.local/state/claude, which
        # is every project's on the host: a session has one of its own,
        # see session_state of home.py.
        DROP_CAPABILITIES,
        NO_NEW_PRIVILEGES,
        "--read-only",
        # No core of a process that crashed: it holds what the process had
        # in memory, and goes to a file in the project or to the host's own
        # collector, whichever the host's kernel is set for
        "--ulimit=core=0",
        *_scratch_args(settings, host),
        # Some runtimes use part of this limit themselves, see runtime.py
        f"--pids-limit={runtime.process_limit(settings.pids)}",
        # Same value for swap, otherwise docker allows as much swap again on top
        f"--memory={settings.memory}",
        f"--memory-swap={settings.memory}",
        # Not ended at this limit as at that of memory, held back: what a
        # session runs gets no more of the machine's CPUs than so many
        *([f"--cpus={settings.cpus}"] if settings.cpus else []),
        # A stronger runtime when asked for, such as gVisor, which keeps
        # the container off the host kernel. It must be registered in the
        # daemon. See runtime.py for what differs under it.
        *([f"--runtime={settings.runtime}"] if settings.runtime else []),
    ]


def _configured_statusline(host: Host) -> list[str]:
    """The files ~/.claude/settings.json may run as its statusline: the
    program of the command, and the first thing that program is given,
    its script when it is an interpreter ("bash ~/.claude/statusline.sh").
    Those that are named by their whole path.

    Of the host's settings alone, which a session cannot write unless
    CLAUDE_AIRLOCK_RW_CONFIG is on: never of a project's, where a session
    could name any file of the home directory to have it mounted next
    time."""
    try:
        settings = settings_object(Path(host.claude_dir, "settings.json"))
        words = shlex.split(statusline_of(settings))
    except ValueError:
        return []
    given = [word for word in words[1:] if not word.startswith("-")]
    named = [expand_home(word, host.home) for word in words[:1] + given[:1]]
    return [os.path.normpath(path) for path in named if os.path.isabs(path)]


def own_statusline_args(
    settings: Settings, host: Host, mounted: Sequence[str]
) -> list[str]:
    """A statusline of the user's own, for Claude Code's native UI: the
    file ~/.claude/settings.json runs as one is mounted alone, read-only,
    where the settings name it. Claude Code runs it in the container,
    which has the settings and without this not the file.

    Only a plain file of the home directory, where a session has nothing
    but what the launcher mounts: a path anywhere else could be a
    program of the image, which the host's must not stand in for. Not
    what is in the project or a directory mounted next to it (mounted),
    which is there already, not a file whose name says it holds
    secrets (see hidden_files of mounts.py), and not one in a directory
    that is never a session's to have (see kept_out of mounts.py): the
    user's keys, the launcher's settings and records. Where a session
    can write the settings (CLAUDE_AIRLOCK_RW_CONFIG, or settings kept
    as a link into a directory it is given), it names the file, and
    would be given any of the home it named. What the script needs
    besides itself has to be in the image, or in a directory mounted
    next to the project (CLAUDE_AIRLOCK_EXTRA_DIRS_RO)."""
    for path in _configured_statusline(host):
        if not is_under(path, host.home) or ":" in path:
            continue
        if not os.path.isfile(path):
            continue
        if any(is_under(path, root) for root in mounted):
            continue
        patterns = SHADOWED_NAMES + settings.shadow
        names = {os.path.basename(path), os.path.basename(os.path.realpath(path))}
        if any(names_secrets(name, patterns) for name in names):
            warn(f"the statusline {path} is not mounted: its name is one of secrets")
            continue
        # Claude's own directory is the one where a statusline is kept as
        # a rule, and what of it a session has is the launcher's to say
        kept = kept_out(path, host, but=(host.claude_dir,))
        if kept:
            warn(
                f"the statusline {path} is not mounted: {kept} is not a"
                " session's to have"
            )
            continue
        inner = os.path.relpath(path, host.home)
        in_claude = os.path.relpath(path, host.claude_dir)
        if not in_claude.startswith(os.pardir) and not place_in_base(host, in_claude):
            # There already with what the launcher mounts of ~/.claude,
            # or no place for it could be made
            continue
        return [mount_arg(path, f"{CONTAINER_HOME}/{inner}", "ro,z")]
    return []


# What a session can write to outside its mounts. /tmp is where builds and
# test binaries run. Each is sized, a tmpfs is as large as half of the
# machine's memory otherwise.
SCRATCH = (
    Tmpfs("/tmp", 4096, runs=True),  # noqa: S108
    Tmpfs(f"{CONTAINER_HOME}/.config", 64),
    Tmpfs(f"{CONTAINER_HOME}/.npm", 1024, runs=True),
)
CACHE = Tmpfs(f"{CONTAINER_HOME}/.cache", 2048, runs=True)
# What is written there counts towards the session's memory limit, and is
# not given back when a process is ended for want of memory. So together
# they get no more than this much of the limit, each less by as much as it
# takes: a full one then says that it is full, with memory left to run in.
SCRATCH_SHARE = 0.5
# A memory limit as docker reads it: a number, and what it counts in
_MEMORY = re.compile(r"(\d+(?:\.\d+)?) ?([kmgtp]?)i?b?", re.IGNORECASE)
_MEGABYTES = {"": 2**-20, "k": 2**-10, "m": 1, "g": 2**10, "t": 2**20, "p": 2**30}


def memory_megabytes(limit: str) -> float | None:
    """A memory limit in megabytes, none for one that cannot be read:
    docker says what is wrong with it."""
    said = _MEMORY.fullmatch(limit.strip())
    if said is None:
        return None
    return float(said.group(1)) * _MEGABYTES[said.group(2).lower()]


def _scratch_args(settings: Settings, host: Host) -> list[str]:
    """What a session writes to that is not mounted from the host: the
    tmpfs of SCRATCH and those of what Claude Code keeps for one session
    (see session_state of home.py), sized for its memory limit (see
    SCRATCH_SHARE), and ~/.cache, which holds the Go module, uv and npm caches. By default
    that is a named volume per project, so sessions do not download
    everything again. Per project on purpose: a shared cache would let a
    compromised session poison the dependencies of every other project.
    Unlike the tmpfs it has no size cap, remove the claude-cache-* volumes
    to reclaim the space."""
    mounts = [*session_state(), *SCRATCH, *([] if settings.cache else [CACHE])]
    limit = memory_megabytes(settings.memory)
    share = 1.0
    # None is set with 0, as docker has it
    if limit:
        wanted = sum(mount.megabytes for mount in mounts)
        share = min(1.0, limit * SCRATCH_SHARE / wanted)
    args = [mount.arg(share) for mount in mounts]
    if settings.cache:
        volume = f"claude-cache-{project_slug(host.project_dir)}"
        args.append(mount_arg(volume, CACHE.target))
    return args


def session_args(action: Action, env: Mapping[str, str]) -> list[str]:
    """What depends on how this one session was started."""
    args = []
    if action is Action.SHELL:
        args.append("--entrypoint=bash")
    # A TTY only when there is one, so piped and scripted runs (claude -p)
    # work instead of failing with "the input device is not a TTY". Never
    # for a chat, which speaks to claude over pipes (see chat/).
    if action is not Action.LINE_MODE and sys.stdin.isatty() and sys.stdout.isatty():
        args.append("--tty")
    # Passed through when set. GH_TOKEN is how gh authenticates in here, its
    # config directory is a tmpfs.
    for name in ("ANTHROPIC_API_KEY", "GH_TOKEN", "CLAUDE_BUFFER_NAME"):
        if name in env:
            args.append(env_arg(name))
    return args


# What git reads of its directory in XDG_CONFIG_HOME that is forwarded. Not
# the directory whole: git's store helper keeps passwords in clear there
# (credentials, or the file its --file names), and whatever else is put
# there is not known to be free of them.
XDG_GIT_FORWARDED = ("config", "ignore", "attributes", "templates")


def _include_withheld(
    path: str, settings: Settings, host: Host, mounted: Sequence[str]
) -> str | None:
    """Why a file the git config includes is not mounted, none when it
    is. A config can be a link into a directory a session was given
    (dotfiles kept in a repository), and what it includes is then the
    session's to name, for the next launch of any project to mount: as
    for the statusline (see own_statusline_args), not what is in a
    directory that is never a session's to have, the user's keys and the
    launcher's settings and records, nor a file whose name says it holds
    secrets, nor one docker cannot take. Empty, for nothing to say, for
    what is in the project or a directory mounted next to it, which is
    there already."""
    if any(is_under(path, root) for root in mounted):
        return ""
    if ":" in path:
        return "docker takes no path with a colon"
    patterns = SHADOWED_NAMES + settings.shadow
    names = {os.path.basename(path), os.path.basename(os.path.realpath(path))}
    if any(names_secrets(name, patterns) for name in names):
        return "its name is one of secrets"
    kept = kept_out(path, host)
    if kept:
        return f"{kept} is not a session's to have"
    return None


def git_config_args(
    settings: Settings, host: Host, mounted: Sequence[str]
) -> list[str]:
    """Forward the git config, read-only, and no credentials with it (see
    XDG_GIT_FORWARDED)."""
    args = []
    gitconfig = os.path.join(host.home, ".gitconfig")
    if os.path.isfile(gitconfig):
        args.append(mount_arg(gitconfig, f"{CONTAINER_HOME}/.gitconfig", "ro,z"))
    xdg_git = os.path.join(host.config_home, "git")
    forwarded = {gitconfig}
    for name in XDG_GIT_FORWARDED:
        path = os.path.join(xdg_git, name)
        if os.path.exists(path):
            target = f"{CONTAINER_HOME}/.config/git/{name}"
            args.append(mount_arg(path, target, "ro,z"))
            forwarded.add(path)

    # Files pulled in with include/includeIf (e.g. a work identity under
    # "gitdir:~/work/") live outside the mounts, so without this they
    # silently never apply. Mounted at their host path, the one the config
    # refers to, and those they pull in too. A relative path is taken
    # from the config that names it, as git takes it. Not what
    # _include_withheld keeps back, nor what that includes, which git in
    # the session cannot read then.
    def taken(path: str) -> bool:
        withheld = _include_withheld(path, settings, host, mounted)
        if withheld:
            warn(f"{path}, which the git config includes, is not mounted: {withheld}")
        return withheld is None

    for path in included_configs(home_git_configs(host), host.home, taken):
        if path not in forwarded:
            args.append(mount_arg(path, path, "ro,z"))
            forwarded.add(path)
    return args


def run_session(
    run_args: list[str],
    image: Image,
    command_args: list[str],
    ending: Ending,
    through: Callable[[list[str]], int] | None = None,
) -> int:
    """Run the container and wait for it. Not an exec: the launcher has to
    outlive the session to check what it left behind, see interrupts_held
    and ending_passed_on. Not at all when the launcher was told to end
    before it got here. With through, that is given the arguments of docker
    to run and returns how it ended, as a chat does (see chat/)."""
    try:
        if ending.signal is not None:
            return 0
        command = ["run", *run_args, image.tag, *command_args]
        if through:
            status = through(command)
        else:
            # For as long as the session runs
            status = docker(*command, timeout=None).returncode
    finally:
        ending.session_over()
    # Killed by a signal: report it the way a shell would
    return status if status >= 0 else 128 - status
