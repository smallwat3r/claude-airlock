"""The session container: its name, its docker run options and the run
itself. What of the host is mounted into it is in mounts.py, how the
launcher ends while it runs in ending.py."""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from .claude_args import is_a_command, says_permissions
from .docker import (
    Tmpfs,
    docker,
    docker_ok,
    docker_safe_name,
    env_arg,
    mount_arg,
    project_slug,
)
from .ending import Ending
from .files import expand_home, json_object, private_dir, try_lock_file
from .home import home_args, session_state, statusline_of
from .image import Image
from .runtime import DOCKERS_OWN, Runtime
from .settings import (
    BIN_DIR,
    CONTAINER_CLAUDE,
    CONTAINER_HOME,
    Host,
    Settings,
)


def claim_name(directory: str, name: str) -> int | None:
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


def connector_args(settings: Settings) -> list[str]:
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


def base_args(
    settings: Settings, host: Host, name: str, runtime: Runtime = DOCKERS_OWN
) -> list[str]:
    """What every session gets: identity, the core mounts, the hardening and
    the resource limits, adjusted for its runtime."""
    return [
        "--rm",
        "--interactive",
        # Claude runs as PID 1 and does not reap orphaned children, without
        # an init, zombies accumulate and count toward --pids-limit
        "--init",
        f"--name={name}",
        f"--user={os.getuid()}:{os.getgid()}",
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
        *telemetry_args(settings),
        *connector_args(settings),
        # Read by bin/claude-statusline to show a sandbox badge and the
        # network mode in the Claude UI
        env_arg("CLAUDE_AIRLOCK_SANDBOX", name),
        env_arg("CLAUDE_AIRLOCK_NET_FILTER", int(settings.net_filter)),
        # The session is told its settings, so that Claude can name the one
        # behind something it could not do (see docker/CLAUDE-airlock.md).
        # The other switches are only set when they are on, by the code
        # that acts on them.
        env_arg("CLAUDE_AIRLOCK_NET_LOG", int(settings.net_log)),
        env_arg("CLAUDE_AIRLOCK_PROC_LOG", int(settings.proc_log)),
        env_arg("CLAUDE_AIRLOCK_CACHE", int(settings.cache)),
        env_arg("CLAUDE_AIRLOCK_MEMORY", settings.memory),
        env_arg("CLAUDE_AIRLOCK_PIDS", settings.pids),
        *([env_arg("CLAUDE_AIRLOCK_CPUS", settings.cpus)] if settings.cpus else []),
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
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        # No core of a process that crashed: it holds what the process had
        # in memory, and goes to a file in the project or to the host's own
        # collector, whichever the host's kernel is set for
        "--ulimit=core=0",
        *scratch_args(settings, host),
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


def configured_statusline(host: Host) -> str | None:
    """The program ~/.claude/settings.json runs as its statusline, if any."""
    try:
        text = Path(host.claude_dir, "settings.json").read_text(encoding="utf-8")
        words = shlex.split(statusline_of(json_object(text) or {}))
    except (OSError, ValueError):
        return None
    program = expand_home(words[0] if words else "", host.home)
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


# What a session can write to outside its mounts. /tmp is where builds and
# test binaries run. Each is sized, a tmpfs is as large as half of the
# machine's memory otherwise.
SCRATCH = (
    Tmpfs("/tmp", 4096, runs=True),
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


def scratch_args(settings: Settings, host: Host) -> list[str]:
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


def session_args(action: str, env: Mapping[str, str]) -> list[str]:
    """What depends on how this one session was started."""
    args = []
    if action == "shell":
        args.append("--entrypoint=bash")
    # A TTY only when there is one, so piped and scripted runs (claude -p)
    # work instead of failing with "the input device is not a TTY". Never
    # for a chat, which speaks to claude over pipes (see chat/).
    if action != "line-mode" and sys.stdin.isatty() and sys.stdout.isatty():
        args.append("--tty")
    # Passed through when set. GH_TOKEN is how gh authenticates in here, its
    # config directory is a tmpfs.
    for name in ("ANTHROPIC_API_KEY", "GH_TOKEN", "CLAUDE_BUFFER_NAME"):
        if name in env:
            args.append(env_arg(name))
    return args


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


# What git reads of its directory in XDG_CONFIG_HOME that is forwarded. Not
# the directory whole: git's store helper keeps passwords in clear there
# (credentials, or the file its --file names), and whatever else is put
# there is not known to be free of them.
XDG_GIT_FORWARDED = ("config", "ignore", "attributes", "templates")


def git_config_args(host: Host) -> list[str]:
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
    # refers to. Relative paths are taken from the home directory, where
    # ~/.gitconfig is.
    for path in git_include_paths():
        # Also one that is absolute, which the join leaves as it is
        path = os.path.normpath(os.path.join(host.home, expand_home(path, host.home)))
        if path in forwarded:
            continue
        if os.path.isfile(path):
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
            status = docker(*command).returncode
    finally:
        ending.session_over()
    # Killed by a signal: report it the way a shell would
    return status if status >= 0 else 128 - status
