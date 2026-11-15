"""The session container: the directories mounted into it, its docker run
options and the run itself."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import shlex
import shutil
import signal
import stat
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .docker import docker, docker_ok, docker_safe_name, env_arg, mount_arg
from .image import Image
from .settings import BIN_DIR, Fatal, Host, Settings

CONTAINER_HOME = "/home/node"

SHADOWED_NAMES = (".env", ".env.*", ".envrc", ".netrc", ".pypirc")
SHADOW_EXEMPT = (".env.example", ".env.sample", ".env.template")
SHADOW_PRUNED_DIRS = ("node_modules", ".git")


@dataclass(frozen=True)
class ExtraDir:
    """A host directory mounted alongside the project, at its host path."""

    path: str
    read_only: bool = False


def refuse_unsafe_dir(path: str, host: Host) -> None:
    """Refuse the filesystem root, the home directory or any of its parents:
    mounting one read-write would expose the whole home and defeat the
    sandbox."""
    directory = path.removesuffix("/")
    if (host.home + "/").startswith(directory + "/"):
        raise Fatal(f"refusing to mount {path}: it would defeat the sandbox")


def resolve_dir(raw: str, host: Host) -> str:
    """Absolute path of an existing directory, expanding a leading ~ (the
    shell does not expand it in the --add-dir=~/x form)."""
    expanded = raw
    if raw == "~":
        expanded = host.home
    elif raw.startswith("~/"):
        expanded = host.home + raw[1:]
    path = os.path.normpath(os.path.join(host.project_dir, expanded))
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


def container_name(host: Host, env: Mapping[str, str]) -> str:
    """claude-{project}[-{instance}], the instance taken from the Emacs
    buffer name (*claude:dir:instance*) so parallel sessions never clash."""
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
    candidate, number = base, 2
    while docker_ok("container", "inspect", candidate):
        candidate = f"{base}-{number}"
        number += 1
    return candidate


def prepare_claude_dir(settings: Settings, host: Host) -> None:
    """Create what the mounts below expect to find in the host's ~/.claude."""
    os.makedirs(host.claude_dir, exist_ok=True)
    os.makedirs(os.path.join(host.home, ".local", "state", "claude"), exist_ok=True)

    # Claude writes its global config atomically (temp file + rename). The
    # default location, a single-file bind mount of ~/.claude.json, can't be
    # renamed over, and the container home is read-only, so every config write
    # is lost and Claude re-prompts (theme, folder trust) on each launch.
    # CLAUDE_CONFIG_DIR points at the mounted ~/.claude directory instead:
    # there the config is a regular file in a writable mount, so atomic
    # writes persist. Seed it from the host's global config on first use so
    # onboarding, theme and account carry over.
    seeded = os.path.join(host.claude_dir, ".claude.json")
    host_config = os.path.join(host.home, ".claude.json")
    if not os.path.isfile(seeded) and os.path.isfile(host_config):
        shutil.copy(host_config, seeded)

    # So there is something to protect, a missing settings file could
    # otherwise be created from inside the container
    settings_json = os.path.join(host.claude_dir, "settings.json")
    if not settings.rw_config and not os.path.exists(settings_json):
        Path(settings_json).write_text("{}\n", encoding="utf-8")


def base_args(settings: Settings, host: Host, name: str) -> list[str]:
    """What every session gets: identity, the core mounts, the hardening and
    the resource limits."""
    state_dir = os.path.join(host.home, ".local", "state", "claude")
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
        # so absolute paths in the shared ~/.claude config resolve consistently
        env_arg("HOME", host.home),
        env_arg("TERM", "xterm-256color"),
        env_arg("INSIDE_EMACS", ""),
        # Claude's TUI defaults to the alternate screen, which has no
        # scrollback of its own (e.g. inside Emacs eat): everything above the
        # current viewport is gone. Render inline instead so old output stays
        # in the terminal's scrollback.
        env_arg("CLAUDE_CODE_DISABLE_ALTERNATE_SCREEN", 1),
        env_arg("CLAUDE_CONFIG_DIR", f"{CONTAINER_HOME}/.claude"),
        # Read by bin/claude-statusline to show a sandbox badge and the
        # network mode in the Claude UI
        env_arg("CLAUDE_DOCKER_SANDBOX", name),
        env_arg("CLAUDE_DOCKER_NET_FILTER", int(settings.net_filter)),
        # No gpg binary (or key) in the image, so a host gitconfig with
        # commit.gpgsign=true would make every commit fail. Sign the
        # sandbox's commits at review time, before pushing.
        env_arg("GIT_CONFIG_COUNT", 2),
        env_arg("GIT_CONFIG_KEY_0", "commit.gpgsign"),
        env_arg("GIT_CONFIG_VALUE_0", "false"),
        env_arg("GIT_CONFIG_KEY_1", "tag.gpgsign"),
        env_arg("GIT_CONFIG_VALUE_1", "false"),
        mount_arg(host.project_dir, host.project_dir, "z"),
        mount_arg(host.claude_dir, f"{CONTAINER_HOME}/.claude", "z"),
        # ~/.local/share/claude is NOT mounted. It holds the versioned claude
        # binary the launcher symlinks to, mounting the host's copy shadows
        # the image's baked-in version, dangling the symlink (exit 127). The
        # image owns the version (auto-updater is off, update = rebuild), so
        # keep it self-contained.
        mount_arg(state_dir, f"{CONTAINER_HOME}/.local/state/claude", "z"),
        *statusline_args(host),
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
    project = docker_safe_name(os.path.basename(host.project_dir))
    suffix = hashlib.sha256(host.project_dir.encode()).hexdigest()[:8]
    return mount_arg(f"claude-cache-{project}-{suffix}", target)


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


PROTECTED_CONFIG = ("settings.json", "hooks", "CLAUDE.md", "skills", "agents")


def protect_config_args(settings: Settings, host: Host) -> list[str]:
    """~/.claude is shared read-write with the host, and settings.json and
    hooks hold commands the host's own claude runs. Left writable, a
    compromised session could plant a hook there and get code execution
    outside the sandbox, so they are mounted read-only on top. CLAUDE.md,
    skills and agents get the same treatment: they are instructions every
    later session follows, on the host too. The cost: none of these can be
    changed from inside the sandbox. CLAUDE_DOCKER_RW_CONFIG=1 opts out.
    Plugins stay writable (claude updates them itself), their hook scripts
    are the remaining gap."""
    if settings.rw_config:
        # Shown by bin/claude-statusline
        return [env_arg("CLAUDE_DOCKER_RW_CONFIG", 1)]
    return [
        mount_arg(
            f"{host.claude_dir}/{item}", f"{CONTAINER_HOME}/.claude/{item}", "ro,z"
        )
        for item in PROTECTED_CONFIG
        if os.path.exists(os.path.join(host.claude_dir, item))
    ]


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


def ssh_agent_args(settings: Settings, env: Mapping[str, str]) -> list[str]:
    """Forward the SSH agent, opt-in with CLAUDE_DOCKER_SSH_AGENT=1: the
    agent lets the container authenticate as you to every host your keys
    reach, not only the git remote. Loading keys with ssh-add -c makes each
    use ask first. Docker Desktop on macOS exposes the host agent at a fixed
    path, the host SSH_AUTH_SOCK is not mountable there."""
    if not settings.ssh_agent:
        return []
    target = "/tmp/ssh-agent.sock"
    macos_sock = "/run/host-services/ssh-auth.sock"
    if sys.platform == "darwin" and os.path.exists(macos_sock):
        agent_mount = mount_arg(macos_sock, target)
    elif env.get("SSH_AUTH_SOCK"):
        agent_mount = mount_arg(env["SSH_AUTH_SOCK"], target, "z")
    else:
        return []
    return [
        agent_mount,
        env_arg("SSH_AUTH_SOCK", target),
        # Shown by bin/claude-statusline
        env_arg("CLAUDE_DOCKER_SSH_AGENT", 1),
    ]


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
    args = []
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
                    args.append(mount_arg("/dev/null", path, "ro"))
    return args


def run_session(run_args: list[str], image: Image, command_args: list[str]) -> int:
    """Run the container and wait for it. Not an exec: the launcher has to
    outlive the session to check what it left behind. Ctrl-C reaches docker
    as well (same foreground process group) and ends the session there, the
    launcher only has to survive it."""
    previous = signal.signal(signal.SIGINT, lambda *_: None)
    try:
        status = docker("run", *run_args, image.tag, *command_args).returncode
    finally:
        signal.signal(signal.SIGINT, previous)
    # Killed by a signal: report it the way a shell would
    return status if status >= 0 else 128 - status
