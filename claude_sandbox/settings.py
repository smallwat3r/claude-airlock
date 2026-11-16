"""What a session is configured from: the CLAUDE_DOCKER_* settings, the
user's config file, and where things are on the host."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

# The checkout's bin and docker directories, found from where this package
# really is, so bin/claude-docker can be symlinked from anywhere
_REPO_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
BIN_DIR = os.path.join(_REPO_DIR, "bin")
DOCKERFILE_DIR = os.path.join(_REPO_DIR, "docker")

# What more than one module has to agree on: the home of the image's user,
# and the port the egress proxy listens on
CONTAINER_HOME = "/home/node"
EGRESS_PORT = 3128

SETTING_PREFIX = "CLAUDE_DOCKER_"
# The settings a config file may hold, without their prefix. EXTRA_DIRS and
# EXTRA_DIRS_RO are left out on purpose, what to mount next to a project is
# a per-project choice, not a default for every session.
CONFIG_FILE_SETTINGS = frozenset(
    {
        "FEATURES",
        "NET_FILTER",
        "NET_LOG",
        "PROC_LOG",
        "TELEMETRY",
        "SSH_AGENT",
        "SOCKET",
        "RW_CONFIG",
        "SHARED_HISTORY",
        "SHADOW",
        "PROTECT",
        "MEMORY",
        "PIDS",
        "CACHE",
        "RUNTIME",
        "SHARED_DIR",
    }
)


def private_dir(path: str) -> str:
    """Create a directory for the launcher's own records, with its parents,
    for the user alone: what is kept there says which hosts a session
    reached. Returns the path."""
    # One level at a time, makedirs gives its mode to the last one alone
    missing = []
    directory = path
    while directory and not os.path.isdir(directory):
        missing.append(directory)
        directory = os.path.dirname(directory)
    for directory in reversed(missing):
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            # Another launcher was first
            continue
    return path


class Fatal(Exception):
    """A problem to report to the user as one line, without a traceback."""


@dataclass(frozen=True)
class Settings:
    """Every CLAUDE_DOCKER_* setting. The defaults here are the launcher's
    defaults, the one place to change them."""

    # None falls back to features.txt, then to every feature, "" selects none
    features: str | None = None
    net_filter: bool = False
    net_log: bool = True
    proc_log: bool = True
    telemetry: bool = False
    ssh_agent: bool = False
    socket: str = "0"  # 0, 1 or full
    rw_config: bool = False
    shared_history: bool = False
    shadow: tuple[str, ...] = ()
    # Paths that are read-only in every session that has them mounted
    protect: tuple[str, ...] = ()
    memory: str = "16g"
    pids: str = "512"
    cache: bool = True
    runtime: str = ""
    # None is ~/claude-shared when it exists, "" no shared directory
    shared_dir: str | None = None
    extra_dirs: tuple[str, ...] = ()
    extra_dirs_ro: tuple[str, ...] = ()


@dataclass(frozen=True)
class Host:
    """The places on the host a session is built from."""

    home: str
    project_dir: str
    config_home: str  # XDG_CONFIG_HOME, ~/.config by default
    state_home: str  # XDG_STATE_HOME, ~/.local/state by default

    @property
    def user_conf(self) -> str:
        return os.path.join(self.config_home, "claude-sandbox")

    @property
    def claude_dir(self) -> str:
        return os.path.join(self.home, ".claude")

    @property
    def claude_state_dir(self) -> str:
        # Claude Code's own state, mounted into a session
        return os.path.join(self.home, ".local", "state", "claude")

    @property
    def state_dir(self) -> str:
        # The launcher's own records. Never mounted into a session, which
        # could otherwise edit what is kept about it, but for
        # sandbox_claude_dir and history_dir.
        return os.path.join(self.state_home, "claude-sandbox")

    @property
    def sandbox_claude_dir(self) -> str:
        # The ~/.claude of the sandboxed sessions, see home.py. Mounted
        # into every session, with the named parts of the host's on top.
        return os.path.join(self.state_dir, "home")

    @property
    def history_dir(self) -> str:
        # What the sessions of each project remember, see history.py.
        # Mounted into a session too, a project's own store into its
        # sessions.
        return os.path.join(self.state_dir, "history")

    @property
    def login_synced_file(self) -> str:
        # The login the host and the sandbox last had in common, see
        # login.py
        return os.path.join(self.state_dir, "login-synced")

    @property
    def transcript_copies_dir(self) -> str:
        # The launcher's copy of each transcript, see recorder.py
        return os.path.join(self.state_dir, "transcripts")

    @property
    def process_records_dir(self) -> str:
        # What ran in each session, see processes.py
        return os.path.join(self.state_dir, "processes")

    @property
    def doors_file(self) -> str:
        # Each use of the SSH agent and of the Docker socket, see doors.py
        return os.path.join(self.state_dir, "door-use.jsonl")

    @property
    def agent_sockets_dir(self) -> str:
        # Where the sessions' way to the SSH agent listens, see doors.py
        return os.path.join(self.state_dir, "agents")

    @property
    def destinations_file(self) -> str:
        # What each project is known to reach, see digest.py
        return os.path.join(self.state_dir, "destinations.json")

    @property
    def pending_checks_dir(self) -> str:
        # A session's starting point for the check of tamper.py
        return os.path.join(self.state_dir, "pending-checks")

    @property
    def names_dir(self) -> str:
        # The names the running launchers have claimed for their sessions,
        # see container_name in session.py
        return os.path.join(self.state_dir, "names")

    @property
    def net_sessions_file(self) -> str:
        # A line per session with a network record, see records.py
        return os.path.join(self.state_dir, "net-sessions.jsonl")

    @property
    def captures_dir(self) -> str:
        return os.path.join(self.state_dir, "captures")

    @property
    def feature_dirs(self) -> list[str]:
        # Searched in order, so a user feature overrides a bundled one of
        # the same name
        return [
            os.path.join(self.user_conf, "features"),
            os.path.join(DOCKERFILE_DIR, "features"),
        ]


def logical_cwd() -> str:
    """The working directory as the shell shows it, symlinks unresolved, so
    the project is mounted at the path the user and their editor refer to."""
    cwd = os.getcwd()
    pwd = os.environ.get("PWD", "")
    try:
        if os.path.isabs(pwd) and os.path.samefile(pwd, cwd):
            return os.path.normpath(pwd)
    except OSError:
        pass
    return cwd


def detect_host(env: Mapping[str, str]) -> Host:
    home = env.get("HOME") or str(Path.home())
    return Host(
        home=home,
        project_dir=logical_cwd(),
        config_home=env.get("XDG_CONFIG_HOME") or os.path.join(home, ".config"),
        state_home=env.get("XDG_STATE_HOME") or os.path.join(home, ".local", "state"),
    )


def read_config_file(path: str) -> dict[str, str]:
    """Defaults for the CLAUDE_DOCKER_* settings from the user's config file:
    one NAME=value per line, # comments, the value taken literally (no
    quotes, no ~ or variable expansion). A line that is not a known setting
    aborts: a typo must not silently leave a restriction off. Deliberately
    not read from the project, the session can write there and could switch
    its own sandboxing off for the next run."""
    values: dict[str, str] = {}
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return values
    for line in text.split("\n"):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name, separator, value = line.partition("=")
        known = (
            name.startswith(SETTING_PREFIX)
            and name[len(SETTING_PREFIX) :] in CONFIG_FILE_SETTINGS
        )
        if not separator or not known:
            raise Fatal(f"{path}: not a known setting: {line}")
        values[name] = value
    return values


def load_settings(env: Mapping[str, str], config_file: str) -> Settings:
    """Settings from the environment, then the config file, then the
    defaults. A list or a name in the environment wins also when set but
    empty, which says none (no features, no shared directory). A switch
    or a limit that is set but empty says nothing, and the config file is
    asked next: an empty variable must not switch off a restriction the
    file switched on."""
    file_values = read_config_file(config_file)
    defaults = Settings()

    def raw(name: str) -> str | None:
        key = SETTING_PREFIX + name
        return env[key] if key in env else file_values.get(key)

    def text(name: str, default: str) -> str:
        key = SETTING_PREFIX + name
        return env.get(key) or file_values.get(key) or default

    def choice(name: str, default: str, allowed: tuple[str, ...]) -> str:
        value = text(name, default)
        # Not just ignored: "true" for a restriction would otherwise leave
        # it off without a word
        if value not in allowed:
            raise Fatal(
                f"{SETTING_PREFIX}{name} must be {' or '.join(allowed)}, got: {value}"
            )
        return value

    def flag(name: str, default: bool) -> bool:
        return choice(name, "1" if default else "0", ("0", "1")) == "1"

    def colon_list(name: str) -> tuple[str, ...]:
        return tuple(item for item in (raw(name) or "").split(":") if item)

    def both_lists(name: str) -> tuple[str, ...]:
        # Of the file and of the environment: what one protects, the other
        # does not take back
        key = SETTING_PREFIX + name
        said = f"{file_values.get(key, '')}:{env.get(key, '')}"
        return tuple(dict.fromkeys(item for item in said.split(":") if item))

    return Settings(
        features=raw("FEATURES"),
        net_filter=flag("NET_FILTER", defaults.net_filter),
        net_log=flag("NET_LOG", defaults.net_log),
        proc_log=flag("PROC_LOG", defaults.proc_log),
        telemetry=flag("TELEMETRY", defaults.telemetry),
        ssh_agent=flag("SSH_AGENT", defaults.ssh_agent),
        socket=choice("SOCKET", defaults.socket, ("0", "1", "full")),
        rw_config=flag("RW_CONFIG", defaults.rw_config),
        shared_history=flag("SHARED_HISTORY", defaults.shared_history),
        shadow=colon_list("SHADOW"),
        protect=both_lists("PROTECT"),
        memory=text("MEMORY", defaults.memory),
        pids=text("PIDS", defaults.pids),
        cache=flag("CACHE", defaults.cache),
        runtime=text("RUNTIME", defaults.runtime),
        shared_dir=raw("SHARED_DIR"),
        extra_dirs=colon_list("EXTRA_DIRS"),
        extra_dirs_ro=colon_list("EXTRA_DIRS_RO"),
    )
