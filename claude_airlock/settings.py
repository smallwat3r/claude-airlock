"""What a session is configured from: the CLAUDE_AIRLOCK_* settings, the
user's config file, and where things are on the host."""

from __future__ import annotations

import dataclasses
import enum
import os
import textwrap
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# The checkout's bin and docker directories, found from where this package
# really is, so bin/claude-airlock can be symlinked from anywhere
_REPO_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
BIN_DIR = os.path.join(_REPO_DIR, "bin")
DOCKERFILE_DIR = os.path.join(_REPO_DIR, "docker")

# What more than one module has to agree on: the home of the image's user,
# where a session finds its ~/.claude, and the port the egress proxy
# listens on
CONTAINER_HOME = "/home/sandbox"
CONTAINER_CLAUDE = f"{CONTAINER_HOME}/.claude"
EGRESS_PORT = 3128
# What Claude follows or runs of ~/.claude, on the host as in a session:
# its settings and its instructions, single files then whole directories.
# A session is given them read-only (home.py) and the check of tamper.py
# watches them, here so that the two cannot come apart.
CONFIG_FILES = ("settings.json", "CLAUDE.md")
CONFIG_TREES = ("hooks", "commands", "skills", "agents", "rules")

SETTING_PREFIX = "CLAUDE_AIRLOCK_"
NAME = "claude-airlock"


class Fatal(Exception):
    """A problem to report to the user as one line, without a traceback."""


class SocketAccess(enum.Enum):
    """What of the host's Docker daemon a session reaches, each by what
    CLAUDE_AIRLOCK_DOCKER_SOCKET says for it, see socket_proxy_options of
    network.py."""

    OFF = "0"
    # docker ps and docker logs
    LIMITED = "1"
    # Every read of a container, which adds inspect, stats and top
    FULL = "full"


@dataclass(frozen=True)
class Settings:
    """The value of every CLAUDE_AIRLOCK_* setting, a field for each of
    SETTINGS. The defaults here are the launcher's defaults, the one place
    to change them."""

    # None falls back to features.txt, then to every feature, "" selects none
    features: str | None = None
    net_filter: bool = False
    net_log: bool = True
    proc_log: bool = True
    telemetry: bool = False
    # Whether a session loads the connectors of the claude.ai account
    connectors: bool = False
    ssh_agent: bool = False
    docker_socket: SocketAccess = SocketAccess.OFF
    rw_config: bool = False
    shared_history: bool = False
    shadow: tuple[str, ...] = ()
    # Paths that are read-only in every session that has them mounted
    protect: tuple[str, ...] = ()
    memory: str = "16g"
    pids: str = "512"
    # How many of the machine's CPUs a session can use at most, as docker
    # reads it (4, 1.5), "" for all of them
    cpus: str = ""
    cache: bool = True
    runtime: str = ""
    # Whether Claude Code asks before it uses a tool, as outside the sandbox
    ask: bool = False
    # Whether a session runs in line mode (chat/), not behind Claude
    # Code's own
    line_mode: bool = True
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
        return os.path.join(self.config_home, NAME)

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
        return os.path.join(self.state_home, NAME)

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
    def changes_file(self) -> str:
        # What chats found changed in what Claude Code says, see changes.py
        return os.path.join(self.state_dir, "claude-code-changes.jsonl")

    @property
    def starts_file(self) -> str:
        # How each session's sandbox was started, see started.py
        return os.path.join(self.state_dir, "session-starts.jsonl")

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


class Kind(enum.Enum):
    """How a setting is read, see load_settings."""

    # On with 1, off with 0
    SWITCH = enum.auto()
    # One of the values it names
    CHOICE = enum.auto()
    # Anything, taken as it is
    TEXT = enum.auto()
    # Anything, and set but empty says none: not the same as not set
    NAME = enum.auto()
    # Several, colon separated
    LIST = enum.auto()
    # Several, those of the config file and of the environment together
    MERGED = enum.auto()


@dataclass(frozen=True)
class Setting:
    """One CLAUDE_AIRLOCK_* setting: its name without the prefix, how it is
    read and what --help says of it. Its value is the field of Settings
    of the same name in lower case, its default is the one there."""

    name: str
    kind: Kind
    says: str
    choices: tuple[str, ...] = ("0", "1")
    # For a choice, what its values are read as: one of these, by value
    of: type[enum.Enum] | None = None
    # What to mount next to a project is a per-project choice, not a
    # default for every session: not taken from the config file
    config_file: bool = True

    @property
    def variable(self) -> str:
        return SETTING_PREFIX + self.name

    @property
    def field(self) -> str:
        return self.name.lower()


# Every setting, the one list of them: load_settings reads these, the
# config file takes these and --help names these. The README has a
# row for each and docker/CLAUDE-airlock.md tells a session of those
# it can run into, test/test_settings.py holds both to this list.
SETTINGS = (
    Setting("FEATURES", Kind.NAME, "features to build in, space or comma separated"),
    Setting("NET_FILTER", Kind.SWITCH, "1 restricts egress to allowed-domains.txt"),
    Setting("NET_LOG", Kind.SWITCH, "0 stops recording what a session connects to"),
    Setting("PROC_LOG", Kind.SWITCH, "0 stops recording the processes of a session"),
    Setting(
        "TELEMETRY", Kind.SWITCH, "1 lets Claude Code send usage and crash reports"
    ),
    Setting(
        "CONNECTORS", Kind.SWITCH, "1 loads the connectors of the claude.ai account"
    ),
    Setting("SSH_AGENT", Kind.SWITCH, "1 forwards the SSH agent"),
    Setting(
        "DOCKER_SOCKET",
        Kind.CHOICE,
        "1 allows docker ps and logs, full adds inspect",
        choices=tuple(access.value for access in SocketAccess),
        of=SocketAccess,
    ),
    Setting(
        "RW_CONFIG", Kind.SWITCH, "1 leaves the protected ~/.claude config writable"
    ),
    Setting(
        "SHARED_HISTORY",
        Kind.SWITCH,
        "1 lets a session see what Claude Code remembers of other projects",
    ),
    Setting("SHADOW", Kind.MERGED, "extra file name globs to hide, colon separated"),
    Setting(
        "PROTECT",
        Kind.MERGED,
        "paths that are read-only wherever they are mounted, colon separated",
    ),
    Setting("MEMORY", Kind.TEXT, "memory limit"),
    Setting("PIDS", Kind.TEXT, "process limit"),
    Setting("CPUS", Kind.TEXT, "CPU limit, e.g. 4 or 1.5, all of them when not set"),
    Setting("CACHE", Kind.SWITCH, "0 keeps ~/.cache on a tmpfs, nothing persists"),
    Setting("RUNTIME", Kind.TEXT, "container runtime, e.g. runsc-hostnet for gVisor"),
    Setting("ASK", Kind.SWITCH, "1 has Claude Code ask before it uses a tool"),
    Setting("LINE_MODE", Kind.SWITCH, "0 runs Claude Code with its native UI"),
    Setting(
        "SHARED_DIR",
        Kind.NAME,
        "scratch directory shared between sessions, empty for none",
    ),
    Setting(
        "EXTRA_DIRS",
        Kind.LIST,
        "directories to mount next to the project, colon separated",
        config_file=False,
    ),
    Setting(
        "EXTRA_DIRS_RO",
        Kind.LIST,
        "the same, mounted read-only",
        config_file=False,
    ),
)
# The settings a config file may hold, without their prefix
CONFIG_FILE_SETTINGS = frozenset(
    setting.name for setting in SETTINGS if setting.config_file
)


def settings_help() -> str:
    """The part of --help about the settings: each with what it does and
    the default of a limit, then how to set one for every session."""
    defaults = Settings()
    width = max(len(setting.variable) for setting in SETTINGS) + 2
    lines = ["Environment, all optional:"]
    for setting in SETTINGS:
        says = setting.says
        default = getattr(defaults, setting.field)
        if setting.kind is Kind.TEXT and default:
            says += f" (default {default})"
        if not setting.config_file:
            says += ", not taken from the config file"
        lines += textwrap.wrap(
            says,
            width=78,
            initial_indent=f"  {setting.variable:<{width}}",
            subsequent_indent=" " * (width + 2),
        )
    merged = " and ".join(s.name for s in SETTINGS if s.kind is Kind.MERGED)
    lines += [
        "",
        "To override a default for every session, put NAME=value lines in",
        "~/.config/claude-airlock/config, the environment still wins. Of",
        f"{merged} the lists of both count.",
    ]
    return "\n".join(lines)


def read_config_file(path: str) -> dict[str, str]:
    """Defaults for the CLAUDE_AIRLOCK_* settings from the user's config
    file: one NAME=value per line, # comments, the value taken literally
    (no quotes, no ~ or variable expansion). A line that is not a known
    setting aborts: a typo must not silently leave a restriction off.
    Deliberately not read from the project, the session can write there
    and could switch its own sandboxing off for the next run."""
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
    defaults, each read as its kind says (see Kind). A list or a name in
    the environment wins also when set but empty, which says none (no
    features, no shared directory). A switch, a choice or a text that is
    set but empty says nothing, and the config file is asked next: an
    empty variable must not switch off a restriction the file switched on.
    What is hidden and what is protected are the lists of both, for the
    same reason: what one hides or protects, the other does not take
    back."""
    file_values = read_config_file(config_file)
    defaults = Settings()

    def items(said: str) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item for item in said.split(":") if item))

    def read(setting: Setting) -> Any:
        key, kind = setting.variable, setting.kind
        in_file = file_values.get(key)
        if kind is Kind.NAME:
            return env.get(key, in_file)
        if kind is Kind.LIST:
            return items(env.get(key, in_file or ""))
        if kind is Kind.MERGED:
            return items(f"{in_file or ''}:{env.get(key, '')}")
        default = getattr(defaults, setting.field)
        if kind is Kind.SWITCH:
            default = "1" if default else "0"
        elif isinstance(default, enum.Enum):
            default = default.value
        value = env.get(key) or in_file or default
        if kind is Kind.TEXT:
            return value
        # Not just ignored: "true" for a restriction would otherwise leave
        # it off without a word
        if value not in setting.choices:
            raise Fatal(f"{key} must be {' or '.join(setting.choices)}, got: {value}")
        if kind is Kind.SWITCH:
            return value == "1"
        return setting.of(value) if setting.of else value

    # Each as its kind gives it, which the fields of Settings are typed for
    values = {setting.field: read(setting) for setting in SETTINGS}
    return dataclasses.replace(defaults, **values)
