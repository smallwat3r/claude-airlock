"""The ~/.claude of a session: a directory of the launcher's, with the
named parts of the host's ~/.claude mounted into it.

Claude Code keeps more in ~/.claude than a session has a use for: the
sessions that run on the host and how to reach them, its background jobs,
its daemon, its debug logs, and whatever a later version adds. Mounted
whole, all of it is a session's to read and to write, and so is every name
that is not there yet. So a session is given a directory of its own, the
base, which the sandboxed sessions share, and of the host's ~/.claude only
what is named here:

  settings.json, CLAUDE.md, hooks,    read-only, see protect_config_args
    commands, skills, agents, rules
  plugins                             read-write, Claude updates them itself
  projects                            read-write, the transcripts, with
                                      those of other projects covered, see
                                      history.py

On top of the base go what a project's sessions remember (history.py) and
a tmpfs for what Claude Code keeps for one session (session_state).
The config (.claude.json) is the base's own, see _seed_config. The login
(.credentials.json) is the base's own too, and the launcher keeps it the
same as the host's, see login.py.

Everything else Claude Code writes stays in the base: the host's claude
does not see it, and a session does not see the host's."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from ..docker import Tmpfs, env_arg, mount_arg
from ..files import json_object, private_dir, write_whole
from ..settings import (
    CONFIG_FILES,
    CONFIG_TREES,
    CONTAINER_CLAUDE,
    CONTAINER_STATE,
    Host,
    Settings,
    variable,
)
from .history import PER_PROJECT_DIRS, PROMPT_HISTORY
from .login import LOGIN

CONFIG = ".claude.json"
# What the config seeded from the host's leaves out, see _seed_config
SEED_LEFT_OUT = ("projects", "mcpServers")
# What Claude Code keeps in ~/.claude for one session and reads back into
# its shell: a snapshot of the shell's setup, and what its hooks export. A
# session is given its own of each, empty, see session_state.
SESSION_STATE = ("shell-snapshots", "session-env")
# What a session cannot change of ~/.claude: all that the check of
# tamper.py watches there, the two are one list in settings.py
PROTECTED_CONFIG = (*CONFIG_FILES, *CONFIG_TREES)
# The directories of the host's ~/.claude that a session can write
WRITABLE_TREES = ("plugins", "projects")
# The names of a session's ~/.claude that the launcher has its own way
# with: a mount, a tmpfs, or a file it keeps in the base
MANAGED = frozenset(
    (
        *PROTECTED_CONFIG,
        *WRITABLE_TREES,
        *SESSION_STATE,
        *PER_PROJECT_DIRS,
        PROMPT_HISTORY,
        CONFIG,
        LOGIN,
    )
)


def _read_config(path: Path, left_out: tuple[str, ...] = ()) -> str | None:
    """A config of Claude Code as text, without some of what it holds.
    None when there is none to carry over, or not one to read."""
    try:
        config = json_object(path.read_bytes())
    except OSError:
        return None
    if config is None:
        return None
    for name in left_out:
        config.pop(name, None)
    return json.dumps(config, indent=2)


def _seed_config(host: Host) -> None:
    """Claude writes its global config atomically (temp file + rename). The
    default location, a single-file bind mount of ~/.claude.json, can't be
    renamed over, and the container home is read-only, so every config write
    is lost and Claude re-prompts (theme, folder trust) on each launch.
    CLAUDE_CONFIG_DIR points at the session's ~/.claude instead: there the
    config is a regular file in a writable mount, so atomic writes persist.

    Seeded on first use, so onboarding, theme and account carry over. From
    the config the sandboxed sessions had when the host's ~/.claude was
    mounted whole (~/.claude/.claude.json), as it is: it is theirs, with
    the trust given to each project. That file is left where it is, nothing
    reads it any more. Otherwise from the host's global config. Not what
    that holds of each project (its path, its settings and the servers set
    up for it alone): a session has no use for those of another project,
    see history.py. Nor the servers set up for every project: each comes
    with what it is started with, a token as often as not, which every
    session could then read, and with a command that the image need not
    have. One wanted in here is added in here (claude mcp add). The config
    the sessions then share still gains an entry for each project that is
    run in here."""
    seeded = os.path.join(host.sandbox_claude_dir, CONFIG)
    if os.path.lexists(seeded):
        return
    text = _read_config(Path(host.claude_dir, CONFIG))
    if text is None:
        text = _read_config(Path(host.home, CONFIG), SEED_LEFT_OUT)
    if text is None:
        # Claude starts afresh
        return
    # Whole or not at all, and never over another launcher's: a session
    # that starts meanwhile must not read half a config
    write_whole(seeded, text, replace=False)


def _make_missing(
    directory: str, trees: tuple[str, ...], files: tuple[str, ...]
) -> None:
    """Make the directories and the files of a directory that are not
    there, empty. A file that holds JSON says nothing as {}."""
    for name in trees:
        os.makedirs(os.path.join(directory, name), exist_ok=True)
    for name in files:
        path = os.path.join(directory, name)
        if os.path.lexists(path):
            continue
        # Left as it is when another launcher was first
        write_whole(path, "{}\n" if name.endswith(".json") else "", replace=False)


def prepare_home(host: Host) -> None:
    """Make the base, and what the mounts expect to find.

    In the base, what each mount goes over: docker would make a missing
    one as root, and a directory where a file was meant.

    In the host's ~/.claude, what is mounted from it. All of it, so that
    there is something to mount for each: what had no mount would be the
    session's to create in the base, and the sandboxed sessions after it
    would follow what it put there. Empty, they say nothing."""
    base = private_dir(host.sandbox_claude_dir)
    _make_missing(
        base,
        (*CONFIG_TREES, *WRITABLE_TREES, *SESSION_STATE, *PER_PROJECT_DIRS),
        (*CONFIG_FILES, PROMPT_HISTORY),
    )
    os.makedirs(host.claude_dir, exist_ok=True)
    _make_missing(host.claude_dir, (*CONFIG_TREES, *WRITABLE_TREES), CONFIG_FILES)
    _seed_config(host)


def place_in_base(host: Host, inner: str) -> bool:
    """Make the place in the base for one file of the host's ~/.claude
    that is mounted alone over it, named from ~/.claude. Whether it is
    there to mount over.

    docker would make it as root otherwise. Not when the launcher has
    its own way with the name it is under (settings.json, hooks, plugins,
    the history of a project): what is mounted there is there already,
    and nothing else goes over the rest. Nor through anything a session
    put in the base that is no plain directory or file: a mount over a
    link would land where the link says."""
    names = inner.split(os.sep)
    if names[0] in MANAGED or not all(names) or ".." in names:
        return False
    place = host.sandbox_claude_dir
    try:
        for name in names[:-1]:
            place = os.path.join(place, name)
            if not os.path.lexists(place):
                os.mkdir(place, 0o700)
            if not stat.S_ISDIR(os.lstat(place).st_mode):
                return False
        place = os.path.join(place, names[-1])
        if not os.path.lexists(place):
            write_whole(place, "", replace=False)
        return stat.S_ISREG(os.lstat(place).st_mode)
    except OSError:
        return False


def home_args(host: Host) -> list[str]:
    """The base as a session's ~/.claude, and the directories of the
    host's that a session writes to. Plugins stay the host's and writable
    (claude updates them itself): what a session changes of them is not
    prevented, it is said when the session ends, see tamper.py."""
    return [
        mount_arg(host.sandbox_claude_dir, CONTAINER_CLAUDE, "z"),
        *(
            mount_arg(
                os.path.join(host.claude_dir, name), f"{CONTAINER_CLAUDE}/{name}", "z"
            )
            for name in WRITABLE_TREES
        ),
    ]


def session_state() -> list[Tmpfs]:
    """Claude Code runs every command of a session through what it keeps
    for that session in ~/.claude: it sources the snapshot of the shell,
    and what the session's hooks exported. Those of the other sandboxed
    sessions would be there too, and one written to from in here would run
    its additions with that session's next command, in another project's
    sandbox. So a session is given a tmpfs in place of each: its own are
    made there and gone with it, and it neither sees nor reaches those of
    another session. Whatever CLAUDE_AIRLOCK_RW_CONFIG says, that is about
    the config and this is not config. The session's user's alone: a tmpfs
    is root's unless told otherwise.

    The same for what Claude Code keeps outside ~/.claude, in
    ~/.local/state/claude (its locks). The host's is one directory for
    all that runs there, of every project and of whatever else the user
    has write to it: mounted, each session would read and write what
    the others and the host left. Nothing in it is needed from one
    session to the next, the image has the one version of Claude Code
    it was built with."""
    user = (os.getuid(), os.getgid())
    return [
        *(
            Tmpfs(f"{CONTAINER_CLAUDE}/{name}", 64, runs=True, owner=user, mode="700")
            for name in SESSION_STATE
        ),
        Tmpfs(CONTAINER_STATE, 64, owner=user, mode="700"),
    ]


def protect_config_args(settings: Settings, host: Host) -> list[str]:
    """The host's settings.json and hooks hold commands the host's own
    claude runs. Writable, a compromised session could plant a hook there
    and get code execution outside the sandbox, so they are mounted
    read-only. CLAUDE.md, skills, agents, commands and rules get the same
    treatment: they are instructions every later session follows, on the
    host too. The ones that are missing were made empty by prepare_home,
    so that none can be created either, in the base, where the sandboxed
    sessions would follow it. The cost: none of these can be changed from
    inside the sandbox. CLAUDE_AIRLOCK_RW_CONFIG=1 opts out, they are then
    the host's and writable."""
    mode = "z" if settings.rw_config else "ro,z"
    args = [
        mount_arg(
            os.path.join(host.claude_dir, item), f"{CONTAINER_CLAUDE}/{item}", mode
        )
        for item in PROTECTED_CONFIG
    ]
    if settings.rw_config:
        # Said in docker/CLAUDE-airlock.md
        args.append(env_arg(variable("rw_config"), 1))
    return args


def statusline_of(settings: dict) -> str:
    """The command a settings.json of Claude Code runs as its statusline,
    empty for none."""
    line = settings.get("statusLine")
    if not isinstance(line, dict) or line.get("type") != "command":
        return ""
    command = line.get("command")
    return command if isinstance(command, str) and command.strip() else ""
