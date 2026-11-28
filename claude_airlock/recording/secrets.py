"""Which files of a session are taken to hold secrets, for what records
its processes to say when one of them opens one (see Secrets of
procwatch.py, and gvisor.py): the logins of the tools a session can have,
the keys of SSH, of GnuPG and of the clouds, and the files of the names
hidden from it as files of secrets, in the directories it is given (see
hidden_files of mounts.py). Those read as empty, what opens one is after
what it held. One of those names made elsewhere, a fixture of a test in
/tmp say, is no secret kept from it.

Each by its kind, which --trace names. Where a session has its home twice,
under the host's path and the image's own, both are looked for: a process
names a file as it likes, the kernel by where it is."""

from __future__ import annotations

import enum
import os
from collections.abc import Sequence

from ..sandbox.mounts import SHADOW_EXEMPT, SHADOWED_NAMES
from ..settings import CONTAINER_CLAUDE, CONTAINER_HOME, Host, Settings
from .procwatch import Secrets

# The program of Claude Code in the image: what opens its login as a rule
CLAUDE_PROGRAM = "/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"


class Kind(enum.StrEnum):
    """The kinds of secrets a file holds, as a record says them."""

    CLAUDE = "claude"
    GH = "gh"
    GIT = "git"
    DOCKER = "docker"
    CLOUD = "cloud"
    SSH = "ssh"
    GNUPG = "gnupg"
    HIDDEN = "hidden"


# How each is said in a trace
SAID = {
    Kind.CLAUDE: "the login of Claude Code",
    Kind.GH: "the login of gh",
    Kind.GIT: "the credentials git keeps",
    Kind.DOCKER: "the logins of Docker",
    Kind.CLOUD: "the keys of a cloud",
    Kind.SSH: "a file of SSH",
    Kind.GNUPG: "the keys of GnuPG",
    Kind.HIDDEN: "a file hidden as one of secrets",
}

# Under a home, the files that hold secrets
HOME_FILES = {
    ".config/gh/hosts.yml": Kind.GH,
    ".git-credentials": Kind.GIT,
    ".config/git/credentials": Kind.GIT,
    ".docker/config.json": Kind.DOCKER,
    ".aws/credentials": Kind.CLOUD,
    ".kube/config": Kind.CLOUD,
}
# Under a home, the directories every file of which does, but for those
# of PASSED
HOME_DIRS = {
    ".ssh": Kind.SSH,
    ".gnupg": Kind.GNUPG,
    ".config/gcloud": Kind.CLOUD,
    ".azure": Kind.CLOUD,
}
# Of those directories, the files that hold nothing secret, which their
# tools read each time they run: what ssh knows of hosts and is told,
# the public half of a key, the keys gpg trusts
PASSED = (
    "known_hosts*",
    "config",
    "*.pub",
    "authorized_keys",
    "pubring.*",
    "trustdb.gpg",
)


def said(kind: str) -> str:
    """A kind of secrets as a trace says it. One no launcher wrote is
    said as it was written, the caller cleans it."""
    try:
        return SAID[Kind(kind)]
    except ValueError:
        return f"secrets ({kind})"


def own_login(kind: str, program: str) -> bool:
    """Whether a file was opened by the one it is for: Claude Code's
    login, by Claude Code. It reads it when it starts and to renew it,
    that is no sign of anything."""
    return kind == Kind.CLAUDE and program == CLAUDE_PROGRAM


def session_secrets(settings: Settings, host: Host, roots: Sequence[str]) -> Secrets:
    """The files of secrets of a session with these settings: those of
    the homes it has, and any of a name hidden from it in the directories
    it is given (roots, see mounted_dirs of mounts.py). Each of those as
    the host names it and, under the user's home, as the session does:
    the image links the host's home to the container's, and the kernel
    names a file a process holds by the second, gVisor one opened through
    the link by the first."""
    homes = dict.fromkeys((CONTAINER_HOME, host.home))
    roots = list(
        dict.fromkeys(
            named for root in roots for named in (root, _as_named(root, host))
        )
    )
    files: dict[str, str] = {
        os.path.join(CONTAINER_CLAUDE, ".credentials.json"): Kind.CLAUDE
    }
    dirs: dict[str, str] = {}
    for home in homes:
        files[os.path.join(home, ".claude", ".credentials.json")] = Kind.CLAUDE
        files.update(
            {os.path.join(home, path): kind for path, kind in HOME_FILES.items()}
        )
        dirs.update(
            {os.path.join(home, path): kind for path, kind in HOME_DIRS.items()}
        )
    names = dict.fromkeys((*SHADOWED_NAMES, *settings.shadow), Kind.HIDDEN)
    return Secrets(files, dirs, PASSED, names, SHADOW_EXEMPT, roots)


def _as_named(root: str, host: Host) -> str:
    """A directory a session is given as the session names it: one under
    the user's home is under the container's there."""
    home = host.home.rstrip(os.sep)
    if root == home or root.startswith(home + os.sep):
        return CONTAINER_HOME + root[len(home) :]
    return root
