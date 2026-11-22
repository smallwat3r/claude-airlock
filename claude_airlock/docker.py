"""Running docker commands, and spelling their options."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import dataclass
from typing import IO, Any

from .errors import Fatal

NOT_FOUND = "docker was not found on PATH"
# What every container the launcher starts is confined by: no capability
# but those it is given back by name, and nothing it runs gains what it
# was not started with
DROP_CAPABILITIES = "--cap-drop=ALL"
NO_NEW_PRIVILEGES = "--security-opt=no-new-privileges"


def docker(
    *args: str,
    stdout: int | IO | None = None,
    stderr: int | IO | None = None,
    text: bool = True,
) -> subprocess.CompletedProcess:
    """Run a docker command, its output going where stdout and stderr say
    (the launcher's own by default), read as text unless told not to."""
    try:
        return subprocess.run(
            ["docker", *args],
            stdout=stdout,
            stderr=stderr,
            text=text,
            errors="replace" if text else None,
            check=False,
        )
    except FileNotFoundError:
        raise Fatal(NOT_FOUND) from None


def docker_popen(*args: str, **options: Any) -> subprocess.Popen:
    """Start a docker command and leave it running, with the options of
    subprocess.Popen. Raises OSError when it cannot be started,
    FileNotFoundError when docker is not on PATH."""
    return subprocess.Popen(["docker", *args], **options)


def exec_args(container: str, command: str, *, stdin: bool = False) -> list[str]:
    """The arguments of docker that run a bash command in a container,
    given the launcher's stdin when told."""
    return ["exec", *(["-i"] if stdin else []), container, "bash", "-c", command]


def docker_ok(*args: str) -> bool:
    """Whether a docker command succeeds, without showing its output."""
    quiet = subprocess.DEVNULL
    return docker(*args, stdout=quiet, stderr=quiet).returncode == 0


def docker_output(*args: str) -> str:
    """Stdout of a docker command, empty when it fails."""
    return docker(*args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout


def running_containers() -> set[str]:
    """The names of the containers that are running now."""
    return set(docker_output("ps", "--format={{.Names}}").split())


def container_running(name: str) -> bool:
    """Whether a container of that name is there and running."""
    state = docker_output("container", "inspect", "--format={{.State.Running}}", name)
    return state.strip() == "true"


def docker_bytes(*args: str) -> bytes | None:
    """Stdout of a docker command as the bytes they are, None when it
    fails."""
    ran = docker(*args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=False)
    return ran.stdout if ran.returncode == 0 else None


def container_label(container: str, label: str) -> str:
    """A label of a container, empty without the one or the other."""
    said = docker_output(
        "container",
        "inspect",
        f'--format={{{{index .Config.Labels "{label}"}}}}',
        container,
    )
    return said.strip()


def docker_must(*args: str) -> None:
    """Run a docker command the session cannot do without. Its stdout (an
    id) is dropped, its own error message says what went wrong."""
    if docker(*args, stdout=subprocess.DEVNULL).returncode != 0:
        raise Fatal(f"docker {' '.join(args[:2])} failed")


def env_arg(name: str, value: object = None) -> str:
    """Set a variable in the container, or with no value pass the launcher's
    own through."""
    return f"--env={name}" if value is None else f"--env={name}={value}"


def mount_arg(source: str, target: str, options: str = "") -> str:
    """A bind mount or named volume. The z option relabels a bind mount so
    containers can read it on SELinux hosts. The three are told apart by
    colons, so a path that has one cannot be mounted: refused here, docker
    would take a part of it for something else. A source that is a path
    and is not there is refused too: docker would make a directory of it,
    owned by root, in the place of the file that was meant."""
    for path in (source, target):
        if ":" in path:
            raise Fatal(f"cannot mount {path}: docker takes no path with a colon")
    if source.startswith("/") and not os.path.lexists(source):
        raise Fatal(
            f"cannot mount {source}: it does not exist, docker would make a"
            " directory of it, owned by root"
        )
    return "--volume=" + ":".join(part for part in (source, target, options) if part)


@dataclass(frozen=True)
class Tmpfs:
    """A directory of a container that is kept in memory and gone with it,
    of at most so many megabytes."""

    target: str
    megabytes: int
    # Whether what is in it can be run
    runs: bool = False
    # Whose it is, as a user and a group, and who else may use it: root's
    # and open to all unless told otherwise
    owner: tuple[int, int] | None = None
    mode: str = ""

    def arg(self, share: float = 1.0) -> str:
        """The mount, with that share of its size. Never of none, which
        would say no limit at all."""
        megabytes = max(1, int(self.megabytes * share))
        size = f"{megabytes}m" if megabytes % 1024 else f"{megabytes // 1024}g"
        options = ["exec"] if self.runs else []
        options.append(f"size={size}")
        if self.owner:
            options += [f"uid={self.owner[0]}", f"gid={self.owner[1]}"]
        if self.mode:
            options.append(f"mode={self.mode}")
        return f"--tmpfs={self.target}:{','.join(options)}"


def docker_safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "-", name)


def project_slug(project_dir: str) -> str:
    """A name for a project that docker and the filesystem take, and that
    two projects of the same name do not share: its last part and a hash
    of its whole path."""
    suffix = hashlib.sha256(project_dir.encode()).hexdigest()[:8]
    return f"{docker_safe_name(os.path.basename(project_dir))}-{suffix}"
