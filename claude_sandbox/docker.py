"""Running docker commands, and spelling their options."""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from .settings import Fatal


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
        raise Fatal("docker was not found on PATH") from None


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
    id) is dropped, its own error message is the report."""
    status = docker(*args, stdout=subprocess.DEVNULL).returncode
    if status != 0:
        raise SystemExit(status)


def env_arg(name: str, value: object = None) -> str:
    """Set a variable in the container, or with no value pass the launcher's
    own through."""
    return f"--env={name}" if value is None else f"--env={name}={value}"


def mount_arg(source: str, target: str, options: str = "") -> str:
    """A bind mount or named volume. The z option relabels a bind mount so
    containers can read it on SELinux hosts."""
    return "--volume=" + ":".join(part for part in (source, target, options) if part)


def docker_safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "-", name)


def process_started(pid: int) -> str:
    """When a process started, as text that is only good to compare, empty
    when that cannot be told or there is no such process."""
    try:
        # Linux: in clock ticks since boot, the 22nd value of the line,
        # counted from behind the command, which can hold anything
        said = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
        return said.rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        pass
    try:
        listed = subprocess.run(
            ["ps", "-o", "lstart=", "-p", str(pid)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="replace",
            check=False,
        )
    except OSError:
        return ""
    return " ".join(listed.stdout.split())


@dataclass(frozen=True)
class Launcher:
    """The launcher of a session as its records know it: by its process
    id, and by when that process started, which tells it from a later
    process that was given the same id. The start is empty when it could
    not be told, and in a record of an earlier version."""

    pid: int
    started: str = ""

    @classmethod
    def current(cls) -> Launcher:
        return cls(os.getpid(), process_started(os.getpid()))

    @property
    def alive(self) -> bool:
        # Zero and below would ask about process groups, not a process
        if self.pid <= 0:
            return False
        try:
            os.kill(self.pid, 0)
        except ProcessLookupError:
            return False
        except OSError:
            # Not ours to signal, so it exists
            pass
        started = process_started(self.pid)
        return not self.started or not started or started == self.started


def session_alive(launcher: Launcher, container: str) -> bool:
    """Whether a session is still going: its launcher or its container is
    there. The container can outlive a killed launcher."""
    return launcher.alive or docker_ok("container", "inspect", container)
