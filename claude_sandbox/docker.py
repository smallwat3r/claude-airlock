"""Running docker commands, and spelling their options."""

from __future__ import annotations

import os
import re
import subprocess

from .settings import Fatal


def docker(*args: str, stdout=None, stderr=None) -> subprocess.CompletedProcess:
    """Run a docker command, its output going where stdout and stderr say
    (the launcher's own by default)."""
    try:
        return subprocess.run(
            ["docker", *args],
            stdout=stdout,
            stderr=stderr,
            text=True,
            errors="replace",
            check=False,
        )
    except FileNotFoundError:
        raise Fatal("docker was not found on PATH") from None


def docker_ok(*args: str) -> bool:
    """Whether a docker command succeeds, without showing its output."""
    quiet = subprocess.DEVNULL
    return docker(*args, stdout=quiet, stderr=quiet).returncode == 0


def session_alive(launcher: int, container: str) -> bool:
    """Whether a session is still going: its launcher (by process id) or
    its container is there. The container can outlive a killed launcher."""
    try:
        # Zero and below would ask about process groups, not a process
        if launcher > 0:
            os.kill(launcher, 0)
            return True
    except ProcessLookupError:
        pass
    except OSError:
        # Not ours to signal, so it exists
        return True
    return docker_ok("container", "inspect", container)


def docker_output(*args: str) -> str:
    """Stdout of a docker command, empty when it fails."""
    return docker(*args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout


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
