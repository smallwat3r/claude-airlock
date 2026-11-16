"""The sidecars of one session: containers the launcher runs next to it,
which hold what they record until the launcher copies it out. Each kind
has its own suffix and label, see capture.py and processes.py."""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, TypeVar

from .docker import docker_ok, docker_output
from .launcher import Launcher, session_alive
from .settings import private_dir

SidecarKind = TypeVar("SidecarKind", bound="Sidecar")


@dataclass(frozen=True)
class Sidecar:
    """A sidecar of one session as its label tells of it: the project and
    the start of its session, and the launcher that started it. The label
    is the launcher's, a session cannot set its own."""

    # What the sidecar's name adds to its session's, and its label. Session
    # names are stepped past the names in use (see container_name), a clash
    # with a session of a project named like a sidecar is left to docker to
    # refuse.
    SUFFIX: ClassVar[str]
    LABEL: ClassVar[str]

    name: str
    project: str
    start: float
    launcher: Launcher

    @classmethod
    def name_for(cls, session: str) -> str:
        return session + cls.SUFFIX

    @classmethod
    def session_of(cls, name: str) -> str:
        """The session a sidecar of this name belongs to."""
        return name[: -len(cls.SUFFIX)]

    @classmethod
    def for_session(  # noqa: PYI019, Self takes Python 3.11
        cls: type[SidecarKind], session: str, project: str
    ) -> SidecarKind:
        """The sidecar this launcher is about to start for a session."""
        return cls(cls.name_for(session), project, time.time(), Launcher.current())

    @property
    def session(self) -> str:
        return self.session_of(self.name)

    @property
    def label(self) -> str:
        about = {
            "project": self.project,
            "start": self.start,
            "pid": self.launcher.pid,
            "launched": self.launcher.started,
        }
        return json.dumps(about)

    @property
    def label_arg(self) -> str:
        return f"--label={self.LABEL}={self.label}"

    @classmethod
    def from_label(  # noqa: PYI019
        cls: type[SidecarKind], name: str, label: str
    ) -> SidecarKind | None:
        """The sidecar of a name and a label, none for a container that
        is not one."""
        try:
            about = json.loads(label)
            project, start = str(about["project"]), float(about["start"])
            # Not in the label of an earlier version
            launcher = Launcher(int(about["pid"]), str(about.get("launched", "")))
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
            return None
        if not name.endswith(cls.SUFFIX) or not math.isfinite(start):
            return None
        return cls(name, project, start, launcher)

    @classmethod
    def listed(  # noqa: PYI019
        cls: type[SidecarKind], ended_too: bool = False
    ) -> list[SidecarKind]:
        """The sidecars of this kind that are running, of every project,
        with those that have stopped when asked for."""
        listed = docker_output(
            "ps",
            *(["--all"] if ended_too else []),
            f"--filter=label={cls.LABEL}",
            f'--format={{{{.Names}}}}\t{{{{.Label "{cls.LABEL}"}}}}',
        )
        found = []
        for line in listed.splitlines():
            name, _, label = line.partition("\t")
            sidecar = cls.from_label(name, label)
            if sidecar:
                found.append(sidecar)
        return found

    @classmethod
    def left_behind(  # noqa: PYI019
        cls: type[SidecarKind],
    ) -> list[SidecarKind]:
        """The sidecars of sessions that ended without their launcher (a
        killed Emacs buffer, a closed terminal): still there, with what
        they recorded."""
        return [
            sidecar
            for sidecar in cls.listed(ended_too=True)
            if not session_alive(sidecar.launcher, sidecar.session)
        ]

    def copy_out(self, file: str, directory: str, extension: str) -> Path | None:
        """Copy a file of the sidecar into a directory of the launcher's
        records, named after the sidecar and its start. None when there
        was nothing to copy. Raises OSError when the directory cannot be
        made."""
        target = Path(
            private_dir(directory), f"{self.name}-{int(self.start)}.{extension}"
        )
        if docker_ok("cp", f"{self.name}:{file}", str(target)):
            return target
        return None

    def remove(self) -> None:
        docker_ok("rm", "--force", self.name)


def keep_latest(directory: Path, pattern: str, kept: int) -> None:
    """Let go of the oldest files of a directory once there are more than
    kept. Launchers of other sessions do the same, a file that has gone
    in the meantime is passed over."""

    def written(file: Path) -> float:
        try:
            return file.stat().st_mtime
        except OSError:
            return 0.0

    files = sorted(directory.glob(pattern), key=written)
    for old in files[: max(len(files) - kept, 0)]:
        old.unlink(missing_ok=True)
