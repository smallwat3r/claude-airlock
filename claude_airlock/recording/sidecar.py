"""The sidecars of one session: containers the launcher runs next to it,
which hold what they record until the launcher copies it out and notes
where it is kept, for --trace to find. Each kind says what it is called,
which file it writes and where that goes, see capture.py and
processes.py."""

from __future__ import annotations

import json
import math
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Self

from ..docker import (
    DROP_CAPABILITIES,
    NO_NEW_PRIVILEGES,
    docker,
    docker_answer,
    docker_ok,
)
from ..files import json_object, private_dir
from ..launcher import Launcher, session_alive
from ..notice import warn
from ..settings import Host
from .records import TracedSession, record_traced_session

# The processes a sidecar can have at once, it runs one program
SIDECAR_PIDS = 16


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
    # What it records, as it is called when that was not kept, and the
    # file it is written to in the sidecar
    RECORD: ClassVar[str]
    FILE: ClassVar[str]
    # What the copies of that file are named with, and how many of them
    # are kept: the oldest go once there are more
    EXTENSION: ClassVar[str]
    KEPT: ClassVar[int]
    # The seconds it is given to stop, docker's own without
    STOP_SECONDS: ClassVar[int | None] = None
    # The memory it runs with, and the capabilities it is given, of none
    MEMORY: ClassVar[str]
    CAPABILITIES: ClassVar[tuple[str, ...]]
    # The processes it can have at once
    PIDS: ClassVar[int] = SIDECAR_PIDS

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
    def for_session(cls, session: str, project: str) -> Self:
        """The sidecar this launcher is about to start for a session."""
        return cls(cls.name_for(session), project, time.time(), Launcher.current())

    @property
    def session(self) -> str:
        return self.session_of(self.name)

    @property
    def label(self) -> str:
        about = {"project": self.project, "start": self.start}
        return json.dumps({**about, **self.launcher.as_fields()})

    @property
    def label_arg(self) -> str:
        return f"--label={self.LABEL}={self.label}"

    def run_args(self) -> list[str]:
        """The options of docker run every sidecar starts with: its name
        and label, as root with CAPABILITIES alone, never more, within its
        bounds."""
        return [
            f"--name={self.name}",
            self.label_arg,
            "--user=0:0",
            DROP_CAPABILITIES,
            *(f"--cap-add={capability}" for capability in self.CAPABILITIES),
            NO_NEW_PRIVILEGES,
            f"--memory={self.MEMORY}",
            f"--pids-limit={self.PIDS}",
        ]

    def last_said(self, lines: int | None = None) -> str:
        """What the sidecar wrote to its output and its errors, the last
        lines of it when told how many."""
        tail = [] if lines is None else [f"--tail={lines}"]
        said = docker(
            "logs", *tail, self.name, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        return said.stdout.strip()

    @classmethod
    def from_label(cls, name: str, label: str) -> Self | None:
        """The sidecar of a name and a label, none for a container that
        is not one."""
        try:
            about = json_object(label) or {}
            project, start = str(about["project"]), float(about["start"])
            launcher = Launcher.from_fields(about)
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
            return None
        if not name.endswith(cls.SUFFIX) or not math.isfinite(start):
            return None
        return cls(name, project, start, launcher)

    @classmethod
    def listed(cls, ended_too: bool = False) -> list[Self] | None:
        """The sidecars of this kind that are running, of every project,
        with those that have stopped when asked for. None when docker
        did not answer."""
        listed = docker_answer(
            "ps",
            *(["--all"] if ended_too else []),
            f"--filter=label={cls.LABEL}",
            f'--format={{{{.Names}}}}\t{{{{.Label "{cls.LABEL}"}}}}',
        )
        if listed is None:
            return None
        found = []
        for line in listed.splitlines():
            name, _, label = line.partition("\t")
            sidecar = cls.from_label(name, label)
            if sidecar:
                found.append(sidecar)
        return found

    @classmethod
    def running(cls, project_dir: str) -> list[tuple[str, float]] | None:
        """Those of the sessions of a project that are running now, as
        the name of each and when it started. None when docker did not
        say: that is not that none runs."""
        listed = cls.listed()
        if listed is None:
            return None
        return [
            (sidecar.name, sidecar.start)
            for sidecar in listed
            if sidecar.project == project_dir
        ]

    @classmethod
    def left_behind(cls) -> list[Self]:
        """The sidecars of sessions that ended without their launcher (a
        killed Emacs buffer, a closed terminal): still there, with what
        they recorded."""
        return [
            sidecar
            for sidecar in cls.listed(ended_too=True) or []
            if not session_alive(sidecar.launcher, sidecar.session)
        ]

    @classmethod
    def collect_left_behind(cls, host: Host) -> None:
        """Collect what sessions that ended without their launcher left
        behind: their sidecar is still there, with what it recorded."""
        for sidecar in cls.left_behind():
            sidecar.collect(host, left_behind=True)

    def directory(self, host: Host) -> str:
        """Where the launcher keeps what sidecars of this kind recorded."""
        raise NotImplementedError

    def noted(self, file: str, end: float) -> TracedSession:
        """The line of the record that says where what this sidecar
        recorded is kept, and which project and time it covers."""
        raise NotImplementedError

    def recorded(self, copied: Path) -> bool:
        """Whether a file copied out of the sidecar holds a record."""
        return True

    def pruned(self, directory: Path) -> None:
        """Called once the oldest copies have gone, for a kind that keeps
        more than one file of each."""

    def nothing_recorded(self) -> None:
        """Called when there was nothing to keep, while the sidecar is
        still there to say why."""

    def copy_out(self, directory: str) -> Path | None:
        """Copy the sidecar's file into a directory of the launcher's
        records, named after the sidecar and its start. None when there
        was nothing to copy. Raises OSError when the directory cannot be
        made."""
        target = Path(
            private_dir(directory), f"{self.name}-{int(self.start)}.{self.EXTENSION}"
        )
        if docker_ok("cp", f"{self.name}:{self.FILE}", str(target)):
            return target
        return None

    def last_wrote(self, copied: Path) -> float:
        """When the sidecar last wrote to a file that was copied out of
        it: docker cp keeps the time of a file. Not before the sidecar
        started nor later than now, whatever the file says. Raises
        OSError for a file that is not there."""
        return min(max(copied.stat().st_mtime, self.start), time.time())

    def collect(self, host: Host, left_behind: bool = False) -> None:
        """Stop the sidecar, copy what it recorded to the host, note
        which project and time that covers for --trace to find it by, let
        go of the oldest copies and remove the sidecar. The time ends
        now, with the session. Not that of a sidecar that was left
        behind, which is collected when a launcher next runs, hours or a
        reboot later: its time ends when it last wrote, there is nothing
        of its session after that."""
        patience = [] if self.STOP_SECONDS is None else [f"--time={self.STOP_SECONDS}"]
        docker_ok("stop", *patience, self.name)
        try:
            directory = self.directory(host)
            copied = self.copy_out(directory)
            if copied and self.recorded(copied):
                end = self.last_wrote(copied) if left_behind else time.time()
                record_traced_session(host, self.noted(copied.name, end))
            else:
                if copied:
                    copied.unlink(missing_ok=True)
                self.nothing_recorded()
            keep_latest(Path(directory), f"*.{self.EXTENSION}", self.KEPT)
            self.pruned(Path(directory))
        except OSError as problem:
            # Said and passed over: this runs as a session ends, and what
            # is left to do then (the check of tamper.py) matters more
            warn(
                f"the {self.RECORD} was not kept: {problem}",
            )
        finally:
            self.remove()

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
