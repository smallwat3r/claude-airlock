"""Noticing what a session left behind that can run commands on the host,
or that Claude follows there: the check of a session, taken as it starts
and run once it is over, by this launcher or by the next one.

What is watched and how it is read is in fingerprint.py, within the bounds
of bounded.py, and what is said of a change in tampered.py."""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ..files import private_dir, write_whole
from ..launcher import Launcher, session_alive
from ..notice import warn
from ..projects import memory_dirs
from ..settings import Host
from .fingerprint import (
    agent_memory_dirs,
    build_fingerprint,
    home_git_configs,
    host_exec_fingerprint,
    project_names,
)
from .history import own_names
from .home import CONFIG
from .tampered import (
    planted_projects,
    report_build_changes,
    report_left_out,
    report_projects,
    report_tampering,
)

# How much is said of what stopped a check that could not be run
PROBLEM_WIDTH = 200


def _texts(value: object) -> list[str]:
    """A list of a pending check as the texts it holds. Raises TypeError
    for what is no list."""
    if not isinstance(value, list):
        raise TypeError("not a list")
    return [str(text) for text in value]


def _fingerprint_of(value: object) -> dict[str, str]:
    """A fingerprint of a pending check. Raises TypeError for what is
    none."""
    if not isinstance(value, dict):
        raise TypeError("not a fingerprint")
    return {str(path): str(stamp) for path, stamp in value.items()}


@dataclass(frozen=True)
class HostCheck:
    """What a session is checked against once it is over: the directories
    it could write, and how the files watched in them were as it started
    (see host_exec_fingerprint and build_fingerprint)."""

    watched: list[str]
    claude_dir: str
    memory: list[str]
    before: dict[str, str]
    # None in a check saved by a version that did not take it
    build: dict[str, str] | None
    # The config the sandboxed sessions share, empty in a check saved by
    # a version that did not watch it
    shared_config: str = ""
    # The names of what Claude Code kept for each project as the session
    # started (see project_names) and those that are the project's own.
    # Not looked at in a check saved by a version that did not take them.
    projects: list[str] | None = None
    own_projects: tuple[str, ...] = ()
    projects_taken: bool = False
    # The user's own git configs, none in a check saved by a version that
    # did not watch them
    git_configs: tuple[str, ...] = ()

    @classmethod
    def take(
        cls,
        watched: list[str],
        claude_dir: str,
        memory: list[str],
        shared_config: str,
        own_projects: Sequence[str] = (),
        git_configs: Sequence[str] = (),
    ) -> HostCheck:
        """The check of a session about to start."""
        before = host_exec_fingerprint(
            watched, claude_dir, memory, shared_config, git_configs
        )
        build = build_fingerprint(watched)
        return cls(
            watched,
            claude_dir,
            memory,
            before,
            build,
            shared_config,
            project_names(claude_dir),
            tuple(sorted(own_projects)),
            projects_taken=True,
            git_configs=tuple(git_configs),
        )

    def as_fields(self) -> dict[str, object]:
        return {
            "watched": self.watched,
            "claude_dir": self.claude_dir,
            "before": self.before,
            "build": self.build or {},
            "memory": self.memory,
            "shared_config": self.shared_config,
            "git_configs": list(self.git_configs),
            **(
                {"projects": self.projects, "own_projects": list(self.own_projects)}
                if self.projects_taken
                else {}
            ),
        }

    @classmethod
    def from_fields(cls, pending: dict) -> HostCheck:
        """A check as it was saved. Raises KeyError or TypeError for
        what is none. The fields after the first two are not in a check
        saved by an earlier version."""
        return cls(
            _texts(pending["watched"]),
            str(pending.get("claude_dir", "")),
            _texts(pending.get("memory", [])),
            _fingerprint_of(pending["before"]),
            _fingerprint_of(pending["build"]) if "build" in pending else None,
            str(pending.get("shared_config", "")),
            None if pending.get("projects") is None else _texts(pending["projects"]),
            tuple(_texts(pending.get("own_projects", []))),
            projects_taken="projects" in pending,
            git_configs=tuple(_texts(pending.get("git_configs", []))),
        )

    def report(self, unchecked: str = "") -> None:
        """Compare with how the files are now and say what changed.
        unchecked is the name of an earlier session that ended without
        this check, when the report is the late one for it."""
        after = host_exec_fingerprint(
            self.watched,
            self.claude_dir,
            self.memory,
            self.shared_config,
            self.git_configs,
        )
        report_tampering(
            self.before,
            after,
            unchecked,
            self.claude_dir,
            self.memory,
            self.shared_config,
        )
        if self.build is not None:
            report_build_changes(self.build, build_fingerprint(self.watched), unchecked)
        if self.projects_taken:
            planted = planted_projects(
                self.projects, self.own_projects, self.claude_dir
            )
            report_projects(planted, unchecked)


class PendingCheck:
    """The check of a session, kept on disk until it has run. A launcher
    that dies with its terminal (a killed Emacs buffer, a closed window,
    a crash) never gets to compare, the next launch finds the file and
    does it instead (see report_unchecked_sessions). The file is named
    after the container."""

    def __init__(self, file: Path, check: HostCheck) -> None:
        self._file = file
        self._check = check

    @classmethod
    def begin(cls, host: Host, session: str, watched: list[str]) -> PendingCheck:
        """Take the check of a session about to start and keep it, once
        the checks earlier sessions left have run. Written whole: a
        launcher that starts meanwhile reads the checks that are there,
        and drops one it cannot read."""
        file = Path(host.pending_checks_dir, session + ".json")
        report_unchecked_sessions(file.parent)
        shared_config = os.path.join(host.sandbox_claude_dir, CONFIG)
        check = HostCheck.take(
            watched,
            host.claude_dir,
            memory_dirs(host) + agent_memory_dirs(watched),
            shared_config,
            sorted(own_names(host)),
            home_git_configs(host),
        )
        report_left_out(check.before, check.build or {})
        private_dir(str(file.parent))
        pending = {**Launcher.current().as_fields(), **check.as_fields()}
        write_whole(str(file), json.dumps(pending))
        return cls(file, check)

    def drop(self) -> None:
        """For a session that did not start: there is nothing of it to
        check."""
        self._file.unlink(missing_ok=True)

    def run(self) -> None:
        """Run the check of the session, now over, see _run_kept."""
        _run_kept(self._check, self._file)


def _run_kept(check: HostCheck, file: Path, unchecked: str = "") -> None:
    """Run the check kept in a file, of the session over now or of one
    that ended without it (unchecked), and remove the file once it has
    run. Whatever a session left that the check does not get through is
    said, and the file kept for the next launch to try again. Passed on,
    it would end this launch and every one after it, of any project, and
    a session could have meant it to."""
    try:
        check.report(unchecked)
    except Exception as problem:  # noqa: BLE001
        said = repr(problem)[:PROBLEM_WIDTH]
        warn(
            f"the session {unchecked} ended without its check, and the check"
            f" cannot be run now: {said}"
            if unchecked
            else f"the check of what the session left behind cannot be run: {said}",
            f"What it left behind is not known. The check is kept in {file}"
            " and tried again by the next launch, remove the file to be"
            " rid of it.",
        )
        return
    file.unlink(missing_ok=True)


def report_unchecked_sessions(directory: Path) -> None:
    """Run the check for every session that ended without it, one still
    going is left alone."""
    for file in sorted(directory.glob("*.json")):
        try:
            pending = json.loads(file.read_text(encoding="utf-8"))
            launcher = Launcher.from_fields(pending)
            check = HostCheck.from_fields(pending)
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            # Said out loud, a check must not vanish without a word
            warn(
                f"dropping an unreadable pending check: {file}",
            )
            file.unlink(missing_ok=True)
            continue
        if session_alive(launcher, file.stem):
            continue
        _run_kept(check, file, file.stem)
