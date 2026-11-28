"""Where Claude Code keeps the transcripts of a project: by what a session
may have known the project as, and which files those are.

Asked by what gives a session its history (history.py), what copies its
transcripts (recorder.py) and what reads them for --trace
(transcript.py). A session has a transcript of its own and one of each
subagent it started, see subagent_files."""

from __future__ import annotations

import os
import re
from pathlib import Path

from .paths import is_within
from .settings import CONTAINER_HOME, Host

# The subagents of one session whose transcripts are read
MOST_SUBAGENTS = 1000
# Where Claude Code keeps the transcripts of a session's subagents, in SESSION/
SUBAGENTS_DIR = "subagents"
# The directory of what Claude Code remembers of a project, by its transcripts
MEMORY_DIR = "memory"
# What a transcript's name ends with, and that of a subagent starts with
TRANSCRIPT_SUFFIX = ".jsonl"
SUBAGENT_PREFIX = "agent-"


def project_roots(host: Host) -> list[str]:
    """The project directory as a session may have known it: its host
    path, and for a project under the user's home the same place under the
    container's. The image links the host home to the container's and
    Claude Code resolves the link, so a sandboxed session records the
    second, one run on the host the first."""
    roots = [host.project_dir]
    home = host.home.rstrip(os.sep)
    if is_within(host.project_dir, home):
        sandboxed = CONTAINER_HOME + host.project_dir[len(home) :]
        if sandboxed != host.project_dir:
            roots.append(sandboxed)
    return roots


def sandboxed_root(host: Host) -> str:
    """The project directory as a sandboxed session knows it, what the
    paths such a session names are to be compared with."""
    return project_roots(host)[-1]


def _transcript_dir(host: Host, root: str) -> Path:
    """Where Claude Code keeps the transcripts of the sessions that knew
    the project as root: named after the path, everything but letters and
    digits dashed."""
    return Path(host.claude_dir, "projects", re.sub(r"[^A-Za-z0-9]", "-", root))


def subagent_session(path: Path) -> Path | None:
    """The directory of the session a subagent's transcript is kept in
    (PROJECT/SESSION/subagents/NAME), none for the transcript of a
    session."""
    return path.parents[1] if path.parent.name == SUBAGENTS_DIR else None


def project_root(path: Path, host: Host) -> str:
    """The project directory as the session of this transcript knew it,
    what the paths it recorded are to be compared with."""
    place = (subagent_session(path) or path).parent
    for root in project_roots(host):
        if _transcript_dir(host, root) == place:
            return root
    return host.project_dir


def transcript_dirs(host: Host) -> list[Path]:
    """Where the project's transcripts are, see project_roots."""
    return list(
        dict.fromkeys(_transcript_dir(host, root) for root in project_roots(host))
    )


def memory_dirs(host: Host) -> list[str]:
    """Where Claude Code keeps what it remembers of the project from one
    session to the next, next to the transcripts."""
    return [str(directory / MEMORY_DIR) for directory in transcript_dirs(host)]


def _plain_files(directory: Path) -> tuple[list[str], set[str]]:
    """The names of the plain files of a directory, and those of its
    directories, neither through a link. None for one that is not there.
    As the listing says, without a look at each: it is listed often while
    a session runs, see recorder.py."""
    files: list[str] = []
    directories: set[str] = set()
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                try:
                    if entry.is_file(follow_symlinks=False):
                        files.append(entry.name)
                    elif entry.is_dir(follow_symlinks=False):
                        directories.add(entry.name)
                except OSError:
                    continue
    except OSError:
        pass
    return files, directories


def _listed_transcripts(directory: Path) -> tuple[list[Path], set[str]]:
    """The transcripts in one of the project's directories, and the names
    of the directories next to them: that of a session holds what its
    subagents wrote."""
    # The directories are writable from inside the sandbox: only plain
    # files, not a link to something else on the host or a pipe that never
    # ends. A session can still put one in a transcript's place after it
    # was listed, so each is opened with open_plain of files.py.
    files, directories = _plain_files(directory)
    found = [directory / name for name in files if name.endswith(TRANSCRIPT_SUFFIX)]
    return found, directories


def transcript_files(host: Host) -> list[Path]:
    """The project's transcripts, in no order, none for a project without
    a session."""
    return [
        transcript
        for directory in transcript_dirs(host)
        for transcript in _listed_transcripts(directory)[0]
    ]


def subagent_files(transcript: Path) -> list[Path]:
    """The transcripts of the subagents of a session, by that of the
    session: Claude Code keeps one of each next to it, in
    SESSION/subagents. What a subagent ran and wrote is in its own and
    nowhere in the session's. In the order of their names, and no more
    than MOST_SUBAGENTS, the directory is the session's to fill."""
    directory = transcript.with_suffix("") / SUBAGENTS_DIR
    # Not through a link, the session can make one to anywhere. The files
    # are opened with open_plain of files.py, as a transcript is.
    if directory.parent.is_symlink() or directory.is_symlink():
        return []
    names = sorted(
        name
        for name in _plain_files(directory)[0]
        if name.startswith(SUBAGENT_PREFIX) and name.endswith(TRANSCRIPT_SUFFIX)
    )
    return [directory / name for name in names[:MOST_SUBAGENTS]]


def subagents_unread(transcript: Path) -> int:
    """How many transcripts of subagents a session has past the
    MOST_SUBAGENTS that subagent_files gives, by that of the session.
    Those are neither copied nor read, and what tells of the session
    says so: which ones they are goes by their names, the session's to
    choose, and any number of names can be made to sort ahead of the one
    a subagent wrote what it ran in."""
    directory = transcript.with_suffix("") / SUBAGENTS_DIR
    if directory.parent.is_symlink() or directory.is_symlink():
        return 0
    there = sum(
        name.startswith(SUBAGENT_PREFIX) and name.endswith(TRANSCRIPT_SUFFIX)
        for name in _plain_files(directory)[0]
    )
    return max(0, there - MOST_SUBAGENTS)


def session_transcripts(host: Host) -> list[Path]:
    """Every transcript the project's sessions write: their own and
    those of their subagents."""
    found: list[Path] = []
    for directory in transcript_dirs(host):
        transcripts, directories = _listed_transcripts(directory)
        for transcript in transcripts:
            found.append(transcript)
            # Most sessions started no subagent and have no directory
            if transcript.name[: -len(TRANSCRIPT_SUFFIX)] in directories:
                found += subagent_files(transcript)
    return found
