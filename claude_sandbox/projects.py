"""Where Claude Code keeps the transcripts of a project: by what a session
may have known the project as, and which files those are.

Asked by what gives a session its history (history.py), what copies its
transcripts (recorder.py) and what reads them for --trace
(transcript.py)."""

from __future__ import annotations

import os
import re
from pathlib import Path

from .settings import CONTAINER_HOME, Host


def project_roots(host: Host) -> list[str]:
    """The project directory as a session may have known it: its host
    path, and for a project under the user's home the same place under the
    container's. The image links the host home to the container's and
    Claude Code resolves the link, so a sandboxed session records the
    second, one run on the host the first."""
    roots = [host.project_dir]
    home = host.home.rstrip(os.sep)
    if host.project_dir == home or host.project_dir.startswith(home + os.sep):
        sandboxed = CONTAINER_HOME + host.project_dir[len(home) :]
        if sandboxed != host.project_dir:
            roots.append(sandboxed)
    return roots


def transcript_dir(host: Host, root: str) -> Path:
    """Where Claude Code keeps the transcripts of the sessions that knew
    the project as root: named after the path, everything but letters and
    digits dashed."""
    return Path(host.claude_dir, "projects", re.sub(r"[^A-Za-z0-9]", "-", root))


def project_root(path: Path, host: Host) -> str:
    """The project directory as the session of this transcript knew it,
    what the paths it recorded are to be compared with."""
    for root in project_roots(host):
        if transcript_dir(host, root) == path.parent:
            return root
    return host.project_dir


def transcript_dirs(host: Host) -> list[Path]:
    """Where the project's transcripts are, see project_roots."""
    return list(
        dict.fromkeys(transcript_dir(host, root) for root in project_roots(host))
    )


def transcript_files(host: Host) -> list[Path]:
    """The project's transcripts, in no order, none for a project without
    a session."""
    # The directories are writable from inside the sandbox: only plain
    # files, not a link to something else on the host or a pipe that never
    # ends. A session can still put one in a transcript's place after it
    # was listed, so each is opened with open_plain of files.py.
    return [
        f
        for directory in transcript_dirs(host)
        for f in directory.glob("*.jsonl")
        if f.is_file() and not f.is_symlink()
    ]
