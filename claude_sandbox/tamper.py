"""Noticing what a session left behind that can run commands on the host."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from .docker import session_alive
from .settings import private_dir


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_config_hash(file: str) -> str:
    """Hash of a git config without its branch tracking entries, they change
    on every push -u or checkout and cannot run anything."""
    try:
        listing = subprocess.run(
            ["git", "config", "--file", file, "--list"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        # Unparseable, or no git: fall back to the file as it is
        listing = Path(file).read_bytes()
    kept = [line for line in listing.split(b"\n") if not line.startswith(b"branch.")]
    return sha256_hex(b"\n".join(kept))


def file_hash(path: str) -> str:
    try:
        if os.path.islink(path):
            return sha256_hex(b"link:" + os.fsencode(os.readlink(path)))
        return sha256_hex(Path(path).read_bytes())
    except OSError:
        return "unreadable"


def host_exec_fingerprint(directories: list[str]) -> dict[str, str]:
    """Hashes, by path, of the files in the mounted directories that run
    commands on the host once the session is over: git config and hooks, and
    the project's Claude settings (hooks, statusline). They have to stay
    writable for git and claude to work, so instead of locking them the
    launcher compares this before and after a session (see
    report_tampering)."""
    fingerprint = {}
    for directory in directories:
        git_config = os.path.join(directory, ".git", "config")
        if os.path.isfile(git_config):
            fingerprint[git_config] = git_config_hash(git_config)
        watched = [
            os.path.join(directory, ".claude", "settings.json"),
            os.path.join(directory, ".claude", "settings.local.json"),
        ]
        for hooks_dir, _, files in os.walk(os.path.join(directory, ".git", "hooks")):
            watched += [os.path.join(hooks_dir, name) for name in files]
        for path in watched:
            if os.path.isfile(path) or os.path.islink(path):
                fingerprint[path] = file_hash(path)
    return fingerprint


def report_tampering(
    before: dict[str, str], after: dict[str, str], unchecked: str = ""
) -> None:
    """Name the files that differ. unchecked is the name of an earlier
    session that ended without this check, when the report is the late one
    for it."""
    changed = sorted(
        path
        for path in before.keys() | after.keys()
        if before.get(path) != after.get(path)
    )
    if not changed:
        return
    if unchecked:
        heading = (
            f"claude-docker: the session {unchecked} ended without its check. Since"
            " it started, by its doing or yours, these files that can run commands"
            " on the host have changed:"
        )
    else:
        heading = (
            "claude-docker: this session changed files that can run commands"
            " on the host:"
        )
    print(
        heading,
        *(f"  {path}" for path in changed),
        "Review them before using git or claude there outside the sandbox.",
        sep="\n",
        file=sys.stderr,
    )


def save_pending_check(file: Path, watched: list[str], before: dict[str, str]) -> None:
    """Keep a session's starting fingerprint on disk until its check has
    run. A launcher that dies with its terminal (a killed Emacs buffer, a
    closed window, a crash) never gets to compare, the next launch finds
    this file and does it instead (see report_unchecked_sessions)."""
    private_dir(str(file.parent))
    pending = {"pid": os.getpid(), "watched": watched, "before": before}
    file.write_text(json.dumps(pending), encoding="utf-8")


def report_unchecked_sessions(directory: Path) -> None:
    """Run the check for every session that ended without it, one still
    going is left alone. The file is named after the container."""
    for file in sorted(directory.glob("*.json")):
        try:
            pending = json.loads(file.read_text(encoding="utf-8"))
            pid, watched, before = (
                int(pending["pid"]),
                [str(watched_dir) for watched_dir in pending["watched"]],
                {str(k): str(v) for k, v in pending["before"].items()},
            )
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            # Said out loud, a check must not vanish without a word
            print(
                f"claude-docker: dropping an unreadable pending check: {file}",
                file=sys.stderr,
            )
            file.unlink(missing_ok=True)
            continue
        if session_alive(pid, file.stem):
            continue
        report_tampering(before, host_exec_fingerprint(watched), unchecked=file.stem)
        file.unlink(missing_ok=True)
