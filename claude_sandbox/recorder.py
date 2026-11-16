"""The launcher's own copy of a session's transcript, and what --trace
makes of the two.

The transcript is written from inside the sandbox, a session could rewrite
its own and take out what it did. So while a session runs, the launcher
copies what the project's transcripts gain to its state directory, which is
not mounted into any session, a moment after it is written. --trace reads
the transcript, and says what the copy has that the transcript no longer
does.

A copy is the transcript's bytes from its first one on, so how long the
copy is says where to go on, whichever launcher does: a transcript is
copied by every session of its project that runs while it is written. One
that got shorter than its copy was rewritten, the copy is then put aside
and a new one started.

What this does not give: a line a session takes back within the moment
before it is copied, and anything of a session run without the launcher."""

from __future__ import annotations

import fcntl
import glob
import hashlib
import os
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .settings import Host, private_dir
from .transcript import modified, open_transcript, parse_entry, transcript_files

# Seconds between two looks at the transcripts
LOOK_EVERY = 0.5
# Read and written at a time
CHUNK = 1 << 20
# A copy stops at this size, and a transcript is put aside at most this
# many times: what a session can make the launcher keep is bounded
MOST_COPIED = 512 * 1024 * 1024
MOST_PUT_ASIDE = 5
# Copies older than this many days go, as long as Claude Code keeps a
# transcript by default
KEPT_DAYS = 30
ASIDE_SUFFIX = ".was"


def copy_path(host: Host, transcript: Path) -> Path:
    """Where the copy of a transcript is kept: by the names of its
    directory and of its file, which are Claude Code's and hold no path."""
    return Path(host.transcript_copies_dir, transcript.parent.name, transcript.name)


def put_aside(copy: Path) -> list[Path]:
    """The earlier copies of a transcript, from before it was rewritten."""
    return sorted(copy.parent.glob(f"{glob.escape(copy.name)}.*{ASIDE_SUFFIX}"))


def catch_up(transcript: Path, copy: Path) -> None:
    """Add to a copy what its transcript has gained. Under a lock, the
    launchers of other sessions of the project copy it too."""
    source = open_transcript(transcript)
    if source is None:
        return
    private_dir(str(copy.parent))
    descriptor = os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with source, os.fdopen(descriptor, "ab") as kept:
        fcntl.flock(kept, fcntl.LOCK_EX)
        have = os.fstat(kept.fileno()).st_size
        if os.fstat(source.fileno()).st_size < have:
            # Rewritten. What it held is kept, and a new copy starts with
            # the next look, unless that has happened too often.
            if len(put_aside(copy)) < MOST_PUT_ASIDE:
                os.replace(copy, f"{copy}.{time.time_ns()}{ASIDE_SUFFIX}")
            return
        source.seek(have)
        while have < MOST_COPIED:
            data = source.read(CHUNK)
            if not data:
                return
            kept.write(data)
            have += len(data)


def copy_what_changed(host: Host, since: float) -> None:
    """Catch up the copy of each of the project's transcripts written to
    since a time."""
    for transcript in transcript_files(host):
        if modified(transcript) >= since:
            try:
                catch_up(transcript, copy_path(host, transcript))
            except OSError:
                # A full disk or the like: the session goes on without
                continue


def let_go_of_old_copies(host: Host) -> None:
    oldest = time.time() - KEPT_DAYS * 86400
    for copy in Path(host.transcript_copies_dir).glob("*/*"):
        try:
            if copy.stat().st_mtime < oldest:
                copy.unlink()
        except OSError:
            continue


def keep_copying(host: Host, since: float, stop: threading.Event) -> None:
    while True:
        last = stop.wait(LOOK_EVERY)
        copy_what_changed(host, since)
        if last:
            # Once more after the session has ended, for its last lines
            return


@contextmanager
def transcripts_copied(host: Host) -> Iterator[None]:
    """While a session runs, keep the launcher's copies of the project's
    transcripts up with them."""
    let_go_of_old_copies(host)
    stop = threading.Event()
    # A transcript written just before is the one a resumed session adds to
    copying = threading.Thread(
        target=keep_copying, args=(host, time.time() - 1, stop), daemon=True
    )
    copying.start()
    try:
        yield
    finally:
        stop.set()
        copying.join()


def lines_of(path: Path) -> list[bytes]:
    """The whole lines of a transcript or of a copy, none for one that
    cannot be read. A last line without its end is still being written,
    or was when the copy was made."""
    file = open_transcript(path)
    if file is None:
        return []
    with file:
        return [line for line in file if line.endswith(b"\n")]


@dataclass
class Compared:
    """A transcript next to the launcher's copies of it."""

    # Whether the launcher has a copy at all
    copied: bool = False
    # How many lines the copies hold
    lines: int = 0
    # The entries the copies have and the transcript no longer does, in
    # the order they were copied
    gone: list[dict] = field(default_factory=list)
    # How often it was rewritten shorter while a launcher watched
    rewritten: int = 0

    def header(self) -> list[str]:
        """The line of a trace that says how far its transcript is to be
        believed."""
        if not self.copied:
            return [
                "transcript  as it is now, the launcher has no copy of it to compare"
            ]
        if not self.gone and not self.rewritten:
            return [f"transcript  as the launcher copied it ({self.lines} lines)"]
        said = f"{len(self.gone)} lines the launcher copied are gone or altered"
        if self.rewritten:
            said += f", it was rewritten {self.rewritten} times"
        return [f"transcript  CHANGED: {said}, they are shown as REMOVED"]


def compare(host: Host, transcript: Path) -> Compared:
    """What the launcher's copies of a transcript have that it no longer
    does, line by line: a session that edits its transcript can do so in
    place, without making it shorter."""
    copy = copy_path(host, transcript)
    copies = [*put_aside(copy), copy]
    copied = [line for path in copies for line in lines_of(path)]
    found = Compared(bool(copied), len(copied), rewritten=len(copies) - 1)
    if not copied:
        return found
    current = {hashlib.sha256(line).digest() for line in lines_of(transcript)}
    seen: set[bytes] = set()
    for line in copied:
        digest = hashlib.sha256(line).digest()
        if digest in current or digest in seen:
            continue
        seen.add(digest)
        entry = parse_entry(line)
        if entry:
            found.gone.append(entry)
    return found
