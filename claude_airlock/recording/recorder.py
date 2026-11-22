"""The launcher's own copy of a session's transcript, and what --trace
makes of the two.

The transcript is written from inside the sandbox, a session could rewrite
its own and take out what it did. So while a session runs, the launcher
copies what the project's transcripts gain to its state directory, which is
not mounted into any session, a moment after it is written. Those of the
subagents too, what a subagent ran is in a transcript of its own. --trace reads
the transcript, and says what the copy has that the transcript no longer
does.

A copy is the transcript's bytes from its first one on, so how long the
copy is says where to go on, whichever launcher does: a transcript is
copied by every session of its project that runs while it is written. One
that got shorter than its copy was rewritten, the copy is then put aside
and a new one started.

Which transcripts a session writes to is not taken from when they say
they were written, that is the session's to set: one whose length has
changed is copied too, and one whose copy is not as long as it is.

What this does not give: a line a session takes back within the moment
before it is copied, and anything of a session run without the launcher."""

from __future__ import annotations

import contextlib
import glob
import hashlib
import os
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from ..background import in_background
from ..files import bounded_lines, line_entry, open_locked, open_plain, private_dir
from ..projects import (
    SUBAGENTS_DIR,
    session_transcripts,
    subagent_session,
    transcript_dirs,
)
from ..settings import Host

# Seconds between two looks at the transcripts
LOOK_EVERY = 0.5
# Read and written at a time
CHUNK = 1 << 20
# A copy stops at this size, and a transcript is put aside at most this
# many times: what a session can make the launcher keep is bounded
MOST_COPIED = 512 * 1024 * 1024
MOST_PUT_ASIDE = 5
# A transcript of more different lines than this is not compared with its
# copies, and of the lines found gone no more bytes are held than this:
# both are a session's to make large
MOST_COMPARED = 1_000_000
MOST_GONE_BYTES = 64 * 1024 * 1024
# Copies older than this many days go, as long as Claude Code keeps a
# transcript by default
KEPT_DAYS = 30
ASIDE_SUFFIX = ".was"
# Of the directory the copies of a session's subagents are kept in
SUBAGENTS_SUFFIX = ".subagents"


def copy_path(host: Host, transcript: Path) -> Path:
    """Where the copy of a transcript is kept: by the names of its
    directory and of its file, which are Claude Code's and hold no path.
    That of a subagent (PROJECT/SESSION/subagents/NAME) is kept in
    PROJECT/SESSION.subagents, which is the copy of no transcript: those
    end in .jsonl."""
    session = subagent_session(transcript)
    if session is not None:
        kept = f"{session.name}{SUBAGENTS_SUFFIX}"
        return Path(
            host.transcript_copies_dir, session.parent.name, kept, transcript.name
        )
    return Path(host.transcript_copies_dir, transcript.parent.name, transcript.name)


def put_aside(copy: Path) -> list[Path]:
    """The earlier copies of a transcript, from before it was rewritten."""
    return sorted(copy.parent.glob(f"{glob.escape(copy.name)}.*{ASIDE_SUFFIX}"))


def still_at(descriptor: int, path: Path) -> bool:
    """Whether an open file is still the one at a path, and not one that
    was renamed or removed since it was opened."""
    try:
        opened, there = os.fstat(descriptor), os.stat(path)
    except OSError:
        return False
    return (opened.st_dev, opened.st_ino) == (there.st_dev, there.st_ino)


def catch_up(transcript: Path, copy: Path) -> None:
    """Add to a copy what its transcript has gained. Under a lock, the
    launchers of other sessions of the project copy it too."""
    source = open_plain(transcript)
    if source is None:
        return
    private_dir(str(copy.parent))
    with source, open_locked(copy, "ab") as kept:
        if not still_at(kept.fileno(), copy):
            # Put aside by the launcher that had the lock: this is no
            # longer the copy, the next look opens the one that is
            return
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


def length(path: Path) -> int | None:
    """How long a file is, none for one that is not there."""
    try:
        return path.stat().st_size
    except OSError:
        return None


class Copier:
    """Keeps the launcher's copies up with the project's transcripts that
    are written to while a session runs."""

    def __init__(self, host: Host, since: float) -> None:
        self._host = host
        # A transcript written just before is the one a resumed session
        # adds to
        self._since = since
        # How long each transcript was when the session started
        self._lengths = {path: length(path) for path in session_transcripts(host)}
        # Where the copy of each transcript there is goes, worked out once
        self._copies: dict[Path, Path] = {}
        # The looks at a transcript that failed, and why the last one did
        self.failed = 0
        self.problem = ""

    def written_to(self, transcript: Path) -> bool:
        """Whether a transcript was written to since the session started:
        it says so, it is new or of another length than it was, or the
        launcher's copy of it is not as long as it is."""
        try:
            about = transcript.stat()
        except OSError:
            return False
        if about.st_mtime >= self._since:
            return True
        if about.st_size != self._lengths.get(transcript):
            return True
        copied = length(self._copy_of(transcript))
        return copied is not None and copied != about.st_size

    def _copy_of(self, transcript: Path) -> Path:
        copy = self._copies.get(transcript)
        if copy is None:
            copy = self._copies[transcript] = copy_path(self._host, transcript)
        return copy

    def look(self) -> None:
        """Catch up the copy of each transcript that was written to."""
        transcripts = session_transcripts(self._host)
        # Not of those that are gone, a session can make any number
        self._copies = {
            transcript: copy
            for transcript in transcripts
            if (copy := self._copies.get(transcript)) is not None
        }
        for transcript in transcripts:
            if self.written_to(transcript):
                try:
                    catch_up(transcript, self._copy_of(transcript))
                except OSError as problem:
                    # A full disk or the like: the session goes on
                    # without, and it is said once it is over
                    self.failed += 1
                    self.problem = str(problem)


def let_go_of_old_copies(host: Host) -> None:
    oldest = time.time() - KEPT_DAYS * 86400
    kept = Path(host.transcript_copies_dir)
    # Those of the sessions, then those of their subagents
    for copy in [*kept.glob("*/*"), *kept.glob(f"*/*{SUBAGENTS_SUFFIX}/*")]:
        try:
            if copy.is_dir():
                continue
            if copy.stat().st_mtime < oldest:
                copy.unlink()
        except OSError:
            continue
    for directory in kept.glob(f"*/*{SUBAGENTS_SUFFIX}"):
        with contextlib.suppress(OSError):
            # Once it is empty
            directory.rmdir()


def keep_copying(copier: Copier, stop: threading.Event) -> None:
    while True:
        last = stop.wait(LOOK_EVERY)
        copier.look()
        if last:
            # Once more after the session has ended, for its last lines
            return


@contextmanager
def transcripts_copied(host: Host) -> Iterator[None]:
    """While a session runs, keep the launcher's copies of the project's
    transcripts up with them."""
    let_go_of_old_copies(host)
    copier = Copier(host, time.time() - 1)
    try:
        with in_background(keep_copying, copier):
            yield
    finally:
        if copier.failed:
            # What was written and taken back meanwhile is not in the
            # copy, and a session can be what made the copying fail
            print(
                "claude-airlock: the transcripts could not be copied at"
                f" {copier.failed} looks, what the session took out of them"
                f" meanwhile is not known: {copier.problem}",
                file=sys.stderr,
            )


def lines_of(path: Path) -> Iterator[bytes]:
    """The whole lines of a transcript or of a copy, one at a time, none
    for one that cannot be read. A last line without its end is still
    being written, or was when the copy was made. Not a line too long to
    be held, see bounded_lines: a trace shows that one as it is found."""
    file = open_plain(path)
    if file is None:
        return
    with file:
        for line in bounded_lines(file):
            if line and line.endswith(b"\n"):
                yield line


def line_digests(path: Path, most: int) -> set[bytes] | None:
    """What stands for each line of a transcript, none for one of more
    than so many different lines: they are not all held to be compared
    with, a transcript can be made of lines of a byte each."""
    digests: set[bytes] = set()
    for line in lines_of(path):
        digests.add(hashlib.sha256(line).digest())
        if len(digests) > most:
            return None
    return digests


def removed_transcripts(host: Host) -> list[Path]:
    """The transcripts of the project's sessions the launcher has a copy
    of and that are no longer there, each by where it was: a session can
    remove its own, and with it everything that lists the transcripts
    would no longer know of the session."""
    removed = []
    for directory in transcript_dirs(host):
        for copy in Path(host.transcript_copies_dir, directory.name).glob("*.jsonl"):
            transcript = directory / copy.name
            if copy.is_file() and not plain_file(transcript):
                removed.append(transcript)
    return removed


def removed_subagents(host: Host, transcript: Path) -> list[Path]:
    """The same of the subagents of one session, by its transcript."""
    copies = copy_path(host, transcript.with_suffix("") / SUBAGENTS_DIR / "any").parent
    return [
        subagent
        for copy in sorted(copies.glob("agent-*.jsonl"))
        for subagent in [transcript.with_suffix("") / SUBAGENTS_DIR / copy.name]
        if copy.is_file() and not plain_file(subagent)
    ]


def plain_file(path: Path) -> bool:
    """Whether a transcript is there to be read, see open_plain."""
    file = open_plain(path)
    if file is None:
        return False
    file.close()
    return True


def copied_at(host: Host, transcript: Path) -> float:
    """When the launcher last added to its copy of a transcript, 0
    without one."""
    try:
        return copy_path(host, transcript).stat().st_mtime
    except OSError:
        return 0.0


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
    # Whether the transcript itself is no longer there
    removed: bool = False
    # Whether the copy stopped at its size limit with more to copy: what
    # the transcript holds past it has nothing to be compared with
    cut_short: bool = False
    # How many more lines are gone than the entries of gone, which holds
    # no more than MOST_GONE_BYTES of them
    more_gone: int = 0
    # Whether the transcript has more lines than are compared: what was
    # taken out of it is then not known
    uncompared: bool = False

    @property
    def missing(self) -> int:
        """How many lines the copies have that the transcript no longer
        does."""
        return len(self.gone) + self.more_gone

    def header(self, subagents: int = 0) -> list[str]:
        """The line of a trace that says how far its transcript is to be
        believed, or those of so many subagents taken together."""
        name = f"subagents   {subagents}, " if subagents else "transcript  "
        it = "them" if subagents else "it"
        if not self.copied:
            if subagents:
                return [f"{name}as they are now, the launcher has not copied them all"]
            return [f"{name}as it is now, the launcher has no copy of it to compare"]
        stopped = (
            f"{name}NOT ALL COPIED: the launcher stops at"
            f" {MOST_COPIED >> 20} MB, what came later cannot be compared"
        )
        limit = [stopped] if self.cut_short else []
        if self.uncompared:
            limit.append(
                f"{name}NOT COMPARED: more than {MOST_COMPARED} lines, what was"
                f" taken out of {it} is not known"
            )
        if self.removed and not subagents:
            said = f"the {self.lines} lines the launcher copied are shown as REMOVED"
            return [f"{name}REMOVED, it is no longer there: {said}", *limit]
        if not self.gone and not self.rewritten:
            said = f"{name}as the launcher copied {it} ({self.lines} lines)"
            return limit or [said]
        said = f"{self.missing} lines the launcher copied are gone or altered"
        if self.rewritten:
            said += f", rewritten {self.rewritten} times"
        return [f"{name}CHANGED: {said}, they are shown as REMOVED", *limit]

    def with_(self, other: Compared) -> Compared:
        """The two as one: copied when both are, and what either lost."""
        return Compared(
            self.copied and other.copied,
            self.lines + other.lines,
            self.gone + other.gone,
            self.rewritten + other.rewritten,
            self.removed or other.removed,
            self.cut_short or other.cut_short,
            self.more_gone + other.more_gone,
            self.uncompared or other.uncompared,
        )


def compare(host: Host, transcript: Path) -> Compared:
    """What the launcher's copies of a transcript have that it no longer
    does, line by line: a session that edits its transcript can do so in
    place, without making it shorter."""
    copy = copy_path(host, transcript)
    copies = [*put_aside(copy), copy]
    found = Compared(rewritten=len(copies) - 1)
    # Neither side is held whole: the copies are read a line at a time,
    # against what stands for each line of the transcript
    current = line_digests(transcript, MOST_COMPARED)
    seen: set[bytes] = set()
    held = 0
    for line in (line for path in copies for line in lines_of(path)):
        found.lines += 1
        if current is None:
            continue
        digest = hashlib.sha256(line).digest()
        if digest in current or digest in seen:
            continue
        if len(seen) < MOST_COMPARED:
            seen.add(digest)
        if held + len(line) > MOST_GONE_BYTES:
            found.more_gone += 1
            continue
        # One that holds no entry is said to be gone too, as that
        entry = line_entry(line)
        if entry:
            held += len(line)
            found.gone.append(entry)
    found.copied = bool(found.lines)
    if not found.copied:
        return found
    found.uncompared = current is None
    found.removed = not plain_file(transcript)
    found.cut_short = (length(copy) or 0) >= MOST_COPIED and (
        length(transcript) or 0
    ) > (length(copy) or 0)
    return found
