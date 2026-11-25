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
and a new one started. Past MOST_PUT_ASIDE of those, what a copy held is
added to the last one put aside, as long as that has room, and the new
copy starts all the same: what is written after any number of rewrites is
still copied, and what could not be kept is counted (see Beyond).

Which transcripts a session writes to is not taken from when they say
they were written, that is the session's to set: one whose length has
changed is copied too, and one whose copy is not as long as it is.

A session can make any number of transcripts, each as long as it likes.
So a launcher adds no more to its copies in one session than
MOST_A_SESSION, to all of them together, and what it adds it adds a turn
at a time, to the transcripts in the order they were first written to
(see Copier). A copy that stopped short for it is noted to have, and
--trace says so of its transcript.

What this does not give: a line a session takes back within the moment
before it is copied, what is written once a launcher has no room left,
and anything of a session run without the launcher."""

from __future__ import annotations

import contextlib
import dataclasses
import glob
import itertools
import json
import os
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from ..background import in_background
from ..files import (
    LINE_LIMIT,
    digested_lines,
    json_object,
    line_entry,
    open_locked,
    open_plain,
    private_dir,
)
from ..notice import warn
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
# many times, the last of those no larger than a copy either: what a
# session can make the launcher keep is bounded
MOST_COPIED = 512 * 1024 * 1024
MOST_PUT_ASIDE = 5
# Nor does one launcher add more than this to its copies in one session,
# to all of them together: a session can make any number of transcripts,
# each a hole that takes no room on its disk and all of its length on the
# launcher's. Far more than the transcripts of a session come to, those
# of its subagents with them.
MOST_A_SESSION = 2 * 1024 * 1024 * 1024
# And no more than this to one copy before the others have their turn: a
# transcript that gained a lot at once, or was made to, does not keep the
# next one waiting for all of it
MOST_A_TURN = 16 * 1024 * 1024
# A transcript of more different lines than this is not compared with its
# copies, and of the lines found gone no more bytes are held than this:
# both are a session's to make large
MOST_COMPARED = 1_000_000
MOST_GONE_BYTES = 64 * 1024 * 1024
# Copies older than this many days go, as long as Claude Code keeps a
# transcript by default
KEPT_DAYS = 30
ASIDE_SUFFIX = ".was"
# Of the file that says what the copies of a transcript do not hold, next
# to its copy, see Beyond. No more of it is read than this
BEYOND_SUFFIX = ".beyond"
BEYOND_BYTES = 4096
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


@dataclass(frozen=True)
class Beyond:
    """What the copies of a transcript do not hold. Of one that was
    rewritten more often than copies are put aside: how many times more,
    and how many bytes of what its copies held then could not be kept.
    And whether a launcher stopped adding to its copy with more to copy,
    for want of room (see MOST_A_SESSION): what was written from then on
    was not copied as it came, also where a later launcher took it up."""

    rewrites: int = 0
    dropped: int = 0
    no_room: bool = False

    @classmethod
    def of(cls, copy: Path) -> Beyond:
        """As noted next to a copy, nothing of one that has no note or
        one that does not hold up: the file is the launcher's own, and
        may be cut off by one that was killed."""
        try:
            with open(f"{copy}{BEYOND_SUFFIX}", "rb") as note:
                said = json_object(note.read(BEYOND_BYTES)) or {}
        except OSError:
            return cls()
        rewrites, dropped = said.get("rewrites"), said.get("dropped")
        # Not in a note of before a launcher had a bound on its room
        no_room = said.get("no_room", False)
        if (
            type(rewrites) is not int
            or type(dropped) is not int
            or type(no_room) is not bool
        ):
            return cls()
        return cls(max(0, rewrites), max(0, dropped), no_room)

    def note(self, copy: Path) -> None:
        """Keep it next to a copy, in place of what was noted before."""
        noted = Path(f"{copy}{BEYOND_SUFFIX}.{os.getpid()}")
        noted.write_text(json.dumps(dataclasses.asdict(self)))
        os.replace(noted, f"{copy}{BEYOND_SUFFIX}")


def keep_with_last(copy: Path, last: Path) -> int:
    """Add what a copy holds to the last copy that was put aside, as far
    as that has room (see MOST_COPIED). From a line of its own on: a
    copy can end within a line. How many bytes had no room."""
    with open(copy, "rb") as held, open(last, "ab") as aside:
        left = os.fstat(held.fileno()).st_size
        room = MOST_COPIED - aside.tell()
        if left and room > 0:
            aside.write(b"\n")
            room -= 1
        while left and room > 0:
            data = held.read(min(CHUNK, left, room))
            if not data:
                break
            aside.write(data)
            left, room = left - len(data), room - len(data)
    return left


def start_anew(copy: Path, kept: int) -> None:
    """Have a copy start over for a transcript that was rewritten, with
    what it held kept. Put aside as it is the first MOST_PUT_ASIDE times,
    a new one then starts with the next look. After that it is emptied in
    its place, what it held added to the last one put aside, and what
    that had no room for counted. Called with the copy locked, by its
    open file."""
    aside = put_aside(copy)
    if len(aside) < MOST_PUT_ASIDE:
        os.replace(copy, f"{copy}.{time.time_ns()}{ASIDE_SUFFIX}")
        return
    before = Beyond.of(copy)
    dropped = keep_with_last(copy, aside[-1])
    # Noted before the copy is emptied: a launcher killed between the two
    # leaves a rewrite counted twice, not one that is not said
    dataclasses.replace(
        before, rewrites=before.rewrites + 1, dropped=before.dropped + dropped
    ).note(copy)
    os.ftruncate(kept, 0)


def note_no_room(copy: Path) -> None:
    """Note next to a copy that a launcher stopped adding to it with more
    to copy, for want of room (see MOST_A_SESSION). Under the lock of the
    copy, which is made as needed: the launchers of other sessions note
    what became of it too, see start_anew."""
    private_dir(str(copy.parent))
    with open_locked(copy, "ab"):
        before = Beyond.of(copy)
        if not before.no_room:
            dataclasses.replace(before, no_room=True).note(copy)


def catch_up(transcript: Path, copy: Path, most: int = MOST_COPIED) -> int:
    """Add to a copy what its transcript has gained, no more than most
    bytes of it, and return how many that was. Under a lock, the launchers
    of other sessions of the project copy it too."""
    source = open_plain(transcript)
    if source is None:
        return 0
    private_dir(str(copy.parent))
    added = 0
    with source, open_locked(copy, "ab") as kept:
        if not still_at(kept.fileno(), copy):
            # Put aside by the launcher that had the lock: this is no
            # longer the copy, the next look opens the one that is
            return 0
        have = os.fstat(kept.fileno()).st_size
        if os.fstat(source.fileno()).st_size < have:
            # Rewritten. What it held is kept, and a new copy starts with
            # the next look, however often that has happened.
            start_anew(copy, kept.fileno())
            return 0
        source.seek(have)
        while have + added < MOST_COPIED and added < most:
            data = source.read(min(CHUNK, most - added))
            if not data:
                break
            kept.write(data)
            added += len(data)
    return added


def length(path: Path) -> int | None:
    """How long a file is, none for one that is not there."""
    try:
        return path.stat().st_size
    except OSError:
        return None


class Copier:
    """Keeps the launcher's copies up with the project's transcripts that
    are written to while a session runs.

    Each of them has its turn at every look, in the order they were first
    seen to be written to, and a turn adds no more to a copy than
    MOST_A_TURN. The transcript of a session is there before anything the
    session runs can make another: it is not kept waiting by those that
    came after it, however many they are and however long. In all no more
    is added than MOST_A_SESSION. A copy that has more to take once that
    is used up stops short, which is noted next to it for --trace to say
    (see Beyond), and counted, to be said when the session is over. Not a
    copy that goes on growing: the launcher of another session of the
    project is adding to it then, and has room."""

    def __init__(self, host: Host, since: float) -> None:
        self._host = host
        # A transcript written just before is the one a resumed session
        # adds to
        self._since = since
        # Where the copy of each transcript there is goes, worked out once
        self._copies: dict[Path, Path] = {}
        there = session_transcripts(host)
        # How long each transcript was when the session started
        self._lengths = {path: length(path) for path in there}
        # Those an earlier launcher had no room to copy all of, left as
        # they are until they change length: taken up again for being
        # behind, what one session left would use up the room of every
        # session after it
        self._left = {path for path in there if Beyond.of(self._copy_of(path)).no_room}
        # The transcripts seen to be written to, the first seen first.
        # Each with how long its copy was when it was last found to have
        # more to take than there is room for, none while it never was
        self._written: dict[Path, int | None] = {}
        # How much may still be added to the copies, see MOST_A_SESSION
        self._room = MOST_A_SESSION
        # The transcripts whose copy this launcher noted to stop short
        # for want of room, and how many they are by now
        self._short: set[Path] = set()
        self.stopped = 0
        # The looks at a transcript that failed, and why the last one did
        self.failed = 0
        self.problem = ""

    @property
    def lengths(self) -> dict[Path, int]:
        """How long each transcript was when the session started, of
        those that were there: what one holds past that was added since,
        by this session or another of the project that ran meanwhile."""
        return {
            path: length for path, length in self._lengths.items() if length is not None
        }

    def written_to(self, transcript: Path) -> bool:
        """Whether a transcript was written to since the session started:
        it is new or of another length than it was, it says so, or the
        launcher's copy of it is not as long as it is. Of one an earlier
        launcher left with a copy that stopped short, the first alone."""
        try:
            about = transcript.stat()
        except OSError:
            return False
        if about.st_size != self._lengths.get(transcript):
            return True
        if transcript in self._left:
            return False
        if about.st_mtime >= self._since:
            return True
        copied = length(self._copy_of(transcript))
        return copied is not None and copied != about.st_size

    def _copy_of(self, transcript: Path) -> Path:
        copy = self._copies.get(transcript)
        if copy is None:
            copy = self._copies[transcript] = copy_path(self._host, transcript)
        return copy

    def look(self, whole: bool = False) -> bool:
        """Give each transcript that was written to its turn, the first
        seen first, see _turn: all it has to copy when told so, of a
        session that is over. Returns whether a turn left more to copy
        that there is room for, the next look is then due at once."""
        transcripts = session_transcripts(self._host)
        there = set(transcripts)
        # Not of those that are gone, a session can make any number
        self._copies = {
            transcript: copy
            for transcript in transcripts
            if (copy := self._copies.get(transcript)) is not None
        }
        self._written = {
            transcript: stuck
            for transcript, stuck in self._written.items()
            if transcript in there
        }
        self._short &= there
        for transcript in transcripts:
            if transcript not in self._written and self.written_to(transcript):
                self._written[transcript] = None
        more = False
        for transcript in self._written:
            try:
                more |= self._turn(transcript, whole)
            except OSError as problem:
                # A full disk or the like: the session goes on without,
                # and it is said once it is over
                self.failed += 1
                self.problem = str(problem)
        return more and self._room > 0

    def _turn(self, transcript: Path, whole: bool) -> bool:
        """Add to the copy of a transcript what it has gained: as much as
        a turn takes, or all of it when told so, and never more than
        there is room for. One that has more to copy with no room left
        stops short, see _stop_short. Returns whether the turn left more
        to copy. Raises OSError as catch_up does."""
        copy = self._copy_of(transcript)
        there, have = length(transcript), length(copy) or 0
        if there is None or there == have or MOST_COPIED <= have < there:
            # Gone, all copied, or copied as far as a copy goes
            return False
        if have < there and not self._room:
            self._stop_short(transcript, copy, have, whole)
            return False
        # Of one that got shorter than its copy too, which takes no room
        most = self._room if whole else min(self._room, MOST_A_TURN)
        added = catch_up(transcript, copy, most)
        self._room -= added
        left = min(there, MOST_COPIED) - have - added
        if left > 0 and not self._room:
            self._stop_short(transcript, copy, have + added, whole)
        # Not of a turn that added nothing, whatever kept it from: the
        # next look would be due at once, and add nothing either
        return left > 0 and added > 0

    def _stop_short(self, transcript: Path, copy: Path, have: int, last: bool) -> None:
        """Note next to the copy of a transcript that it stopped short
        for want of room, once: have is how long the copy is. Not the
        first time it is found so, unless that is at the last look: a
        copy that is longer by the next look is added to by the launcher
        of another session of the project, and is short of nothing."""
        if transcript in self._short:
            return
        if last or self._written[transcript] == have:
            note_no_room(copy)
            self._short.add(transcript)
            self.stopped += 1
        self._written[transcript] = have


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
    more = False
    while True:
        # Without the wait after a look whose turns left more to copy: a
        # transcript that gained more than a turn takes is caught up with
        # as fast as it would be in one go, the others in between
        last = stop.wait(0 if more else LOOK_EVERY)
        # Once more after the session has ended, for its last lines, and
        # then all there is of each: nothing is written to them any more
        more = copier.look(whole=last)
        if last:
            return


@contextmanager
def transcripts_copied(host: Host) -> Iterator[Copier]:
    """While a session runs, keep the launcher's copies of the project's
    transcripts up with them. Gives what copies them, which knows how
    long each was when the session started."""
    let_go_of_old_copies(host)
    copier = Copier(host, time.time() - 1)
    try:
        with in_background(keep_copying, copier):
            yield copier
    finally:
        if copier.failed:
            # What was written and taken back meanwhile is not in the
            # copy, and a session can be what made the copying fail
            warn(
                "the transcripts could not be copied at"
                f" {copier.failed} looks, what the session took out of them"
                f" meanwhile is not known: {copier.problem}",
            )
        if copier.stopped:
            # A session can be what used the room up, with transcripts
            # that are none
            warn(
                f"{copier.stopped} transcripts were not all copied, the"
                f" launcher copies no more than {MOST_A_SESSION >> 20} MB in"
                " one session: what the session took out of them after"
                " that is not known, --trace says NOT ALL COPIED of each",
            )


def lines_of(path: Path) -> Iterator[tuple[bytes, bytes | None]]:
    """The whole lines of a transcript or of a copy, one at a time, each
    as what stands for it and the line itself, none for a file that
    cannot be read. A last line without its end is still being written,
    or was when the copy was made. Of a line too long to be held there is
    what stands for it alone, see digested_lines: it is compared like any
    other, by that."""
    file = open_plain(path)
    if file is None:
        return
    with file:
        yield from digested_lines(file, LINE_LIMIT)


def line_digests(path: Path, most: int) -> set[bytes] | None:
    """What stands for each line of a transcript, none for one of more
    than so many different lines: they are not all held to be compared
    with, a transcript can be made of lines of a byte each."""
    digests: set[bytes] = set()
    for digest, _ in lines_of(path):
        digests.add(digest)
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


def last_written(host: Host, transcript: Path) -> float:
    """When a transcript was last written, 0 for one that is gone and was
    never copied: by the time of the file or by that of the launcher's
    copy, whichever is later. The first is the session's to set, and one
    set back would have its transcript pass for an older session's."""
    try:
        written = transcript.stat().st_mtime
    except OSError:
        written = 0.0
    return max(written, copied_at(host, transcript))


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
    # How many bytes of what the copies held when it was rewritten could
    # not be kept, see Beyond: what was taken out among them is not known
    dropped: int = 0
    # Whether a launcher stopped adding to the copy with more to copy,
    # for want of room, see Beyond: what was written from then on was not
    # copied as it came
    no_room: bool = False

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
        full = (
            f"{name}NOT ALL COPIED: a launcher copies no more than"
            f" {MOST_A_SESSION >> 20} MB in one session, what was taken out"
            f" of {it} after that is not known"
        )
        short = [full] if self.no_room else []
        if not self.copied:
            if subagents:
                said = f"{name}as they are now, the launcher has not copied them all"
            else:
                said = f"{name}as it is now, the launcher has no copy of it to compare"
            return [said, *short]
        stopped = (
            f"{name}NOT ALL COPIED: the launcher stops at"
            f" {MOST_COPIED >> 20} MB, what came later cannot be compared"
        )
        limit = [*([stopped] if self.cut_short else []), *short]
        if self.uncompared:
            limit.append(
                f"{name}NOT COMPARED: more than {MOST_COMPARED} lines, what was"
                f" taken out of {it} is not known"
            )
        if self.dropped:
            limit.append(
                f"{name}NOT ALL KEPT: rewritten {self.rewritten} times, of what"
                f" the launcher had copied {self.dropped} bytes had no room"
                f" left, what was taken out of {it} with them is not known"
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
            self.dropped + other.dropped,
            self.no_room or other.no_room,
        )


def compare(host: Host, transcript: Path) -> Compared:
    """What the launcher's copies of a transcript have that it no longer
    does, line by line: a session that edits its transcript can do so in
    place, without making it shorter."""
    copy = copy_path(host, transcript)
    copies = [*put_aside(copy), copy]
    beyond = Beyond.of(copy)
    found = Compared(
        rewritten=len(copies) - 1 + beyond.rewrites,
        dropped=beyond.dropped,
        no_room=beyond.no_room,
    )
    copied = (line for path in copies for line in lines_of(path))
    first = next(copied, None)
    if first is None:
        # Nothing to compare with, the transcript is not read for it: a
        # session can make any number that were never copied
        return found
    found.copied = True
    # Neither side is held whole: the copies are read a line at a time,
    # against what stands for each line of the transcript
    current = line_digests(transcript, MOST_COMPARED)
    seen: set[bytes] = set()
    held = 0
    for digest, line in itertools.chain([first], copied):
        found.lines += 1
        if current is None or digest in current or digest in seen:
            continue
        if len(seen) < MOST_COMPARED:
            seen.add(digest)
        # Nothing is held of a line that was too long to be
        size = 0 if line is None else len(line)
        if held + size > MOST_GONE_BYTES:
            found.more_gone += 1
            continue
        # One that holds no entry is said to be gone too, as that, and so
        # is one too long to be read
        entry = line_entry(line)
        if entry:
            held += size
            found.gone.append(entry)
    found.uncompared = current is None
    found.removed = not plain_file(transcript)
    found.cut_short = (length(copy) or 0) >= MOST_COPIED and (
        length(transcript) or 0
    ) > (length(copy) or 0)
    return found
