"""What Claude Code sends to the model and what the model answers, kept
when CLAUDE_AIRLOCK_API_LOG is on.

A transcript tells what a session did, not all of what the model was given
to do it with: the system prompt, the definitions of the tools, what
Claude Code adds to a prompt on its own, and the requests it makes besides
the conversation (a title, a summary, what a page it fetched says). Claude
Code writes all of it out when told to (OTEL_LOG_RAW_API_BODIES=file:DIR):
the request of each call as a file, its answer as another, and a line of
an index once the answer is whole, with the ids a transcript knows the
step by.

It writes them from inside the sandbox. So a session is given a directory
for them, its drop, mounted into that session alone, and the launcher
takes each request out of it as its line of the index comes (see Keeper):
it measures the two files, copies them to a directory no session has, lets
go of them in the drop, and notes the request in a record of its own (see
api_calls.py), a line per request. That line is what line mode, --trace
and what follows the sessions show (see report/api_events.py). The drop
is gone with the session.

Three things, each with one part in it. The Drop is all that touches what
a session wrote. The Shelf is where the launcher keeps the bodies, and the
record of api_calls.py what it notes of each request. The Keeper takes a
request from the first to the other two.

What this is: the session's own word, as a transcript is. Claude Code
writes the files, and anything else a session runs can write there too.
The launcher adds when it saw each request, and a copy made within a
moment, which a session cannot take back. What did go over the network is
told by the capture, not by this.

What a session can make the launcher read and keep is bounded. A body
longer than MOST_BODY is neither read nor kept, no more than
MOST_READ_A_SESSION of bodies is read of one session, no more than
MOST_A_SESSION of them kept and MOST_SESSION_CALLS requests noted, and of
the index no more is read at a look than MOST_INDEX_A_LOOK. A request
past one of those is noted by how long its files are, without its bodies,
or counted, and said. What is kept goes after KEPT_DAYS, the oldest
sessions first once there is more than MOST_KEPT in all: a body holds
everything the session read up to it, and is kept as a transcript is, for
the user alone."""

from __future__ import annotations

import contextlib
import dataclasses
import enum
import itertools
import json
import os
import re
import shutil
import threading
import time
from collections import deque
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from ..background import in_background
from ..docker import env_arg, mount_arg
from ..errors import Fatal
from ..files import (
    MOST_LINE_HELD,
    held_size,
    json_object,
    open_plain,
    private_dir,
    try_lock_file,
    write_whole,
)
from ..notice import warn
from ..settings import CONTAINER_HOME, Host, Settings
from .api_calls import Call, Part, SessionCalls, Tokens, count, noted_text

# Where a session has its drop, and what tells Claude Code to write there
DROP_TARGET = f"{CONTAINER_HOME}/.local/state/api-log"
WRITE_BODIES = "OTEL_LOG_RAW_API_BODIES"
# What a session is told the setting by, see docker/CLAUDE-airlock.md
SESSION_TOLD = "CLAUDE_AIRLOCK_API_LOG"
# The index Claude Code adds a line to with each answer
INDEX = "index.jsonl"
# Seconds between two looks at the drop
LOOK_EVERY = 0.5
# Of the index, as much as one look takes in, and the last one of a
# session that is over. A line of it is a few hundred bytes, one longer
# than INDEX_LINE is none of Claude Code's
MOST_INDEX_A_LOOK = 1 << 20
MOST_INDEX_AT_LAST = 16 << 20
INDEX_LINE = 16 * 1024
# A body longer than this is neither read nor kept: the API takes no
# request of more than 32 MB
MOST_BODY = 48 << 20
# Seconds a line of the index is given for its answer to be whole in its
# file: Claude Code writes the two at once, and the line can be first
ANSWER_WAIT = 2.0
# The lines of the index that wait for their answer at once
MOST_WAITING = 1000
# Seconds within which a request is noted once its answer is in the
# transcript, as a rule: what looks for the requests of a span of time
# looks this much past its end, see report/api_events.py
NOTED_WITHIN = ANSWER_WAIT + 2 * LOOK_EVERY
# No more of bodies than this is kept of one session, each request holds
# the conversation up to it again. And no more than this is read of them,
# to be measured: past it a request is noted by how long its files are
MOST_A_SESSION = 1 << 30
MOST_READ_A_SESSION = 4 << 30
# And no more of them is kept in all, nor for longer than so many days
MOST_KEPT = 4 << 30
KEPT_DAYS = 14
# No more names of a drop than this are looked at for the requests that
# had no answer, the drop is the session's to fill
MOST_LISTED = 10_000
# What the name of a drop ends with that was put aside, see _fresh_drop
ASIDE_SUFFIX = ".left"
# What a body says in the place of what Claude Code did not write out
WITHHELD = "not_recorded"
# Where the API says how many of the tokens written were thinking
OUTPUT_DETAILS = "output_tokens_details"


class BodyKind(enum.StrEnum):
    """Which of the two files of a request one is, by what its name
    ends with, in a drop and where the launcher keeps it."""

    REQUEST = "request"
    RESPONSE = "response"

    def file_name(self, stem: str) -> str:
        """The name of the file of this kind that starts so."""
        return f"{stem}.{self.value}.json"

    def names(self, value: object) -> str:
        """A name Claude Code gives a file of this kind, empty for
        anything that is not such a name: an id, never a path."""
        if not isinstance(value, str):
            return ""
        named = _BODY_NAME.fullmatch(value)
        return value if named and named.group(1) == self.value else ""


_BODY_NAME = re.compile(
    rf"[A-Za-z0-9_-]{{1,128}}\.({'|'.join(BodyKind)})\.json", re.ASCII
)


def api_log_args(drop: str) -> list[str]:
    """What gives a session its drop and has Claude Code write there."""
    return [
        mount_arg(drop, DROP_TARGET, "z"),
        env_arg(WRITE_BODIES, f"file:{DROP_TARGET}"),
        env_arg(SESSION_TOLD, 1),
    ]


@dataclass(frozen=True)
class Claimed:
    """A line of the index: the request as Claude Code tells of it, and
    the names of its two files, each empty when the line names none."""

    call: Call
    request_file: str = ""
    response_file: str = ""

    @classmethod
    def of(cls, line: bytes) -> Claimed | None:
        """What a line of the index tells of, none for a line that names
        neither a request nor an answer."""
        said = json_object(line)
        if said is None:
            return None
        call = Call(
            source=noted_text(said.get("query_source")),
            model=noted_text(said.get("model")),
            claude_session=noted_text(said.get("session_id")),
            request_id=noted_text(said.get("request_id")),
            message_id=noted_text(said.get("message_id")),
            message_uuid=noted_text(said.get("message_uuid")),
            # A line comes once the answer has
            answered=True,
        )
        claimed = cls(
            call,
            BodyKind.REQUEST.names(said.get("request_file")),
            BodyKind.RESPONSE.names(said.get("response_file")),
        )
        return claimed if claimed.files else None

    @property
    def files(self) -> tuple[str, ...]:
        """The names of the files it has."""
        return tuple(filter(None, (self.request_file, self.response_file)))


@dataclass(frozen=True)
class Body:
    """The file of a request or of an answer as it was found in a drop:
    how long it is, what it holds unless that was too long to read, and
    the object that is when it reads as one."""

    size: int = 0
    data: bytes | None = None
    held: dict | None = None

    @classmethod
    def read(cls, path: Path, most: int) -> Body:
        """The body at a path, nothing for one that is not there or is
        no plain file (see open_plain). A session wrote it: one longer
        than most is not read, and one is not taken apart when that
        would hold more than a line of a transcript may (see
        held_size)."""
        file = open_plain(path)
        if file is None:
            return cls()
        try:
            with file:
                size = os.fstat(file.fileno()).st_size
                if size > most:
                    return cls(size)
                # As long as it was when measured: what it gains meanwhile
                # is not read, a session can go on writing for ever
                data = file.read(size)
        except OSError:
            return cls()
        held = json_object(data) if held_size(data) <= MOST_LINE_HELD else None
        return cls(len(data), data, held)


def _written_size(value: object) -> int:
    """How many bytes a value of a body takes written out, as Claude
    Code writes it, 0 for one that cannot be."""
    try:
        written = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except (ValueError, RecursionError):
        return 0
    return len(written.encode("utf-8", "replace"))


def _length(asked: Mapping, part: Part) -> int | None:
    """How many there are of a part of a request that is a list, none
    for one that is not."""
    listed = asked.get(part)
    return len(listed) if isinstance(listed, list) else None


def with_request(call: Call, request: Body) -> Call:
    """A request with what its body measures: how long it is, and once
    it is read how much of it the definitions of the tools, the system
    prompt and the conversation take, how many tools and messages there
    are, and whether Claude Code says it left the body out. The model of
    one no line of the index named is the one its body names."""
    asked = request.held
    if asked is None:
        return dataclasses.replace(call, sent=request.size or None)
    return dataclasses.replace(
        call,
        sent=request.size,
        parts={part: _written_size(asked[part]) for part in Part if part in asked},
        tool_count=_length(asked, Part.TOOLS),
        message_count=_length(asked, Part.MESSAGES),
        withheld=WITHHELD in asked,
        model=call.model or noted_text(asked.get("model")),
    )


def with_answer(call: Call, answer: Body) -> Call:
    """A request with what its answer measures: how long it is, and once
    it is read what the API says the request used and why the model
    stopped."""
    answered = answer.held
    if answered is None:
        return dataclasses.replace(call, received=answer.size or None)
    given = answered.get("usage")
    usage = given if isinstance(given, dict) else {}
    details = usage.get(OUTPUT_DETAILS)
    thinking = details.get(Tokens.THINKING) if isinstance(details, dict) else None
    said = {**usage, Tokens.THINKING: thinking}
    return dataclasses.replace(
        call,
        received=answer.size,
        used={
            kind: used for kind in Tokens if (used := count(said.get(kind))) is not None
        },
        stop=noted_text(answered.get("stop_reason")),
    )


class IndexTail:
    """The index of a drop read as it grows, a line at a time. It is the
    session's to write: no more of it is read at once than asked for, and
    a line longer than INDEX_LINE is passed over, not held."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._offset = 0
        # The start of a line whose end is not written yet
        self._partial = b""
        # Whether what is read is the rest of a line that was too long
        self._dropping = False
        # The lines passed over for being too long
        self.too_long = 0

    def new_lines(self, most: int) -> list[bytes]:
        """The lines completed since the last time, of no more than most
        bytes of it: the rest is for the next time. None while it is not
        a plain file that can be read."""
        file = open_plain(self._path)
        if file is None:
            return []
        try:
            with file:
                size = os.fstat(file.fileno()).st_size
                if size < self._offset:
                    # Written anew and shorter: from where it ends now
                    self._offset, self._partial, self._dropping = size, b"", False
                file.seek(self._offset)
                data = file.read(min(most, size - self._offset))
        except OSError:
            return []
        self._offset += len(data)
        if self._dropping:
            _, ended, data = data.partition(b"\n")
            self._dropping = not ended
        *lines, self._partial = (self._partial + data).split(b"\n")
        if len(self._partial) > INDEX_LINE:
            self._partial, self._dropping = b"", True
            self.too_long += 1
        whole = [line for line in lines if line.strip()]
        self.too_long += sum(len(line) > INDEX_LINE for line in whole)
        return [line for line in whole if len(line) <= INDEX_LINE]


def _open_up(top: str) -> None:
    """Have a drop and the directories in it be the launcher's to read
    and to empty again. A session can take that away, it owns them as the
    launcher does: with a mode of none on its drop nothing would be taken
    from it, and nothing of it removed. Never the mode of what a link
    leads to, and of no more directories than MOST_LISTED."""
    left = [top]
    for _ in range(MOST_LISTED):
        if not left:
            return
        directory = left.pop()
        # Not where the mode of a link itself cannot be asked for: that
        # one is left as it is
        with contextlib.suppress(OSError, NotImplementedError):
            os.chmod(directory, 0o700, follow_symlinks=False)
        with contextlib.suppress(OSError), os.scandir(directory) as entries:
            left += [
                entry.path
                for entry in itertools.islice(entries, MOST_LISTED)
                if entry.is_dir(follow_symlinks=False)
            ]


def _removed(drop: str) -> bool:
    """Remove a drop with all a session left in it, never through a
    link. Whether it is gone."""
    _open_up(drop)
    shutil.rmtree(drop, ignore_errors=True)
    return not os.path.lexists(drop)


class Drop:
    """The drop of one session, where Claude Code leaves its requests
    and answers. All that touches what a session wrote is here: a name
    is one of the drop and never a path, nothing is read through a link,
    and no more is read of the bodies of a session than
    MOST_READ_A_SESSION, of one no more than MOST_BODY."""

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._index = IndexTail(self._path / INDEX)
        # How much of bodies may still be read
        self._readable = MOST_READ_A_SESSION
        # Whether it could not be listed when that was last tried
        self.closed = False

    def open_up(self) -> None:
        """Have it be the launcher's to read again, see _open_up: for
        the last look, at what a session closed while it ran."""
        _open_up(str(self._path))

    @property
    def unread(self) -> int:
        """The lines of the index that were too long to be one."""
        return self._index.too_long

    def claimed(self, most: int) -> list[Claimed]:
        """What the index gained since the last time, of no more than
        most bytes of it, see IndexTail."""
        lines = self._index.new_lines(most)
        return [claimed for claimed in map(Claimed.of, lines) if claimed]

    def body(self, name: str) -> Body:
        """The body of a name, nothing for no name, as far as there is
        room left to read it."""
        if not name:
            return Body()
        body = Body.read(self._path / name, min(MOST_BODY, self._readable))
        self._readable -= len(body.data or b"")
        return body

    def let_go(self, *names: str) -> None:
        """Remove what was taken: Claude Code does not read it again,
        and left there a request would be kept twice, or pass for one
        that had no answer."""
        for name in filter(None, names):
            with contextlib.suppress(OSError):
                # Never through a link: the name is removed, whatever it is
                os.unlink(self._path / name)

    def requests_left(self) -> list[str]:
        """The names of the requests that are still there, the first
        written first as far as the files say. Of no more names than
        MOST_LISTED, the drop is the session's to fill."""
        found: list[tuple[float, str]] = []
        try:
            with os.scandir(self._path) as entries:
                for entry in itertools.islice(entries, MOST_LISTED):
                    if not BodyKind.REQUEST.names(entry.name):
                        continue
                    with contextlib.suppress(OSError):
                        written = entry.stat(follow_symlinks=False).st_mtime
                        found.append((written, entry.name))
        except OSError:
            self.closed = True
            return []
        self.closed = False
        return [name for _, name in sorted(found)]


class Shelf:
    """Where the launcher keeps the bodies of one session, out of every
    session's reach: a directory of its own, the bodies of each request
    under a number of their own, in the order they came. No more than
    MOST_A_SESSION in all, each request holds the conversation up to it
    again."""

    def __init__(self, host: Host, session: str, started: float) -> None:
        self._all = host.api_bodies_dir
        # Under a name no other session has: its container and when it
        # started, a later moment when one of that very second was there
        moment = int(started)
        while os.path.lexists(os.path.join(self._all, f"{session}-{moment}")):
            moment += 1
        self._name = f"{session}-{moment}"
        self._room = MOST_A_SESSION
        # The number given last
        self._number = 0
        # The requests whose bodies had no room left
        self.unkept = 0

    @property
    def directory(self) -> str:
        """Where the bodies are, made when the first one is kept."""
        return os.path.join(self._all, self._name)

    def keep(self, bodies: Mapping[BodyKind, Body]) -> str:
        """Keep the bodies of a request, those that were read, under the
        next number. What they are kept as, empty when there is nothing
        to keep or no room left for it. Raises OSError when they cannot
        be written: the number is used up all the same, what was written
        under it is never taken for a body of the next request."""
        read = {kind: body.data for kind, body in bodies.items() if body.data}
        wanted = sum(map(len, read.values()))
        if not wanted:
            return ""
        if wanted > self._room:
            self.unkept += 1
            return ""
        self._number += 1
        directory = private_dir(self.directory)
        stem = f"{self._number:06d}"
        for kind, data in read.items():
            write_whole(os.path.join(directory, kind.file_name(stem)), data)
        self._room -= wanted
        return f"{self._name}/{stem}"


class Keeper:
    """Takes the requests of one session out of its drop, a look at a
    time, in the order the index has them: each is measured, its bodies
    put on the shelf, and noted.

    A request is taken once its answer reads whole, or has had
    ANSWER_WAIT to: Claude Code writes the line of the index and the
    file of the answer at once, either can be first. When the session is
    over the requests still in the drop are those that had no answer (a
    turn that was interrupted, a request that failed): each is noted as
    that.

    Not used from several threads."""

    def __init__(self, drop: Drop, shelf: Shelf, calls: SessionCalls) -> None:
        self._drop = drop
        self._shelf = shelf
        self._calls = calls
        # The requests whose answer is waited for, each with since when
        self._waiting: deque[tuple[Claimed, float]] = deque()
        # The requests that could not be taken, and why the last one was
        # not
        self.failed = 0
        self.problem = ""

    @classmethod
    def of(cls, host: Host, session: str, drop: str, started: float) -> Keeper:
        """What takes the requests of the session of a container out of
        its drop, started at that time."""
        return cls(
            Drop(drop), Shelf(host, session, started), SessionCalls(host, session)
        )

    @property
    def kept_dir(self) -> str:
        """Where the bodies of this session are kept."""
        return self._shelf.directory

    @property
    def unkept(self) -> int:
        """The requests whose bodies had no room left."""
        return self._shelf.unkept

    @property
    def unread(self) -> int:
        """The lines of the index that were too long to be one."""
        return self._drop.unread

    @property
    def closed(self) -> bool:
        """Whether the drop could not be read at the last look: what
        the session left there was not taken."""
        return self._drop.closed

    def look(self, last: bool = False) -> None:
        """Take what the index gained since the last look, and the
        requests that waited for their answer. At the last look of a
        session that is over nothing is waited for any more, and what is
        left in the drop is taken as the requests that had no answer."""
        most = MOST_INDEX_AT_LAST if last else MOST_INDEX_A_LOOK
        if last:
            # What a session closed to the launcher while it ran: its
            # index is then read from where it was left
            self._drop.open_up()
        for claimed in self._drop.claimed(most):
            if len(self._waiting) >= MOST_WAITING:
                self._count(claimed)
                continue
            self._waiting.append((claimed, time.monotonic()))
        while self._waiting:
            claimed, since = self._waiting[0]
            waited = time.monotonic() - since >= ANSWER_WAIT
            if not self._attempt(claimed, whatever=last or waited):
                break
            self._waiting.popleft()
        if last:
            self._take_unanswered()
            self._calls.close()

    def _attempt(self, claimed: Claimed, whatever: bool) -> bool:
        """Take a request, see _take. One that cannot be taken for what
        the disk says is counted and let go of: the session goes on
        without, and it is said once it is over."""
        try:
            return self._take(claimed, whatever)
        except OSError as problem:
            self._failed(problem)
            self._drop.let_go(*claimed.files)
            return True

    def _failed(self, problem: OSError) -> None:
        self.failed += 1
        self.problem = str(problem)

    def _take(self, claimed: Claimed, whatever: bool) -> bool:
        """Note a request of the index and keep its bodies. Whether it
        was taken: not while its answer does not read whole, unless told
        to take it whatever is there. Raises OSError when it cannot be
        kept or noted."""
        if self._calls.full:
            self._count(claimed)
            return True
        answer = self._drop.body(claimed.response_file)
        if answer.held is None and not whatever:
            return False
        request = self._drop.body(claimed.request_file)
        self._note(with_answer(claimed.call, answer), request, answer)
        self._drop.let_go(*claimed.files)
        return True

    def _note(self, call: Call, request: Body, answer: Body) -> None:
        """Add a request to the record, with what its body measures and
        where its bodies are kept. Raises OSError when they cannot be
        kept, or the record not written."""
        bodies = {BodyKind.REQUEST: request, BodyKind.RESPONSE: answer}
        kept = self._shelf.keep(bodies)
        self._calls.note(dataclasses.replace(with_request(call, request), kept=kept))

    def _count(self, claimed: Claimed) -> None:
        """Count a request of the index that is not noted on its own,
        and let go of its files unread."""
        self._calls.count()
        self._drop.let_go(*claimed.files)

    def _take_unanswered(self) -> None:
        """Note the requests that are still in the drop once the session
        is over: no line of the index came for them, so no answer did."""
        for name in self._drop.requests_left():
            if self._calls.full:
                self._calls.count()
                continue
            try:
                self._note(Call(), self._drop.body(name), Body())
            except OSError as problem:
                self._failed(problem)


def _session_over(host: Host, name: str) -> bool:
    """Whether no launcher has the session of a name any more, by the
    claim each holds on its name while it runs (see container_name of
    sandbox/session.py). Not when that cannot be told."""
    try:
        claim = try_lock_file(os.path.join(host.names_dir, name))
    except OSError:
        return False
    if claim is None:
        return False
    os.close(claim)
    return True


def let_go_of_left_drops(host: Host) -> None:
    """Remove the drops of the sessions that ended without their
    launcher: what such a drop still holds was the last moment of its
    session, and nothing takes it any more."""
    try:
        with os.scandir(host.api_drop_dir) as entries:
            left = [entry.path for entry in entries]
    except OSError:
        return
    for drop in left:
        if _session_over(host, os.path.basename(drop)):
            # Tried again by the next launcher when it could not be
            _removed(drop)


def _fresh_drop(host: Host, session: str) -> str:
    """Make the drop of a session, empty: one left under its name is of
    a session that ended without its launcher. One that cannot be
    removed is put aside under a name no session has, and said: left in
    its place, no later session of that name could have its requests
    kept. Raises OSError when the drop cannot be made."""
    drop = os.path.join(private_dir(host.api_drop_dir), session)
    if not _removed(drop):
        aside = f"{drop}.{time.time_ns()}{ASIDE_SUFFIX}"
        os.rename(drop, aside)
        warn(f"what a session left in {aside} cannot be removed, it is yours to")
    os.mkdir(drop, 0o700)
    return drop


def _kept_size(directory: Path) -> int:
    """How much the bodies kept of one session take."""
    total = 0
    with contextlib.suppress(OSError), os.scandir(directory) as entries:
        for entry in entries:
            with contextlib.suppress(OSError):
                total += entry.stat(follow_symlinks=False).st_size
    return total


def let_go_of_old_bodies(host: Host) -> None:
    """Remove what is kept of the sessions of more than KEPT_DAYS ago,
    and of the oldest ones once there is more than MOST_KEPT in all. By
    when each was last added to: one that is still running was just
    now."""
    kept: list[tuple[float, Path]] = []
    try:
        with os.scandir(host.api_bodies_dir) as entries:
            for entry in entries:
                with contextlib.suppress(OSError):
                    if entry.is_dir(follow_symlinks=False):
                        kept.append((entry.stat().st_mtime, Path(entry.path)))
    except OSError:
        return
    oldest = time.time() - KEPT_DAYS * 86400
    room = MOST_KEPT
    # The latest first, each as long as there is room for it
    for written, directory in sorted(kept, reverse=True):
        room -= _kept_size(directory)
        if written < oldest or room < 0:
            shutil.rmtree(directory, ignore_errors=True)


def _keep_taking(keeper: Keeper, stop: threading.Event) -> None:
    while True:
        # Once more after the session has ended, for its last requests
        # and for those that had no answer
        last = stop.wait(LOOK_EVERY)
        keeper.look(last=last)
        if last:
            return


def _say_what_is_missing(keeper: Keeper) -> None:
    """Say what of a session's requests was not kept as asked, once it
    is over."""
    if keeper.failed:
        warn(
            f"{keeper.failed} requests to the model could not be kept: {keeper.problem}"
        )
    if keeper.unkept:
        warn(
            f"{keeper.unkept} requests to the model were noted without"
            " their bodies, the launcher keeps no more than"
            f" {MOST_A_SESSION >> 20} MB of them in one session"
        )
    if keeper.closed:
        warn(
            "the requests to the model could not be taken, the session"
            " closed the directory they are left in: what it sent is not"
            " known"
        )
    if keeper.unread:
        warn(
            f"{keeper.unread} lines of the index of the requests to the"
            " model were too long to be read, what they told of is not"
            " noted"
        )


@contextmanager
def api_logged(settings: Settings, host: Host, session: str) -> Iterator[list[str]]:
    """While a session runs, take what Claude Code sends to the model and
    what is answered out of the session's drop, see the module. Gives the
    options of docker run that have the session write there, none unless
    CLAUDE_AIRLOCK_API_LOG is on."""
    # Also when it is off: what was kept while it was on goes all the
    # same, a body is not kept for longer because nothing is added
    let_go_of_old_bodies(host)
    let_go_of_left_drops(host)
    if not settings.api_log:
        yield []
        return
    try:
        drop = _fresh_drop(host, session)
    except OSError as problem:
        # Asked for and not to be had: not a session without it
        raise Fatal(f"the requests to the model cannot be kept: {problem}") from problem
    keeper = Keeper.of(host, session, drop, time.time())
    try:
        with in_background(_keep_taking, keeper):
            yield api_log_args(drop)
    finally:
        _say_what_is_missing(keeper)
        if not _removed(drop):
            warn(f"what the session left in {drop} cannot be removed, it is yours to")
