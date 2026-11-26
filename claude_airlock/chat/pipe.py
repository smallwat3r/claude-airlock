"""Claude Code at the other end of a pipe: the process a chat talks to,
what it is told, and what it says as it comes.

Claude Code runs in its print mode and speaks JSON Lines over its standard
input and output, the protocol of the Agent SDK. A line each way is one
object: a prompt, a request (to interrupt, to change the mode) or the
answer to one of its own going in, what it does and asks coming out.

What comes out is the session's to write, as its transcript is. It is
bounded as it is read here, and what is taken from it is checked for being
what it should be in said.py."""

from __future__ import annotations

import collections
import contextlib
import enum
import itertools
import json
import queue
import subprocess
import sys
import threading
from collections.abc import Callable

from ..docker import NOT_FOUND, docker_popen
from ..errors import Fatal
from ..events import clean
from ..files import MOST_LINE_HELD, held_size, json_object

# What claude is run with: print mode, JSON Lines both ways, its questions
# about permissions asked over the same pipe, and a reply told as it is made
CHAT_ARGS = (
    "--print",
    "--verbose",
    "--input-format=stream-json",
    "--output-format=stream-json",
    "--permission-prompt-tool=stdio",
    "--include-partial-messages",
)
# A line longer than this is not taken in, nor is one that holds more
# once read than a line may (MOST_LINE_HELD): Unread stands for it. No
# more than so many wait to be taken in, nor more bytes of them than
# BACKLOG_BYTES, as they are held (see held_size): a line can be long, a
# result with a picture in it is, but not a thousand of them at once
LINE_LIMIT = 64 << 20
BACKLOG = 1000
BACKLOG_BYTES = 256 << 20
# No more than so many lines wait to be said to claude, see Agent.send
SAID_BACKLOG = 256
# Of a line claude writes that is no object, what is shown
PLAIN_WIDTH = 2000
# What is told the answer claude gives to a request of the chat's
type Answer = Callable[[dict], None]


class Unread(enum.Enum):
    """What stands, among what claude said, for a line of its that was
    not taken in: too long, or holding too much once read. Nothing is
    known of what it said, which may be a request claude waits for the
    answer to, or the end of a turn: that there was such a line is not
    to go without a word."""

    LINE = enum.auto()


# What claude said, as it waits to be taken in: an object, the text of a
# line that is none, what stands for a line that was not read, then None
# when claude has ended
type Said = dict | str | Unread | None


class Backlog:
    """What claude said and waits to be taken in, bounded by how many and
    by how large they are together: past either, what is to be added
    waits, and claude with it on a pipe that is no longer read. What is
    said is the session's to write, and to write a lot of."""

    def __init__(self, most: int = BACKLOG, most_bytes: int = BACKLOG_BYTES) -> None:
        self._most = most
        self._most_bytes = most_bytes
        self._held: collections.deque[tuple[Said, int]] = collections.deque()
        self._bytes = 0
        self._changed = threading.Condition()

    def _full(self, size: int) -> bool:
        # One alone always fits, however large: it is bounded as a line
        if not self._held:
            return False
        return len(self._held) >= self._most or self._bytes + size > self._most_bytes

    def put(self, item: Said, size: int = 0, timeout: float | None = None) -> None:
        """Add what was said, of so many bytes as it was read. Waits for
        room, raises queue.Full when there is none within the timeout."""
        with self._changed:
            if not self._changed.wait_for(lambda: not self._full(size), timeout):
                raise queue.Full
            self._held.append((item, size))
            self._bytes += size
            self._changed.notify_all()

    def get(self, timeout: float | None = None) -> Said:
        """Take the oldest, raises queue.Empty when there is none within
        the timeout."""
        with self._changed:
            if not self._changed.wait_for(lambda: bool(self._held), timeout):
                raise queue.Empty
            item, size = self._held.popleft()
            self._bytes -= size
            self._changed.notify_all()
            return item


class Agent:
    """Claude Code in its container, spoken to over the pipes of the
    docker command that runs it. With run, what starts that command in
    docker's place, given what docker_popen is."""

    def __init__(
        self,
        docker_args: list[str],
        on_end: Callable[[], None],
        run: Callable[..., subprocess.Popen] = docker_popen,
    ):
        try:
            # A session of its own: Ctrl-C at the terminal is for the chat
            # to pass on as an interrupt, not for docker to end claude with
            self._process = run(
                *docker_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                # Read and cleaned as the rest is, see _read_errors
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except FileNotFoundError:
            raise Fatal(NOT_FOUND) from None
        self._on_end = on_end
        # What is to be said to claude, a line each, then None when no
        # more is: written by a thread of its own, see _write
        self._to_say: queue.Queue[bytes | None] = queue.Queue(SAID_BACKLOG)
        self._requests = itertools.count(1)
        # What waits for the answer to a request of the chat's, by the id
        # it was asked under
        self._answers: dict[str, Answer] = {}
        # Those of them the chat does not wait for the answer to
        self._unwaited: set[str] = set()
        self._asking = threading.Lock()
        # What claude said, see Said
        self.messages = Backlog()
        self.ended = threading.Event()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._errors = threading.Thread(target=self._read_errors, daemon=True)
        self._writer = threading.Thread(target=self._write, daemon=True)
        self._errors.start()
        self._reader.start()
        self._writer.start()

    def _write(self) -> None:
        """Say to claude what waits to be said, in the order it was
        given. In a thread of its own: a session that stops reading what
        it is told, and goes on asking, would otherwise hold whoever
        answers it on a pipe that is full, the thread that listens and
        acts on Ctrl-C, and with it the chat."""
        pipe = self._process.stdin
        while pipe:
            line = self._to_say.get()
            try:
                if line is None:
                    pipe.close()
                    return
                pipe.write(line)
                pipe.flush()
            except (OSError, ValueError):
                # One that has ended: nothing more is said to it
                return

    def _read(self) -> None:
        """Take in what claude says, a line each, until it has ended. A
        line that is too long, or holds too much once read, is not: what
        stands for it is, once for the whole of it (see Unread)."""
        out = self._process.stdout
        dropping = False
        try:
            while out:
                line = out.readline(LINE_LIMIT)
                if not line:
                    break
                # Without its end, a line shorter than the limit is the
                # last one, written as claude ended: a line all the same
                whole = line.endswith(b"\n") or len(line) < LINE_LIMIT
                # What it takes once read, which is what waits: a line
                # of small values takes dozens of times its length
                held = held_size(line)
                if not whole or dropping or held > MOST_LINE_HELD:
                    # The rest of a line that was too long goes with its
                    # start, and is said with its end
                    if whole:
                        self.messages.put(Unread.LINE)
                else:
                    # Not an object: claude run for something else than a
                    # conversation, which is then shown as it is written
                    plain = line[:PLAIN_WIDTH].decode("utf-8", "replace")
                    found = json_object(line)
                    said = plain if found is None else found
                    self.messages.put(said, held)
                dropping = not whole
            if dropping:
                # One that was too long and ended with claude
                self.messages.put(Unread.LINE)
        finally:
            # What it had to say for itself as it ended comes first
            self._errors.join(1.0)
            self.ended.set()
            self._on_end()
            self.messages.put(None)

    def _read_errors(self) -> None:
        """Pass on what the session writes to its errors, as lines that
        are no object: docker's own word when it cannot run the session,
        and whatever a process of the session writes there, which is not
        to reach the terminal as it is."""
        errors = self._process.stderr
        while errors:
            line = errors.readline(PLAIN_WIDTH)
            if not line:
                return
            text = line.decode("utf-8", "replace").rstrip("\n")
            if not text.strip():
                continue
            if not self._passed_on(text, len(line)):
                # Nobody listens any more
                print(clean(text), file=sys.stderr)

    def _passed_on(self, text: str, size: int) -> bool:
        """Have a line of the errors wait to be taken in with what claude
        said. Whether it does: not once claude has ended. Without room
        for it, it waits for some, and whatever writes there waits with
        it on a pipe that is no longer read, as claude does. Written
        around a listener that is slow, it would be on the terminal
        among the lines of the chat wherever it came, and for as long
        as a session cares to write."""
        while not self.ended.is_set():
            with contextlib.suppress(queue.Full):
                self.messages.put(text, size, timeout=1.0)
                return True
        return False

    def send(self, message: dict) -> bool:
        """Say something to claude, nothing to one that has ended. It is
        said in its turn, see _write. Whether it is: not once as much
        waits to be said as SAID_BACKLOG, to a session that does not
        read it."""
        try:
            self._to_say.put_nowait(json.dumps(message).encode() + b"\n")
        except queue.Full:
            return False
        return True

    def prompt(self, text: str) -> bool:
        """Give claude what the user asks, whether it could be, see
        send."""
        content = [{"type": "text", "text": text}]
        message = {"role": "user", "content": content}
        return self.send({"type": "user", "message": message})

    def request(
        self,
        subtype: str,
        on_answer: Answer | None = None,
        waited: bool = True,
        **more: object,
    ) -> str:
        """Ask claude for something of its own doing. The id its answer
        will name, which on_answer is given when it comes, see answered.
        Not waited for when the chat goes on the same without the
        answer, see pending."""
        asked = f"chat-{next(self._requests)}"
        request = {"subtype": subtype, **more}
        if on_answer:
            # Before it is asked: the answer may come at once
            with self._asking:
                self._answers[asked] = on_answer
                if not waited:
                    self._unwaited.add(asked)
        self.send({"type": "control_request", "request_id": asked, "request": request})
        return asked

    def answered(self, message: dict) -> None:
        """Take in what claude answers to a request of the chat's, for
        what waits for it. Nothing waits for the answer to an interrupt,
        which shows in how its turn ends."""
        response = message.get("response")
        asked = response.get("request_id") if isinstance(response, dict) else None
        if not isinstance(response, dict) or not isinstance(asked, str):
            return
        with self._asking:
            take = self._answers.pop(asked, None)
            self._unwaited.discard(asked)
        if take:
            take(response)

    @property
    def pending(self) -> bool:
        """Whether a request of the chat's waits for its answer, of
        those that are waited for."""
        with self._asking:
            return bool(self._answers.keys() - self._unwaited)

    def respond(self, asked: object, decision: dict) -> None:
        """Answer what claude asked under an id."""
        response = {"request_id": asked, "subtype": "success", "response": decision}
        self.send({"type": "control_response", "response": response})

    def refuse(self, asked: object, why: str) -> None:
        """Say that what claude asked under an id is not answered."""
        response = {"request_id": asked, "subtype": "error", "error": why}
        self.send({"type": "control_response", "response": response})

    def close(self) -> None:
        """Say that no more prompts come, which is how claude is left,
        once what waits to be said was. Not waited for: a session that
        does not read is ended by stopping it."""
        with contextlib.suppress(queue.Full):
            self._to_say.put_nowait(None)

    def drain(self) -> bool:
        """Let go of what claude still says, for it not to wait on a full
        pipe. Whether it may say more."""
        with contextlib.suppress(queue.Empty):
            self.messages.get(timeout=0.1)
        return self._reader.is_alive()

    def status(self) -> int:
        return self._process.wait()

    def over_within(self, seconds: float) -> bool:
        """Whether the session has ended, once that long was waited."""
        try:
            self._process.wait(seconds)
        except subprocess.TimeoutExpired:
            return False
        return True
