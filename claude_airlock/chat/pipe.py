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

import contextlib
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
from ..files import json_object

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
# A line longer than this is dropped, and no more than so many wait to be
# taken in
LINE_LIMIT = 64 << 20
BACKLOG = 1000
# Of a line claude writes that is no object, what is shown
PLAIN_WIDTH = 2000
# What is told the answer claude gives to a request of the chat's
Answer = Callable[[dict], None]


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
        self._speaking = threading.Lock()
        self._requests = itertools.count(1)
        # What waits for the answer to a request of the chat's, by the id
        # it was asked under
        self._answers: dict[str, Answer] = {}
        self._asking = threading.Lock()
        # What claude said, each an object, or the text of a line that is
        # none, then None when it has ended
        self.messages: queue.Queue[dict | str | None] = queue.Queue(BACKLOG)
        self.ended = threading.Event()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._errors = threading.Thread(target=self._read_errors, daemon=True)
        self._errors.start()
        self._reader.start()

    def _read(self) -> None:
        out = self._process.stdout
        dropping = False
        try:
            while out:
                line = out.readline(LINE_LIMIT)
                if not line:
                    break
                complete = line.endswith(b"\n")
                if complete and not dropping:
                    # Not an object: claude run for something else than a
                    # conversation, which is then shown as it is written
                    plain = line[:PLAIN_WIDTH].decode("utf-8", "replace")
                    self.messages.put(json_object(line) or plain)
                # The rest of a line that was too long goes with its start
                dropping = not complete
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
            if not self.ended.is_set():
                with contextlib.suppress(queue.Full):
                    self.messages.put(text, timeout=1.0)
                    continue
            # Nobody listens any more, or not fast enough
            print(clean(text), file=sys.stderr)

    def send(self, message: dict) -> None:
        """Say something to claude, nothing to one that has ended."""
        pipe = self._process.stdin
        try:
            # Whole lines: more than one thread speaks
            with self._speaking:
                if pipe:
                    pipe.write(json.dumps(message).encode() + b"\n")
                    pipe.flush()
        except (OSError, ValueError):
            pass

    def prompt(self, text: str) -> None:
        """Give claude what the user asks."""
        content = [{"type": "text", "text": text}]
        message = {"role": "user", "content": content}
        self.send({"type": "user", "message": message})

    def request(
        self, subtype: str, on_answer: Answer | None = None, **more: object
    ) -> str:
        """Ask claude for something of its own doing. The id its answer
        will name, which on_answer is given when it comes, see answered."""
        asked = f"chat-{next(self._requests)}"
        request = {"subtype": subtype, **more}
        if on_answer:
            # Before it is asked: the answer may come at once
            with self._asking:
                self._answers[asked] = on_answer
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
        if take:
            take(response)

    @property
    def pending(self) -> bool:
        """Whether a request of the chat's waits for its answer."""
        with self._asking:
            return bool(self._answers)

    def respond(self, asked: object, decision: dict) -> None:
        """Answer what claude asked under an id."""
        response = {"request_id": asked, "subtype": "success", "response": decision}
        self.send({"type": "control_response", "response": response})

    def refuse(self, asked: object, why: str) -> None:
        """Say that what claude asked under an id is not answered."""
        response = {"request_id": asked, "subtype": "error", "error": why}
        self.send({"type": "control_response", "response": response})

    def close(self) -> None:
        """Say that no more prompts come, which is how claude is left."""
        with contextlib.suppress(OSError, ValueError):
            if self._process.stdin:
                self._process.stdin.close()

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
