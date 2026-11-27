"""!COMMAND: a command of the user's run in the session's container, and
ended there when they interrupt it.

Whoever reads the lines the user types waits for it to be over, and reads
none meanwhile. Unless the user is asked something: the answer is a line,
and what asks may be what the command waits for, a request of its for a
host the egress filter does not allow (see hosts.py). The command is then
left to run, and to write, while the line is read."""

from __future__ import annotations

import contextlib
import re
import subprocess
import threading
from collections.abc import Callable

from ..docker import docker_ok, docker_popen, exec_args
from ..events import flat
from .console import Page

# Of a line a command of the user's writes, what is shown as one line
SHELL_WIDTH = 4096
# What a command of the user's is run through in the container: in a
# process group of its own, whose id it says first. docker passes no
# signal on to what it runs without a terminal, so Ctrl-C ends docker's
# end of it alone, and the command is then ended by its group.
SHELL_WRAPPER = 'echo "$$"; exec bash -c "$1"'
_GROUP = re.compile(rb"[1-9][0-9]{0,9}\n")
# Seconds between two looks at whether the user is asked something while
# a command runs
ASKED_EVERY = 0.1


class Shell:
    """Runs the commands of the user's in the container of a name, one at
    a time. With asked, whether the user is asked something: a command
    is then no longer waited for, see wait."""

    def __init__(
        self, page: Page, name: str, asked: Callable[[], bool] = lambda: False
    ):
        self._page = page
        # Of the session's container
        self._name = name
        self._asked = asked
        # Whether a command runs: Ctrl-C is then for it and not for
        # claude's turn, see interrupt
        self.running = False
        self._process: subprocess.Popen | None = None
        self._interrupted = False
        # Set while no command is being run, all it wrote written and
        # how it ended said
        self._over = threading.Event()
        self._over.set()

    def run(self, command: str) -> None:
        """Run a command in the session's container, and wait for it as
        wait does. Claude is not told of it and the transcript does not
        have it, the record of what ran does. What it writes is the
        session's word as anything else from there: shown a line at a
        time, cleaned (see Page.said). Ctrl-C is for the command while
        it runs, see running."""
        if not command:
            return
        if not self._over.is_set():
            # Entered where a line was read for a question, see wait
            still = "a command of yours still runs, Ctrl-C ends it"
            self._page.note("shell", f"not run: {still}")
            return
        self._page.note("shell", f"$ {flat(command)}  (claude is not told)")
        process = self._started(command)
        if process is None:
            return
        self._over.clear()
        # What it writes is written by a thread of its own: the one that
        # runs it may have a line to read before it is over
        follower = threading.Thread(target=self._follow, args=(process,), daemon=True)
        try:
            follower.start()
        except RuntimeError:
            # No thread is to be had, the sandbox of the launcher may be
            # at its limit of them: written from here, and waited for
            self._follow(process)
        self.wait()

    def _started(self, command: str) -> subprocess.Popen | None:
        """Start a command in the session's container, none when docker
        could not be run. From here on Ctrl-C is for it, see running."""
        wrapped = ("setsid", "--wait", "bash", "-c", SHELL_WRAPPER, "bash", command)
        self._interrupted = False
        self.running = True
        try:
            self._process = docker_popen(
                *("exec", self._name, *wrapped),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        except OSError:
            self._page.note("shell", "docker could not be run")
        finally:
            self.running = self._process is not None
        if self._process is not None and self._interrupted:
            # Ctrl-C came while it was being started, when there was no
            # process yet to end: ended now, see interrupt
            with contextlib.suppress(OSError):
                self._process.terminate()
        return self._process

    def wait(self) -> None:
        """Wait until the command that runs is over, if one does, or
        the user is asked something: whoever reads their lines then
        reads one, and comes back here for the rest of the command."""
        while not self._over.wait(ASKED_EVERY):
            if self._asked():
                return

    def _follow(self, process: subprocess.Popen) -> None:
        """Write what a command writes until it is over, and say how it
        ended, on a thread of its own."""
        try:
            group = self._written(process)
            if group is not None:
                self._ended(process, group)
        except Exception as error:  # noqa: BLE001
            # Whatever it is, it is said: nobody else hears of what goes
            # wrong on this thread
            self._page.note("shell", f"FAILED to follow it: {flat(repr(error))}")
        finally:
            # Whatever came of it, nobody waits for it any longer
            self._over.set()

    def _written(self, process: subprocess.Popen) -> bytes | None:
        """Write what a command writes, a line at a time, until it is
        over. The id of its process group, which it says first, empty
        when it said none. None when docker could not be read to its
        end."""
        group = b""
        try:
            with process:
                out = process.stdout
                first = True
                while out and (line := out.readline(SHELL_WIDTH)):
                    if first and _GROUP.fullmatch(line):
                        group = line.strip()
                    else:
                        text = line.decode("utf-8", "replace").rstrip("\r\n")
                        self._page.put_said([text])
                    first = False
        except OSError:
            self._page.note("shell", "docker could not be run")
            return None
        finally:
            self._process = None
            self.running = False
        return group

    def _ended(self, process: subprocess.Popen, group: bytes) -> None:
        """Say how a command ended when not well, and end what it left
        running when it was interrupted."""
        if self._interrupted:
            # What it left running in the container goes with it
            ended = bool(group) and docker_ok(
                *exec_args(self._name, f"kill -TERM -- -{group.decode()}")
            )
            left = "" if ended else ", what it ran may still be running"
            self._page.note("shell", f"interrupted{left}")
        elif process.returncode:
            self._page.note("shell", f"ended with {process.returncode}")

    def interrupt(self) -> None:
        """Ctrl-C while a command runs: docker's end of it is ended here,
        the command itself once that is over, see _ended. Called from
        the handler of the signal, so it does no more."""
        self._interrupted = True
        process = self._process
        if process is not None:
            with contextlib.suppress(OSError):
                process.terminate()
