"""!COMMAND: a command of the user's run in the session's container, and
ended there when they interrupt it."""

from __future__ import annotations

import contextlib
import re
import subprocess

from ..docker import docker_ok, docker_popen, exec_args
from ..events import clean, flat
from .console import Page

# Of a line a command of the user's writes, what is shown as one line
SHELL_WIDTH = 4096
# What a command of the user's is run through in the container: in a
# process group of its own, whose id it says first. docker passes no
# signal on to what it runs without a terminal, so Ctrl-C ends docker's
# end of it alone, and the command is then ended by its group.
SHELL_WRAPPER = 'echo "$$"; exec bash -c "$1"'
_GROUP = re.compile(rb"[1-9][0-9]{0,9}\n")


class Shell:
    """Runs the commands of the user's in the container of a name, one at
    a time."""

    def __init__(self, page: Page, name: str):
        self._page = page
        # Of the session's container
        self._name = name
        # Whether a command runs: Ctrl-C is then for it and not for
        # claude's turn, see interrupt
        self.running = False
        self._process: subprocess.Popen | None = None
        self._interrupted = False

    def run(self, command: str) -> None:
        """Run a command in the session's container. Claude is not told
        of it and the transcript does not have it, the record of what ran
        does. What it writes is the session's word as anything else from
        there: shown a line at a time, cleaned, behind the mark of what
        the session wrote (see Page.said). Ctrl-C is for the command while
        it runs, see running."""
        if not command:
            return
        self._page.note("shell", f"$ {flat(command)}  (claude is not told)")
        wrapped = ("setsid", "--wait", "bash", "-c", SHELL_WRAPPER, "bash", command)
        group = b""
        self._interrupted = False
        self.running = True
        try:
            process = docker_popen(
                *("exec", self._name, *wrapped),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            self._process = process
            with process:
                out = process.stdout
                first = True
                while out and (line := out.readline(SHELL_WIDTH)):
                    if first and _GROUP.fullmatch(line):
                        group = line.strip()
                    else:
                        text = line.decode("utf-8", "replace").rstrip("\r\n")
                        self._page.put_said([clean(text)])
                    first = False
        except OSError:
            self._page.note("shell", "docker could not be run")
            return
        finally:
            self._process = None
            self.running = False
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
        the command itself once that is over, see run. Called from the
        handler of the signal, so it does no more."""
        self._interrupted = True
        process = self._process
        if process is not None:
            with contextlib.suppress(OSError):
                process.terminate()
