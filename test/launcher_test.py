#!/usr/bin/env python3
"""Checks the launcher's security-relevant behaviour without Docker.

The launcher is run as a command against a throwaway home and project, with a
fake docker first on PATH that records every call and can play a session
(see harness.py). A few checks call the claude_airlock package directly
instead. The checks are in the test_*.py files next to this one, each of
which also runs on its own.

The files are run at the same time, each by a Python of its own: a check
shares nothing with the checks of another file, and most of what one takes
is waiting for the launcher it started. A line is said per file, with what
it put out when it failed. A file that takes too long is ended and says
where it was, so that a check that hangs fails the run instead of holding
it. What follows the options below is passed on to each file as it is.

  test/launcher_test.py           all of them
  test/launcher_test.py -k trace  those with trace in their name
  test/launcher_test.py --jobs 1  one file at a time
  test/launcher_test.py --patience 60  a file is stuck after a minute
  test/test_capture.py            one file
"""

from __future__ import annotations

import argparse
import os
import re
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
# What unittest ends with since Python 3.12 when no test was picked, which
# -k does to most files
NO_TESTS = 5
# The status of a file that was ended for taking too long, as timeout says it
STUCK = 124
# How long a file that is ended has to say where it was
LAST_WORDS = 10.0
RAN = re.compile(r"^Ran (\d+) tests? in", re.MULTILINE)


@dataclass(frozen=True)
class Outcome:
    """How the checks of one file went."""

    file: Path
    status: int
    output: str
    seconds: float

    @property
    def tests(self) -> int:
        ran = RAN.search(self.output)
        return int(ran.group(1)) if ran else 0

    @property
    def failed(self) -> bool:
        return self.status != 0 and not (self.status == NO_TESTS and not self.tests)

    @property
    def line(self) -> str:
        verdict = "FAILED" if self.failed else "ok"
        return (
            f"{self.file.name:<22} {self.tests:>4} tests"
            f" {self.seconds:>6.1f}s  {verdict}"
        )


def run_file(file: Path, passed_on: list[str], patience: float) -> Outcome:
    """The checks of one file, by a Python of its own. One that takes
    longer than the patience is ended, having said where each of its
    threads was."""
    start = time.monotonic()
    process = subprocess.Popen(
        [sys.executable, str(file), *passed_on],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        # SIGABRT then has Python write what every thread was at
        env={**os.environ, "PYTHONFAULTHANDLER": "1"},
    )
    try:
        output, _ = process.communicate(timeout=patience)
        status = process.returncode
    except subprocess.TimeoutExpired:
        process.send_signal(signal.SIGABRT)
        output = last_words(process)
        output += f"\nSTUCK: ended after {patience:.0f}s, see where above\n"
        status = STUCK
    return Outcome(file, status, output, time.monotonic() - start)


def last_words(process: subprocess.Popen[str]) -> str:
    """What a file that was told to end wrote. Not waited for longer than
    a moment: what it started may hold its output open after it."""
    try:
        output, _ = process.communicate(timeout=LAST_WORDS)
    except subprocess.TimeoutExpired as late:
        process.kill()
        said = late.output or ""
        output = said if isinstance(said, str) else said.decode(errors="replace")
        if process.stdout:
            process.stdout.close()
        process.wait()
    return output


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Run the checks of every test_*.py, the files side by side.",
        epilog="Anything else is passed on to each file, as -k NAME is.",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=os.cpu_count() or 1,
        help="how many files run at the same time, as many as CPUs by default",
    )
    parser.add_argument(
        "--patience",
        type=float,
        default=300.0,
        help="seconds a file may take before it is ended as stuck, 300 by default",
    )
    options, passed_on = parser.parse_known_args(argv)
    files = sorted(HERE.glob("test_*.py"))
    start = time.monotonic()
    outcomes = []
    with ThreadPoolExecutor(max_workers=max(1, options.jobs)) as pool:
        for outcome in pool.map(
            lambda file: run_file(file, passed_on, options.patience), files
        ):
            outcomes.append(outcome)
            if outcome.tests or outcome.failed:
                print(outcome.line, flush=True)
            if outcome.failed:
                print(outcome.output, flush=True)
    tests = sum(outcome.tests for outcome in outcomes)
    failed = [outcome.file.name for outcome in outcomes if outcome.failed]
    print(f"\nRan {tests} tests in {time.monotonic() - start:.1f}s")
    if failed:
        print(f"FAILED: {', '.join(failed)}")
        return 1
    if not tests:
        print("NO TESTS RAN")
        return NO_TESTS
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
