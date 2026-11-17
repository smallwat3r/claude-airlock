#!/usr/bin/env python3
"""Checks the launcher's security-relevant behaviour without Docker.

The launcher is run as a command against a throwaway home and project, with a
fake docker first on PATH that records every call and can play a session
(see harness.py). A few checks call the claude_sandbox package directly
instead. The checks are in the test_*.py files next to this one, each of
which also runs on its own.

The files are run at the same time, each by a Python of its own: a check
shares nothing with the checks of another file, and most of what one takes
is waiting for the launcher it started. A line is said per file, with what
it put out when it failed. What follows the options below is passed on to
each file as it is.

  test/launcher_test.py           all of them
  test/launcher_test.py -k trace  those with trace in their name
  test/launcher_test.py --jobs 1  one file at a time
  test/test_capture.py            one file
"""

from __future__ import annotations

import argparse
import os
import re
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


def run_file(file: Path, passed_on: list[str]) -> Outcome:
    """The checks of one file, by a Python of its own."""
    start = time.monotonic()
    done = subprocess.run(
        [sys.executable, str(file), *passed_on],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        check=False,
    )
    return Outcome(file, done.returncode, done.stdout, time.monotonic() - start)


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
    options, passed_on = parser.parse_known_args(argv)
    files = sorted(HERE.glob("test_*.py"))
    start = time.monotonic()
    outcomes = []
    with ThreadPoolExecutor(max_workers=max(1, options.jobs)) as pool:
        for outcome in pool.map(lambda file: run_file(file, passed_on), files):
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
