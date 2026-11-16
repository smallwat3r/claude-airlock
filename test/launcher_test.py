#!/usr/bin/env python3
"""Checks the launcher's security-relevant behaviour without Docker.

The launcher is run as a command against a throwaway home and project, with a
fake docker first on PATH that records every call and can play a session
(see harness.py). A few checks call the claude_sandbox package directly
instead. The checks are in the test_*.py files next to this one, each of
which also runs on its own.

  test/launcher_test.py           all of them
  test/launcher_test.py -k trace  those with trace in their name
  test/test_capture.py            one file
"""

import sys
import unittest
from pathlib import Path

if __name__ == "__main__":
    here = str(Path(__file__).resolve().parent)
    discover = ["discover", "--start-directory", here, "--pattern", "test_*.py"]
    unittest.main(module=None, argv=[sys.argv[0], *discover, *sys.argv[1:]])
