#!/usr/bin/env python3
"""What the launcher keeps of earlier launches, for later ones to go by."""

from __future__ import annotations

import json
from unittest import mock

import pytest
from harness import LauncherTest

from claude_airlock.sandbox import remembered
from claude_airlock.sandbox.remembered import Remembered, remember


class RememberedTest(LauncherTest):
    def test_what_is_kept_is_the_latest_of_what_is_still_there(self):
        files = [self.project / f"{n}.secrets" for n in range(4)]
        for file in files:
            file.touch()
        remember(self.host, hidden_through_links=map(str, files[:2]))
        remember(self.host, written=[str(self.project), str(self.home / "gone")])
        kept = Remembered.load(self.host)
        assert kept.hidden_through_links == tuple(map(str, files[:2]))
        # A directory that is not there holds no link
        assert kept.written == (str(self.project),)
        # Said again, it is the latest, and no more are kept than so many
        files[3].unlink()
        with mock.patch.object(remembered, "MOST_REMEMBERED", 2):
            remember(self.host, hidden_through_links=map(str, files[::-1]))
        assert Remembered.load(self.host).hidden_through_links == (
            str(files[1]),
            str(files[0]),
        )

    def test_a_record_that_cannot_be_read_is_said(
        self, capsys: pytest.CaptureFixture[str]
    ):
        self.state.mkdir(parents=True)
        record = self.state / "remembered.json"
        record.write_text("{")
        assert Remembered.load(self.host) == Remembered()
        assert f"{record} cannot be read" in capsys.readouterr().err
        # And what is in it that is no absolute path is passed over
        record.write_text(json.dumps({"written": ["rel", 3, "/abs"]}))
        assert Remembered.load(self.host).written == ("/abs",)
        # Nothing is said of none at all
        record.unlink()
        assert Remembered.load(self.host) == Remembered()
        assert capsys.readouterr().err == ""
