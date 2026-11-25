#!/usr/bin/env python3
"""What docker/update-pins.py takes from a registry before it writes it
into the Dockerfiles and the launcher's own code."""

from __future__ import annotations

import importlib.util

import pytest
from harness import ROOT

SCRIPT = ROOT / "docker" / "update-pins.py"
spec = importlib.util.spec_from_file_location("pins", SCRIPT)
assert spec is not None
assert spec.loader is not None
pins = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pins)


def test_a_version_or_a_checksum_is_taken_as_it_is():
    for said in ("go1.27.4", "v0.4.0", "2.1.326", "1.0.0+build-1", "ab" * 32):
        assert pins.plain(said, "x") == said


def test_what_would_be_read_as_more_than_a_pin_ends_the_run():
    for said in ('1.0"; import os', "1.0\nRUN id", "1 2", "-rf", "", None, 1):
        with pytest.raises(SystemExit, match="failed to resolve x"):
            pins.plain(said, "x")


def test_only_a_digest_is_one():
    digest = "sha256:" + "a" * 64
    assert pins.DIGEST.fullmatch(digest)
    for said in (
        digest + '"; import os',
        digest + "\n",
        "sha256:abc",
        "md5:" + "a" * 64,
    ):
        assert not pins.DIGEST.fullmatch(said)


def test_a_pin_is_set_where_it_is_and_no_other_is_written(tmp_path):
    file = tmp_path / "x.Dockerfile"
    file.write_text("ARG GO_VERSION=go1.0\nRUN true\n")
    held = pins.Pins([file])
    held.set_arg("GO_VERSION", "go1.27.4")
    assert held.texts[file] == "ARG GO_VERSION=go1.27.4\nRUN true\n"
    with pytest.raises(SystemExit):
        held.set_arg("GO_VERSION", "go1\nRUN id")
    assert held.texts[file] == "ARG GO_VERSION=go1.27.4\nRUN true\n"
