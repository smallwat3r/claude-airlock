#!/usr/bin/env python3
"""What docker/update-pins.py takes from a registry before it writes it
into the Dockerfiles and the launcher's own code."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

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


DOCKERFILES = sorted((ROOT / "docker").glob("**/*.Dockerfile"))
# A download, into a file
DOWNLOAD = re.compile(r"\bcurl -fsSL \S+\s+-o (\S+) ")


def instructions(path: Path) -> list[str]:
    """The instructions of a Dockerfile, each on a line of its own."""
    return path.read_text().replace("\\\n", " ").splitlines()


def test_every_download_of_the_image_is_checked_by_its_checksum():
    downloaded = []
    for path in DOCKERFILES:
        for instruction in instructions(path):
            # Nothing fetched any other way, a pipe into a shell among them
            assert instruction.count("curl -") == len(DOWNLOAD.findall(instruction))
            for download in DOWNLOAD.finditer(instruction):
                file = download[1]
                after = instruction[download.end() :]
                checked = rf"{re.escape(file)}[^|&]*\| sha256sum -c -"
                assert re.search(checked, after), f"{path.name}: {file} is not checked"
                downloaded.append(file)
    # The keyrings of the apt repositories among them
    assert len(downloaded) >= len(pins.KEYRINGS)


def test_the_checksum_of_each_keyring_is_refreshed():
    texts = "".join(path.read_text() for path in DOCKERFILES)
    markers = [marker for marker, _ in pins.PINNERS]
    for arg, url in pins.KEYRINGS.items():
        assert re.search(rf"(?m)^ARG {arg}=[0-9a-f]{{64}}$", texts)
        assert url in texts
        assert pins.arg_marker(arg) in markers
