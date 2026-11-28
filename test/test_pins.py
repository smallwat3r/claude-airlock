#!/usr/bin/env python3
"""What docker/update-pins.py takes from a registry before it writes it
into the Dockerfiles and the launcher's own code."""

from __future__ import annotations

import http.client
import importlib.util
import io
import json
import re
import stat
import urllib.request
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


def test_a_redirect_is_followed_to_https_alone():
    handler = pins._HttpsOnly()
    asked = urllib.request.Request("https://github.com/a/releases/download/v1/x")
    headers = http.client.HTTPMessage()
    for elsewhere in ("http://objects.example/x", "ftp://objects.example/x"):
        with pytest.raises(ValueError, match="not HTTPS"):
            handler.redirect_request(
                asked, io.BytesIO(), 302, "Found", headers, elsewhere
            )
    followed = handler.redirect_request(
        asked, io.BytesIO(), 302, "Found", headers, "https://objects.example/x"
    )
    assert followed is not None
    assert followed.full_url == "https://objects.example/x"


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


def test_the_versions_uv_takes_on_the_image_are_written_as_the_pins(
    monkeypatch: pytest.MonkeyPatch,
):
    asked: list[tuple[list[str], str]] = []

    def uv(command: list[str], cwd: str) -> None:
        asked.append((command, Path(cwd, "wanted.in").read_text()))
        # As uv writes them, with what they need and by their PEP 503 names
        Path(cwd, "wanted.txt").write_text(
            "mcap-ros1-support==0.9.0\nnumpy==2.4.6\nscapy==2.8.0\n"
        )

    monkeypatch.setattr(pins, "run_tool", uv)
    text = "# The packages\nScapy==1.0\nmcap_ros1_support==0.1 \\\n"
    refreshed = pins.refreshed_pins(text)
    assert refreshed == "# The packages\nScapy==2.8.0\nmcap_ros1_support==0.9.0 \\\n"
    # The bare names, so that uv takes the latest that runs on the image
    ((command, wanted),) = asked
    assert wanted == "Scapy\nmcap_ros1_support\n"
    assert f"--python-version={pins.image_python()}" in command
    assert "--universal" not in command
    # Nothing to resolve, nothing is run
    assert pins.refreshed_pins("RUN true\n") == "RUN true\n"
    assert len(asked) == 1
    # A package uv took no version for ends the run
    with pytest.raises(SystemExit, match="failed to resolve lief"):
        pins.refreshed_pins("lief==0.1\n")


def test_the_pins_of_a_source_of_a_lock_are_refreshed_with_the_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    mine = tmp_path / "mine.Dockerfile"
    mine.write_text("RUN uv pip install x==1\n")
    named = tmp_path / "requirements.in"
    named.write_text("x==1\n")
    monkeypatch.setattr(pins, "refreshed_pins", lambda text: text + "# seen\n")
    held = pins.Pins([mine, named])
    pins.pin_pypi(held)
    assert held.texts == {mine: "RUN uv pip install x==1\n# seen\n", named: "x==1\n"}


def test_the_python_of_the_image_is_the_one_its_python_code_is_written_for():
    python = pins.image_python()
    assert python == pins.DEBIAN_PYTHONS["bookworm"]
    pyproject = (ROOT / "pyproject.toml").read_text()
    target = "py" + "".join(python.split(".")[:2])
    script = "docker/features/excalidraw/excalidraw-export"
    assert f'"{script}" = "{target}"' in pyproject


FEATURES = ROOT / "docker" / "features"
# A requirement of a lock with what follows it, its hashes
LOCKED = re.compile(r"(?m)^([a-z0-9][a-z0-9._-]*)==(\S+)((?:[^\n]*\\\n)+[^\n]*)")


def test_every_python_package_of_a_feature_is_installed_by_hash():
    locked = []
    for path in DOCKERFILES:
        for instruction in instructions(path):
            if "pip install" not in instruction:
                continue
            name = path.stem
            lock = f"/tmp/{name}-requirements.txt"
            assert f"--require-hashes -r {lock}" in instruction, path.name
            assert f"COPY {name}/requirements.txt {lock}" in instructions(path)
            locked.append(name)
    assert locked
    for name in locked:
        named = (FEATURES / name / "requirements.in").read_text()
        lock = (FEATURES / name / "requirements.txt").read_text()
        requirements = LOCKED.findall(lock)
        found = {package: version for package, version, _ in requirements}
        # What the feature names, at its version, with what it needs
        for package, version in re.findall(pins.PYPI_PIN, named):
            assert found[package.lower()] == version
        for package, _, hashes in requirements:
            assert "--hash=sha256:" in hashes, f"{name}: {package} has no hash"
        # Every one of the lock, none is left without its hashes
        assert len(requirements) == len(re.findall(r"(?m)^\S+==", lock))


def test_what_excalidraw_is_built_from_is_locked_and_run_without_scripts():
    manifest = json.loads((FEATURES / "excalidraw" / "package.json").read_text())
    lock = json.loads((FEATURES / "excalidraw" / "package-lock.json").read_text())
    assert lock["packages"][""]["dependencies"] == manifest["dependencies"]
    for place, package in lock["packages"].items():
        if place:
            assert package["integrity"].startswith("sha512-"), place
            assert package["resolved"].startswith("https://registry.npmjs.org/")
    # Exact versions, as update-pins.py writes them, never a range
    for version in manifest["dependencies"].values():
        assert pins.PLAIN.fullmatch(version)
        assert version[0].isdigit()
    for path in DOCKERFILES:
        for instruction in instructions(path):
            # A package of its own, pinned by an ARG, or what a lock names
            for npm in re.findall(r"npm (?:install|ci)\b[^&]*", instruction):
                if npm.startswith("npm ci"):
                    assert "--ignore-scripts" in npm
                else:
                    assert npm.startswith("npm install -g "), npm
                    for package in npm.split()[3:]:
                        assert re.fullmatch(
                            r'"?[@\w/.-]+@(\$\{\w+\}|[\d.]+)"?', package
                        )


def test_the_packages_of_a_manifest_are_refreshed_but_those_held(
    monkeypatch: pytest.MonkeyPatch,
):
    said = {"dependencies": {"esbuild": "0.1.0", "react": "18.3.1"}}
    monkeypatch.setattr(pins, "npm_latest", lambda package: "0.28.9")
    refreshed = json.loads(pins.refreshed_manifest(json.dumps(said)))
    assert refreshed == {"dependencies": {"esbuild": "0.28.9", "react": "18.3.1"}}
    monkeypatch.setattr(pins, "npm_latest", lambda package: '1"; rm')
    with pytest.raises(SystemExit):
        pins.refreshed_manifest(json.dumps(said))


def test_a_lock_is_made_of_its_source_refreshed_and_written_with_the_pins(
    tmp_path: Path,
):
    feature = tmp_path / "mine"
    feature.mkdir()
    named = feature / "requirements.in"
    named.write_text("scapy==2.0\n")
    manifest = feature / "package.json"
    manifest.write_text("{}\n")
    (feature / "package-lock.json").write_text("old\n")
    held = pins.Pins([named, manifest])
    locks = (
        pins.Lock(
            "requirements.in",
            "requirements.txt",
            lambda text: text.replace("2.0", "2.8.0"),
            lambda text: f"locked {text}",
        ),
        pins.Lock("package.json", "package-lock.json", str, lambda text: f"npm {text}"),
    )
    for lock in locks:
        lock.lock(held)
    # Nothing is written before the run is through
    assert not (feature / "requirements.txt").exists()
    assert (feature / "package-lock.json").read_text() == "old\n"
    written = held.write()
    assert sorted(path.name for path in written) == [
        "package-lock.json",
        "requirements.in",
        "requirements.txt",
    ]
    lock = feature / "requirements.txt"
    assert named.read_text() == "scapy==2.8.0\n"
    assert lock.read_text() == "locked scapy==2.8.0\n"
    assert stat.S_IMODE(lock.stat().st_mode) == 0o644
    assert (feature / "package-lock.json").read_text() == "npm {}\n"
    # The kinds the run makes
    assert [(lock.source, lock.name) for lock in pins.LOCKS] == [
        ("requirements.in", "requirements.txt"),
        ("package.json", "package-lock.json"),
    ]


def test_what_the_locks_are_made_from_is_among_the_files_of_a_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    mine = tmp_path / "claude-airlock" / "features" / "mine"
    mine.mkdir(parents=True)
    (mine / "requirements.in").write_text("x==1\n")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    paths = pins.default_paths()
    assert mine / "requirements.in" in paths
    assert FEATURES / "python" / "requirements.in" in paths
    assert FEATURES / "excalidraw" / "package.json" in paths
    assert not [path for path in paths if path.name.endswith((".txt", "lock.json"))]
