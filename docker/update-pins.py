#!/usr/bin/env python3
"""Refresh every pinned version, sha256 and image digest of the sandbox.

Covers the Dockerfile parts (base, tail, features, plus your own features in
~/.config/claude-sandbox/features) and the sidecar images in
claude_sandbox/network.py.
A pin that appears in none of the files is skipped, so removing a feature
needs no change here.

Versions come from the upstream release feeds, checksums are computed on the
freshly downloaded artifacts. All edits happen on in-memory copies written
out only once everything has resolved, so a failed run never leaves the files
with mixed pins. PyPI and npm packages are pinned by version only.

Usage: update-pins.py [file]...   (defaults to all of the above)
"""

import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

REGISTRY_ACCEPT = (
    "application/vnd.oci.image.index.v1+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json"
)
# name:tag@sha256:digest, the name optionally prefixed by a registry host
IMAGE_REF = r"(?<![\w./-])([a-z0-9][a-z0-9._/-]*):([\w.-]+)@sha256:[0-9a-f]{64}"
# name==version, as written in the uv pip install lines
PYPI_PIN = r"(?<![\w.-])([A-Za-z0-9][A-Za-z0-9._-]*)==(\d[\w.]*)"


def fetch(url: str, headers: dict | None = None, method: str = "GET"):
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    return urllib.request.urlopen(req, timeout=60)


def fetch_json(url: str, headers: dict | None = None):
    with fetch(url, headers) as resp:
        return json.load(resp)


def fetch_sha256(url: str) -> str:
    with fetch(url) as resp:
        return hashlib.sha256(resp.read()).hexdigest()


def github_latest_tag(repo: str) -> str:
    tag = fetch_json(f"https://api.github.com/repos/{repo}/releases/latest")["tag_name"]
    if not tag:
        sys.exit(f"failed to resolve latest release of {repo}")
    return tag


def image_digest(image: str, tag: str) -> str:
    """Current digest of image:tag, on Docker Hub or a host-prefixed registry
    that hands out anonymous pull tokens the way ghcr.io does."""
    first, _, rest = image.partition("/")
    if "." in first:
        host, repo = first, rest
        token_url = f"https://{host}/token?scope=repository:{repo}:pull"
    else:
        host = "registry-1.docker.io"
        repo = image if rest else f"library/{image}"
        token_url = (
            "https://auth.docker.io/token"
            f"?service=registry.docker.io&scope=repository:{repo}:pull"
        )
    token = fetch_json(token_url)["token"]
    with fetch(
        f"https://{host}/v2/{repo}/manifests/{tag}",
        headers={"Authorization": f"Bearer {token}", "Accept": REGISTRY_ACCEPT},
        method="HEAD",
    ) as resp:
        digest = resp.headers["Docker-Content-Digest"]
    if not digest:
        sys.exit(f"failed to resolve digest of {image}:{tag}")
    return digest


class Pins:
    """The files holding pins, edited in memory and written out together."""

    def __init__(self, paths: list[Path]) -> None:
        self.original = {path: path.read_text() for path in paths}
        self.texts = dict(self.original)

    def has(self, pattern: str) -> bool:
        return any(re.search(pattern, text) for text in self.texts.values())

    def findall(self, pattern: str) -> set:
        return {m for text in self.texts.values() for m in re.findall(pattern, text)}

    def substitute(self, pattern: str, replacement: str, label: str) -> None:
        total = 0
        for path, text in self.texts.items():
            # A callable, so backslashes in the replacement stay literal
            self.texts[path], count = re.subn(pattern, lambda _: replacement, text)
            total += count
        if total == 0:
            sys.exit(f"nothing matched for {label}")

    def set_arg(self, name: str, value: str | None) -> None:
        if not value:
            sys.exit(f"failed to resolve {name}")
        self.substitute(rf"(?m)^ARG {name}=.*$", f"ARG {name}={value}", name)

    def write(self) -> list[Path]:
        changed = [p for p, text in self.texts.items() if text != self.original[p]]
        for path in changed:
            staged = path.with_name(path.name + ".new")
            staged.write_text(self.texts[path])
            # write_text creates a plain file, keep the launcher executable
            staged.chmod(path.stat().st_mode)
            staged.replace(path)
        return changed


def pin_node(pins: Pins) -> None:
    # node tracks the current LTS line, its digest is refreshed by pin_digests
    lts = next(r for r in fetch_json("https://nodejs.org/dist/index.json") if r["lts"])
    major = lts["version"].removeprefix("v").split(".")[0]
    pins.substitute(r"node:\d+-(?=[a-z]+-slim)", f"node:{major}-", "node tag")
    print("node", major)


def pin_go(pins: Pins) -> None:
    go = fetch_json("https://go.dev/dl/?mode=json")[0]
    pins.set_arg("GO_VERSION", go["version"])
    for arch in ("amd64", "arm64"):
        tarball = f"{go['version']}.linux-{arch}.tar.gz"
        sha = next((f["sha256"] for f in go["files"] if f["filename"] == tarball), None)
        pins.set_arg(f"GO_SHA256_{arch.upper()}", sha)
    print("go", go["version"])


def pin_typst(pins: Pins) -> None:
    typst = github_latest_tag("typst/typst")
    url = f"https://github.com/typst/typst/releases/download/{typst}"
    pins.set_arg("TYPST_VERSION", typst)
    for arg_arch, typst_arch in [("AMD64", "x86_64"), ("ARM64", "aarch64")]:
        sha = fetch_sha256(f"{url}/typst-{typst_arch}-unknown-linux-musl.tar.xz")
        pins.set_arg(f"TYPST_SHA256_{arg_arch}", sha)
    print("typst", typst)


def pin_mcap(pins: Pins) -> None:
    # mcap releases share a repo with the language libraries, so filter for
    # the CLI's release train rather than taking the repo's latest release
    releases = fetch_json(
        "https://api.github.com/repos/foxglove/mcap/releases?per_page=100"
    )
    prefix = "releases/mcap-cli/"
    tags = (r["tag_name"] for r in releases)
    mcap = next((t.removeprefix(prefix) for t in tags if t.startswith(prefix)), None)
    pins.set_arg("MCAP_VERSION", mcap)
    url = f"https://github.com/foxglove/mcap/releases/download/{prefix}{mcap}"
    for arch in ("amd64", "arm64"):
        pins.set_arg(
            f"MCAP_SHA256_{arch.upper()}", fetch_sha256(f"{url}/mcap-linux-{arch}")
        )
    print("mcap", mcap)


def pin_ocrab(pins: Pins) -> None:
    ocrab = github_latest_tag("smallwat3r/ocrab-font")
    url = f"https://raw.githubusercontent.com/smallwat3r/ocrab-font/{ocrab}/fonts/ocrab.otf"
    pins.set_arg("OCRAB_VERSION", ocrab)
    pins.set_arg("OCRAB_SHA256", fetch_sha256(url))
    print("ocrab", ocrab)


def pin_uv(pins: Pins) -> None:
    uv = github_latest_tag("astral-sh/uv")
    pins.substitute(r"astral-sh/uv:[0-9.]+", f"astral-sh/uv:{uv}", "uv")
    print("uv", uv)


def npm_latest(package: str) -> str:
    return fetch_json(f"https://registry.npmjs.org/{package}/latest")["version"]


def pin_claude_code(pins: Pins) -> None:
    version = npm_latest("@anthropic-ai/claude-code")
    pins.set_arg("CLAUDE_CODE_VERSION", version)
    print("claude-code", version)


def pin_pyright(pins: Pins) -> None:
    version = npm_latest("pyright")
    pins.set_arg("PYRIGHT_VERSION", version)
    print("pyright", version)


def pin_gopls(pins: Pins) -> None:
    latest = fetch_json("https://proxy.golang.org/golang.org/x/tools/gopls/@latest")
    pins.set_arg("GOPLS_VERSION", latest["Version"])
    print("gopls", latest["Version"])


def pin_pypi(pins: Pins) -> None:
    for name in sorted({name for name, _ in pins.findall(PYPI_PIN)}):
        version = fetch_json(f"https://pypi.org/pypi/{name}/json")["info"]["version"]
        pins.substitute(
            rf"(?<![\w.-]){re.escape(name)}==\d[\w.]*", f"{name}=={version}", name
        )
        print(name, version)


def pin_digests(pins: Pins) -> None:
    # Runs last, so it resolves the tags the functions above just moved
    for image, tag in sorted(pins.findall(IMAGE_REF)):
        digest = image_digest(image, tag)
        pins.substitute(
            rf"(?<![\w./-]){re.escape(image)}:{re.escape(tag)}@sha256:[0-9a-f]{{64}}",
            f"{image}:{tag}@{digest}",
            image,
        )
        print(f"{image}:{tag} {digest}")


# Each pin runs only when its marker appears in one of the files
PINNERS: list[tuple[str, Callable[[Pins], None]]] = [
    (r"node:\d+-[a-z]+-slim", pin_node),
    (r"(?m)^ARG GO_VERSION=", pin_go),
    (r"(?m)^ARG TYPST_VERSION=", pin_typst),
    (r"(?m)^ARG MCAP_VERSION=", pin_mcap),
    (r"(?m)^ARG OCRAB_VERSION=", pin_ocrab),
    (r"astral-sh/uv:[0-9.]+", pin_uv),
    (r"(?m)^ARG CLAUDE_CODE_VERSION=", pin_claude_code),
    (r"(?m)^ARG PYRIGHT_VERSION=", pin_pyright),
    (r"(?m)^ARG GOPLS_VERSION=", pin_gopls),
    (PYPI_PIN, pin_pypi),
    (IMAGE_REF, pin_digests),
]


def default_paths() -> list[Path]:
    here = Path(__file__).resolve().parent
    config = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return [
        here / "base.Dockerfile",
        here / "tail.Dockerfile",
        *sorted((here / "features").glob("*.Dockerfile")),
        *sorted((config / "claude-sandbox" / "features").glob("*.Dockerfile")),
        here.parent / "claude_sandbox" / "network.py",
    ]


def main() -> None:
    pins = Pins([Path(arg) for arg in sys.argv[1:]] or default_paths())
    for marker, pin in PINNERS:
        if pins.has(marker):
            pin(pins)
    changed = pins.write()
    print(f"\nDone, {len(changed)} file(s) changed. Review with git diff, then")
    print("start claude-docker, the image rebuilds itself when its parts change.")


if __name__ == "__main__":
    try:
        main()
    except urllib.error.URLError as err:
        sys.exit(f"download failed: {err}")
