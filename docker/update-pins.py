#!/usr/bin/env python3
"""Refresh every pinned version, sha256 and image digest of the sandbox.

Covers the Dockerfile parts (base, tail, features, plus your own features in
~/.config/claude-airlock/features), the sidecar images in
claude_airlock/sandbox/egress_proxy.py and socket_proxy.py, and the actions
of the CI workflow, each pinned to the commit of its latest release.
A pin that appears in none of the files is skipped, so removing a feature
needs no change here.

Versions come from the upstream release feeds, checksums are computed on the
freshly downloaded artifacts. All edits happen on in-memory copies written
out only once everything has resolved, so a failed run never leaves the files
with mixed pins.

The Python packages of a feature are named in a requirements.in in the
directory of the feature, and locked with all they need into the
requirements.txt next to it, by version and with the hashes of their
files, for the Python of the image (uv). A package.json there is locked
into its package-lock.json (npm). Both locks are made anew on every run,
so what the packages need is refreshed with them. The versions a
requirements.in names are those uv takes for its packages on the Python
of the image, so a package is only moved to one that runs there.

Usage: update-pins.py [file]...   (defaults to all of the above)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable
from functools import cache
from pathlib import Path
from typing import NamedTuple

REGISTRY_ACCEPT = (
    "application/vnd.oci.image.index.v1+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json"
)
# name:tag@sha256:digest, the name optionally prefixed by a registry host
IMAGE_REF = r"(?<![\w./-])([a-z0-9][a-z0-9._/-]*):([\w.-]+)@sha256:[0-9a-f]{64}"
# name==version, as written in the uv pip install lines
PYPI_PIN = r"(?<![\w.-])([A-Za-z0-9][A-Za-z0-9._-]*)==(\d[\w.]*)"
# An action of a workflow, pinned to a commit and named by its tag after it
ACTION_PIN = r"uses: ([\w.-]+/[\w.-]+)@[0-9a-f]{40} # [\w.+-]+"
COMMIT = re.compile(r"[0-9a-f]{40}")
# What a pin is written as: the digest of an image, and a version or a
# checksum, see plain
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
PLAIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")

HERE = Path(__file__).resolve().parent
# The Python the packages of the features are installed into, Debian's,
# by the release of Debian the base image is of
DEBIAN_PYTHONS = {"bookworm": "3.11.2", "trixie": "3.13.5"}
BASE_RELEASE = re.compile(r"\bnode:\d+-([a-z]+)-slim@")
# What a lock says it was made by, the same wherever it was made
COMPILE_COMMAND = "docker/update-pins.py"
# The packages of a package.json that are not refreshed. React is a peer
# dependency of Excalidraw that the export never renders with, it follows
# the major Excalidraw was built for.
NPM_HELD = frozenset(("react", "react-dom"))


def fetch(url: str, headers: dict | None = None, method: str = "GET"):
    # Pins are only as good as where they are from: nothing but HTTPS,
    # never a file or another scheme a built URL could turn out to be
    if not url.startswith("https://"):
        raise ValueError(f"not an HTTPS URL: {url}")
    req = urllib.request.Request(url, headers=headers or {}, method=method)  # noqa: S310
    return urllib.request.urlopen(req, timeout=60)  # noqa: S310


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


def tag_commit(repo: str, tag: str) -> str:
    """The commit a tag of a repository on GitHub points to, through the
    tag object of one that is annotated."""
    target = fetch_json(f"https://api.github.com/repos/{repo}/git/ref/tags/{tag}")
    found = target["object"]
    # A tag of a tag is followed, not for ever
    for _ in range(3):
        if found["type"] != "tag":
            break
        found = fetch_json(found["url"])["object"]
    commit = found["sha"]
    if found["type"] != "commit" or not COMMIT.fullmatch(commit):
        sys.exit(f"failed to resolve the commit of {repo} {tag}, got {found!r}")
    return commit


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
    if not digest or not DIGEST.fullmatch(digest):
        sys.exit(f"failed to resolve digest of {image}:{tag}, got {digest!r}")
    return digest


def plain(value: object, label: str) -> str:
    """A version or a checksum as a registry gave it, or the end of the
    run: it is written into the Dockerfiles and the launcher's own code
    as it is, where a quote, a blank or a line break would be read as
    more than the pin."""
    if not isinstance(value, str) or not PLAIN.fullmatch(value):
        sys.exit(f"failed to resolve {label}, got {value!r}")
    return value


class Pins:
    """The files holding pins, edited in memory and written out together."""

    def __init__(self, paths: list[Path]) -> None:
        self.original: dict[Path, str | None] = {
            path: path.read_text() for path in paths
        }
        self.texts: dict[Path, str] = {path: path.read_text() for path in paths}

    def put(self, path: Path, text: str) -> None:
        """Have a file written with this text, one that is not among the
        files read too: the lock made of one of them."""
        if path not in self.original:
            self.original[path] = path.read_text() if path.exists() else None
        self.texts[path] = text

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
        self.substitute(
            rf"(?m)^ARG {name}=.*$", f"ARG {name}={plain(value, name)}", name
        )

    def write(self) -> list[Path]:
        changed = [p for p, text in self.texts.items() if text != self.original[p]]
        for path in changed:
            staged = path.with_name(path.name + ".new")
            staged.write_text(self.texts[path])
            # write_text creates a plain file, keep the launcher executable
            staged.chmod(path.stat().st_mode if path.exists() else 0o644)
            staged.replace(path)
        return changed


def pin_node(pins: Pins) -> None:
    # node tracks the current LTS line, its digest is refreshed by pin_digests
    lts = next(r for r in fetch_json("https://nodejs.org/dist/index.json") if r["lts"])
    major = plain(lts["version"].removeprefix("v").split(".")[0], "node")
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


def pin_ast_grep(pins: Pins) -> None:
    ast_grep = github_latest_tag("ast-grep/ast-grep")
    url = f"https://github.com/ast-grep/ast-grep/releases/download/{ast_grep}"
    pins.set_arg("AST_GREP_VERSION", ast_grep)
    for arg_arch, zip_arch in [("AMD64", "x86_64"), ("ARM64", "aarch64")]:
        sha = fetch_sha256(f"{url}/app-{zip_arch}-unknown-linux-gnu.zip")
        pins.set_arg(f"AST_GREP_SHA256_{arg_arch}", sha)
    print("ast-grep", ast_grep)


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


def pin_hashicorp(pins: Pins, product: str, arg: str) -> None:
    # The release API names the version, the shas are computed on the zips
    # rather than taken from the SHA256SUMS on the same server
    version = fetch_json(
        f"https://api.releases.hashicorp.com/v1/releases/{product}/latest"
    )["version"]
    pins.set_arg(f"{arg}_VERSION", version)
    url = f"https://releases.hashicorp.com/{product}/{version}"
    for arch in ("amd64", "arm64"):
        sha = fetch_sha256(f"{url}/{product}_{version}_linux_{arch}.zip")
        pins.set_arg(f"{arg}_SHA256_{arch.upper()}", sha)
    print(product, version)


def pin_terraform(pins: Pins) -> None:
    pin_hashicorp(pins, "terraform", "TERRAFORM")


def pin_terraform_ls(pins: Pins) -> None:
    pin_hashicorp(pins, "terraform-ls", "TERRAFORM_LS")


# The keys of the apt repositories of their vendors, by the ARG that pins
# each: the packages are not pinned, the key they are signed with is
KEYRINGS = {
    "GH_KEYRING_SHA256": "https://cli.github.com/packages/githubcli-archive-keyring.gpg",
    "DOCKER_KEYRING_SHA256": "https://download.docker.com/linux/debian/gpg",
}


def pin_keyring(arg: str) -> Callable[[Pins], None]:
    """A pinner that sets the ARG to the checksum of its keyring as it is
    now."""

    def pin(pins: Pins) -> None:
        sha = fetch_sha256(KEYRINGS[arg])
        pins.set_arg(arg, sha)
        print(arg, sha)

    return pin


def pin_uv(pins: Pins) -> None:
    uv = plain(github_latest_tag("astral-sh/uv"), "uv")
    pins.substitute(r"astral-sh/uv:[0-9.]+", f"astral-sh/uv:{uv}", "uv")
    print("uv", uv)


def npm_latest(package: str) -> str:
    return fetch_json(f"https://registry.npmjs.org/{package}/latest")["version"]


def pin_npm(packages: dict[str, str]) -> Callable[[Pins], None]:
    """A pinner that sets each ARG to the latest version of its package."""

    def pin(pins: Pins) -> None:
        for arg, package in packages.items():
            version = npm_latest(package)
            pins.set_arg(arg, version)
            print(package, version)

    return pin


def refreshed_manifest(text: str) -> str:
    """A package.json with each package it depends on at its latest
    version, but those held (see NPM_HELD)."""
    manifest = json.loads(text)
    dependencies = manifest.get("dependencies", {})
    for package in sorted(set(dependencies) - NPM_HELD):
        dependencies[package] = plain(npm_latest(package), package)
        print(package, dependencies[package])
    return json.dumps(manifest, indent=2) + "\n"


def run_tool(command: list[str], cwd: str) -> None:
    """Run what resolves or makes a lock, or end the run with what it
    said."""
    try:
        done = subprocess.run(command, cwd=cwd, check=False)
    except FileNotFoundError:
        sys.exit(f"{command[0]} is needed to make the locks of the features")
    if done.returncode != 0:
        sys.exit(f"failed to make a lock: {' '.join(command)}")


def resolved(names: list[str]) -> dict[str, str]:
    """The versions uv takes for packages, together, on the Python of the
    image: the latest that run there. By their names as PEP 503 writes
    them."""
    with tempfile.TemporaryDirectory() as work:
        Path(work, "wanted.in").write_text("".join(f"{name}\n" for name in names))
        run_tool(
            [
                *("uv", "pip", "compile", "wanted.in"),
                f"--python-version={image_python()}",
                "--python-platform=linux",
                *("--no-header", "--no-annotate", "--quiet"),
                "--output-file=wanted.txt",
            ],
            work,
        )
        said = Path(work, "wanted.txt").read_text()
    return {
        normalised(name): version
        for name, version in re.findall(r"(?m)^([\w.-]+)==(\S+)", said)
    }


def normalised(name: str) -> str:
    """The name of a Python package as PEP 503 compares them."""
    return re.sub(r"[-_.]+", "-", name).lower()


def refreshed_pins(text: str) -> str:
    """A text with each Python package it pins (name==version) at the
    version uv takes for it, see resolved."""
    names = sorted({name for name, _ in re.findall(PYPI_PIN, text)})
    if not names:
        return text
    versions = resolved(names)
    for name in names:
        version = plain(versions.get(normalised(name)), name)
        # Both plain, so nothing in the replacement is read as more
        pin = rf"(?<![\w.-]){re.escape(name)}==\d[\w.]*"
        text = re.sub(pin, f"{name}=={version}", text)
        print(name, version)
    return text


def python_lock(requirements: str) -> str:
    """The lock of the Python packages of a feature: every package they
    need, for the Python of the image on any machine, by version and with
    the hashes of its files."""
    with tempfile.TemporaryDirectory() as work:
        Path(work, "requirements.in").write_text(requirements)
        run_tool(
            [
                *("uv", "pip", "compile", "requirements.in", "--universal"),
                f"--python-version={image_python()}",
                "--generate-hashes",
                f"--custom-compile-command={COMPILE_COMMAND}",
                "--output-file=requirements.txt",
                "--quiet",
            ],
            work,
        )
        return Path(work, "requirements.txt").read_text()


def npm_lock(manifest: str) -> str:
    """The lock of a package.json, made without running a script of any
    package it names."""
    with tempfile.TemporaryDirectory() as work:
        Path(work, "package.json").write_text(manifest)
        run_tool(
            [
                *("npm", "install", "--package-lock-only", "--ignore-scripts"),
                *("--no-audit", "--no-fund"),
            ],
            work,
        )
        return Path(work, "package-lock.json").read_text()


class Lock(NamedTuple):
    """A kind of lock of the features: the file it is made from, in the
    directory of a feature, the one it is written to next to it, what
    moves the packages the first names to their latest versions, and
    what locks them with all they need."""

    source: str
    name: str
    refresh: Callable[[str], str]
    make: Callable[[str], str]

    def lock(self, pins: Pins) -> None:
        """Refresh each file of this kind among the pins, and make its
        lock anew from what it says then."""
        for path in sorted(path for path in pins.texts if path.name == self.source):
            pins.texts[path] = self.refresh(pins.texts[path])
            pins.put(path.with_name(self.name), self.make(pins.texts[path]))
            print("locked", path.parent.name, self.name)


LOCKS = (
    Lock("requirements.in", "requirements.txt", refreshed_pins, python_lock),
    Lock("package.json", "package-lock.json", refreshed_manifest, npm_lock),
)


def pin_gopls(pins: Pins) -> None:
    latest = fetch_json("https://proxy.golang.org/golang.org/x/tools/gopls/@latest")
    pins.set_arg("GOPLS_VERSION", latest["Version"])
    print("gopls", latest["Version"])


@cache
def image_python() -> str:
    """The version of the Python of the image, by the Debian release of
    the base image."""
    found = BASE_RELEASE.search((HERE / "base.Dockerfile").read_text())
    python = DEBIAN_PYTHONS.get(found[1]) if found else None
    if python is None:
        sys.exit(
            "the Debian release of the base image has no Python known here,"
            " add the version of its python3 to DEBIAN_PYTHONS"
        )
    return python


def pin_pypi(pins: Pins) -> None:
    """The Python packages pinned in a file that is no source of a lock,
    a Dockerfile of your own: those are refreshed with their locks."""
    sources = {lock.source for lock in LOCKS}
    for path, text in pins.texts.items():
        if path.name not in sources:
            pins.texts[path] = refreshed_pins(text)


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


def pin_actions(pins: Pins) -> None:
    for repo in sorted(pins.findall(ACTION_PIN)):
        tag = plain(github_latest_tag(repo), repo)
        commit = tag_commit(repo, tag)
        pins.substitute(
            rf"uses: {re.escape(repo)}@[0-9a-f]{{40}} # [\w.+-]+",
            f"uses: {repo}@{commit} # {tag}",
            repo,
        )
        print(repo, tag, commit)


def arg_marker(arg: str) -> str:
    """The marker of a pin that is an ARG of a Dockerfile."""
    return rf"(?m)^ARG {arg}="


# The npm packages pinned by ARGs, by the ARG that marks them. Each
# depends on nothing that is not pinned with it.
NPM_PINS = {
    "CLAUDE_CODE_VERSION": {"CLAUDE_CODE_VERSION": "@anthropic-ai/claude-code"},
    "PYRIGHT_VERSION": {"PYRIGHT_VERSION": "pyright"},
    "TYPESCRIPT_LANGUAGE_SERVER_VERSION": {
        "TYPESCRIPT_LANGUAGE_SERVER_VERSION": "typescript-language-server"
    },
}

# Each pin runs only when its marker appears in one of the files
PINNERS: list[tuple[str, Callable[[Pins], None]]] = [
    (r"node:\d+-[a-z]+-slim", pin_node),
    (arg_marker("GO_VERSION"), pin_go),
    (arg_marker("TYPST_VERSION"), pin_typst),
    (arg_marker("AST_GREP_VERSION"), pin_ast_grep),
    (arg_marker("MCAP_VERSION"), pin_mcap),
    (arg_marker("TERRAFORM_VERSION"), pin_terraform),
    (arg_marker("TERRAFORM_LS_VERSION"), pin_terraform_ls),
    (r"astral-sh/uv:[0-9.]+", pin_uv),
    *((arg_marker(arg), pin_npm(packages)) for arg, packages in NPM_PINS.items()),
    (arg_marker("GOPLS_VERSION"), pin_gopls),
    *((arg_marker(arg), pin_keyring(arg)) for arg in KEYRINGS),
    (PYPI_PIN, pin_pypi),
    (IMAGE_REF, pin_digests),
    (ACTION_PIN, pin_actions),
]


def default_paths() -> list[Path]:
    config = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    features = (HERE / "features", config / "claude-airlock" / "features")
    return [
        HERE / "base.Dockerfile",
        HERE / "tail.Dockerfile",
        *(path for place in features for path in sorted(place.glob("*.Dockerfile"))),
        # What the locks of the features are made from
        *(
            path
            for place in features
            for lock in LOCKS
            for path in sorted(place.glob(f"*/{lock.source}"))
        ),
        HERE.parent / "claude_airlock" / "sandbox" / "egress_proxy.py",
        HERE.parent / "claude_airlock" / "sandbox" / "socket_proxy.py",
        HERE.parent / ".github" / "workflows" / "ci.yml",
    ]


def main() -> None:
    pins = Pins([Path(arg) for arg in sys.argv[1:]] or default_paths())
    for marker, pin in PINNERS:
        if pins.has(marker):
            pin(pins)
    # Each lock with what it is made from
    for lock in LOCKS:
        lock.lock(pins)
    changed = pins.write()
    print(f"\nDone, {len(changed)} file(s) changed. Review with git diff, then")
    print("start claude-airlock, the image rebuilds itself when its parts change.")


if __name__ == "__main__":
    try:
        main()
    except urllib.error.URLError as err:
        sys.exit(f"download failed: {err}")
