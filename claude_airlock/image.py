"""The sandbox image: which features go in, the Dockerfile and CLAUDE.md
assembled from them, and the build."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .docker import docker, docker_ok, docker_output
from .errors import Fatal
from .settings import DOCKERFILE_DIR, Host, Settings

IMAGE_NAME = "claude-airlock"
# The lines of a part that the launcher reads. One of the first kind is a
# bullet of the image's CLAUDE.md, one of the second names the features a
# fragment cannot do without.
CLAUDE_MD_MARKER = "# claude-feat-md: "
REQUIRES_MARKER = "# claude-feat-requires: "
# One of the third kind declares language servers the part installs, as the
# "lspServers" of a Claude Code plugin: a JSON object of them by name.
LSP_MARKER = "# claude-feat-lsp: "
# Where the plugin made of those is in the build context and in the image.
# With a dot, which a feature's name cannot have, a feature's directory goes
# into the context by that name.
PLUGIN_CONTEXT = "claude.plugin"
PLUGIN_DIR = "/opt/claude-airlock-plugin"
# What the first was called, in fragments written before. Refused, so that a
# tool does not drop out of what Claude is told without a word.
FORMER_CLAUDE_MD_MARKER = "# claude: "


@dataclass(frozen=True)
class Image:
    tag: str
    dockerfile: str
    claude_md: str
    # Directories copied into the build context, by their name there
    context_dirs: dict[str, Path]
    # The manifest of the plugin at PLUGIN_DIR, and the language servers it
    # has by name, without any claude is not given the plugin
    plugin: str
    language_servers: tuple[str, ...]

    @property
    def has_language_servers(self) -> bool:
        return bool(self.language_servers)


def text_lines(text: str) -> list[str]:
    """Lines of a file, without an empty last one for the final newline."""
    lines = text.split("\n")
    return lines[:-1] if lines[-1] == "" else lines


def marked(text: str, marker: str) -> list[str]:
    """What follows the marker on each line of a part that starts with it."""
    return [line[len(marker) :] for line in text_lines(text) if line.startswith(marker)]


def available_features(host: Host) -> list[str]:
    names = set()
    for directory in host.feature_dirs:
        for file in Path(directory).glob("*.Dockerfile"):
            if file.is_file():
                names.add(file.name[: -len(".Dockerfile")])
    return sorted(names)


def selected_features(settings: Settings, host: Host) -> list[str]:
    """Names of the selected features. First match wins:
    CLAUDE_AIRLOCK_FEATURES (set but empty selects none), then
    ~/.config/claude-airlock/features.txt (one name per line, # comments),
    then everything available. Sorted, so the same set always generates the
    same Dockerfile whatever order it was written in. Toggling a feature
    rebuilds the ones sorted after it, name a heavy one early if that hurts."""
    features_txt = Path(host.user_conf, "features.txt")
    if settings.features is not None:
        listing = settings.features
    elif features_txt.is_file():
        lines = features_txt.read_text(encoding="utf-8").split("\n")
        listing = "\n".join(line.split("#", 1)[0] for line in lines)
    else:
        return available_features(host)
    return sorted(set(re.split(r"[,\s]+", listing)) - {""})


def feature_file(name: str, host: Host) -> Path:
    """Path of the Dockerfile fragment for a feature. The name is validated,
    it ends up in a path and comes from the environment or a config file."""
    if not re.fullmatch(r"[a-z0-9_-]+", name):
        raise Fatal(f"invalid feature name: {name}")
    for directory in host.feature_dirs:
        file = Path(directory, f"{name}.Dockerfile")
        if file.is_file():
            return file
    available = " ".join(available_features(host))
    raise Fatal(f"unknown feature: {name} (available: {available})")


def with_required(names: list[str], host: Host) -> list[str]:
    """The features with those they require, and those these require in
    turn, sorted like the selection."""
    found: set[str] = set()
    pending = list(names)
    while pending:
        name = pending.pop()
        if name in found:
            continue
        found.add(name)
        text = feature_file(name, host).read_text(encoding="utf-8")
        for required in marked(text, REQUIRES_MARKER):
            pending.extend(required.split())
    return sorted(found)


def language_servers(parts: list[Path], texts: list[str]) -> dict:
    """The language servers the parts declare, by name."""
    servers: dict = {}
    for part, text in zip(parts, texts):
        for line in marked(text, LSP_MARKER):
            try:
                declared = json.loads(line)
            except ValueError as error:
                raise Fatal(
                    f'{part}: a "{LSP_MARKER}" line is not JSON: {error}'
                ) from error
            if not isinstance(declared, dict):
                raise Fatal(f'{part}: a "{LSP_MARKER}" line is not a JSON object')
            servers.update(declared)
    return servers


def lsp_plugin(servers: dict) -> str:
    """The manifest of the plugin that gives a session the language
    servers of its image."""
    manifest = {
        "name": "claude-airlock-lsp",
        "description": "The language servers built into this sandbox image",
        "version": "1.0.0",
        "lspServers": servers,
    }
    return json.dumps(manifest, indent=2)


def sandbox_claude_md(parts: list[Path], texts: list[str]) -> str:
    """The CLAUDE.md of the image: the template, with the tools the parts
    say they bring in place of its placeholder bullet, which is there to
    be seen when the template is read on its own. The list is made of the
    "# claude-feat-md: " lines of the parts, so it always matches what is
    built."""
    for part, text in zip(parts, texts):
        if marked(text, FORMER_CLAUDE_MD_MARKER):
            raise Fatal(
                f'{part}: its "{FORMER_CLAUDE_MD_MARKER}" lines are now written'
                f' "{CLAUDE_MD_MARKER}", rename them'
            )
    template = Path(DOCKERFILE_DIR, "CLAUDE-airlock.md").read_text(encoding="utf-8")
    lines = [
        line for line in text_lines(template) if not line.startswith("- _Placeholder:")
    ]
    lines += ["- " + tool for text in texts for tool in marked(text, CLAUDE_MD_MARKER)]
    return "\n".join(lines).rstrip("\n")


def image_tag(
    host: Host, dockerfile: str, claude_md: str, context_dirs: dict[str, Path]
) -> str:
    """The tag of the image: a hash of everything it is built from, the
    files of the build context and the host home included."""
    # The plugin is made of lines of the Dockerfile, so it is in the tag too
    content = f"{host.home}\n{dockerfile}\n{claude_md}\n"
    digest = hashlib.sha256(content.encode())
    for name, directory in context_dirs.items():
        for file in sorted(path for path in directory.rglob("*") if path.is_file()):
            digest.update(f"{name}/{file.relative_to(directory)}\n".encode())
            digest.update(file.read_bytes())
    return f"{IMAGE_NAME}:{digest.hexdigest()[:12]}"


def prepare_image(settings: Settings, host: Host) -> Image:
    """Assemble the Dockerfile and the CLAUDE.md baked into the image from
    the base, the selected features and the tail. A feature can come with
    files for its fragment to COPY, in a directory of its name next to the
    fragment, which goes into the build context under that name. The image
    tag is a hash of all of it plus the host home (the image symlinks it to
    /home/sandbox), so editing a part, changing the selection or moving home
    rebuilds, with the layer cache, and each feature set keeps its own
    image. The language servers the parts declare become a plugin in the
    image, which claude is started with (see cli.py), so that a session has
    the servers of its image and no other, whatever the host has enabled."""
    features = {
        name: feature_file(name, host)
        for name in with_required(selected_features(settings, host), host)
    }
    parts = [
        Path(DOCKERFILE_DIR, "base.Dockerfile"),
        *features.values(),
        Path(DOCKERFILE_DIR, "tail.Dockerfile"),
    ]
    context_dirs = {
        name: file.with_suffix("")
        for name, file in features.items()
        if file.with_suffix("").is_dir()
    }
    texts = [part.read_text(encoding="utf-8") for part in parts]
    dockerfile = "".join(text.rstrip("\n") + "\n\n" for text in texts)
    claude_md = sandbox_claude_md(parts, texts)
    servers = language_servers(parts, texts)
    tag = image_tag(host, dockerfile, claude_md, context_dirs)
    plugin = lsp_plugin(servers)
    return Image(
        tag, dockerfile, claude_md, context_dirs, plugin, tuple(sorted(servers))
    )


def build_image(image: Image, host: Host, *build_options: str) -> int:
    print(f"Building Claude sandbox image {image.tag}...", file=sys.stderr)
    with tempfile.TemporaryDirectory() as context:
        for name, content in (
            ("Dockerfile", image.dockerfile),
            ("CLAUDE.md", image.claude_md),
        ):
            Path(context, name).write_text(content + "\n", encoding="utf-8")
        for name, directory in image.context_dirs.items():
            shutil.copytree(directory, Path(context, name))
        manifest = Path(context, PLUGIN_CONTEXT, ".claude-plugin", "plugin.json")
        manifest.parent.mkdir(parents=True)
        manifest.write_text(image.plugin + "\n", encoding="utf-8")
        # COPY keeps the modes of the context and the files are root's in
        # the image. Set here, a strict umask on the host would otherwise
        # leave them unreadable to the session's user.
        for directory in (manifest.parent.parent, manifest.parent):
            directory.chmod(0o755)
        for file in (manifest, Path(context, "CLAUDE.md")):
            file.chmod(0o644)
        # Build output goes to stderr, stdout stays clean for the session
        return docker(
            "build",
            *build_options,
            f"--tag={image.tag}",
            f"--build-arg=HOST_HOME={host.home}",
            context,
            stdout=sys.stderr,
        ).returncode


def prune_images(current: str) -> int:
    """Remove the sandbox images that are not the one the settings ask for
    now, current being its tag. Every edit of a part, change of the
    selection or refreshed pin makes a new image and leaves the one
    before, several GB each. One that
    a container still uses is kept, docker refuses to remove it. Another
    project's image, of other features, goes too: it is built again from
    the layers the build cache has, the next time it is asked for."""
    listed = docker_output(
        "images", "--format={{.Repository}}:{{.Tag}}", IMAGE_NAME
    ).split()
    removed = 0
    for tag in sorted(set(listed).difference([current])):
        if docker_ok("rmi", tag):
            removed += 1
            print(f"removed  {tag}")
        else:
            print(f"kept     {tag}, a container uses it")
    print(f"{removed} images removed, kept as current: {current}")
    print(
        "What the builds left in docker's cache is not the launcher's alone"
        " to remove: docker builder prune"
    )
    return 0
