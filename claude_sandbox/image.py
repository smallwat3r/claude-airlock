"""The sandbox image: which features go in, the Dockerfile and CLAUDE.md
assembled from them, and the build."""

from __future__ import annotations

import hashlib
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .docker import docker
from .settings import DOCKERFILE_DIR, Fatal, Host, Settings

IMAGE_NAME = "claude-code-sandbox"
# A fragment names the features it cannot do without on such a line
REQUIRES_MARKER = "# requires: "


@dataclass(frozen=True)
class Image:
    tag: str
    dockerfile: str
    claude_md: str
    # Directories copied into the build context, by their name there
    context_dirs: dict[str, Path]


def text_lines(text: str) -> list[str]:
    """Lines of a file, without an empty last one for the final newline."""
    lines = text.split("\n")
    return lines[:-1] if lines[-1] == "" else lines


def available_features(host: Host) -> list[str]:
    names = set()
    for directory in host.feature_dirs:
        for file in Path(directory).glob("*.Dockerfile"):
            if file.is_file():
                names.add(file.name[: -len(".Dockerfile")])
    return sorted(names)


def selected_features(settings: Settings, host: Host) -> list[str]:
    """Names of the selected features. First match wins:
    CLAUDE_DOCKER_FEATURES (set but empty selects none), then
    ~/.config/claude-sandbox/features.txt (one name per line, # comments),
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
        for line in text_lines(text):
            if line.startswith(REQUIRES_MARKER):
                pending.extend(line[len(REQUIRES_MARKER) :].split())
    return sorted(found)


def prepare_image(settings: Settings, host: Host) -> Image:
    """Assemble the Dockerfile and the CLAUDE.md baked into the image from
    the base, the selected features and the tail. A feature can come with
    files for its fragment to COPY, in a directory of its name next to the
    fragment, which goes into the build context under that name. The image
    tag is a hash of all of it plus the host home (the image symlinks it to
    /home/node), so editing a part, changing the selection or moving home
    rebuilds, with the layer cache, and each feature set keeps its own
    image."""
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

    # The template ends with a placeholder bullet, visible when the file is
    # read on its own, the generated tool list takes its place. The list is
    # the "# claude: " lines of the parts, so it always matches what is built.
    template = Path(DOCKERFILE_DIR, "CLAUDE-sandbox.md").read_text(encoding="utf-8")
    marker = "# claude: "
    claude_md_lines = [
        line for line in text_lines(template) if not line.startswith("- _Placeholder:")
    ] + [
        "- " + line[len(marker) :]
        for text in texts
        for line in text_lines(text)
        if line.startswith(marker)
    ]
    claude_md = "\n".join(claude_md_lines).rstrip("\n")

    content = f"{host.home}\n{dockerfile}\n{claude_md}\n"
    digest = hashlib.sha256(content.encode())
    for name, directory in context_dirs.items():
        for file in sorted(path for path in directory.rglob("*") if path.is_file()):
            digest.update(f"{name}/{file.relative_to(directory)}\n".encode())
            digest.update(file.read_bytes())
    tag = f"{IMAGE_NAME}:{digest.hexdigest()[:12]}"
    return Image(tag, dockerfile, claude_md, context_dirs)


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
        # Build output goes to stderr, stdout stays clean for the session
        return docker(
            "build",
            *build_options,
            f"--tag={image.tag}",
            f"--build-arg=HOST_HOME={host.home}",
            context,
            stdout=sys.stderr,
        ).returncode
