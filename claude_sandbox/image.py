"""The sandbox image: which features go in, the Dockerfile and CLAUDE.md
assembled from them, and the build."""

from __future__ import annotations

import hashlib
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .docker import docker
from .settings import DOCKERFILE_DIR, Fatal, Host, Settings

IMAGE_NAME = "claude-code-sandbox"


@dataclass(frozen=True)
class Image:
    tag: str
    dockerfile: str
    claude_md: str


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


def prepare_image(settings: Settings, host: Host) -> Image:
    """Assemble the Dockerfile and the CLAUDE.md baked into the image from
    the base, the selected features and the tail. The image tag is a hash of
    both plus the host home (the image symlinks it to /home/node), so editing
    a part, changing the selection or moving home rebuilds, with the layer
    cache, and each feature set keeps its own image."""
    parts = [
        Path(DOCKERFILE_DIR, "base.Dockerfile"),
        *(feature_file(name, host) for name in selected_features(settings, host)),
        Path(DOCKERFILE_DIR, "tail.Dockerfile"),
    ]
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
    digest = hashlib.sha256(content.encode()).hexdigest()
    return Image(f"{IMAGE_NAME}:{digest[:12]}", dockerfile, claude_md)


def build_image(image: Image, host: Host, *build_options: str) -> int:
    print(f"Building Claude sandbox image {image.tag}...", file=sys.stderr)
    with tempfile.TemporaryDirectory() as context:
        for name, content in (
            ("Dockerfile", image.dockerfile),
            ("CLAUDE.md", image.claude_md),
        ):
            Path(context, name).write_text(content + "\n", encoding="utf-8")
        # Build output goes to stderr, stdout stays clean for the session
        return docker(
            "build",
            *build_options,
            f"--tag={image.tag}",
            f"--build-arg=HOST_HOME={host.home}",
            context,
            stdout=sys.stderr,
        ).returncode
