# Sandboxed environment for running Claude Code via Docker.
#
# This is the first of three parts: bin/claude-docker concatenates
# base.Dockerfile, the selected features/*.Dockerfile and tail.Dockerfile
# into the Dockerfile it builds. Lines starting with "# claude: " are
# collected into the image's /etc/claude-code/CLAUDE.md, so the tool list
# Claude sees always matches what was built.
#
# Every image, download and Python package is pinned, refresh them all with
# update-pins.py. Debian packages are not: apt drops old versions from its
# mirrors, so they follow the pinned base image's release instead.
#
# claude: Python 3 with uv, mypy, ruff, black, pytest, ipython
# claude: Node.js and npm/npx, gcc/g++/make/pkg-config
# claude: git, gh, ssh, ripgrep, fd, jq, tree

# uv comes from its official image, as a named stage so it can be pinned by
# digest (COPY --from cannot take a digest held in an ARG on the legacy builder)
FROM ghcr.io/astral-sh/uv:0.12.10@sha256:2bb3ebca0a796a155094a27773d290c4b074572e6107f171d88d086682fd2500 AS uv

# The Debian release is part of the tag on purpose, a new Node major must not
# silently move the image to another release
FROM node:24-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) \
    signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] \
    https://cli.github.com/packages stable main" \
    > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
    # Version control and remote
    git \
    openssh-client \
    gh \
    # SSH-over-proxy tunnel for the egress allowlist (see bin/claude-docker)
    netcat-openbsd \
    # Search and filesystem
    ripgrep \
    fd-find \
    tree \
    jq \
    # Build tools
    make \
    gcc \
    g++ \
    pkg-config \
    python3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=uv /uv /uvx /usr/local/bin/

# The home directory is read-only at runtime, so point uv's tool installs and
# npm's cache at the writable ~/.cache, which also persists per project
ENV UV_TOOL_DIR=/home/node/.cache/uv-tools \
    UV_TOOL_BIN_DIR=/home/node/.cache/bin \
    NPM_CONFIG_CACHE=/home/node/.cache/npm
ENV PATH="/home/node/.cache/bin:${PATH}"

# Python tooling (available system-wide)
RUN uv pip install --system --break-system-packages \
    mypy==2.4.1 \
    ruff==0.17.5 \
    black==26.10.1 \
    pytest==9.2.0 \
    ipython==9.18.1
