# Sandboxed environment for running Claude Code via Docker.
#
# This is the first of three parts: claude_sandbox/image.py concatenates
# base.Dockerfile, the selected features/*.Dockerfile and tail.Dockerfile
# into the Dockerfile it builds. Lines starting with "# claude-feat-md: " are
# collected into the image's /etc/claude-code/CLAUDE.md, so the tool list
# Claude sees always matches what was built. A feature starts with a header:
# its name on a "# claude-feat: " line, the features it needs on a
# "# claude-feat-requires: " line, which are then built with it, its
# "# claude-feat-md: " lines, and on a "# claude-feat-lsp: " line the language
# servers it installs, for the plugin the image is given (see
# tail.Dockerfile).
#
# Every image, download and Python package is pinned, refresh them all with
# update-pins.py. Debian packages are not: apt drops old versions from its
# mirrors, so they follow the pinned base image's release instead.
#
# claude-feat-md: Python 3 with uv
# claude-feat-md: Node.js and npm/npx, gcc/g++/make/pkg-config
# claude-feat-md: git, gh, ssh, ripgrep, fd, jq, tree

# uv comes from its official image, as a named stage so it can be pinned by
# digest (COPY --from cannot take a digest held in an ARG on the legacy builder)
FROM ghcr.io/astral-sh/uv:0.13.8@sha256:5cc1805e2426484abca4ad46ea783bab281fdb225fd82d8ce6d66a81254bac85 AS uv

# The Debian release is part of the tag on purpose, a new Node major must not
# silently move the image to another release
FROM node:26-bookworm-slim@sha256:5df79989ed685e09f0a98019db4cebfb22fb9df1a53c0161664a011f7ff6b0f1

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
    # SSH-over-proxy tunnel for the egress allowlist (see claude_sandbox/network.py)
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
