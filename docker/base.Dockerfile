# Sandboxed environment for running Claude Code via Docker.
#
# This is the first of three parts: claude_airlock/sandbox/image.py concatenates
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
# claude-feat-md: ast-grep (the command is ast-grep, sg is another tool here), universal-ctags (ctags)

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
    # SSH-over-proxy tunnel for the egress allowlist (see claude_airlock/sandbox/network.py)
    netcat-openbsd \
    # Search and filesystem
    ripgrep \
    fd-find \
    universal-ctags \
    tree \
    jq \
    # Build tools
    make \
    gcc \
    g++ \
    pkg-config \
    python3 \
    # Debian ships fd as fdfind, the name fd was already taken there
    && ln -s /usr/bin/fdfind /usr/local/bin/fd \
    && rm -rf /var/lib/apt/lists/*

# ast-grep is not packaged by Debian, so the official zip of its GitHub
# release is pinned and checksum-verified. The base has no unzip, Python's
# zipfile extracts it instead. Only ast-grep is taken out of the zip: its
# short alias sg would shadow the sg of Debian's login package.
ARG AST_GREP_VERSION=0.51.3
ARG AST_GREP_SHA256_AMD64=22803eb0c5bf83164fb7fd76d4721d355ecf0c8466ef47342c1ec7d80897ca47
ARG AST_GREP_SHA256_ARM64=5b44fd68e78744934b359b07badce347d4197ed50b341d50f1f99d056ecedb08
RUN ARCH="$(dpkg --print-architecture)" \
    && case "${ARCH}" in \
    amd64) AST_GREP_ARCH=x86_64; AST_GREP_SHA256="${AST_GREP_SHA256_AMD64}" ;; \
    arm64) AST_GREP_ARCH=aarch64; AST_GREP_SHA256="${AST_GREP_SHA256_ARM64}" ;; \
    *) echo "unsupported arch: ${ARCH}" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://github.com/ast-grep/ast-grep/releases/download/${AST_GREP_VERSION}/app-${AST_GREP_ARCH}-unknown-linux-gnu.zip" \
    -o /tmp/ast-grep.zip \
    && printf '%s  %s\n' "${AST_GREP_SHA256}" /tmp/ast-grep.zip | sha256sum -c - \
    && python3 -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extract(sys.argv[2], sys.argv[3])' \
    /tmp/ast-grep.zip ast-grep /usr/local/bin \
    && chmod 755 /usr/local/bin/ast-grep \
    && rm /tmp/ast-grep.zip

COPY --from=uv /uv /uvx /usr/local/bin/

# The base image calls its user and that user's home node, after what it is
# for upstream. Here they are named for what they are in a session.
RUN groupmod --new-name sandbox node \
    && usermod --login sandbox --home /home/sandbox --move-home node

# The home directory is read-only at runtime, so point uv's tool installs and
# npm's cache at the writable ~/.cache, which also persists per project
ENV UV_TOOL_DIR=/home/sandbox/.cache/uv-tools \
    UV_TOOL_BIN_DIR=/home/sandbox/.cache/bin \
    NPM_CONFIG_CACHE=/home/sandbox/.cache/npm
# After the image's own directories: ~/.cache outlives a session, and a
# command put there must not stand in for git or npm in the next one
ENV PATH="${PATH}:/home/sandbox/.cache/bin"

# Turn off notices that say nothing about what a command did: funding and
# new version notices of npm and pip, usage hints of git
ENV NPM_CONFIG_FUND=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    GH_NO_UPDATE_NOTIFIER=1
RUN git config --system advice.detachedHead false \
    && git config --system advice.statusHints false

# No usage reports from gh, nor from what a project commonly installs. Each
# is named, as DO_NOT_TRACK would also bind Claude Code, whose reports are
# for CLAUDE_AIRLOCK_TELEMETRY to decide (see sandbox/session.py).
ENV GH_TELEMETRY=false \
    NEXT_TELEMETRY_DISABLED=1 \
    NUXT_TELEMETRY_DISABLED=1 \
    ASTRO_TELEMETRY_DISABLED=1 \
    GATSBY_TELEMETRY_DISABLED=1 \
    STORYBOOK_DISABLE_TELEMETRY=1 \
    TURBO_TELEMETRY_DISABLED=1 \
    NG_CLI_ANALYTICS=false \
    SCARF_ANALYTICS=false \
    HF_HUB_DISABLE_TELEMETRY=1
