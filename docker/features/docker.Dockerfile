# claude-feat: docker
# claude-feat-md: docker CLI, for what CLAUDE_DOCKER_SOCKET allows (see above). docker logs does not work for containers run with a TTY, and without full inspect returns a stub

RUN curl -fsSL https://download.docker.com/linux/debian/gpg \
    -o /usr/share/keyrings/docker-archive-keyring.asc \
    && echo "deb [arch=$(dpkg --print-architecture) \
    signed-by=/usr/share/keyrings/docker-archive-keyring.asc] \
    https://download.docker.com/linux/debian \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*
