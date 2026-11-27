# claude-feat: docker
# claude-feat-md: docker CLI, for what CLAUDE_AIRLOCK_DOCKER_SOCKET allows (see above). docker logs does not work for containers run with a TTY, and without full inspect returns a stub

# The key the Docker repository is signed with
ARG DOCKER_KEYRING_SHA256=1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570
RUN curl -fsSL https://download.docker.com/linux/debian/gpg \
    -o /usr/share/keyrings/docker-archive-keyring.asc \
    && printf '%s  %s\n' "${DOCKER_KEYRING_SHA256}" \
    /usr/share/keyrings/docker-archive-keyring.asc | sha256sum -c - \
    && echo "deb [arch=$(dpkg --print-architecture) \
    signed-by=/usr/share/keyrings/docker-archive-keyring.asc] \
    https://download.docker.com/linux/debian \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# No "What's next" suggestions after a command
ENV DOCKER_CLI_HINTS=false
