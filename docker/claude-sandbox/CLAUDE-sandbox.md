<!-- Template: bin/claude-docker appends one bullet per "# claude:" line of the base and selected feature Dockerfiles after the last line. -->
# Docker sandbox
You are running inside a sandboxed Docker image. The container is read-only
(no sudo, no apt), writable space is /tmp, ~/.cache, ~/.npm and the mounted
project. ~/.cache usually persists between sessions of the same project,
everything else outside the project is gone when the session ends. For extra
Python packages create a venv (e.g. uv venv /tmp/venv), npm packages install
locally into the project.

~/.claude is shared with the host and writable, except settings.json and
hooks, which are read-only unless CLAUDE_DOCKER_RW_CONFIG=1 is set. Do not
try to change them from here, ask the user to do it on the host.

If CLAUDE_DOCKER_NET_FILTER=1 is set, egress goes through a proxy that only
allows listed domains, direct connections and DNS lookups fail. A 403 from
the proxy means the domain is blocked: do not retry or work around it, tell
the user which domain to add to allowed-domains.txt.

Preinstalled, so do not install them again:
