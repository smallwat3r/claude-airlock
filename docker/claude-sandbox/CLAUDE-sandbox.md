# Docker sandbox
You are running inside a sandboxed Docker image. The container is read-only
(no sudo, no apt), writable space is /tmp, ~/.cache, ~/.npm and the mounted
project. ~/.cache usually persists between sessions of the same project,
everything else outside the project is gone when the session ends. For extra
Python packages create a venv (e.g. uv venv /tmp/venv), npm packages install
locally into the project.

Preinstalled, so do not install them again:
