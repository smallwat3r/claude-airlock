# Docker sandbox
You are running inside a sandboxed Docker image. The container is read-only
(no sudo, no apt), writable space is /tmp, ~/.cache, ~/.npm and the mounted
project. ~/.cache usually persists between sessions of the same project,
everything else outside the project is gone when the session ends. For extra
Python packages create a venv (e.g. uv venv /tmp/venv), npm packages install
locally into the project.

## Settings of this session
The user starts the sandbox with CLAUDE_DOCKER_* settings, which decide what
you can do here. They are set on the host and fixed for the session: you
cannot change them, and you must not work around what they block. When
something fails because of one, do not retry it another way. Say what you
could not do, and name the setting and the value that would allow it, so
the user can restart the session with it if they want to (in their shell,
or in ~/.config/claude-sandbox/config for every session).

Check the values with `env | grep CLAUDE_DOCKER_`. A switch that is not
listed there is off.

- CLAUDE_DOCKER_NET_FILTER (off unless 1). If on, egress goes through a
  proxy that only allows listed domains, and only HTTP, HTTPS and git over
  SSH get out: direct connections, DNS lookups and other protocols (a
  database, say) fail. A 403 from the proxy means the domain is blocked,
  tell the user which domain to add to docker/allowed-domains.txt of their
  claude-sandbox checkout. If off, the network is open.
- CLAUDE_DOCKER_NET_LOG (on unless 0). If on, every connection you open,
  whatever you send by UDP or as a ping and every name you look up is
  recorded for the user to review. It blocks nothing.
- CLAUDE_DOCKER_PROC_LOG (on unless 0). If on, the processes that run here
  and the one behind each connection are recorded for the user to review.
  The root-owned python3 process you can see is that recorder, it is not
  yours to stop. It blocks nothing.
- CLAUDE_DOCKER_SHARED_HISTORY (off unless 1). If off, what Claude Code
  remembers of other projects is not here: their directories under
  ~/.claude/projects are empty and read-only, and the prompt history, the
  paste cache and the file history are this project's own. That is not a
  bug, do not go looking for them elsewhere. If on, all of it is here.
- CLAUDE_DOCKER_SSH_AGENT (off unless 1). If on, the user's SSH agent is
  forwarded, git over SSH and ssh work with their keys, and each use of a
  key is recorded for the user to review. If off, there are
  no SSH keys here: a push or fetch over SSH ends in "Permission denied
  (publickey)". If the user set it and it is still not listed, no agent was
  running on the host.
- CLAUDE_DOCKER_SOCKET (off unless 1 or full). If 1, docker ps and docker
  logs work against the host's daemon, full adds inspect, stats and top.
  Every other docker call is denied in both, never run or build, and every
  call is recorded for the user to review. If off,
  no Docker daemon can be reached at all. The docker CLI itself comes with
  the docker feature of the image.
- CLAUDE_DOCKER_RW_CONFIG (off unless 1). ~/.claude is shared with the
  host and writable, except settings.json, CLAUDE.md, hooks, commands,
  skills, agents and rules: if off these are read-only, a change to them
  fails with
  "Read-only file system". Ask the user to make it on the host. If on,
  they are writable.
- CLAUDE_DOCKER_CACHE (on unless 0). If on, ~/.cache persists between
  sessions of this project. If off, it is a 2g tmpfs that is gone when the
  session ends, and large downloads can fill it.
- CLAUDE_DOCKER_MEMORY and CLAUDE_DOCKER_PIDS, the container's memory and
  process limits. A process killed without a reason of its own (exit code
  137) ran into the first, "Resource temporarily unavailable" or a failure
  to fork into the second. Say which limit and its current value.
- CLAUDE_DOCKER_DIRS, the directories mounted next to the project. One
  marked (ro) is read-only, the user mounts it writable with --add-dir. Any
  other path of the host is not here at all, that takes --add-dir too.
- CLAUDE_DOCKER_SHADOW (not listed in the environment). Files named .env,
  .env.*, .envrc, .netrc and .pypirc, and what the user added with this
  setting, read as empty: the secrets stay on the host. That is not a bug,
  do not recreate or fill them. Templates such as .env.example are
  readable. If you need a value from one, ask the user.
- CLAUDE_DOCKER_FEATURES (not listed in the environment), the tools built
  into this image, named below. If one you need is missing and cannot be
  installed in /tmp or the project, say so: the user adds its feature and
  the image is rebuilt.

## Tools
Preinstalled, so do not install them again:
- _Placeholder: at build time bin/claude-docker replaces this line with one bullet per `# claude-feat-md:` line of the base and selected feature Dockerfiles._
