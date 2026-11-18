# Docker sandbox
You run in a sandboxed Docker container. It is read-only (no sudo, no apt),
writable are /tmp, ~/.cache, ~/.npm and the mounted project. Outside the
project only ~/.cache outlives the session. Extra Python packages go in a
venv (uv venv /tmp/venv), npm packages in the project.

## Settings of this session
The user's CLAUDE_DOCKER_* settings decide what you can do here. They are
set on the host and fixed for the session: never work around what they
block, and do not retry another way. Say what you could not do and name the
setting and the value that would allow it, for the user to restart with (in
their shell, or in ~/.config/claude-sandbox/config for every session).

`env | grep CLAUDE_DOCKER_` gives the values, a switch not listed is off.

- CLAUDE_DOCKER_NET_FILTER (off unless 1). On, egress goes through a proxy
  that allows listed domains only, over HTTP, HTTPS and git over SSH:
  direct connections, DNS lookups and other protocols (a database, say)
  fail. A 403 from the proxy is a blocked domain, tell the user to add it
  to docker/allowed-domains.txt of their claude-sandbox checkout.
- CLAUDE_DOCKER_NET_LOG and CLAUDE_DOCKER_PROC_LOG (on unless 0) record
  for the user's review every connection, UDP send, ping and name lookup,
  and the processes that run. They block nothing. The root-owned python3
  process is that recorder, not yours to stop.
- CLAUDE_DOCKER_SHARED_HISTORY (off unless 1). Off, what Claude Code
  remembers of other projects is not here: their directories under
  ~/.claude/projects are empty and read-only, and the prompt history, paste
  cache and file history are this project's own. Not a bug, do not look
  for them elsewhere.
- CLAUDE_DOCKER_SSH_AGENT (off unless 1). On, git over SSH and ssh work
  with the user's keys, each use recorded for review. Only listing keys
  and signing work, adding or removing a key and locking the agent are
  refused. Off, there are no SSH keys: SSH ends in "Permission denied
  (publickey)". Set by the user but not listed: no agent ran on the host.
- CLAUDE_DOCKER_SOCKET (off unless 1 or full). 1 allows docker ps and
  docker logs against the host's daemon, full adds inspect, stats and top.
  Everything else is denied, never run or build, and every call is
  recorded. Off, no daemon can be reached. The docker CLI comes with the
  docker feature of the image.
- CLAUDE_DOCKER_CONNECTORS (off unless 1, not listed in the environment).
  Off, the connectors of the user's claude.ai account (Gmail, Google Drive
  and the like) are not loaded.
- ~/.claude is the sandbox's own, shared by the sandboxed sessions: the
  sessions, jobs and logs of the host's Claude Code are not here, not a
  bug. From the host come settings.json, CLAUDE.md, hooks, commands,
  skills, agents, rules, plugins, projects and the login.
- CLAUDE_DOCKER_RW_CONFIG (off unless 1). Off, settings.json, CLAUDE.md,
  hooks, commands, skills, agents and rules of ~/.claude are read-only
  ("Read-only file system"), ask the user to change them on the host.
- CLAUDE_DOCKER_CACHE (on unless 0). On, ~/.cache persists between
  sessions of this project. Off, it is a tmpfs of at most 2g that large
  downloads can fill.
- CLAUDE_DOCKER_MEMORY and CLAUDE_DOCKER_PIDS, the memory and process
  limits. Exit code 137 without a reason of its own is the first,
  "Resource temporarily unavailable" or a failed fork the second. Say
  which limit and its value.
- CLAUDE_DOCKER_CPUS (no limit unless listed), the CPUs the container can
  use. nproc still counts all of the host's and work beyond the limit is
  held back: give builds and tests that many jobs (make -j4 for 4).
- CLAUDE_DOCKER_DIRS, the directories mounted next to the project, (ro)
  marks a read-only one. --add-dir mounts one writable, or any other path
  of the host, none of which is here.
- CLAUDE_DOCKER_PROTECT, paths of the project or a mounted directory that
  are read-only ("Read-only file system"), ask the user to change them on
  the host.
- ~/.claude/shell-snapshots and ~/.claude/session-env are this session's
  own and start empty.
- MCP servers the user set up on the host for every project are not here.
  Ask the user before adding one with `claude mcp add`.
- CLAUDE_DOCKER_SHADOW (not listed in the environment). Files named .env,
  .env.*, .envrc, .netrc and .pypirc, and those this setting adds, read as
  empty: the secrets stay on the host. Not a bug, do not recreate or fill
  them, ask the user for a value you need. Templates such as .env.example
  are readable.
- CLAUDE_DOCKER_FEATURES (not listed in the environment), the tools built
  into this image, named below. If one you need is missing and cannot be
  installed in /tmp or the project, say so: the user adds its feature and
  the image is rebuilt.

## Tools
Preinstalled, so do not install them again:
- _Placeholder: at build time the launcher replaces this line with one bullet per `# claude-feat-md:` line of the base and selected feature Dockerfiles._
