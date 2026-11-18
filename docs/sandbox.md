# What the sandbox does

What a session is given and what it is kept from.

## Mounts

- The project and any extra directories, read-write at their host paths.
  Never the home directory, its parents or the filesystem root.
- As `~/.claude`, a directory of the launcher's that the sandboxed sessions
  share, not yours. Of your own `~/.claude` only the configuration listed
  below, `plugins` and `projects` (the transcripts) are mounted into it.
  What else Claude Code keeps there (its host sessions, jobs, logs) stays
  on the host.
- The login is one all the same: the launcher carries it between the two
  while a session runs, so a session starts logged in.
- `~/.cache` (Go modules, uv, npm) as a Docker volume per project, so one
  session cannot poison another project's dependencies.
  `CLAUDE_DOCKER_CACHE=0` goes back to a tmpfs of at most 2g.
- The git config, read-only. Of `~/.config/git` that is `config`, `ignore`,
  `attributes` and `templates`, and the files the config includes: the rest
  stays on the host, as git's `store` helper keeps passwords in clear
  there. There is no gpg in the image, so sign the commits on the host
  before pushing.

## What is read-only or hidden

- **Claude's configuration.** `settings.json`, `hooks`, `CLAUDE.md`,
  `commands`, `skills`, `agents` and `rules` of `~/.claude` run commands
  on the host or are followed by every later session, so they are
  read-only. `CLAUDE_DOCKER_RW_CONFIG=1` makes them writable.
- **What you name.** `CLAUDE_DOCKER_PROTECT` makes a path read-only inside
  whatever mounts it.
- **Secrets.** `.env`, `.env.*`, `.envrc`, `.netrc` and `.pypirc` files read
  as empty. Templates such as `.env.example` stay readable,
  `CLAUDE_DOCKER_SHADOW` hides more, by file name globs (`*.pem:.npmrc`).
- **The history of other projects.** Their transcripts are covered by
  empty directories, and the prompt history, the paste cache and the file
  history are kept per project. So `claude` on the host cannot rewind the
  files of a session run in the sandbox. `CLAUDE_DOCKER_SHARED_HISTORY=1`
  shares it all again.
- **The shell snapshots of other sessions.** `~/.claude/shell-snapshots`
  and `session-env` are each session's own.

## Hardening

- Runs as your user, with a read-only root filesystem, all capabilities
  dropped, `no-new-privileges`, and PID and memory limits. A CPU limit with
  `CLAUDE_DOCKER_CPUS`.
- What a session installs in `~/.cache` (`uv tool install`, `go install`)
  comes last in `PATH`: the cache outlives the session, and a command left
  there cannot stand in for one of the image.
- Writable space is the mounts, the cache volume and a few size-capped
  tmpfs (`/tmp`, `~/.npm`, `~/.config`).
- Containers still share the host kernel. `CLAUDE_DOCKER_RUNTIME=runsc`
  runs the session under gVisor if you have it.

## How Claude Code is started

- **Without asking.** Claude Code is started with
  `--dangerously-skip-permissions`: the container is what keeps a session
  from the host. `CLAUDE_DOCKER_ASK=1` has it ask as it does outside the
  sandbox, and a `--permission-mode` of your own is left alone.
- **Without telemetry.** `DISABLE_TELEMETRY=1` and
  `DISABLE_ERROR_REPORTING=1` are set, so it sends no usage events and no
  crash reports. `CLAUDE_DOCKER_TELEMETRY=1` sends both. `DO_NOT_TRACK=1`
  is set with them, for the tools a session runs that go by it, and the
  image turns off the usage reports of gh and of common frameworks (Next.js,
  Nuxt, Astro and the like) whatever the setting.
- **Without the connectors of claude.ai.** `ENABLE_CLAUDEAI_MCP_SERVERS=false`
  is set, so the connectors of your account (Gmail, Google Drive and the
  like) are not loaded: they reach your data from inside the sandbox, and
  their tools and instructions take room in every request.
  `CLAUDE_DOCKER_CONNECTORS=1` loads them.

## The check when a session ends

Some files run commands on the host, or are followed by Claude there. They
have to stay writable for git and claude to work, so they are checked
rather than locked: the launcher warns when a session changed one.

- In the project and every extra directory: `.git/config` and the git
  hooks, `.claude/settings.json`, `settings.local.json` and `.mcp.json`
  with the scripts they name, `CLAUDE.md`, and the `hooks`, `commands`,
  `skills`, `agents` and `rules` of `.claude`.
- In `~/.claude`: the plugins, and what `CLAUDE_DOCKER_RW_CONFIG=1` made
  writable.

Said apart, as something to read before you build, test or commit there:

- What your tools run, wherever it is in the project or an extra
  directory: Makefiles and other build files, `package.json`,
  `pyproject.toml`, `conftest.py`, the configuration of a hook manager
  (`.pre-commit-config.yaml`, `.husky`), `.envrc`, CI workflows, and what
  an editor runs (`.vscode`, `.devcontainer`).
- Below the top of a project: `CLAUDE.md` and the `.claude` of a
  subdirectory, and the config and hooks of a repository that is there, or
  that a session planted there.

Said apart too, as something to read before the next session here:

- What Claude remembers of the project, the `memory` directory next to its
  transcripts in `~/.claude/projects`. A session writes there when you
  tell it something to keep, and what is there is given to every later
  session as your own notes: something a session read can have it leave
  instructions for the next ones.

All name a file however it was changed, by a command as by an edit, and
only when what it holds is no longer what it was. Not looked into:
`node_modules`, `.venv`, and the working trees of `--worktree`, each the
whole project again.

A session that ends without its launcher, a killed terminal say, is
checked by the next `claude-docker` launch instead.

## The opt-in doors

Each is off until you switch it on, and each use is noted for `--trace`.

**The SSH agent**, with `CLAUDE_DOCKER_SSH_AGENT=1`:

- Opt-in because the agent lets the container authenticate as you to every
  host your keys reach. Loading keys with `ssh-add -c` makes each use ask
  first.
- The session gets a socket of the launcher's in front of the agent. It
  passes on listing the keys and signing with one. Adding or removing
  keys and locking the agent are refused. A session has 16 connections to
  it at most, and one that asks nothing for two minutes is closed.
- On macOS its use is not noted.

**The Docker socket**, with `CLAUDE_DOCKER_SOCKET` (and the `docker` feature
for the CLI), through
[docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy):

| Value | Allowed | Hidden |
| --- | --- | --- |
| `1` | `docker ps` and `docker logs` | Everything else, container environments included |
| `full` | Every read under `/containers`, which adds real `inspect`, `stats` and `top` | Nothing of the containers: the environment of every one on the host shows, secrets included |

Writes are blocked in both modes, a write to the root daemon would let the
container escape. Command lines and logs can still carry secrets.

**The egress filter**, with `CLAUDE_DOCKER_NET_FILTER=1`:

- The session joins an internal network with no route out. Egress goes
  through a squid sidecar that only allows the domains in
  `docker/allowed-domains.txt`, and external DNS is blackholed. What the
  host listens on is out of reach too (Docker 28 and later).
- `claude-docker --net-log` lists the domains it refused, most frequent
  first, the quickest way to find what a project needs.
- An edited allowlist is picked up by the next filtered session, or at once
  with `claude-docker --net-reload`.
