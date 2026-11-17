# What the sandbox does

What a session is given and what it is kept from:

- [Mounts](#mounts): what a session sees of your files
- [What is read-only or hidden](#what-is-read-only-or-hidden)
- [Hardening](#hardening) of the container
- [How Claude Code is started](#how-claude-code-is-started): permissions
  and telemetry
- [The check when a session ends](#the-check-when-a-session-ends)
- [The opt-in doors](#the-opt-in-doors): the SSH agent, the Docker socket
  and the egress filter

## Mounts

- The project and any extra directories, read-write at their host paths.
- As `~/.claude`, a directory of the launcher's that the sandboxed sessions
  share (`~/.local/state/claude-sandbox/home`), not yours. Of your own
  `~/.claude` only what is named is mounted into it: the configuration
  listed below, `plugins` and `projects` (the transcripts).
  - Everything else Claude Code keeps there stays on its side: the sessions
    running on the host, its background jobs, its daemon, its logs, and
    whatever a later version adds. A session neither reads nor writes
    yours, and your host `claude` does not see the sandbox's.
  - The login is one all the same. The launcher carries
    `.credentials.json` between the two directories while a session runs,
    in both directions, so a session starts logged in and a login renewed
    on either side is the other's a moment later. `/logout` on one side
    logs out the other.
  - The sandbox has its own Claude Code config (theme, folder trust, MCP
    servers), `.claude.json` in that directory.
- Never the home directory, its parents or the filesystem root, the
  launcher refuses those.
- `~/.cache` (Go modules, uv, npm) as a Docker volume per project, so a
  session does not download its dependencies again.
  - Per project on purpose: a shared cache would let one session poison
    another project's dependencies.
  - The volumes have no size cap, `docker volume ls --filter
    name=claude-cache-` lists them.
  - `CLAUDE_DOCKER_CACHE=0` goes back to a 2g tmpfs.
- Claude Code's own state directory, `~/.local/state/claude`, read-write.
- The git config, read-only, with the files it pulls in through `include`
  and `includeIf`. There is no gpg in the image, so commit signing is off
  inside the container: sign the commits on the host before pushing.

## What is read-only or hidden

- **Claude's configuration.** `~/.claude/settings.json` and `hooks` hold
  commands your host `claude` runs, and `CLAUDE.md`, `commands`, `skills`,
  `agents` and `rules` are instructions every later session follows. A
  session must not be able to plant either, so they are read-only, and the
  ones you do not have are made empty so that none can be created.
  `CLAUDE_DOCKER_RW_CONFIG=1` makes them writable.
- **What you name.** `CLAUDE_DOCKER_PROTECT` makes a path read-only inside
  whatever mounts it. For what a session has to read and must not change:
  a kit of skills in the shared directory that your host `claude` follows,
  say. A path that is in nothing mounted is not brought in, and one that is
  missing where a session could create it stops the launch.
- **What Claude Code keeps for one session.** `~/.claude/shell-snapshots`
  and `session-env` are sourced by every command of the session they are
  of. Those of your host sessions are not in the sandbox, and a sandboxed
  session gets an empty tmpfs in place of each, so it can neither read nor
  add to those of another sandboxed session.
- **Secrets.** `.env`, `.env.*`, `.envrc`, `.netrc` and `.pypirc` files read
  as empty (`/dev/null` is mounted over them). Templates such as
  `.env.example` stay readable, `CLAUDE_DOCKER_SHADOW` hides more, by
  file name globs (`*.pem:.npmrc`).
- **The history of other projects.** A session could otherwise read every
  prompt, command output and file of all of them.
  - Under `~/.claude/projects`, the directory of each other project is
    covered by an empty one. The project's own and those of its worktrees
    stay.
  - The prompt history, the paste cache and the file history are kept per
    project under `~/.local/state/claude-sandbox/history`. The prompt
    history starts from the project's own lines of yours.
  - So the up-arrow history of a sandboxed session is its project's, and
    `claude` on the host cannot rewind the files of a session run in the
    sandbox.
  - A directory mounted with `--add-dir` does not bring its history along.
  - `CLAUDE_DOCKER_SHARED_HISTORY=1` shares it all again.

## Hardening

- Runs as your user, with a read-only root filesystem, all capabilities
  dropped, `no-new-privileges`, and PID and memory limits.
- Writable space is the mounts, the cache volume and a few size-capped
  tmpfs (`/tmp`, `~/.npm`, `~/.config`).
- Containers still share the host kernel. `CLAUDE_DOCKER_RUNTIME=runsc`
  runs the session under gVisor if you have it.

## How Claude Code is started

- **Without asking.** Claude Code is started with
  `--dangerously-skip-permissions` and does not ask before it uses a tool:
  the container is what keeps a session from the host.
  `CLAUDE_DOCKER_ASK=1` has it ask as it does outside the sandbox. The
  flag is not added when you give `--permission-mode` or one of the two
  flags yourself, nor to a command of claude's (`claude-docker mcp list`).
- **Without telemetry.** Claude Code is started with `DISABLE_TELEMETRY=1`
  and `DISABLE_ERROR_REPORTING=1`: it sends no usage events and no crash
  reports, which otherwise go out in the background, to Datadog among
  others. Sessions work the same, though features Anthropic rolls out
  gradually may stay at their defaults. `CLAUDE_DOCKER_TELEMETRY=1` sends
  both as outside the sandbox.

## The check when a session ends

Some files run commands on the host, or are followed by Claude there. They
have to stay writable for git and claude to work, so they are checked
rather than locked: the launcher warns when a session changed one.

| Where | What is checked |
| --- | --- |
| The project and every extra directory | `.git/config` (branch tracking aside) and git hooks, of submodules too and where `core.hooksPath` moved them (husky and the like) |
| | `.claude/settings.json`, `settings.local.json` and `.mcp.json`, with the scripts their commands name |
| | `CLAUDE.md` and the `hooks`, `commands`, `skills`, `agents` and `rules` of `.claude` |
| `~/.claude` | What is not mounted read-only: a script `settings.json` names outside `hooks`, and with `CLAUDE_DOCKER_RW_CONFIG=1` all of `settings.json`, `CLAUDE.md`, `hooks`, `commands`, `skills`, `agents` and `rules` |
| | The plugins, which stay writable: those installed (`plugins/cache`), where they are installed from (`plugins/marketplaces`) and the two files that list them. A changed plugin is named by its directory, with how many of its files changed. By each file's size and times, not its content: an update by Claude Code itself shows too |

- The warning is printed when the launcher returns. Ctrl-C does not end
  the launcher before it, only the session.
- A session that ends without it, because its Emacs buffer or terminal was
  killed, is checked by the next `claude-docker` launch instead. That
  report also lists what you changed yourself in the meantime.

## The opt-in doors

**The SSH agent**, with `CLAUDE_DOCKER_SSH_AGENT=1`:

- Opt-in because the agent lets the container authenticate as you to every
  host your keys reach. Loading keys with `ssh-add -c` makes each use ask
  first.
- The session is not given the agent's socket but one of the launcher's in
  front of it, which notes every request for `--trace`: which key signed,
  and what for. It is there for as long as the launcher runs.
- That socket passes on what a session has a use for, listing the keys and
  signing with one. A request to add a key, to remove them or to lock the
  agent is refused there and never reaches your agent.
- On macOS the agent comes from inside Docker Desktop's machine, where the
  launcher cannot listen, and its use is not noted.

**The Docker socket**, with `CLAUDE_DOCKER_SOCKET` (and the `docker` feature
for the CLI), through
[docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy):

| Value | Allowed | Hidden |
| --- | --- | --- |
| `1` | `docker ps` and `docker logs`, by our own rules (`docker/docker-socket-proxy.cfg`) | Everything else. `docker inspect` gets a stub answer, enough for the CLI to fetch logs, so container environments stay hidden |
| `full` | Every read under `/containers`, which adds real `inspect`, `stats` and `top` | Nothing of the containers: the environment of every one on the host shows, secrets included |

- Writes are blocked in both modes, a write to the root daemon would let
  the container escape.
- Command lines and logs can still carry secrets, which is why this stays
  opt-in.
- With `1`, the logs of containers started with a TTY cannot be decoded.
- Every call a session makes is noted for `--trace`, the denied ones too.
- A session only shares a network with the proxy of its own mode, so one
  started without the setting has no way to a proxy another session was
  given.
- A proxy sidecar is started by the first session that needs it and
  removed with the last one, so the host's Docker socket is not held open
  for no one. Edited rules or a new pinned image are picked up by the next
  session of that mode, which replaces the proxy.

**The egress filter**, with `CLAUDE_DOCKER_NET_FILTER=1`:

- The session joins an internal network with no route out, and the
  launcher refuses a network of that name that has one. Egress goes
  through a squid sidecar that only allows the domains in
  `docker/allowed-domains.txt`, and external DNS is blackholed.
- The host is kept off that network too (Docker 28 and later): its bridge
  is given no address there, so what the host listens on is not a way
  around the filter. A network made before this is made anew by the first
  filtered session started while none is on it.
- The proxy is removed with the last filtered session. Its log is in a
  volume and stays, `--net-log` and `--trace` read it either way.
- `claude-docker --net-log` lists the domains it refused, most frequent
  first, the quickest way to find what a project needs.
- An edited allowlist is picked up by the next filtered session, or at once
  with `claude-docker --net-reload`. Either way the proxy restarts, briefly
  dropping the connections of other filtered sessions.
