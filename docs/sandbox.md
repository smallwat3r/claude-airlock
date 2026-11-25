# What the sandbox does

What a session is given and what it is kept from.

## Mounts

- The project and any extra directories, read-write at their host paths.
  Never the home directory, its parents or the filesystem root. Nor what
  is kept out of every session, whether named itself, by something in it
  or by a directory around it: `~/.ssh`, `~/.gnupg`, `~/.claude`, and the
  launcher's own settings and records (`~/.config/claude-airlock`,
  `~/.local/state/claude-airlock`). A session that could write those
  would decide how the next one is sandboxed.
- An extra directory is named by where it is. A path inside the project,
  or inside another directory a session can write, that leads out of it
  through a link is refused: a session could have left the link there, to
  be given what it points to the next time.
- As `~/.claude`, a directory of the launcher's that the sandboxed sessions
  share, not yours. Of your own `~/.claude` only the configuration listed
  below, `plugins` and `projects` (the transcripts) are mounted into it.
  What else Claude Code keeps there (its host sessions, jobs, logs) stays
  on the host.
- The login is one all the same: the launcher carries it between the two
  while a session runs, so a session starts logged in. On macOS, where
  Claude Code keeps the login in the Keychain, the launcher reads it
  there and writes back what a session renews, with `security` as Claude
  Code does. A locked Keychain is left alone, the session then has the
  login it was last given. What a session leaves in the place of its
  login that does not read as one is never carried to the host, the
  host's is put back instead.
- `~/.cache` (Go modules, uv, npm) as a Docker volume per project, so one
  session cannot poison another project's dependencies.
  `CLAUDE_AIRLOCK_CACHE=0` goes back to a tmpfs of at most 2g.
- The git config, read-only. Of `~/.config/git` that is `config`, `ignore`,
  `attributes` and `templates`, and the files the config includes: the rest
  stays on the host, as git's `store` helper keeps passwords in clear
  there. There is no gpg in the image, so sign the commits on the host
  before pushing.

## What is read-only or hidden

- **Claude's configuration.** `settings.json`, `hooks`, `CLAUDE.md`,
  `commands`, `skills`, `agents` and `rules` of `~/.claude` run commands
  on the host or are followed by every later session, so they are
  read-only. `CLAUDE_AIRLOCK_RW_CONFIG=1` makes them writable.
- **What you name.** `CLAUDE_AIRLOCK_PROTECT` makes a path read-only inside
  whatever mounts it. The directories between the two cannot be renamed
  or removed in a session, their content can: a path that was moved
  aside could be made again with other content, for the host to read.
- **Secrets.** `.env`, `.env.*`, `.envrc`, `.netrc` and `.pypirc` files read
  as empty. Templates such as `.env.example` stay readable,
  `CLAUDE_AIRLOCK_SHADOW` hides more, by file name globs (`*.pem:.npmrc`).
- **The history of other projects.** Their transcripts are covered by
  empty directories, and the prompt history, the paste cache and the file
  history are kept per project. So `claude` on the host cannot rewind the
  files of a session run in the sandbox. `CLAUDE_AIRLOCK_SHARED_HISTORY=1`
  shares it all again.
- **The shell snapshots of other sessions.** `~/.claude/shell-snapshots`
  and `session-env` are each session's own.

## Hardening

- Runs as your user, with a read-only root filesystem, all capabilities
  dropped, `no-new-privileges`, and PID and memory limits. A CPU limit with
  `CLAUDE_AIRLOCK_CPUS`.
- No program of the image is setuid or setgid, and a process that crashes
  leaves no core dump.
- What a session installs in `~/.cache` (`uv tool install`, `go install`)
  comes last in `PATH`: the cache outlives the session, and a command left
  there cannot stand in for one of the image.
- Writable space is the mounts, the cache volume and a few size-capped
  tmpfs (`/tmp`, `~/.npm`, `~/.config`).
- Containers still share the host kernel, unless the session runs under
  [gVisor](#gvisor).

## gVisor

[gVisor](https://gvisor.dev) runs a session on its own kernel, in user
space, so a session cannot exploit a flaw in the host's kernel. It is
available on Linux only. To use it, install `runsc`, register it in
`/etc/docker/daemon.json` with the two arguments below, restart the daemon,
and name the runtime in `CLAUDE_AIRLOCK_RUNTIME`:

```json
{
  "runtimes": {
    "runsc-hostnet": {
      "path": "/usr/local/bin/runsc",
      "runtimeArgs": ["--network=host", "--host-uds=open"]
    }
  }
}
```

```
CLAUDE_AIRLOCK_RUNTIME=runsc-hostnet claude-airlock
```

The launcher asks Docker which runtime a session will use and recognises
gVisor by its program, `runsc`, whatever name it is registered under. This
also works when gVisor is the daemon's default runtime. At each launch it
prints what differs from Docker's own runtime:

- **`--network=host` is required.** By default gVisor uses its own network
  stack, which cannot reach Docker's resolver. No name resolves, so access
  by name, the egress filter and the socket proxy all fail. With
  `--network=host` gVisor uses the host's network stack instead. The
  session still has its own network namespace. The cost is that the
  network stack of the host's kernel is exposed to the session again. The
  rest of the kernel is not.
- **`--host-uds=open` is required for the SSH agent**, because the agent is
  reached through a socket of the host. Without it, a session that asks
  for the agent is refused.
- **Processes are not recorded**, nor which process made each connection.
  A sidecar that joins the session sees gVisor's kernel process, not the
  session's processes, and the launcher does not run a watcher inside the
  session. The capture, the egress filter and the records of the SSH agent
  and Docker socket work as they do under Docker's own runtime.
- **Memory and CPU use are still recorded.** The launcher reads them from
  the cgroup of the container, along with the time the session waited for
  memory, CPU or disk. The process count, the use of each tmpfs and the
  largest process are not available. This requires the daemon to run on
  the same host and to use cgroup version 2.
- **A session that reaches its memory limit is ended as a whole.** Under
  Docker's own runtime the kernel ends one process. Under gVisor the
  host's kernel sees a single program, gVisor itself.
- **The process limit is an estimate.** The host counts gVisor's own
  threads: a few dozen, plus two to three for each process of the session,
  more for processes that start and end fast. gVisor keeps them once a
  process has ended, so the count only grows, to what the busiest moment
  of the session took. The launcher gives Docker four times
  `CLAUDE_AIRLOCK_PIDS` plus 128, which leaves a session room for more
  processes than the setting says, never fewer. A session that reaches
  that limit is also ended as a whole, with an exit status of 2. The
  launcher says so when the session is over, and `--trace` has it. Raise
  `CLAUDE_AIRLOCK_PIDS` if that happens to a session that was not running
  away.

## How Claude Code is started

- **Without asking.** Claude Code is started with
  `--dangerously-skip-permissions`: the container is what keeps a session
  from the host. `CLAUDE_AIRLOCK_ASK=1` has it ask as it does outside the
  sandbox, and a `--permission-mode` of your own is left alone.
- **Without telemetry.** `DISABLE_TELEMETRY=1` and
  `DISABLE_ERROR_REPORTING=1` are set, so it sends no usage events and no
  crash reports. `CLAUDE_AIRLOCK_TELEMETRY=1` sends both. `DO_NOT_TRACK=1`
  is set with them, for the tools a session runs that go by it, and the
  image turns off the usage reports of gh and of common frameworks (Next.js,
  Nuxt, Astro and the like) whatever the setting.
- **Without the connectors of claude.ai.** `ENABLE_CLAUDEAI_MCP_SERVERS=false`
  is set, so the connectors of your account (Gmail, Google Drive and the
  like) are not loaded: they reach your data from inside the sandbox, and
  their tools and instructions take room in every request.
  `CLAUDE_AIRLOCK_CONNECTORS=1` loads them.

## The check when a session ends

Some files run commands on the host, or are followed by Claude there. They
have to stay writable for git and claude to work, so they are checked
rather than locked: the launcher warns when a session changed one.

- In the project and every extra directory: `.git/config` and the git
  hooks, also of the directory a `.git/commondir` has git read them from
  in place of its own, `.claude/settings.json`, `settings.local.json` and `.mcp.json`
  with the scripts they name, `CLAUDE.md`, and the `hooks`, `commands`,
  `skills`, `agents` and `rules` of `.claude`.
- In `~/.claude`: the plugins, and what `CLAUDE_AIRLOCK_RW_CONFIG=1` made
  writable.

Said apart, as something to read before you build, test or commit there:

- What your tools run, wherever it is in the project or an extra
  directory: Makefiles and other build files, `package.json`,
  `pyproject.toml`, `conftest.py`, the configuration of a hook manager
  (`.pre-commit-config.yaml`, `.husky`), `.envrc`, CI workflows, and what
  an editor runs (`.vscode`, `.devcontainer`, `.dir-locals.el`).
- Below the top of a project: `CLAUDE.md` and the `.claude` of a
  subdirectory, and the config and hooks of a repository that is there, or
  that a session planted there.

Said apart too, as something to read before the next session here:

- What Claude remembers of the project, the `memory` directory next to its
  transcripts in `~/.claude/projects`. A session writes there when you
  tell it something to keep, and what is there is given to every later
  session as your own notes: something a session read can have it leave
  instructions for the next ones.
- The MCP servers of the config the sandboxed sessions share (the
  `.claude.json` of their `~/.claude`), those set up for every project and
  for each one. A server is a command: one a session added there is
  started by the next session of another project too, in that project's
  sandbox. Only the servers are compared, every session rewrites the rest
  of that file.
- A directory of `~/.claude/projects` that is not the project's own and
  was not there when the session started. A session is kept out of those
  of the other projects that are there, but can make one for a project
  that has none yet, and what it puts there as that project's memory is
  told to its next session, to `claude` on the host too. A project first
  used while the session ran has one made for it as well, so the line
  says by whose doing it may be.
- The launcher itself, when the session could write its checkout: the
  project is the checkout, or holds it, or it is mounted next to it. What
  changed in its `bin`, `claude_airlock` and `docker` starts and sandboxes
  the next session, the allowlist of the egress filter and the rules of
  the socket proxy among it. The launch says so too. Not watched there:
  what Python compiled of the modules (`__pycache__`), which changes
  without a session's doing.

All name a file however it was changed, by a command as by an edit, and
only when what it holds is no longer what it was. Not looked into:
`node_modules`, `.venv`, and the working trees of `--worktree`, each the
whole project again.

The check is bounded, a session can write any number of files of any
size: 5000 files of each watched directory, 5000 build files, the
submodules of 1000 git directories, and 1 GB read in all. What is past a
count is said as `the rest`, unwatched, when a session made it so, and
so is a watched directory with more entries or more directories below it
than that. A file
past 64 MB is read that far, one past what is read in all is not read:
both are still told from one written since by when they changed.

A session that ends without its launcher, a killed terminal say, is
checked by the next `claude-airlock` launch instead.

## The opt-in doors

Each is off until you switch it on, and each use is noted for `--trace`.

**The SSH agent**, with `CLAUDE_AIRLOCK_SSH_AGENT=1`:

- Opt-in because the agent lets the container authenticate as you to every
  host your keys reach. Loading keys with `ssh-add -c` makes each use ask
  first.
- The session gets a socket of the launcher's in front of the agent. It
  passes on listing the keys and signing with one. Adding or removing
  keys and locking the agent are refused. A session has 16 connections to
  it at most, and one that asks nothing for two minutes is closed.
- On macOS its use is not noted.

**The Docker socket**, with `CLAUDE_AIRLOCK_DOCKER_SOCKET` (and the `docker`
feature for the CLI), through
[docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy):

| Value | Allowed | Hidden |
| --- | --- | --- |
| `1` | `docker ps` and `docker logs` | Everything else, container environments included |
| `full` | The same, and the real `docker inspect`, `docker stats` and `docker top`, with the daemon's `info` and `events` | Nothing of the containers: the environment of every one on the host shows, secrets included |

Writes are blocked in both modes, a write to the root daemon would let the
container escape. Each mode has rules of its own (`docker/docker-socket-proxy.cfg`
and `docker/docker-socket-proxy-full.cfg`) that name the reads it allows,
whatever they do not name is refused: `docker attach`, `cp`, `export` and
`diff` among them, in `full` too. Command lines and logs can still carry
secrets.

**The egress filter**, with `CLAUDE_AIRLOCK_NET_FILTER=1`:

- The session joins an internal network with no route out. Egress goes
  through a squid sidecar that only allows the domains in
  `docker/allowed-domains.txt`, and external DNS is blackholed. What the
  host listens on is out of reach too (Docker 28 and later).
- `claude-airlock --net-log` lists the domains it refused, most frequent
  first, the quickest way to find what a project needs.
- An edited allowlist is picked up by the next filtered session, or at once
  with `claude-airlock --net-reload`.
- With `CLAUDE_AIRLOCK_NET_ASK=1` as well, a host that is not on the list
  is yours to allow, in [line mode](line-mode.md). The proxy holds the
  request, you are asked, and a yes lets it through. Nothing is looked up
  or sent for the host before that. The answer is for that host alone,
  not the names under it, and holds until the session ends: the list is
  not changed. Only a name of the public DNS is asked about, never an
  address or the bare name of a container, and a yes does not reach a
  private address the name leads to: a host of your own network goes on
  the list. Nothing gets through the proxy to its own loopback (0.0.0.0/8
  too, which leads there) or link
  (169.254.0.0/16, where a cloud keeps a machine's credentials), on the
  list or not. A session that is not in line mode has nowhere to ask, its
  filter refuses as without this, and says so when it starts. A request
  made in the first moment of a session, before the launcher knows its
  address, is refused too.
