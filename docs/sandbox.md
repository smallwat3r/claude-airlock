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
  be given what it points to the next time. The same in a directory a
  session could write at an earlier launch, and cannot now: the launcher
  keeps the latest 1000 such directories, of every project.
- Read-only wins. A directory asked for both ways, by `--add-dir` and
  `--add-dir-ro` or their settings, the shared directory too, is mounted
  read-only, whichever was said first. The project itself is always
  writable: asked for read-only, it is refused.
- A directory mounted inside another stays where it is, the project
  too: the directories between the two cannot be renamed or removed in a
  session, as with a protected path below.
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
  host's is put back instead. The logins to MCP servers, which Claude
  Code keeps in the same place, are not carried either way: the host's
  stay on the host, a session's in the sandbox.
- With `CLAUDE_AIRLOCK_API_LOG=1`, a directory of the launcher's for
  this session alone at `~/.local/state/api-log`, where Claude Code
  leaves what it sends to the model. What the launcher keeps of it is
  nowhere in a session.
- `~/.cache` (Go modules, uv, npm) as a Docker volume per project, so one
  session cannot poison another project's dependencies.
  `CLAUDE_AIRLOCK_CACHE=0` goes back to a tmpfs of at most 2g.
- The git config, read-only. Of `~/.config/git` that is `config`, `ignore`,
  `attributes` and `templates`, and the files the config includes: the rest
  stays on the host, as git's `store` helper keeps passwords in clear
  there. There is no gpg in the image, so sign the commits on the host
  before pushing.
- Not an included file that is kept out of every session, or named as a
  file of secrets is, nor what that one includes. Nor any file a config
  names that is, or leads into, a directory a session can write, or
  could at an earlier launch: a config kept in a repository a session was
  given can name any file, `~/.aws/credentials` as well, for the next
  launch to mount. The launcher says which it left out.
- The file `~/.claude/settings.json` runs as its statusline, read-only,
  when it is a file of your home directory, see
  [Statusline](#statusline).

## What is read-only or hidden

- **Claude's configuration.** `settings.json`, `hooks`, `CLAUDE.md`,
  `commands`, `skills`, `agents` and `rules` of `~/.claude` run commands
  on the host or are followed by every later session, so they are
  read-only. `CLAUDE_AIRLOCK_RW_CONFIG=1` makes them writable.
- **What you name.** `CLAUDE_AIRLOCK_PROTECT` makes a path read-only inside
  whatever mounts it. The directories between the two cannot be renamed
  or removed in a session, their content can: a path that was moved
  aside could be made again with other content, for the host to read. A
  directory mounted from inside a protected path is read-only too,
  however it was asked for, and the launch says so. A path that is, or
  goes through, a link in a directory a session can write is refused: no
  mount holds a link, a session could put another in its place. Name
  the path it leads to. A protected path that is also hidden is hidden.
- **Secrets.** `.env`, `.env.*`, `.envrc`, `.netrc` and `.pypirc` files read
  as empty. Templates such as `.env.example` stay readable,
  `CLAUDE_AIRLOCK_SHADOW` hides more, by file name globs (`*.pem:.npmrc`).
  Not hidden: one under `node_modules` or `.git`, which are not looked
  into for them, and one made after the session started. Of a link
  under such a name, the file it leads to is hidden, where it is in a
  mounted directory. It stays hidden at later launches while it is there,
  the link gone or not: a session can remove the link. The launcher keeps
  the latest 1000 such files, of every project.
  - The directories above a hidden file cannot be renamed or removed in a
    session (`Device or resource busy`). A session cannot read the file,
    but it could otherwise move it under `node_modules`, where the next
    launch would not hide it.
  - A directory the launcher cannot look into for such files, and that a
    session could open, is hidden whole: it is empty and read-only in the
    session, and the launch names it. A session can take the right to
    list a directory away and give it back the next time. Make it yours
    to read again (`chmod u+rx`) to have it back.
  - More than 1000 such files and directories, or more than 2000
    directories held above them, end the launch with one of them named:
    each is a mount of its own, and docker takes only so many.
- **The history of other projects.** Their transcripts are covered by
  empty directories, and the prompt history, the paste cache and the file
  history are kept per project. So `claude` on the host cannot rewind the
  files of a session run in the sandbox. `CLAUDE_AIRLOCK_SHARED_HISTORY=1`
  shares it all again. More than 2000 directories of other projects end
  the launch, as too many to cover. A project's prompt history starts
  from its latest lines of the host's, those in its last 64 MB.
- **The shell snapshots of other sessions.** `~/.claude/shell-snapshots`
  and `session-env` are each session's own.
- **What Claude Code keeps in `~/.local/state/claude`.** A session has
  a directory of its own there, empty and gone with it: the host's is
  one for every project, and nothing in it is a session's to read.

## Hardening

- Runs as your user, with a read-only root filesystem, all capabilities
  dropped, `no-new-privileges`, and PID and memory limits. A CPU limit with
  `CLAUDE_AIRLOCK_CPUS`. The image has one user, numbered 1000: with
  another number (501 on macOS, a second account) the session is given
  its own `/etc/passwd`, where that number is the image's user, or `ssh`
  would refuse to run for a user it has no entry for.
- No program of the image is setuid or setgid, and a process that crashes
  leaves no core dump.
- What a session installs in `~/.cache` (`uv tool install`, `go install`)
  comes last in `PATH`: the cache outlives the session, and a command left
  there cannot stand in for one of the image.
- Writable space is the mounts, the cache volume and a few size-capped
  tmpfs (`/tmp`, `~/.npm`, `~/.config`, `~/.local/state/claude`).
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
- **The session is told.** Nothing in it fails first at a limit, so it
  cannot find out by itself: it is told that it runs on gVisor, and to
  keep its builds and tests to a few jobs (`docker/CLAUDE-airlock.md`).

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
- **Without a copy of what it sends.** With `CLAUDE_AIRLOCK_API_LOG=1`
  it is told to write every request to the model and each answer to a
  directory (`OTEL_LOG_RAW_API_BODIES`), which the launcher mounts for
  that session alone and empties as it goes, see
  [The requests to the model](trace.md#the-requests-to-the-model).
  Nothing of it is sent anywhere, telemetry stays off.
- **Without the connectors of claude.ai.** `ENABLE_CLAUDEAI_MCP_SERVERS=false`
  is set, so the connectors of your account (Gmail, Google Drive and the
  like) are not loaded: they reach your data from inside the sandbox, and
  their tools and instructions take room in every request.
  `CLAUDE_AIRLOCK_CONNECTORS=1` loads them.

## Statusline

For Claude Code's native UI. The launcher has no statusline of its own
and adds none: the one of your `~/.claude/settings.json` works in the
sandbox as on the host. The file its command runs is mounted read-only
where the settings name it, whether it is the program
(`~/.claude/statusline.sh`) or the script an interpreter is given
(`bash ~/bin/statusline.sh`):

- It has to be a file of your home directory, named by its whole path.
  A command the image has (`npx some-statusline`) needs no mount.
- Only that file is mounted. What it runs has to be in the image (bash,
  `jq`, Python and Node.js are), and what it reads besides in a directory
  mounted with `CLAUDE_AIRLOCK_EXTRA_DIRS_RO`.
- A file with the name of a secrets file (`.env`, `.netrc`) is not
  mounted, nor one in a directory no session is given: `~/.ssh`,
  `~/.gnupg`, the launcher's settings and its records, by where the path
  leads. The launch says so.
- Only the statusline of `~/.claude/settings.json` on the host, not one a
  project's settings name.
- It can show the sandbox from the variables a session has of how it was
  started, `env | grep CLAUDE_AIRLOCK_` in a session lists them: the name
  of the container, which is not set outside the sandbox, the network
  mode and the doors that are open.

[Line mode](line-mode.md) does not run it. It shows a status of its own
above its prompt, made from what it knows of the session, with the
effort and the weekly limit of Fable while that is the model.

## The check when a session ends

Some files run commands on the host, or are followed by Claude there. They
have to stay writable for git and claude to work, so they are checked
rather than locked: the launcher warns when a session changed one.

- In the project and every extra directory, for git: `.git/config` with
  the files it includes, and the git hooks. Also those of the directory a
  `.git/commondir` has git read them from in place of its own, and of
  each working tree made of it (`git worktree add`), whose own
  `commondir` can lead elsewhere too.
- There too, for Claude: `.claude/settings.json`, `settings.local.json`
  and `.mcp.json` with the scripts they name, a server's among its `args`
  too, and those Claude Code runs as a helper (`apiKeyHelper`,
  `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`),
  `CLAUDE.md` and `AGENTS.md` with the files they have Claude read (`@docs/style.md`), the prompts
  Claude Code runs by itself (`.claude/scheduled_tasks.json`,
  `.claude/loop.md`), and the `hooks`, `commands`, `skills`, `agents`,
  `rules`, `output-styles`, `workflows` and `routines` of `.claude`.
- In `~/.claude`: the plugins, and what `CLAUDE_AIRLOCK_RW_CONFIG=1` made
  writable.
- Your own git config, `~/.gitconfig` and `~/.config/git/config`, with
  the files they include, where a session could write one: it is, or
  leads to, a file of the project or of an extra directory, as dotfiles
  kept in a repository often are. Git on the host runs what it says
  (`core.fsmonitor`, an alias) wherever it is run.

Said apart, as something to read before you build, test or commit there:

- What your tools run, wherever it is in the project or an extra
  directory: Makefiles and other build files, `package.json`,
  `pyproject.toml`, `conftest.py`, the configuration of a hook manager
  (`.pre-commit-config.yaml`, `.husky`), `.envrc` and the Nix files it
  can have direnv evaluate (`flake.nix`, `shell.nix`), CI workflows, the
  release of yarn `.yarnrc.yml` runs (`.yarn/releases`), and what runs
  as an editor opens a file, with no command typed: `.vscode`,
  `.devcontainer`, `.dir-locals.el`, the configs of ESLint, Prettier and
  Stylelint that are code (`eslint.config.js` and its kin) and
  `.cargo/config.toml`. By their names in any case: on macOS make reads
  `GNUMAKEFILE` as `GNUmakefile`.
- Below the top of a project: `CLAUDE.md` and the `.claude` of a
  subdirectory, and the config and hooks of a repository that is there, or
  that a session planted there, with its submodules and the hooks its
  `core.hooksPath` names, as at the top, and what is still to be done of
  a rebase or a cherry-pick: an `exec` line of it runs on
  `git rebase --continue`.

Said apart too, as something to read before the next session here:

- What Claude remembers of the project, the `memory` directory next to its
  transcripts in `~/.claude/projects`, and what its agents remember, in
  `.claude/agent-memory` of the project. A session writes there when you
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
  without a session's doing. The launcher does not run it either: it
  keeps what it compiles with its own records, where no session writes.
  Watched too: what Python would take for a module or a package at the
  top of the checkout, where the launcher finds its own. One named as a
  module of the standard library is not run, the launcher looks there
  last.

All name a file however it was changed, by a command as by an edit, and
only when what it holds is no longer what it was. Not looked into:
`node_modules`, `.venv`, and the working trees of `--worktree`, each the
whole project again. A directory the check cannot list is named as one
it cannot look into, when a session made it so: a file in it is found by
its name all the same, by make, git and Claude. A link to a directory is
followed when it leads into the project or an extra directory, so hooks
or skills kept elsewhere in the project, or in a repository of dotfiles
that is the project, are watched where git and Claude find them. One
that leads anywhere else is watched as the link.

The check is bounded, a session can write any number of files of any
size: 5000 files of each watched directory, 1000 of what Claude remembers
of a project, 5000 build files, the submodules of 1000 git directories,
200 working trees of each, 100 files a git config includes and as many a
`CLAUDE.md` has Claude read, and 1 GB read for what git and Claude
follow, as much again for the build files. A git config past 1 MB, or
one git lists as more than 4 MB, is told from one written since by what
it holds as a file. The plugins, thousands of files as they come, are not read: up to
100 000 of them are told from one written since by when they changed. What is past a
count is said as `the rest`, unwatched, when a session made it so, and
so is a watched directory with more entries or more directories below it
than that. A launch says which are past a count already as the session
starts: a change there goes unseen, review it yourself. A file
past 64 MB is read that far, one past what is read in all is not read:
both are still told from one written since by when they changed.

A session that ends without its launcher, a killed terminal say, is
checked by the next `claude-airlock` launch instead. Should that check
fail to run, the launch says so and goes on, and the launch after it
tries again.

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

The proxy is given the daemon's socket at `/var/run/docker.sock`. A
daemon that keeps its socket elsewhere, rootless or colima, is not
reached: the session has no Docker, and the launch says so.

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

## Known limits

The [README](../README.md#known-limits) has the limits that change how
you use the sandbox. The narrower ones:

- `~/.claude/plugins` stays writable, Claude updates plugins itself, so a
  plugin's hook scripts are not protected the way `settings.json` is. A
  change to them is reported when the session ends, not prevented.
- The MCP servers you set up for every project on the host are not in the
  sandbox: the config it starts from leaves them out, they come with
  tokens. Add the ones you want there from inside a session.
- Of the history of other projects, some is still there to read: the
  transcripts of a project first used after the session started, the paths
  of the projects you ran in the sandbox (in its `.claude.json`), and what
  Claude Code keeps by session rather than by project (`jobs`, its debug
  log) of the other sandboxed sessions. Those of the host are not there.
- The sandboxed sessions of every project share one `.claude.json`. An
  MCP server a session adds there is started by the next session of
  another project. The launcher says so when the session ends, it does
  not prevent it.
- The filter goes by the name a connection asks the proxy for, and does
  not look into what is then sent over it. A name on the list that is
  served by a network of many sites (npm, PyPI and GitHub's files are)
  leads to that network's addresses, and a session can ask there for
  another site of the same network. One that asks for it in the hello
  of its TLS is flagged in the trace (see
  [What a connection is](trace.md#what-a-connection-is)), one that asks
  for it inside the encryption is not seen.
- What Python compiled of a project's modules (`__pycache__`) is run in
  the place of a module whose time and size it carries, and no diff
  shows it. A session can leave such a file. The launcher does not run
  its own from there, your tools still do: remove those directories
  before you run a project's Python on the host after a session you do
  not trust.
- Claude Code names the directory of a project's transcripts after its
  path, with every character that is no letter or digit as a dash. Two
  projects whose paths differ in such characters alone (`my-app` and
  `my_app`) share one, and a session of either reads what the other's
  sessions said and remember.
