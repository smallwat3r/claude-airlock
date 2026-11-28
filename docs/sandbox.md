# What the sandbox does

What a session is given and what it is kept from.

## Mounts

- The project and any extra directories, read-write at their host paths.
  Never the home directory, its parents or the filesystem root.
- Some directories are kept out of every session: `~/.ssh`, `~/.gnupg`,
  `~/.claude`, and the launcher's own settings and records
  (`~/.config/claude-airlock`, `~/.local/state/claude-airlock`). Nothing
  in them is mounted, nor a directory that holds them. A session that
  could write those would decide how the next one is sandboxed.
- A path to an extra directory that is, or goes through, a link in the
  project (or in another directory a session can write) and leads out of
  it is refused, wherever the path is named from (`~/kit` as a link into
  the project too). A session could have left that link there, to be
  given what it points to next time. The same goes for a directory a
  session could write at an earlier launch but cannot now: the launcher
  remembers the latest 1000 such directories, across all projects.
- Read-only wins. A directory asked for both ways, by `--add-dir` and
  `--add-dir-ro` or their settings, the shared directory too, is mounted
  read-only, whichever came first. The project itself is always
  writable: asking for it read-only is refused.
- A directory mounted inside another stays where it is, the project
  too: in a session, the directories between the two cannot be renamed
  or removed, as with a protected path below.
- `~/.claude` is a directory of the launcher's, shared by the sandboxed
  sessions, not yours. Only parts of your own `~/.claude` are mounted
  into it: the configuration listed below, `plugins` and `projects` (the
  transcripts). The rest (Claude Code's host sessions, jobs, logs) stays
  on the host.
- The login is shared all the same. The launcher carries it between the
  host and the sandbox while a session runs, so a session starts logged
  in. On macOS, where Claude Code keeps the login in the Keychain, the
  launcher reads it there and writes back what a session renews, with
  `security` as Claude Code does. A locked Keychain is left alone, and
  the session keeps the login it was last given. If a session leaves
  something in place of its login that does not read as one, it is never
  carried to the host, the host's login is put back instead. Logins to
  MCP servers, kept in the same place, are not carried either way: the
  host's stay on the host, a session's in the sandbox.
- With `CLAUDE_AIRLOCK_API_LOG=1`, a directory for this session alone at
  `~/.local/state/api-log`, where Claude Code writes what it sends to
  the model. The copy the launcher keeps is in no session.
- `~/.cache` (Go modules, uv, npm) is a Docker volume per project, so one
  session cannot poison another project's dependencies.
  `CLAUDE_AIRLOCK_CACHE=0` makes it a tmpfs of at most 2g instead.
- The git config, read-only: `~/.gitconfig`, and of `~/.config/git` only
  `config`, `ignore`, `attributes` and `templates`, with the files the
  config includes. The rest of `~/.config/git` stays on the host, as
  git's `store` helper keeps passwords in clear text there. The image has
  no gpg, so sign commits on the host before pushing.
- Some git config files are left out, and the launcher says which:
  - An included file that is kept out of every session or named as a
    secrets file, and what that one includes.
  - Any file a config names that is in, or leads into, a directory a
    session can write, or could at an earlier launch. A config kept in a
    repository a session was given can name any file, `~/.aws/credentials`
    too, for the next launch to mount.
  - The config itself, or a file it includes, when it goes through a link
    in such a directory and leads out of it, as with an extra directory.
    `~/.gitconfig` as a link into a dotfiles repository is mounted while
    it leads to the file there, not once a session has made that file a
    link to a key.
- The file your `~/.claude/settings.json` runs as its statusline,
  read-only, when it is in your home directory, see
  [Statusline](#statusline).

## What is read-only or hidden

- **Claude's configuration.** `settings.json`, `hooks`, `CLAUDE.md`,
  `commands`, `skills`, `agents` and `rules` of `~/.claude` are
  read-only: they run commands on the host or are followed by every
  later session. `CLAUDE_AIRLOCK_RW_CONFIG=1` makes them writable.
- **What you name.** `CLAUDE_AIRLOCK_PROTECT` makes a path read-only in
  whatever mounts it. The directories between the mount and the path
  cannot be renamed or removed in a session, though their content can
  change: otherwise a session could move the path aside and make it again
  with other content, for the host to read. A directory mounted from
  inside a protected path is read-only too, however it was asked for, and
  the launch says so. A path that is, or goes through, a link in a
  directory a session can write is refused, as a mount does not hold a
  link and a session could put another in its place. Name the path it
  leads to instead. A path both protected and hidden is hidden.
- **Secrets.** `.env`, `.env.*`, `.envrc`, `.netrc` and `.pypirc` files
  read as empty. Templates such as `.env.example` stay readable.
  `CLAUDE_AIRLOCK_SHADOW` hides more, by file name globs (`*.pem:.npmrc`).
  Not hidden: files under `node_modules` or `.git`, which are not
  searched, and files made after the session started. For a link with
  such a name, the file it leads to is hidden, if it is in a mounted
  directory. That file stays hidden at later launches while it is there,
  link or no link, since a session can remove the link. The launcher
  remembers the latest 1000 such files, across all projects.
  - The directories above a hidden file cannot be renamed or removed in a
    session (`Device or resource busy`). A session cannot read the file,
    but could otherwise move it under `node_modules`, where the next
    launch would not hide it.
  - A directory the launcher cannot look into for such files, and that a
    session could open, is hidden whole: it is empty and read-only in the
    session, and the launch names it. A session can take away the right
    to list a directory and give it back later. Make it yours to read
    again (`chmod u+rx`) to have it back.
  - More than 1000 such files and directories, or more than 2000
    directories held above them, end the launch, with one of them named.
    Each is a mount of its own, and docker takes only so many.
- **The history of other projects.** Their transcripts are covered by
  empty directories. The prompt history, the paste cache and the file
  history are kept per project, so `claude` on the host cannot rewind the
  files of a session run in the sandbox. A project's prompt history
  starts from the host's latest lines of it, those in its last 64 MB.
  `CLAUDE_AIRLOCK_SHARED_HISTORY=1` shares it all again. The launch ends
  when there are more than 2000 directories of other projects to cover,
  or when it cannot list `~/.claude/projects`. A session can make that
  directory unlistable, so the next one would start with none covered.
  Make it yours to list again (`chmod u+rwx`) to have it back.
- **The shell snapshots of other sessions.** `~/.claude/shell-snapshots`
  and `session-env` are each session's own.
- **What Claude Code keeps in `~/.local/state/claude`.** A session has
  its own directory there, empty and gone with it. The host's is shared
  by every project, and nothing in it is a session's to read.

## Hardening

- Runs as your user, with a read-only root filesystem, all capabilities
  dropped, `no-new-privileges`, and PID and memory limits. A CPU limit with
  `CLAUDE_AIRLOCK_CPUS`. The image has one user, numbered 1000. With
  another number (501 on macOS, a second account), the session is given
  its own `/etc/passwd` where that number is the image's user, as `ssh`
  refuses to run for a user it has no entry for.
- No program of the image is setuid or setgid, and a process that crashes
  leaves no core dump.
- What a session installs in `~/.cache` (`uv tool install`,
  `uv python install`, `go install`)
  comes last in `PATH`. The cache outlives the session, and a command left
  there cannot stand in for one of the image.
- Writable space is the mounts, the cache volume and a few size-capped
  tmpfs (`/tmp`, `~/.config`, `~/.local/state/claude`).
- Containers still share the host kernel, unless the session runs under
  [gVisor](#gvisor).

## gVisor

[gVisor](https://gvisor.dev) runs a session on its own kernel, in user
space, so a session cannot exploit a flaw in the host's kernel. It is
Linux only. To use it, install `runsc`, register it in
`/etc/docker/daemon.json` with the arguments below, restart the daemon,
and name the runtime in `CLAUDE_AIRLOCK_RUNTIME`:

```json
{
  "runtimes": {
    "runsc-hostnet": {
      "path": "/usr/local/bin/runsc",
      "runtimeArgs": [
        "--network=host",
        "--host-uds=open",
        "--pod-init-config=/home/<user>/.local/state/claude-airlock/gvisor/pod-init.json"
      ]
    }
  }
}
```

The path of `--pod-init-config` is under your own home, in
`$XDG_STATE_HOME` when that is set. A session started without it says
which path to use.

```
CLAUDE_AIRLOCK_RUNTIME=runsc-hostnet claude-airlock
```

The launcher asks Docker which runtime a session will use, and
recognises gVisor by its program, `runsc`, whatever name it is
registered under. This also works when gVisor is the daemon's default
runtime. At each launch it prints what differs from Docker's own
runtime:

- **`--network=host` is required.** By default gVisor uses its own network
  stack, which cannot reach Docker's resolver. No name resolves, so access
  by name, the egress filter and the socket proxy all fail. With
  `--network=host` gVisor uses the host's network stack instead. The
  session still has its own network namespace. The cost is that the
  network stack of the host's kernel is exposed to the session again. The
  rest of the kernel is not.
- **`--host-uds=open` is required for the SSH agent**, as the agent is
  reached through a socket of the host. Without it, a session that asks
  for the agent is refused.
- **`--pod-init-config` is required to record processes.** A sidecar
  that joins the session sees only gVisor's kernel process, and the
  launcher runs no watcher inside the session. Instead gVisor reports
  what runs (its runtime monitoring) to a socket the launcher listens on
  for the session: each program started, each connection with the
  process that made it, and each secrets file opened. As it is reported,
  not looked for, a process that lives a moment and a file opened and
  closed at once are seen too. gVisor reads the file when a sandbox is
  made, so the launcher writes its session's socket into it and holds it
  until the session runs, other launchers wait meanwhile. What gVisor
  cannot send in time is retried, which slows the session a little, then
  dropped and counted. Without the argument, processes are not recorded.
  The capture, the egress filter and the records of the SSH agent and
  Docker socket work as under Docker's own runtime.
- **Memory and CPU use are still recorded.** The launcher reads them from
  the cgroup of the container, with the time the session waited for
  memory, CPU or disk. The process count, the use of each tmpfs and the
  largest process are not available. This needs the daemon to run on the
  same host and to use cgroup version 2.
- **A session that reaches its memory limit is ended as a whole.** Under
  Docker's own runtime the kernel ends one process. Under gVisor the
  host's kernel sees a single program, gVisor itself.
- **The process limit is an estimate.** The host counts gVisor's own
  threads: a few dozen, plus two to three for each process of the
  session, more for processes that start and end fast. gVisor keeps them
  once a process has ended, so the count only grows, up to what the
  busiest moment of the session took. The launcher gives Docker four
  times `CLAUDE_AIRLOCK_PIDS` plus 128, so a session has room for at
  least as many processes as the setting says. A session that reaches
  that limit is also ended as a whole, with an exit status of 2. The
  launcher says so when the session is over, and `--trace` shows it.
  Raise `CLAUDE_AIRLOCK_PIDS` if that happens to a session that was not
  running away.
- **The session is told.** Nothing in it fails first at a limit, so it
  cannot find out by itself. It is told that it runs on gVisor, and to
  keep its builds and tests to a few jobs (`docker/CLAUDE-airlock.md`).

## How Claude Code is started

- **Without asking.** Claude Code is started with
  `--dangerously-skip-permissions`: the container is what keeps a session
  from the host. `CLAUDE_AIRLOCK_ASK=1` has it ask as it does outside the
  sandbox, and a `--permission-mode` of your own is left alone.
- **On Opus at high effort.** Claude Code is started with `--model=opus`
  and `--effort=high`. `CLAUDE_AIRLOCK_MODEL` and `CLAUDE_AIRLOCK_EFFORT`
  choose others, and an empty value leaves the choice to Claude Code.
  They are passed as arguments because `claude --print`, which
  [line mode](line-mode.md) runs, takes no `effortLevel` from
  `settings.json`. A `--model` or `--effort` of your own is left alone.
- **Without telemetry.** `DISABLE_TELEMETRY=1` and
  `DISABLE_ERROR_REPORTING=1` are set, so it sends no usage events and no
  crash reports. `CLAUDE_AIRLOCK_TELEMETRY=1` sends both. `DO_NOT_TRACK=1`
  is set with them, for the tools a session runs that respect it. The
  image turns off the usage reports of gh and of common frameworks
  (Next.js, Nuxt, Astro and the like) whatever the setting.
- **Without a copy of what it sends.** With `CLAUDE_AIRLOCK_API_LOG=1`
  it is told to write every request to the model and each answer to a
  directory (`OTEL_LOG_RAW_API_BODIES`). The launcher mounts it for that
  session alone and empties it as it goes, see
  [The requests to the model](trace.md#the-requests-to-the-model).
  Nothing of it is sent anywhere, and telemetry stays off.
- **Without the connectors of claude.ai.** `ENABLE_CLAUDEAI_MCP_SERVERS=false`
  is set, so the connectors of your account (Gmail, Google Drive and the
  like) are not loaded. They reach your data from inside the sandbox, and
  their tools and instructions take room in every request.
  `CLAUDE_AIRLOCK_CONNECTORS=1` loads them.

## Statusline

For Claude Code's native UI. The launcher has no statusline of its own
and adds none: the one in your `~/.claude/settings.json` works in the
sandbox as on the host. The file its command runs is mounted read-only
where the settings name it, whether it is the program
(`~/.claude/statusline.sh`) or the script given to an interpreter
(`bash ~/bin/statusline.sh`):

- It has to be a file in your home directory, named by its full path.
  A command the image has (`npx some-statusline`) needs no mount.
- Only that file is mounted. What it runs has to be in the image (bash,
  `jq`, Python and Node.js are), and anything else it reads in a
  directory mounted with `CLAUDE_AIRLOCK_EXTRA_DIRS_RO`.
- It is not mounted, and the launch says so, when:
  - it has the name of a secrets file (`.env`, `.netrc`)
  - it leads into a directory no session is given: `~/.ssh`, `~/.gnupg`,
    the launcher's settings or its records
  - it goes through a link in a directory a session can write, or could
    at an earlier launch, and leads out of it. A script kept in a project
    and linked to from `~/bin` is mounted while it is there, not once a
    session has made it a link to `~/.aws/credentials`.
- Only the statusline of `~/.claude/settings.json` on the host is
  mounted, not one a project's settings name.
- It can show the sandbox from the variables a session is started with,
  `env | grep CLAUDE_AIRLOCK_` in a session lists them: the name of the
  container (not set outside the sandbox), the network mode and the
  doors that are open.

[Line mode](line-mode.md) does not run it. It shows its own status above
its prompt, from what it knows of the session, with the effort, and the
weekly limit of Fable while that is the model.

## The check when a session ends

Some files run commands on the host, or are followed by Claude there. They
have to stay writable for git and claude to work, so they are checked
rather than locked: the launcher warns when a session changed one.

- In the project and every extra directory, for git: `.git/config` with
  the files it includes, and the git hooks. Also those of the directory
  that `.git/commondir` points git to instead of its own, and of each
  working tree made from it (`git worktree add`), whose own `commondir`
  can point elsewhere too.
- There too, for Claude: `.claude/settings.json`, `settings.local.json`
  and `.mcp.json` with the scripts they name (a server's `args` among
  them), and the helpers Claude Code runs (`apiKeyHelper`,
  `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`).
  `CLAUDE.md`, `CLAUDE.local.md` and `AGENTS.md`, with the files they
  have Claude read (`@docs/style.md`). The prompts Claude Code runs by
  itself (`.claude/scheduled_tasks.json`, `.claude/loop.md`). And the
  `hooks`, `commands`, `skills`, `agents`, `rules`, `output-styles`,
  `workflows` and `routines` of `.claude`.
- In `~/.claude`: the plugins, and what `CLAUDE_AIRLOCK_RW_CONFIG=1` made
  writable.
- Your own git config, `~/.gitconfig` and `~/.config/git/config`, with
  the files they include, where a session could write one: it is, or
  leads to, a file of the project or of an extra directory, as dotfiles
  kept in a repository often are. Git on the host runs what it says
  (`core.fsmonitor`, an alias) wherever it is run.

Listed apart, to read before you build, test or commit there:

- What your tools run, anywhere in the project or an extra directory:
  - Makefiles and other build files, `package.json`, `pyproject.toml`,
    `conftest.py`
  - the configuration of a hook manager (`.pre-commit-config.yaml`,
    `.husky`)
  - `.envrc` and the Nix files direnv can evaluate for it (`flake.nix`,
    `shell.nix`)
  - CI workflows, and the yarn release `.yarnrc.yml` runs
    (`.yarn/releases`)
  - what runs when an editor opens a file, with no command typed:
    `.vscode`, `.devcontainer`, `.dir-locals.el`, the ESLint, Prettier
    and Stylelint configs that are code (`eslint.config.js` and its kin)
    and `.cargo/config.toml`

  Names are matched in any case: on macOS make reads `GNUMAKEFILE` as
  `GNUmakefile`.
- Below the top of a project: `CLAUDE.md` and `.claude` of a
  subdirectory, and the config and hooks of a repository there (or one a
  session planted there), with its submodules and the hooks its
  `core.hooksPath` names, as at the top. Also what is left to do of a
  rebase or a cherry-pick: an `exec` line of it runs on
  `git rebase --continue`.

Listed apart too, to read before the next session here:

- What Claude remembers of the project: the `memory` directory next to
  its transcripts in `~/.claude/projects`, and what its agents remember,
  in `.claude/agent-memory` of the project. A session writes there when
  you tell it something to keep, and every later session is given it as
  your own notes. Something a session read could have it leave
  instructions there for the next ones.
- The MCP servers in the config the sandboxed sessions share (the
  `.claude.json` of their `~/.claude`), both those for every project and
  those for each one. A server is a command: one a session added there is
  started by the next session of another project too, in that project's
  sandbox. Only the servers are compared, every session rewrites the rest
  of that file.
- A directory of `~/.claude/projects` that is not the project's own and
  was not there when the session started. A session is kept out of the
  other projects' directories that exist, but can make one for a project
  that has none yet. What it puts there as that project's memory is given
  to that project's next session, and to `claude` on the host too. A
  project first used while the session ran gets one made for it as well,
  so the line says who may have made it.
- The launcher itself, when the session could write its checkout: the
  project is the checkout, holds it, or is mounted next to it. What
  changed in its `bin`, `claude_airlock` and `docker` starts and
  sandboxes the next session, including the egress filter's allowlist and
  the socket proxy's rules. The launch says so too. Not watched: Python's
  compiled modules (`__pycache__`), which change without a session's
  doing. The launcher does not run those either, it keeps what it
  compiles with its own records, where no session writes. Watched too:
  anything at the top of the checkout that Python would take for a module
  or a package, where the launcher finds its own. One with the name of a
  standard library module is not run, as the launcher looks there last.

All of these name a file however it was changed, by a command or an
edit, and only when its content is no longer what it was. Not looked
into: `node_modules`, `.venv`, and the working trees of `--worktree`, each
the whole project again. A directory the check cannot list is named as
one it cannot look into, when a session made it so: make, git and Claude
still find a file in it by its name. A link to a directory is followed
when it leads into the project or an extra directory, so hooks or skills
kept elsewhere in the project, or in a dotfiles repository that is the
project, are watched where git and Claude find them. A link that leads
anywhere else is watched as a link.

The check is bounded, as a session can write any number of files of any
size. It watches at most 5000 files of each watched directory, 1000 of
what Claude remembers of a project, 5000 build files, the submodules of
1000 git directories, 200 working trees of each, 100 files a git config
includes and as many a `CLAUDE.md` has Claude read. It reads at most
1 GB for what git and Claude follow, and as much again for the build
files. Beyond that:

- A git config over 1 MB, or one git lists as more than 4 MB, is compared
  by its content as a file.
- The plugins, thousands of files as they come, are not read: up to
  100 000 of them are compared by when they changed.
- What is past a count shows as `the rest`, unwatched, when a session
  made it so, and so does a watched directory with more entries, or more
  directories below it, than the count. A launch says which are past a
  count already as the session starts. A change there goes unseen, review
  it yourself.
- A file over 64 MB is read that far, and one past the total that is read
  is not read at all. Both are still compared by when they changed.

A session that ends without its launcher, a killed terminal say, is
checked by the next `claude-airlock` launch instead. If that check fails
to run, the launch says so and goes on, and the launch after it tries
again.

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
- On macOS the session gets the agent Docker Desktop exposes, with no
  socket of the launcher's in front of it: its use is not noted, and
  nothing is refused.

**The Docker socket**, with `CLAUDE_AIRLOCK_DOCKER_SOCKET` (and the `docker`
feature for the CLI), through
[docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy):

| Value | Allowed | Hidden |
| --- | --- | --- |
| `1` | `docker ps` and `docker logs` | Everything else, container environments included |
| `full` | The same, and the real `docker inspect`, `docker stats` and `docker top`, with the daemon's `info` and `events` | Nothing of the containers: the environment of every one on the host shows, secrets included |

Writes are blocked in both modes, as a write to the root daemon would let
the container escape. Each mode has its own rules
(`docker/docker-socket-proxy.cfg` and `docker/docker-socket-proxy-full.cfg`)
naming the reads it allows, and whatever they do not name is refused:
`docker attach`, `cp`, `export` and `diff` among them, in `full` too.
Command lines and logs can still carry secrets.

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
- Nothing gets through the proxy to its own loopback (and 0.0.0.0/8,
  which leads there) or its link (169.254.0.0/16, where a cloud keeps a
  machine's credentials), on the list or not.
- With `CLAUDE_AIRLOCK_NET_ASK=1` as well, you can allow a host that is
  not on the list, in [line mode](line-mode.md). The proxy holds the
  request, you are asked, and a yes lets it through. Nothing is looked up
  or sent for the host before that.
  - The question names the port (`example.com on port 443 (https)`). A
    yes is for that host at that port alone, not another port of it nor
    the names under it: a yes to its HTTPS lets no SSH through to it.
  - A yes holds until the session ends, the list is not changed.
  - Only a public DNS name is asked about, never an address or the bare
    name of a container. A yes does not reach a private address the name
    leads to: put a host of your own network on the list.
  - A session not in line mode has nowhere to ask: its filter refuses as
    without this, and says so when it starts. A request made in the first
    moment of a session, before the launcher knows its address, is
    refused too.

## Known limits

The [README](../README.md#known-limits) has the limits that change how
you use the sandbox. The narrower ones:

- `~/.claude/plugins` stays writable, as Claude updates plugins itself,
  so a plugin's hook scripts are not protected the way `settings.json`
  is. A change to them is reported when the session ends, not prevented.
- The MCP servers you set up for every project on the host are not in
  the sandbox: they come with tokens, so the config it starts from leaves
  them out. Add the ones you want from inside a session.
- Some of the history of other projects is still there to read: the
  transcripts of a project first used after the session started, the
  paths of the projects you ran in the sandbox (in its `.claude.json`),
  and what Claude Code keeps per session rather than per project (`jobs`,
  its debug log) of the other sandboxed sessions. Those of the host are
  not there.
- The sandboxed sessions of every project share one `.claude.json`. An
  MCP server a session adds there is started by the next session of
  another project. The launcher says so when the session ends, it does
  not prevent it.
- The filter goes by the name a connection asks the proxy for, and does
  not look into what is then sent over it. A name on the list that is
  served by a network of many sites (npm, PyPI and GitHub's files are)
  leads to that network's addresses, and a session can ask there for
  another site of the same network. Asking for it in the TLS hello is
  flagged in the trace (see
  [What a connection is](trace.md#what-a-connection-is)), asking for it
  inside the encryption is not seen.
- Python runs a project's compiled modules (`__pycache__`) in place of a
  module whose time and size they carry, and no diff shows them. A
  session can leave such a file. The launcher does not run its own from
  there, but your tools still do: remove those directories before you run
  a project's Python on the host after a session you do not trust.
- Claude Code names the directory of a project's transcripts after its
  path, with every character that is not a letter or digit turned into a
  dash. Two projects whose paths differ only in such characters (`my-app`
  and `my_app`) share one, and a session of either reads what the other's
  sessions said and remember.
