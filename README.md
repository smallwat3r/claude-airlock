# claude-sandbox

Run [Claude Code](https://claude.com/claude-code) inside a hardened Docker
container, with only the current project mounted. Works from any shell, and
from editors that can launch a custom `claude` program.

![The launcher on the host starts the session container, a capture sidecar
and a process sidecar that share one network namespace, the egress proxy,
the Docker socket proxy and the SSH agent are opt-in](docs/architecture.excalidraw.png)

Contents:

- [Requirements](#requirements), [Install](#install) and [Usage](#usage),
  with the [settings](#settings)
- [What the sandbox does](#what-the-sandbox-does) and its
  [known limits](#known-limits)
- [Reviewing a session](#reviewing-a-session) with `--trace`
- [The image](#the-image) and its features
- [Tests](#tests), [Statusline](#statusline) and
  [Editor integration](#editor-integration)

## Requirements

- Docker (Linux, or Docker Desktop on macOS)
- Python 3.9 or later for the launcher, standard library only
- bash and `jq` on the host if you use the statusline outside the sandbox

## Install

```
git clone https://github.com/smallwat3r/claude-sandbox.git ~/code/claude-sandbox
export PATH="$HOME/code/claude-sandbox/bin:$PATH"
```

Or leave `PATH` alone and symlink the launcher into a directory already on
it, it finds the rest of the checkout from where it really is:

```
ln -s ~/code/claude-sandbox/bin/claude-docker ~/.local/bin/claude-docker
```

## Usage

```
cd ~/code/my-project
claude-docker                       # builds the image on first use
claude-docker -p "summarise this" < notes.txt   # piped, no TTY needed
```

Any other argument is forwarded to `claude`. Since the container is the
sandbox, it is common to run with `--dangerously-skip-permissions`.

The launcher's own options, `claude-docker --help` lists them with the
settings:

```
# What a session gets
claude-docker --add-dir ~/code/api  # mount a second project read-write
claude-docker --add-dir-ro ~/code/lib   # mount reference code read-only
claude-docker --worktree feature-x  # second session on its own git worktree
claude-docker --shell               # bash in the same sandbox, to look around

# The image, see "The image"
claude-docker --rebuild             # clean image rebuild, then exit
claude-docker --prune               # delete all sandbox images but the current one
claude-docker --dockerfile          # print the generated Dockerfile, then exit

# The egress filter, see "The opt-in doors"
claude-docker --net-log             # domains the egress filter denied
claude-docker --net-reload          # restart the egress filter

# What a session did, see "Reviewing a session"
claude-docker --trace               # what the latest session here did
claude-docker --trace list          # this project's sessions, latest first
claude-docker --trace 3fa9 --verbose > trace.txt   # one session, in detail
claude-docker --trace --json | jq 'select(.what == "net")'   # as JSON Lines
claude-docker --trace --only bash,net   # just the commands and the network
claude-docker --trace --failed      # just what went wrong
claude-docker --trace --follow      # what the sessions here do, as they do it
```

### Settings

All optional, set in the environment. The on and off switches are shown at
their default, the others with an example value:

- `CLAUDE_DOCKER_EXTRA_DIRS=a:b` (default: none)

  Extra directories to mount, same as repeated `--add-dir`

- `CLAUDE_DOCKER_EXTRA_DIRS_RO=a:b` (default: none)

  The same read-only, as repeated `--add-dir-ro`

- `CLAUDE_DOCKER_FEATURES="go typst"` (default: `features.txt`, else every feature)

  Tools to build into the image, see [The image](#the-image)

- `CLAUDE_DOCKER_NET_FILTER=0` (the default)

  If on, egress goes through a proxy that only allows the domains in `docker/allowed-domains.txt`, and only HTTP, HTTPS and git over SSH get out. If off, the network is open

- `CLAUDE_DOCKER_NET_LOG=1` (the default)

  If on, records every TCP connection the session opens, what it sends by anything else (UDP, a ping) and every name it looks up, over IPv4 and IPv6, shown by `--trace`, see [Reviewing a session](#reviewing-a-session). If off, nothing is captured, and `--trace` only has the network use of a filtered session, from the proxy's log

- `CLAUDE_DOCKER_PROC_LOG=1` (the default)

  If on, records the processes that run in the session and which of them made each connection, shown by `--trace`. If off, a connection is only known by the tool call that ran at its time

- `CLAUDE_DOCKER_TELEMETRY=0` (the default)

  If off, Claude Code is started with `DISABLE_TELEMETRY=1` and `DISABLE_ERROR_REPORTING=1`: it sends no usage events and no crash reports, which otherwise go out in the background, to Datadog among others. Sessions work the same, though features Anthropic rolls out gradually may stay at their defaults. If on, it sends both as it does outside the sandbox

- `CLAUDE_DOCKER_SSH_AGENT=0` (the default)

  If on, forwards your SSH agent, so git over SSH and `ssh` work with your keys. If off, the session has no SSH keys

- `CLAUDE_DOCKER_SOCKET=0` (the default)

  If `1`, `docker ps` and `docker logs` work against the host daemon, `full` adds `inspect`, `stats` and `top`. If off, the session cannot reach Docker at all

- `CLAUDE_DOCKER_RW_CONFIG=0` (the default)

  If on, `~/.claude/settings.json`, `CLAUDE.md`, `hooks`, `commands`, `skills`, `agents` and `rules` are writable from the session. If off, they are read-only there, and the ones you do not have are made empty so that a session cannot create them

- `CLAUDE_DOCKER_SHARED_HISTORY=0` (the default)

  If off, a session sees what Claude Code remembers of its own project alone: the transcripts, prompt history, pastes and file history of other projects are left out. If on, it sees those of every project

- `CLAUDE_DOCKER_SHADOW="*.pem:.npmrc"` (default: none)

  Extra file name globs to hide, on top of the `.env` family. What the config file names and what the environment names both count

- `CLAUDE_DOCKER_PROTECT="~/claude-shared/kit:docs"` (default: none)

  Paths that are read-only in every session that has them mounted, inside the project or a directory mounted next to it. What the config file names and what the environment names both count

- `CLAUDE_DOCKER_MEMORY=32g` (default: `16g`)

  Container memory limit

- `CLAUDE_DOCKER_PIDS=1024` (default: `512`)

  Container process limit

- `CLAUDE_DOCKER_CACHE=1` (the default)

  If on, `~/.cache` is a per-project volume that persists between sessions. If off, it is a 2g tmpfs that is gone when the session ends

- `CLAUDE_DOCKER_SHARED_DIR=~/scratch` (default: `~/claude-shared` if it exists)

  Scratch directory shared between sessions, empty for none

- `CLAUDE_DOCKER_RUNTIME=runsc` (default: Docker's own)

  Container runtime, e.g. gVisor, must be installed in Docker

- `ANTHROPIC_API_KEY`, `GH_TOKEN` (default: unset)

  Passed through when set, `GH_TOKEN` is how `gh` logs in

The on and off switches take `1` for on and `0` for off
(`CLAUDE_DOCKER_SOCKET` also `full`). Any other value, such as `true`, stops the launcher instead of
quietly leaving a restriction off.

### The config file

To change a default for every session, put the same variables in
`~/.config/claude-sandbox/config`, one per line. The environment still wins,
so a single session can override the file:

```
# ~/.config/claude-sandbox/config
CLAUDE_DOCKER_MEMORY=8g
CLAUDE_DOCKER_NET_FILTER=1
CLAUDE_DOCKER_SHARED_DIR=/home/me/scratch
```

Values are taken literally, without quotes or `~` expansion, and an unknown
name stops the launcher instead of being ignored. The file is only read from
your config directory, never from the project, which the session can write to.
`CLAUDE_DOCKER_EXTRA_DIRS` and `CLAUDE_DOCKER_EXTRA_DIRS_RO` are not accepted
there, extra directories belong to one project, not to every session.
A switch or a limit that is set but empty in the environment says nothing,
the file is asked next: an empty variable does not switch off what the file
switched on.

`~/claude-shared` is always mounted when it exists, as a scratch directory
shared between sessions. `CLAUDE_DOCKER_SHARED_DIR` names another directory,
or none when set empty.

## What the sandbox does

### Mounts

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

### What is read-only or hidden

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
  `.env.example` stay readable, `CLAUDE_DOCKER_SHADOW` hides more.
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

### Hardening

- Runs as your user, with a read-only root filesystem, all capabilities
  dropped, `no-new-privileges`, and PID and memory limits.
- Writable space is the mounts, the cache volume and a few size-capped
  tmpfs (`/tmp`, `~/.npm`, `~/.config`).
- Containers still share the host kernel. `CLAUDE_DOCKER_RUNTIME=runsc`
  runs the session under gVisor if you have it.

### The check when a session ends

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

### The opt-in doors

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

## Known limits

The sandbox contains what a session can reach, it does not make a
read-write project safe to trust blindly afterwards:

- Anything in the project can be changed, including files that run code on
  the host later. The launcher warns about git's and Claude's own (see
  above). The rest is for you to review in the diff before running things
  outside the sandbox: Makefiles, build files, package scripts, the
  configuration of a hook manager such as pre-commit, a `CLAUDE.md` below
  the top of the project, and a repository planted in a subdirectory.
- `~/.claude/plugins` stays writable, Claude updates plugins itself, so a
  plugin's hook scripts are not protected the way `settings.json` is. A
  change to them is reported when the session ends, not prevented.
- With the network open, a session reaches whatever the host listens on,
  like the rest of your network. Only the egress filter keeps it off.
- The MCP servers you set up for every project on the host are not in the
  sandbox: the config it starts from leaves them out, they come with
  tokens. Add the ones you want there from inside a session.
- Of the history of other projects, some is still there to read: the
  transcripts of a project first used after the session started, the paths
  of the projects you ran in the sandbox (in its `.claude.json`), and what
  Claude Code keeps by session rather than by project (`jobs`, its debug
  log) of the other sandboxed sessions. Those of the host are not there.
- The login is in the sandbox, a session can read it and use it elsewhere.
- The egress allowlist includes GitHub, so with a forwarded SSH agent or a
  `GH_TOKEN` a session can still push data out to a repository or gist.
- Secrets that are not in a shadowed file (hard-coded, or in git history)
  are readable.

## Reviewing a session

`claude-docker --trace` shows what the latest session of the current project
did: what it ran, where and why, what it wrote and what it reached on the
network, in the order it happened.

```
# session     3fa9c0de-...  Fix the build
# transcript  as the launcher copied it (212 lines)
# project     /home/me/code/api
# permissions bypassPermissions
# tool calls  12 (Bash 9, Edit 2, Read 1)
# failed      1
# files written
#   /home/me/code/api/Makefile x2
# network
#   captured in claude-api from 10:02:11 to 10:31:40
#   tcp/https registry.npmjs.org (104.16.3.35):443 x4
#   tcp/postgres 10.0.0.7:5432 x1
#
# time                 who      what        details
2026-01-02 10:02:30  user     prompt      fix the build
2026-01-02 10:02:41  claude   bash        $ npm ci
2026-01-02 10:02:41  claude   bash        why: Install the dependencies
2026-01-02 10:02:41  claude   bash        result: ok, 8.2s, 14 lines out
2026-01-02 10:02:42  sandbox  net         tcp/https registry.npmjs.org (104.16.3.35):443  x4
2026-01-02 10:03:05  claude   edit        file: /home/me/code/api/Makefile
2026-01-02 10:03:05  claude   edit        diff: -	go build ./..
2026-01-02 10:03:05  claude   edit        diff: +	go build ./...
2026-01-02 10:03:05  claude   edit        result: ok, 0.0s, 1 line out
```

That is how it looks in a file or a pipe: plain text, every line starting
with when, who and what, so any line `grep` finds says it all. On a
terminal an event says so once, and its other lines are indented under it:

```
# time      who      what        details
# day         2026-01-02
10:02:30  user     prompt      fix the build
10:02:41  claude   bash        $ npm ci
                               why: Install the dependencies
                               result: ok, 8.2s, 14 lines out
10:02:42  sandbox  net         tcp/https registry.npmjs.org (104.16.3.35):443  x4
```

### Options

| Option | Shows |
| --- | --- |
| `list` | The project's sessions with when each last did something, the latest first |
| `3fa9` | The session whose id starts so, instead of the latest |
| `--verbose` | Commands, diffs and replies whole, the output of every call, each step of the model, lookup and process |
| `--only bash,net` | The events of the kinds named, by what the `what` column says |
| `--failed` | What went wrong, see below |
| `--json` | JSON Lines, see [As JSON](#as-json) |
| `--follow` | The sessions as they run, see [Following a session](#following-a-session) |

- `--failed` picks: a failed call, a write outside the project, a refused
  request, a connection that was refused or not answered, a lookup that
  stands out, a signature the SSH agent refused, and what was taken out of
  the transcript.
- `--only` and `--failed` work with `--json` and `--follow`. The header
  stays that of the whole session, and says what is shown.
- On a terminal the result goes through your pager.
- Sessions run outside the sandbox in the same directory are listed too,
  Claude Code keeps them in the same place.

### Reading the lines

| Column | Values |
| --- | --- |
| `who` | `user`, `claude`, `agent` (a subagent), or `sandbox`: what the launcher recorded of the container from outside, not what the transcript says |
| `what` | `prompt`, `reply`, `step`, the tool (`bash`, `edit`, `write`, `read`, ...), `net`, `dns`, `exec`, `ssh-agent` or `docker` |

- A tool of an MCP server shows by its own name without the server's. A
  name longer than the column is cut (`notebooke~`), `--json` has it whole.
- A command comes with the reason Claude gave for it (`why:`), its working
  directory when that is not the project (`cwd:`), how it ended and how
  many lines it put out.
- What went wrong is in capitals: `FAILED` for a call, `OUTSIDE PROJECT`
  for a file written there, `DENIED` for a request the egress filter
  refused.
- Long commands, diffs and replies are cut to a few lines. What a command
  feeds to another through a here-document (`python3 - <<'EOF'`) is said to
  be so many lines.
- The output of a call is shown when it failed: its first 2 lines and its
  last 6, the end is where a command says what went wrong. `--verbose`
  shows the first and last 10 lines of every call, never all: one `cat`
  can put out thousands.
- The same thing on the network several times in a row is one line with
  how often (`x4`). Claude Code's own connections come by the dozen and
  would bury the one a command made.

With `--verbose`, a `step` line comes ahead of what one answer of the model
did, and says what that answer used:

```
claude   step        1.4k tokens out (300 thinking), 182.0k in (2.0k new)
```

- Out is what the model wrote.
- In is what it read, the whole conversation so far.
- New is the part added since the step before: the results of the calls
  before it, and your prompt.
- The API counts by step, not by tool call, so calls issued together share
  one line. The header sums the steps up (`tokens`).

The colours on a terminal make what the session did out of your sight stand
out:

| Colour | What |
| --- | --- |
| Yellow | Commands |
| Magenta | Files it wrote |
| Cyan | The network |
| Blue | Pages it fetched or searched for with its tools |
| Bold red | What went wrong |
| Dimmed | The conversation, which you saw anyway |

A file or a pipe gets plain text. `NO_COLOR=1` switches the colours off and
`FORCE_COLOR=1` on wherever the output goes, for an Emacs shell buffer say.

### As JSON

`--json` gives the same events as JSON Lines, one object each, nothing
shortened, for `jq` or to load into a database:

```
{"session": "3fa9c0de-...", "time": "2026-01-02T10:02:41.120+01:00", "who": "claude", "what": "bash", "tool": "Bash", "input": {"command": "npm ci", "description": "Install the dependencies"}, "cwd": "/home/me/code/api", "failed": false, "output": "...", "seconds": 8.2}
{"session": "3fa9c0de-...", "time": "2026-01-02T10:02:42.480+01:00", "who": "sandbox", "what": "net", "protocol": "tcp/https", "name": "registry.npmjs.org", "address": "104.16.3.35", "port": 443}
```

Every object has `session`, `time`, `who` and `what`, then:

| Event | Fields |
| --- | --- |
| Prompt, reply | `text` |
| Step | `output_tokens`, `thinking_tokens`, `input_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`, as the API names them. The three input counts add up to what the step read |
| Tool call | `tool`, `id`, `input`, `cwd`, `failed`, `seconds`, `output`, and `outside_project` for a file it wrote |
| Connection | `protocol`, `address`, `port`, `source_port`, `name`. When the capture tells, `outcome` (`closed`, `open`, `refused` or `no answer`), and for a closed one `seconds`, `bytes_out`, `bytes_in`. When its process was seen, `process` (`pid`, `exe`, `argv`, `parents`) |
| Sent by another protocol | `protocol`, `address`, `port`, `name`, `packets`, `bytes_out` |
| Plain HTTP request | `protocol`, `method`, `url`, `address`, `port` |
| Proxy request | `protocol`, `method`, `url`, `port`, `denied`, `bytes`, `seconds` |
| Lookup | `name`, `type`, `addresses`, `error`, and `flagged` when it stands out |
| Process | `pid`, `ppid`, `exe`, `argv` |
| SSH agent | `did` (`sign`, `list` or `other`), `key`, `comment`, `what` |
| Docker socket | `method`, `path`, `status`, `denied` |

What happened on the network also has `during`, the ids of the tool calls
running at that time. An entry that was taken out of the transcript has
`removed`.

### The network

The network lines come from two records the launcher keeps. The session
cannot forge or edit either, both are taken outside of it.

| Record | Kept when | Holds |
| --- | --- | --- |
| The egress proxy's log | `CLAUDE_DOCKER_NET_FILTER=1` | What the session asked the proxy for: method, host, allowed or `DENIED`, bytes and duration. HTTPS shows as the host, not the URL |
| The capture | Unless `CLAUDE_DOCKER_NET_LOG=0` | Every TCP connection whatever the protocol, what was sent by anything but TCP, and every name looked up. Over IPv4 and IPv6 |

The proxy's log is shared by all sessions, so the launcher notes the address
each session's container had and picks its requests by that.

How the capture works:

- The session's route out is not changed. A sidecar that owns its network
  namespace captures the packets that say where a connection goes and how
  it went: its start, the answer to it and its end, the DNS answers, the
  TLS hello and the request line of plain HTTP.
- Of what goes out by UDP or another protocol every packet is taken, there
  a conversation has no start to pick out. It is read for where it went and
  how long it was.
- It works with the filter too, where it shows what a session tried to
  reach around the proxy.
- The name of a destination comes from the DNS answers and the TLS hello,
  a connection to a bare address shows as the address. The address is what
  was reached, the name is what the session looked up or asked for: trust
  the address where the two matter.
- Not recorded: what was sent, so of HTTPS neither the URL nor the content,
  and what comes in other than by TCP or as an answer of the resolver.

A line of the network says more than where to:

```
sandbox  net         tcp/https registry.npmjs.org (104.16.3.35):443  closed after 8.1s, 2 kB out, 41 MB in  during: $ npm ci
sandbox  net         tcp/postgres 10.0.0.7:5432  REFUSED  during: $ make test
sandbox  net         http GET http://deb.debian.org/debian/InRelease  during: $ apt-get update
sandbox  net         tcp/https api.anthropic.com (160.79.104.10):443  left open  (no call running)
sandbox  net         udp/https www.google.com (142.250.74.4):443  212 packets, 31 kB out
sandbox  net         icmp 10.0.0.7  3 packets, 252 B out
sandbox  dns         lookup registry.npmjs.org A -> 104.16.3.35, 104.16.0.35
sandbox  dns         lookup nope.internal A FAILED: no such name
sandbox  dns         lookup 4a6f...3d.x.example.com TXT FLAGGED: an unusually long name
```

| On the line | Means |
| --- | --- |
| `closed after` | How long the connection was open, with the bytes each way. From its sequence numbers, nothing of what was sent is kept |
| `left open` | The capture ended before the connection did |
| `REFUSED`, `NO ANSWER` | The other end refused, or the first attempt had to be sent again |
| `during:` | The tool call that was running when the connection was made, the innermost of several. By the clock, not proof |
| `(no call running)` | Claude Code itself (the API, its telemetry), or something a command left running |
| `by:` | The process that made the connection and those it comes from, see [What ran](#what-ran). Not by the clock: it was seen to hold the socket |
| `udp/...`, `icmp` | What went out by another protocol than TCP, one line per destination at the time of the first packet. QUIC shows as `udp/https` |
| `http GET ...` | A request over plain HTTP, the one kind that can be read |
| `lookup` | The kind of record asked for and the addresses that came back, or what the resolver said went wrong. With `--verbose` |
| `FLAGGED` | A lookup that stands out, shown without `--verbose` |

A lookup is flagged when its name is longer than names are (over 100
characters, or 40 in one label), or when it is the 30th different name
under one parent. Data can be carried out in the names a session asks a
resolver for, which takes long names or many of them. Some services do
this on their own, it is a prompt to look.

### The transcript

The transcript is written from inside the sandbox, a session could rewrite
its own. So while a session runs, the launcher copies what the project's
transcripts gain to its state directory, half a second or so after it is
written, and `--trace` compares the two. The `transcript` line of the
header says what came of it:

```
# transcript  as the launcher copied it (212 lines)
# transcript  CHANGED: 3 lines the launcher copied are gone or altered, they are shown as REMOVED
# transcript  as it is now, the launcher has no copy of it to compare
```

- What the copy has and the transcript no longer does is shown where it
  happened, marked `REMOVED FROM THE TRANSCRIPT`. `--failed` picks it out.
- The last line is that of a session run outside the sandbox, or before
  copies were kept.
- Still out of reach: a line a session takes back within the moment before
  it is copied.

### What ran

The transcript says what a tool call was, not what the command it ran went
on to do. Unless `CLAUDE_DOCKER_PROC_LOG=0`, a second sidecar joins the
session's process and network namespaces and notes, from `/proc`, each
process it sees and the processes that hold each TCP connection. `--trace`
ties a connection of the capture to its process by its ports:

```
sandbox  net   tcp/https example.com (93.184.215.14):443  closed after 0.2s, 1 kB out, 2 kB in  by: [812] curl -sS https://example.com < bash < claude  during: $ make deploy
```

With `--verbose` every process is a line of its own (`exec`), with its
program and its parent. The program is named as it really is (`exe`), what
a process calls itself is its own to choose.

What to know about the sidecar:

- It looks 25 times a second, it is not told: nothing short of privileges
  it should not have reports every start of a process. What lived shorter
  than that can be missed, and a connection without a `by:` falls back on
  `during:`.
- It comes up a moment after the session.
- It does not tie what goes out by UDP to a process.
- It runs as root without capabilities, so the session can neither stop it
  nor reach its record.
- It costs a few percent of one core.

### The SSH agent and the Docker socket

A session started with `CLAUDE_DOCKER_SSH_AGENT=1` or `CLAUDE_DOCKER_SOCKET`
has each use of them noted by the launcher:

```
sandbox  ssh-agent   listed the keys, 2 of them
sandbox  ssh-agent   signed a login as git with SHA256:Xk3... (me@laptop)
sandbox  ssh-agent   asked for a signature for git with SHA256:Xk3... (me@laptop)  REFUSED by the agent
sandbox  docker      GET /v1.47/containers/json 200
sandbox  docker      POST /v1.47/containers/create 403  DENIED
```

A signature says which key was asked and what for, as far as what was
signed tells: a login says as whom, to which host is the connection next
to it. The header counts both.

### When a session ends

The launcher says what is worth a look, next to its check of the files
that can run commands on the host:

```
claude-docker: of this session, claude-docker --trace has the rest:
  reached for the first time from this project:
    tcp/https transfer.example (203.0.113.9):443
  sent 14 MB to tcp/https gist.github.com (140.82.121.4):443
  refused by the egress filter:
    example.org:443 x3
  lookups that stand out:
    4a6f...3d.x.example.com: an unusually long name
  written outside the project:
    /home/me/.bashrc
  the transcript of 3fa9c0de was changed: 3 lines the launcher copied are gone or altered
  ssh agent 4 requests, 2 signatures
```

- It is silent when there is nothing of this, and about the first recorded
  session of a project, whose destinations are all new.
- A destination is known by its name where it has one, addresses change
  too often to go by. The name is the session's own word: a session that
  wants to pass for a known name can, the trace has the address.
- An upload is said from 10 MB to one destination on. Not for the model's
  API, told by Anthropic's published addresses and not by name. And not
  for a filtered session, where everything goes to the proxy.

### What is kept

All of it under `~/.local/state/claude-sandbox`, but for the proxy's log:

| What | Holds | How much |
| --- | --- | --- |
| `claude-egress-log`, a Docker volume | The proxy's log, which so survives a proxy restart | Rotated past 10 MB when a filtered session starts, one rotated file kept, about 20 MB at most |
| `captures` | The capture of each session | A few kB each as a rule, the latest 100. One stops at 100,000 packets, about 100 MB at the very worst, and the trace says so |
| `net-sessions.jsonl` | A line per recorded session | The latest 1000 |
| `transcripts` | The launcher's copy of each transcript a sandboxed session wrote to | For 30 days, as long as Claude Code keeps its own by default. As large as the transcripts are, each up to 512 MB |
| `processes` | What ran in each session | A few hundred kB each as a rule and 20 MB at most, the latest 100 |
| `door-use.jsonl` | A line per use of the SSH agent and the Docker socket | The latest 5000 |
| `destinations.json` | What each project is known to reach | 2000 destinations per project |
| `names`, `proxies`, `sidecars.lock` | Not records: what the running launchers hold a lock on, so that two do not take the same container name, start the same proxy at once or remove one another still uses | Empty files |
| `agents`, `pending-checks`, `login-synced` | Not records: the sockets in front of the SSH agent, where each running session started from for the check when it ends, and the login the host and the sandbox last had in common | A few small files |
| `history` | Not a record: what the sessions of each project remember, see [What is read-only or hidden](#what-is-read-only-or-hidden). The one part mounted into a session | As much as Claude Code writes |

- `docker volume rm claude-egress-log` (with the proxy removed) clears the
  proxy's log.
- A capture and a record of processes are copied out when the launcher
  returns. A launcher that is told to end (a killed Emacs buffer, a closed
  terminal, `kill`) stops its session first and then returns as after any
  session. The sidecars of a session that ended without it (`kill -9`, a
  crash) are collected by the next `claude-docker` launch.

### Following a session

`claude-docker --trace --follow`, run on the host in a second terminal, shows
the same lines while the sessions of the project run, until you interrupt
it:

```
# following   /home/me/code/api, until interrupted
# time                 who      what        details
# network     following the capture of claude-api
# 41 earlier events, see claude-docker --trace
# session     3fa9c0de-...  Fix the build
2026-01-02 10:02:41  claude   bash        [7] $ npm ci
2026-01-02 10:02:41  claude   bash        why: Install the dependencies
2026-01-02 10:02:42  sandbox  net         tcp/https registry.npmjs.org (104.16.3.35):443  during: [7] $ npm ci
2026-01-02 10:02:49  claude   bash        [7] result: ok, 8.2s, 14 lines out
```

It needs nothing from the session and changes nothing about it, so it can be
started and stopped at any time, before the session too.

Which sessions:

- It starts with the last 10 events of the latest session, then follows
  every session of the project that does something. One you start, resume
  or clear later is picked up, and a `# session` line says whose lines
  come next.
- The start of a session id follows that session alone.

What differs from the trace of a session that is over:

- A tool call shows when it is issued, and its result on a line of its own
  when that comes. The two have the same number (`[7]`), which tells apart
  the results of calls that ran together.
- When something else came between the two, the result also names its call
  (`of: $ npm ci`). Always so with `--only` or `--failed`, where the call
  itself may not be shown.
- A connection shows with the name known when it was made, and what became
  of it on a line of its own when it does.
- A tunnel through the proxy is logged when it closes, so it shows then, at
  the time it began. A refused request shows at once.
- The uses of the SSH agent and of the Docker socket show as they are
  noted. Which process made a connection does not, `--trace` tells that
  once the session is over.
- Of a prompt or a reply only the first line is shown, with `--verbose`
  too: you are after what the session does, what it says is on its own
  screen.

`--verbose`, `--json`, `--only` and `--failed` work as above. With `--json`:

- A prompt or reply is there whole.
- A call and its result are two objects that share an `id`, with `stage`
  set to `call` or `result`.
- A connection has `stage` set to `open`, then `outcome`, and carries the
  id of the session that wrote last.

```
claude-docker --trace --follow --json | jq -c 'select(.denied or .failed)'
```

## The image

The image is assembled from the parts in `docker/`: `base.Dockerfile`
(Claude Code's needs plus git, gh, Python with uv, Node.js and a C
toolchain), the features you select, then `tail.Dockerfile`.

### Features

Each feature is one plain Dockerfile fragment in `docker/features/`, some
with a directory of the same name holding files the fragment copies in:

| Feature | Adds |
| --- | --- |
| `ble` | tshark and scapy, for offline analysis of BLE captures |
| `cad` | OpenSCAD, admesh |
| `cpp` | cmake, clangd |
| `docker` | Docker CLI, for `CLAUDE_DOCKER_SOCKET` |
| `docs` | pandoc, poppler-utils, qpdf, gnuplot |
| `excalidraw` | `excalidraw-export`, renders an [Excalidraw](https://excalidraw.com) scene to PNG or SVG offline, and takes the scene back out of one. Brings in `playwright` for its headless Chromium |
| `font` | fontforge, fonttools, ttfautohint, woff2, fontconfig and the Ocrab font |
| `go` | Go, gopls |
| `kicad` | KiCad 9 with `kicad-cli` |
| `loadtest` | wrk, hey, for HTTP load testing |
| `media` | ffmpeg, ImageMagick, webp |
| `playwright` | Playwright (Python) with headless Chromium |
| `python` | mypy, ruff, black, pytest, ipython, pyright (Python 3 and uv are already in the base) |
| `reverse` | gdb-multiarch, binutils-multiarch, strace, ltrace (not on arm64), binwalk and the Python capstone, lief, pyelftools libraries |
| `rosbag` | mcap CLI, sqlite3 CLI and the Python rosbag libraries |
| `shell` | shellcheck, shfmt |
| `typescript` | typescript-language-server, `tsc` |
| `typst` | Typst |

With no selection every feature is built, which is large. Select a subset
either way, the environment variable wins:

```
export CLAUDE_DOCKER_FEATURES="go typst"       # empty string for none

mkdir -p ~/.config/claude-sandbox
printf 'go\ntypst\n' > ~/.config/claude-sandbox/features.txt
```

### A feature of your own

Drop a fragment into `~/.config/claude-sandbox/features/NAME.Dockerfile`.
It runs as root after the base, so `apt-get install` and friends work, and
a same-named file there overrides a bundled feature:

```dockerfile
# claude-feat: sqlite
# claude-feat-md: sqlite3 CLI
RUN apt-get update \
    && apt-get install -y --no-install-recommends sqlite3 \
    && rm -rf /var/lib/apt/lists/*
```

What the comment lines of a fragment say:

| Line | Says |
| --- | --- |
| `# claude-feat: NAME` | The feature, for whoever reads the fragment. Its name is that of the file |
| `# claude-feat-md: ...` | What it adds. Baked into the image as system-level memory, so Claude always knows exactly what is installed |
| `# claude-feat-requires: other` | A feature it needs, selecting the first then builds both |
| `# claude-feat-lsp: ...` | A language server it installs, as the `lspServers` of a Claude Code plugin (see `docker/features/go.Dockerfile`) |

- A fragment that needs files finds those of a `NAME` directory next to it
  in the build context, as `COPY NAME/file ...`.
- The `claude-feat-md` lines were written `# claude:` before. The launcher
  stops at a fragment that still has one and says so.

### Language servers

The launcher makes one plugin of the `claude-feat-lsp` lines, builds it
into the image and starts `claude` with it. So a session has
go-to-definition and find-references for the languages of its image
without a plugin being enabled on the host.

- The `python`, `go`, `cpp` and `typescript` features have one.
- If the host enables the official plugin for the same server as well
  (`gopls-lsp`, `clangd-lsp`, `typescript-lsp`, `pyright-lsp`), the sandbox
  does not need it.

### Rebuilds and pins

- The image tag is a hash of the generated Dockerfile. Changing the
  selection or editing a part rebuilds on the next start, reusing cached
  layers, and each feature set keeps its own image.
- Old images pile up, several GB each. `claude-docker --prune` removes
  them all but the one your settings ask for now, and any a container
  still uses. Another feature set's image is built again from the layer
  cache when it is next asked for. The build cache itself is docker's:
  `docker builder prune`.
- Images, downloads and Python packages are pinned by digest, checksum or
  version. Debian packages follow the pinned base image.
- Claude Code's auto-updater is off, so upgrading means refreshing the
  pins, your own fragments and the two sidecar images included:

```
docker/update-pins.py
```

## Tests

`test/launcher_test.py` checks the launcher's security-relevant behaviour
without needing Docker: what gets mounted, shadowed and switched off by
default, the tamper check, the network capture, the records the launcher
keeps of a session and `--trace`. It runs the
launcher against a fake `docker` that records every call. CI runs it on
Python 3.9 and the latest, together with ruff, mypy, shellcheck and a small
image build.

The checks are in `test/test_*.py`, by topic, with what they share in
`test/harness.py`. They need nothing but Python: `test/launcher_test.py`
runs them all, `test/launcher_test.py -k trace` those with trace in their
name, and each file runs on its own. `pytest test` works too if you have
it.

The `Makefile` has a shortcut for each of these and for the upkeep of the
image, `make` lists them:

```
make check          # ruff, shellcheck, mypy and the tests, as CI runs them
make test K=trace   # the tests with trace in their name
make smoke          # test/smoke-test.sh
make upgrade        # refresh the pins, then rebuild the image
```

`test/smoke-test.sh` is the end-to-end check, run by hand on the host against
a real Docker daemon. It replaces the sidecars, then starts open, filtered
and socket-proxy sessions in a throwaway project and checks the sandbox from
the inside. Run it after changing the launcher, the Dockerfile parts or the
sidecar configuration, or after moving the checkout.

## Statusline

`bin/claude-statusline` shows the model, the 5h and 7d usage limits, and
inside the sandbox the container name, network mode, the opt-in doors that
are open (SSH agent, Docker socket, writable settings) and extra mounts. Enable
it in `~/.claude/settings.json`:

```json
{
  "statusLine": {
    "type": "command",
    "command": "~/code/claude-sandbox/bin/claude-statusline"
  }
}
```

The script is mounted into the container at its host path, so the same
setting works inside and outside the sandbox. That also holds when the
setting names a symlink to the script, it is mounted there as well.

## Editor integration

Point your editor's Claude Code integration at `claude-docker` instead of
`claude`. For Emacs with
[claude-code.el](https://github.com/stevemolitor/claude-code.el):

```elisp
(setq claude-code-program (executable-find "claude-docker")
      claude-code-program-switches '("--dangerously-skip-permissions"))
```

`CLAUDE_BUFFER_NAME`, which claude-code.el exports, is used to give parallel
sessions on the same project distinct container names.
