# claude-sandbox

Run [Claude Code](https://claude.com/claude-code) inside a hardened Docker
container, with only the current project mounted. Works from any shell, and
from editors that can launch a custom `claude` program.

![The launcher on the host starts the session container, a capture sidecar
and a process sidecar that share one network namespace, the egress proxy,
the Docker socket proxy and the SSH agent are
opt-in](docs/architecture.excalidraw.png)

Contents:

- [Requirements](#requirements), [Install](#install) and [Usage](#usage),
  with the [settings](#settings)
- [What the sandbox does](#what-the-sandbox-does) and its
  [known limits](#known-limits)
- [Reviewing a session](#reviewing-a-session) with `--trace`
- [Line mode](#line-mode), Claude Code without its full-screen UI
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
sandbox, `claude` is started with `--dangerously-skip-permissions`: it does
not ask before it uses a tool. `CLAUDE_DOCKER_ASK=1` has it ask as it does
outside the sandbox, and a `--permission-mode` of your own is left as it
is. See [Known limits](#known-limits) for what a session can reach without
being asked.

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

# Claude Code's full-screen UI in place of line mode, see "Line mode"
CLAUDE_DOCKER_LINE_MODE=0 claude-docker  # or in the config file, for every session
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

- `CLAUDE_DOCKER_ASK=0` (the default)

  If off, Claude Code is started with `--dangerously-skip-permissions` and does not ask before it uses a tool: the container is what keeps a session from the host. If on, it asks as it does outside the sandbox. Not added when you give `--permission-mode` or one of the two flags yourself, nor to a command of claude's (`claude-docker mcp list`)

- `CLAUDE_DOCKER_LINE_MODE=1` (the default)

  If on, a session runs in line mode, Claude Code without its full-screen UI: lines are only ever added, never redrawn, see [Line mode](#line-mode). If off, it runs in Claude Code's full-screen UI, and `claude-docker --line-mode` is one session in line mode

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

What a session is given and kept from: what is mounted and how, what is
read-only or hidden, the hardening of the container, the check of the files
that run code on the host when a session ends, and the opt-in doors (the SSH
agent, the Docker socket). See [docs/sandbox.md](docs/sandbox.md).

## Known limits

The sandbox contains what a session can reach, it does not make a
read-write project safe to trust blindly afterwards. A session is not asked
before it uses a tool unless `CLAUDE_DOCKER_ASK=1`, so all of this it can
do on its own, also when something it read told it to:

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

`claude-docker --trace` shows what the latest session of the project did: what it ran, where and why, what it wrote and what it reached on the network, in the order it happened. `--trace --follow` shows it as it happens. How to read it, the JSON Lines, the network capture, the copy of the transcript and what is kept: [docs/trace.md](docs/trace.md).

## Line mode

A session runs in line mode by default: Claude Code without its
full-screen UI. You get a prompt and, under it, what the session
does in the lines of `--trace`, the network included. Lines are only ever
added, never redrawn, in a terminal, an Emacs shell buffer or a file alike.
`CLAUDE_DOCKER_LINE_MODE=0` gives the full-screen UI back. See
[docs/line-mode.md](docs/line-mode.md).

## The image

The image is assembled from `docker/base.Dockerfile`, the features you pick
and `docker/tail.Dockerfile`. Which features there are, how to add your own,
the language servers and how versions are pinned:
[docs/image.md](docs/image.md).

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

The files are run side by side, as many at a time as there are CPUs, which
`--jobs` changes. A file that takes much longer than the others sets how
long it all takes, so one that grows is better split.

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
setting works inside and outside the sandbox. In [line mode](#line-mode)
the statusline heads the prompt, as a multi-line `PS1` would, and is
refreshed at the end of each turn. That also holds when the
setting names a symlink to the script, it is mounted there as well.

## Editor integration

Point your editor's Claude Code integration at `claude-docker` instead of
`claude`. For Emacs with
[claude-code.el](https://github.com/stevemolitor/claude-code.el):

```elisp
(setq claude-code-program (executable-find "claude-docker"))
```

`CLAUDE_BUFFER_NAME`, which claude-code.el exports, is used to give parallel
sessions on the same project distinct container names.

That buffer runs in [line mode](#line-mode)
in place of Claude Code's full-screen UI. It needs no terminal emulator either:
`claude-docker` run from `M-x shell` works the same, there nothing is ever
written twice.
