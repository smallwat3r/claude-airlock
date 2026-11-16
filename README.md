# claude-sandbox

Run [Claude Code](https://claude.com/claude-code) inside a hardened Docker
container, with only the current project mounted. Works from any shell, and
from editors that can launch a custom `claude` program.

![The launcher on the host starts the session container and a capture
sidecar that share one network namespace, the egress proxy and the Docker
socket proxy are opt-in](docs/architecture.excalidraw.png)

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
claude-docker --add-dir ~/code/api  # mount a second project read-write
claude-docker --add-dir-ro ~/code/lib   # mount reference code read-only
claude-docker --worktree feature-x  # second session on its own git worktree
claude-docker --rebuild             # clean image rebuild, then exit
claude-docker --dockerfile          # print the generated Dockerfile, then exit
claude-docker --shell               # bash in the same sandbox, to look around
claude-docker --net-log             # domains the egress filter denied
claude-docker --net-reload          # restart the egress filter
claude-docker --trace               # what the latest session here did
claude-docker --trace list          # this project's sessions, latest first
claude-docker --trace 3fa9 --full > trace.txt   # one session, in full
claude-docker --trace --json | jq 'select(.what == "net")'   # as JSON Lines
claude-docker -p "summarise this" < notes.txt   # piped, no TTY needed
```

Any other argument is forwarded to `claude`. Since the container is the
sandbox, it is common to run with `--dangerously-skip-permissions`.

The settings, each shown with an example value:

- `CLAUDE_DOCKER_EXTRA_DIRS=a:b` (default: none)

  Extra directories to mount, same as repeated `--add-dir`

- `CLAUDE_DOCKER_EXTRA_DIRS_RO=a:b` (default: none)

  The same read-only, as repeated `--add-dir-ro`

- `CLAUDE_DOCKER_FEATURES="go typst"` (default: `features.txt`, else every feature)

  Tools to build into the image, see [The image](#the-image)

- `CLAUDE_DOCKER_NET_FILTER=1` (default: `0`)

  If on, egress goes through a proxy that only allows the domains in `docker/allowed-domains.txt`, and only HTTP, HTTPS and git over SSH get out

- `CLAUDE_DOCKER_NET_LOG=0` (default: `1`)

  If on, records every TCP connection the session opens and every name it looks up, shown by `--trace`, see [Reviewing a session](#reviewing-a-session)

- `CLAUDE_DOCKER_SSH_AGENT=1` (default: `0`)

  If on, forwards your SSH agent, so git over SSH and `ssh` work with your keys. If off, the session has no SSH keys

- `CLAUDE_DOCKER_SOCKET=1` (default: `0`)

  If on, `docker ps` and `docker logs` work against the host daemon, `full` adds `inspect`, `stats` and `top`. If off, the session cannot reach Docker at all

- `CLAUDE_DOCKER_RW_CONFIG=1` (default: `0`)

  If on, `~/.claude/settings.json`, `hooks`, `CLAUDE.md`, `skills` and `agents` are writable from the session. If off, they are read-only there

- `CLAUDE_DOCKER_SHADOW="*.pem:.npmrc"` (default: none)

  Extra file name globs to hide, on top of the `.env` family

- `CLAUDE_DOCKER_MEMORY=32g` (default: `16g`)

  Container memory limit

- `CLAUDE_DOCKER_PIDS=1024` (default: `512`)

  Container process limit

- `CLAUDE_DOCKER_CACHE=0` (default: `1`)

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

`~/claude-shared` is always mounted when it exists, as a scratch directory
shared between sessions. `CLAUDE_DOCKER_SHARED_DIR` names another directory,
or none when set empty.

## What the sandbox does

- Mounts the project directory (and any extra directories) read-write at
  their host paths, plus `~/.claude` so login, settings and history persist.
  `~/.claude/settings.json` and `~/.claude/hooks` are read-only on top: they
  hold commands your host `claude` runs, so a session must not be able to
  plant one. `~/.claude/CLAUDE.md`, `skills` and `agents` are read-only too,
  they are instructions every later session follows. None of these can be
  changed inside the sandbox, unless you set `CLAUDE_DOCKER_RW_CONFIG=1`.
- Refuses to mount the home directory, its parents or the filesystem root.
- Keeps `~/.cache` (Go modules, uv, npm) in a Docker volume per project, so
  a session does not download its dependencies again. Per project on
  purpose, a shared cache would let one session poison another project's
  dependencies. The volumes have no size cap, list them with
  `docker volume ls --filter name=claude-cache-` and remove what you no
  longer need. `CLAUDE_DOCKER_CACHE=0` goes back to a 2g tmpfs.
- When a session ends, warns if it changed files that run commands on the
  host, or that Claude follows there. In the project and every extra
  directory: `.git/config` (branch tracking aside) and git hooks, of
  submodules too and where `core.hooksPath` moved them (husky and the
  like), Claude's `.claude/settings.json`, `settings.local.json` and
  `.mcp.json` with the scripts their commands name, and its instructions,
  `CLAUDE.md` and the `hooks`, `commands`, `skills`, `agents` and `rules`
  of `.claude`. In `~/.claude` the same, where it matters for what is not
  mounted read-only: `commands`, `rules`, and a script `settings.json`
  names outside `hooks`. They have to stay writable for git and
  claude to work, so they are checked rather than locked. The warning is
  printed when the launcher returns, so end a session with `/exit` or
  Ctrl-D to see it there. A session that ends without it, because its Emacs
  buffer or terminal was killed, is checked by the next `claude-docker`
  launch instead, which then also lists what you changed yourself in the
  meantime.
- Shadows `.env`, `.env.*`, `.envrc`, `.netrc` and `.pypirc` files with
  `/dev/null`, so secrets stay on the host. Templates such as `.env.example`
  remain readable, and `CLAUDE_DOCKER_SHADOW` hides more.
- Runs as your user with a read-only root filesystem, all capabilities
  dropped, `no-new-privileges`, and PID and memory limits. Writable space is
  the mounts, the cache volume and a few size-capped tmpfs (`/tmp`,
  `~/.npm`). Containers still share the host kernel, set
  `CLAUDE_DOCKER_RUNTIME=runsc` to run under gVisor if you have it.
- Mounts the git config read-only, including files it pulls in with
  `include` and `includeIf`. There is no gpg in the image, so commit signing
  is switched off inside the container, sign the commits on the host before
  pushing.
- With `CLAUDE_DOCKER_SSH_AGENT=1`, forwards the SSH agent. It is opt-in
  because the agent lets the container authenticate as you to every host
  your keys reach. Loading keys with `ssh-add -c` makes each use ask first.
- With `CLAUDE_DOCKER_SOCKET=1` (and the `docker` feature for the CLI), lets
  the session see the host's containers through
  [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)
  with our own rules (`docker/docker-socket-proxy.cfg`): `docker ps` and
  `docker logs` work, everything else is denied. `docker inspect` gets a
  stub answer, enough for the CLI to fetch logs, so container environments
  stay hidden. Logs of containers started with a TTY cannot be decoded in
  this mode. `CLAUDE_DOCKER_SOCKET=full` allows every read under
  `/containers` instead, which adds real `inspect`, `stats` and `top`, and
  with them the environment of every container on the host, secrets
  included. Writes are blocked in both modes, since a write to the root
  daemon would let the container escape. Command lines and logs can still
  carry secrets, which is why this stays opt-in. The proxy sidecars keep
  running between sessions, after editing the rules or to switch them off
  remove them with `docker rm -f claude-docker-ps-proxy claude-docker-proxy`.
- With `CLAUDE_DOCKER_NET_FILTER=1`, joins an internal network with no route
  out. Egress goes through a squid sidecar that only allows the listed
  domains, and external DNS is blackholed. `claude-docker --net-log` lists
  the domains it refused, most frequent first, which is the quickest way to
  find what a project needs. An edited allowlist is picked up by the next
  filtered session, or at once with `claude-docker --net-reload`. Either
  way the proxy restarts, briefly dropping the connections of other
  filtered sessions.

## Known limits

The sandbox contains what a session can reach, it does not make a
read-write project safe to trust blindly afterwards:

- Anything in the project can be changed, including files that run code on
  the host later: `.git/config` (`core.fsmonitor`, `core.hooksPath`), git
  hooks, `.claude/settings.json`, Makefiles and scripts. The launcher warns
  about git's and Claude's own when a session ends (see above), the rest is
  for you to review in the diff before running things outside the sandbox:
  build files, package scripts, the configuration of a hook manager such
  as pre-commit, a `CLAUDE.md` below the top of the project, and a
  repository planted in a subdirectory.
- `~/.claude/plugins` stays writable, Claude updates plugins itself, so a
  plugin's hook scripts are not protected the way `settings.json` is.
- The egress allowlist includes GitHub, so with a forwarded SSH agent or a
  `GH_TOKEN` a session can still push data out to a repository or gist.
- Secrets that are not in a shadowed file (hard-coded, or in git history)
  are readable.

## Reviewing a session

`claude-docker --trace` shows what the latest session of the current project
did: what it ran, where and why, what it wrote and what it reached on the
network, in the order it happened. It is plain text made to be kept in a
file or searched, every line starts with when, who and what:

```
# session     3fa9c0de-...  Fix the build
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
# time                 who      what      details
2026-01-02 10:02:30  user     prompt    fix the build
2026-01-02 10:02:41  claude   bash      $ npm ci
2026-01-02 10:02:41  claude   bash      why: Install the dependencies
2026-01-02 10:02:41  claude   bash      result: ok, 8.2s
2026-01-02 10:02:42  sandbox  net       tcp/https registry.npmjs.org (104.16.3.35):443
2026-01-02 10:03:05  claude   edit      file: /home/me/code/api/Makefile
2026-01-02 10:03:05  claude   edit      diff: -	go build ./..
2026-01-02 10:03:05  claude   edit      diff: +	go build ./...
2026-01-02 10:03:05  claude   edit      result: ok, 0.0s
```

- `who` is `user`, `claude`, `agent` (a subagent) or `sandbox`, the
  container as a whole: a connection is known by its container, not by the
  command that opened it. Its place in time says which that probably was.
- `what` is `prompt`, `reply`, the tool (`bash`, `edit`, `write`, `read`,
  ...), `net` or `dns`.
- A command comes with the reason Claude gave for it (`why:`), its working
  directory when that is not the project (`cwd:`) and how it ended. Calls
  that failed say `FAILED`, files written outside the project `OUTSIDE
  PROJECT`, requests the egress filter refused `DENIED`.
- Long commands, diffs and replies are cut to a few lines and the output of
  a call is only shown when it failed, `--full` shows everything.
- `--trace list` lists the project's sessions, and the start of an id picks
  one. On a terminal the result goes through your pager.

`--json` gives the same events as JSON Lines, one object each, nothing
shortened, for `jq` or to load into a database:

```
{"session": "3fa9c0de-...", "time": "2026-01-02T10:02:41.120+01:00", "who": "claude", "what": "bash", "tool": "Bash", "input": {"command": "npm ci", "description": "Install the dependencies"}, "cwd": "/home/me/code/api", "failed": false, "output": "...", "seconds": 8.2}
{"session": "3fa9c0de-...", "time": "2026-01-02T10:02:42.480+01:00", "who": "sandbox", "what": "net", "protocol": "tcp/https", "name": "registry.npmjs.org", "address": "104.16.3.35", "port": 443}
```

Every object has `session`, `time`, `who` and `what`. A prompt or reply
adds `text`, a tool call `tool`, `input`, `cwd`, `failed`, `seconds` and
`output` (and `outside_project` for a file it wrote), a connection
`protocol`, `address`, `port` and `name`, a proxy request `protocol`,
`method`, `url`, `port`, `denied`, `bytes` and `seconds`, a lookup `name`.

The network lines need a record the launcher keeps, of which there are two:

- With `CLAUDE_DOCKER_NET_FILTER=1`, what the session asked the egress
  proxy for: method, host, allowed or `DENIED`, bytes and duration. HTTPS
  shows as the host it connected to, not the URL. The proxy's log is shared
  by all sessions, so the launcher notes the address each session's
  container had and picks its requests by that.
- Unless `CLAUDE_DOCKER_NET_LOG=0`, every TCP connection the session opened,
  whatever the protocol, and with `--full` every name it looked up. The
  session's route out is not changed, a sidecar that owns its network
  namespace captures the packets that say where a connection goes: its
  start, the DNS answers and the TLS hello. The name of a destination comes
  from those, a connection to a bare address shows as the address. The
  address is what was reached, the name is what the session looked up or
  asked for, so trust the address where the two matter. It works
  with the filter too, where it shows what a session tried to reach around
  the proxy. Not recorded: UDP other than DNS, IPv6, and what was sent.

Neither can be forged or edited by the session: the address and the capture
are taken outside of it. The transcript is another matter, it is written
from inside the sandbox, so treat that part as a convenience and not as an
audit log, a session could rewrite its own. A tool call is recorded as
issued, what a command went on to spawn or touch is not. Sessions run
outside the sandbox in the same directory are listed too, Claude Code keeps
them in the same place.

What is kept, all of it under `~/.local/state/claude-sandbox` unless noted:

- The proxy's log, in the `claude-egress-log` Docker volume, so it survives
  a proxy restart. It is rotated once it passes 10 MB, checked when a
  filtered session starts, and one rotated file is kept, about 20 MB at
  most. `docker volume rm claude-egress-log` (with the proxy removed)
  clears it.
- The captures, a few kB each as a rule, the latest 100. One stops at
  100,000 packets, about 100 MB at the very worst, and the trace says so
  when that happened.
- `net-sessions.jsonl`, a line per recorded session.

A capture is copied out when the launcher returns. The sidecar of a session
that ended without it (a killed Emacs buffer) is collected by the next
`claude-docker` launch.

## The image

The image is assembled from the parts in `docker/`: `base.Dockerfile`
(Claude Code's needs plus git, gh, Python with uv, Node.js and a C
toolchain), the features you select, then `tail.Dockerfile`. Each feature
is one plain Dockerfile fragment in `docker/features/`, some with a
directory of the same name holding files the fragment copies in:

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
| `reverse` | gdb-multiarch, binutils-multiarch, strace, ltrace, binwalk and the Python capstone, lief, pyelftools libraries |
| `rosbag` | mcap CLI, sqlite3 CLI and the Python rosbag libraries |
| `shell` | shellcheck, shfmt |
| `typst` | Typst |

With no selection every feature is built, which is large. Select a subset
either way, the environment variable wins:

```
export CLAUDE_DOCKER_FEATURES="go typst"       # empty string for none

mkdir -p ~/.config/claude-sandbox
printf 'go\ntypst\n' > ~/.config/claude-sandbox/features.txt
```

To add a tool of your own, drop a fragment into
`~/.config/claude-sandbox/features/NAME.Dockerfile`. It runs as root after
the base, so `apt-get install` and friends work, and a same-named file
there overrides a bundled feature:

```dockerfile
# claude-feat: sqlite
# claude-feat-md: sqlite3 CLI
RUN apt-get update \
    && apt-get install -y --no-install-recommends sqlite3 \
    && rm -rf /var/lib/apt/lists/*
```

A fragment that needs files finds those of a `NAME` directory next to it in
the build context, as `COPY NAME/file ...`. One that needs another feature
names it on a `# claude-feat-requires: other` line, and selecting the first then
builds both.

A fragment that installs a language server declares it on a
`# claude-feat-lsp:` line, as the `lspServers` of a Claude Code plugin (see
`docker/features/go.Dockerfile`). The launcher makes one plugin of those
lines, builds it into the image and starts `claude` with it, so a session
has go-to-definition and find-references for the languages of its image
without a plugin being enabled on the host. The `python`, `go`, `cpp` and
`typescript` features have one. If the host enables the official plugin for
the same server as well (`gopls-lsp`, `clangd-lsp`, `typescript-lsp`,
`pyright-lsp`), the sandbox does not need it.

The `# claude-feat-md:` lines of the parts that were built are baked into the
image as system-level memory, so Claude always knows exactly what is
installed. They were written `# claude:` before, the launcher stops at a
fragment that still has one and says so.

The image tag is a hash of the generated Dockerfile, so changing the
selection or editing a part rebuilds on the next start, reusing cached
layers, and each feature set keeps its own image. Old ones pile up, list
them with `docker images claude-code-sandbox` and remove what you no longer
use.

Images, downloads and Python packages are pinned by digest, checksum or
version, Debian packages follow the pinned base image. Claude Code's
auto-updater is off, so upgrading means refreshing the pins:

```
docker/update-pins.py
```

It also covers your own fragments and the two sidecar images.

## Tests

`test/launcher_test.py` checks the launcher's security-relevant behaviour
without needing Docker: what gets mounted, shadowed and switched off by
default, the tamper check, the network capture and `--trace`. It runs the
launcher against a fake `docker` that records every call. CI runs it
together with ruff, shellcheck and a small image build.

The checks are in `test/test_*.py`, by topic, with what they share in
`test/harness.py`. They need nothing but Python: `test/launcher_test.py`
runs them all, `test/launcher_test.py -k trace` those with trace in their
name, and each file runs on its own. `pytest test` works too if you have
it.

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
