# claude-sandbox

Run [Claude Code](https://claude.com/claude-code) inside a hardened Docker
container, with only the current project mounted. Works from any shell, and
from editors that can launch a custom `claude` program.

## Requirements

- Docker (Linux, or Docker Desktop on macOS)
- bash, and `jq` on the host if you use the statusline outside the sandbox

## Install

```
git clone https://github.com/smallwat3r/claude-sandbox.git ~/code/claude-sandbox
export PATH="$HOME/code/claude-sandbox/bin:$PATH"
```

Put `bin/` on your `PATH` rather than symlinking the script, it locates the
Dockerfile relative to its own directory.

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
claude-docker -p "summarise this" < notes.txt   # piped, no TTY needed
```

Any other argument is forwarded to `claude`. Since the container is the
sandbox, it is common to run with `--dangerously-skip-permissions`.

| Variable | Effect |
| --- | --- |
| `CLAUDE_DOCKER_EXTRA_DIRS=a:b` | Extra directories to mount, same as repeated `--add-dir` |
| `CLAUDE_DOCKER_EXTRA_DIRS_RO=a:b` | The same read-only, as repeated `--add-dir-ro` |
| `CLAUDE_DOCKER_FEATURES="go typst"` | Tools to build into the image, see [The image](#the-image) |
| `CLAUDE_DOCKER_NET_FILTER=1` | Restrict egress to `docker/claude-sandbox/allowed-domains.txt` |
| `CLAUDE_DOCKER_SSH_AGENT=1` | Forward the SSH agent, needed for git over SSH |
| `CLAUDE_DOCKER_SOCKET=1` | `docker ps` and `docker logs` on the host daemon, `full` adds `inspect` |
| `CLAUDE_DOCKER_RW_CONFIG=1` | Leave `~/.claude/settings.json` and `hooks` writable |
| `CLAUDE_DOCKER_SHADOW="*.pem:.npmrc"` | Extra file name globs to hide, on top of the `.env` family |
| `CLAUDE_DOCKER_MEMORY=16g`, `CLAUDE_DOCKER_PIDS=512` | Container limits, defaults shown |
| `CLAUDE_DOCKER_CACHE=0` | Keep `~/.cache` on a tmpfs instead of a per-project volume |
| `CLAUDE_DOCKER_RUNTIME=runsc` | Container runtime, e.g. gVisor, must be installed in Docker |
| `ANTHROPIC_API_KEY`, `GH_TOKEN` | Passed through when set, `GH_TOKEN` is how `gh` logs in |

`~/claude-shared` is always mounted when it exists, as a scratch directory
shared between sessions.

## What the sandbox does

- Mounts the project directory (and any extra directories) read-write at
  their host paths, plus `~/.claude` so login, settings and history persist.
  `~/.claude/settings.json` and `~/.claude/hooks` are read-only on top: they
  hold commands your host `claude` runs, so a session must not be able to
  plant one. Settings changed inside the sandbox are therefore not saved,
  unless you set `CLAUDE_DOCKER_RW_CONFIG=1`.
- Refuses to mount the home directory, its parents or the filesystem root.
- Keeps `~/.cache` (Go modules, uv, npm) in a Docker volume per project, so
  a session does not download its dependencies again. Per project on
  purpose, a shared cache would let one session poison another project's
  dependencies. The volumes have no size cap, list them with
  `docker volume ls --filter name=claude-cache-` and remove what you no
  longer need. `CLAUDE_DOCKER_CACHE=0` goes back to a 2g tmpfs.
- When a session ends, warns if it changed files that run commands on the
  host: `.git/config` (branch tracking aside), git hooks, and the
  project's `.claude/settings.json`. They have to stay writable for git and
  claude to work, so they are checked rather than locked.
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
  with our own rules (`docker-socket-proxy.cfg`): `docker ps` and
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
  about the first three when a session ends, the rest is for you to review
  in the diff before running things outside the sandbox.
- `~/.claude/plugins` stays writable, Claude updates plugins itself, so a
  plugin's hook scripts are not protected the way `settings.json` is.
- The egress allowlist includes GitHub, so with a forwarded SSH agent or a
  `GH_TOKEN` a session can still push data out to a repository or gist.
- Secrets that are not in a shadowed file (hard-coded, or in git history)
  are readable.

## The image

The image is assembled from `docker/claude-sandbox`: `base.Dockerfile`
(Claude Code's needs plus git, gh, Python with uv, Node.js and a C
toolchain), the features you select, then `tail.Dockerfile`. Each feature
is one plain Dockerfile fragment in `features/`:

| Feature | Adds |
| --- | --- |
| `ble` | tshark and scapy, for offline analysis of BLE captures |
| `cad` | OpenSCAD, admesh |
| `cpp` | cmake, clangd |
| `docker` | Docker CLI, for `CLAUDE_DOCKER_SOCKET` |
| `docs` | pandoc, poppler-utils, qpdf, gnuplot |
| `go` | Go, gopls |
| `kicad` | KiCad 9 with `kicad-cli` |
| `loadtest` | wrk, hey, for HTTP load testing |
| `media` | ffmpeg, ImageMagick, webp |
| `ocrab` | Ocrab font |
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
# claude: sqlite3 CLI
RUN apt-get update \
    && apt-get install -y --no-install-recommends sqlite3 \
    && rm -rf /var/lib/apt/lists/*
```

The `# claude:` lines of the parts that were built are baked into the image
as system-level memory, so Claude always knows exactly what is installed.

The image tag is a hash of the generated Dockerfile, so changing the
selection or editing a part rebuilds on the next start, reusing cached
layers, and each feature set keeps its own image. Old ones pile up, list
them with `docker images claude-code-sandbox` and remove what you no longer
use.

Images, downloads and Python packages are pinned by digest, checksum or
version, Debian packages follow the pinned base image. Claude Code's
auto-updater is off, so upgrading means refreshing the pins:

```
docker/claude-sandbox/update-pins.py
```

It also covers your own fragments and the two sidecar images.

## Tests

`test/launcher-test.sh` checks the launcher's security-relevant behaviour
without needing Docker: what gets mounted, shadowed and switched off by
default. CI runs it together with shellcheck and a small image build.

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
setting works inside and outside the sandbox.

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
