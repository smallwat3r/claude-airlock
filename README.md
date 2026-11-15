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
claude-docker --worktree feature-x  # second session on its own git worktree
claude-docker --rebuild             # clean image rebuild, then exit
```

Any other argument is forwarded to `claude`. Since the container is the
sandbox, it is common to run with `--dangerously-skip-permissions`.

| Variable | Effect |
| --- | --- |
| `CLAUDE_DOCKER_EXTRA_DIRS=a:b` | Extra directories to mount, same as repeated `--add-dir` |
| `CLAUDE_DOCKER_NET_FILTER=1` | Restrict egress to `docker/claude-sandbox/allowed-domains.txt` |
| `ANTHROPIC_API_KEY` | Passed through when set |

`~/claude-shared` is always mounted when it exists, as a scratch directory
shared between sessions.

## What the sandbox does

- Mounts the project directory (and any extra directories) read-write at
  their host paths, plus `~/.claude` so login, settings and history persist.
- Refuses to mount the home directory, its parents or the filesystem root.
- Shadows `.env`, `.env.*` and `.envrc` files with `/dev/null`, so secrets
  stay on the host. Templates such as `.env.example` remain readable.
- Runs as your user with a read-only root filesystem, all capabilities
  dropped, `no-new-privileges`, and PID and memory limits. Writable space is
  the mounts and a few size-capped tmpfs (`/tmp`, `~/.cache`, `~/.npm`).
- Gives read-only visibility into the host Docker daemon through
  [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy):
  `ps`, `inspect` and `logs` work, every write call is blocked, since a
  write to the root daemon would let the container escape.
- Forwards the SSH agent and mounts the git config read-only. There is no
  gpg in the image, so commit signing is switched off inside the container,
  sign the commits on the host before pushing.
- With `CLAUDE_DOCKER_NET_FILTER=1`, joins an internal network with no route
  out. Egress goes through a squid sidecar that only allows the listed
  domains, and external DNS is blackholed. After editing the allowlist,
  restart the proxy with `docker rm -f claude-egress-proxy`.

## The image

`docker/claude-sandbox/Dockerfile` is opinionated: besides Claude Code it
ships Python (uv, ruff, mypy, pytest), Go, Node.js, a C toolchain, Playwright
with Chromium, Typst, KiCad, OpenSCAD and rosbag tooling. Trim or extend it
to taste, and keep `CLAUDE-sandbox.md` in sync, it is baked into the image
as system-level memory telling Claude what is installed.

Everything is pinned by version, checksum or digest. Claude Code's
auto-updater is off, so upgrading means refreshing the pins and rebuilding:

```
docker/claude-sandbox/update-pins.py
claude-docker --rebuild
```

## Statusline

`bin/claude-statusline` shows the model, the 5h and 7d usage limits, and
inside the sandbox the container name, network mode and extra mounts. Enable
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
