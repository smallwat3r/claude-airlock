# The image

The image is assembled from the parts in `docker/`: `base.Dockerfile`
(Claude Code's needs plus git, gh, Python with uv, Node.js and a C
toolchain), the features you select, then `tail.Dockerfile`.

## Features

Each feature is one plain Dockerfile fragment in `docker/features/`, some
with a directory of the same name holding files the fragment copies in:

| Feature | Adds |
| --- | --- |
| `ble` | tshark and scapy, for offline analysis of BLE captures |
| `cad` | OpenSCAD, admesh |
| `cpp` | cmake, clangd |
| `docker` | Docker CLI, for `CLAUDE_AIRLOCK_DOCKER_SOCKET` |
| `docs` | pandoc, poppler-utils, qpdf, gnuplot |
| `excalidraw` | `excalidraw-export`, renders an [Excalidraw](https://excalidraw.com) scene to PNG or SVG offline, and takes the scene back out of one. Brings in `playwright` for its headless Chromium |
| `font` | fontforge, fonttools, ttfautohint, woff2, fontconfig and the common monospace fonts (DejaVu Sans Mono, Liberation Mono, Noto Mono, JetBrains Mono, Fira Code, Hack, Inconsolata, Anonymous Pro, Courier Prime, Mononoki, Go Mono) |
| `go` | Go, gopls |
| `kicad` | KiCad 9 with `kicad-cli` |
| `loadtest` | wrk, hey, for HTTP load testing |
| `media` | ffmpeg, ImageMagick, webp |
| `playwright` | Playwright (Python) with headless Chromium |
| `python` | mypy, ruff, black, pytest, ipython, pyright (Python 3 and uv are already in the base) |
| `reverse` | gdb-multiarch, binutils-multiarch, strace, ltrace (not on arm64), binwalk and the Python capstone, lief, pyelftools libraries |
| `rosbag` | mcap CLI, sqlite3 CLI and the Python rosbag libraries |
| `shell` | shellcheck, shfmt |
| `terraform` | Terraform, terraform-ls |
| `typescript` | typescript-language-server, `tsc` |
| `typst` | Typst |

With no selection every feature is built, which is large. Select a subset
either way, the environment variable wins:

```
export CLAUDE_AIRLOCK_FEATURES="go typst"       # empty string for none

mkdir -p ~/.config/claude-airlock
printf 'go\ntypst\n' > ~/.config/claude-airlock/features.txt
```

## A feature of your own

Drop a fragment into `~/.config/claude-airlock/features/NAME.Dockerfile`.
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

A fragment that needs files finds those of a `NAME` directory next to it
in the build context, as `COPY NAME/file ...`. The Python packages of a
feature are named there in a `requirements.in`, which `update-pins.py`
locks into the `requirements.txt` next to it, as the bundled features do
(see `docker/features/python.Dockerfile`).

## Language servers

The launcher makes one plugin of the `claude-feat-lsp` lines, builds it
into the image and starts `claude` with it. So a session has
go-to-definition and find-references for the languages of its image
without a plugin being enabled on the host. The `python`, `go`, `cpp`,
`typescript` and `terraform` features have one.

## Rebuilds and pins

- The image tag is a hash of the generated Dockerfile. Changing the
  selection or editing a part rebuilds on the next start, and each feature
  set keeps its own image.
- Old images pile up, several GB each. `claude-airlock --prune` removes
  them all but the one your settings ask for now.
- Images and downloads are pinned by digest or checksum. Claude Code's
  auto-updater is off, so upgrading means refreshing the pins:

```
docker/update-pins.py
```

- The Python packages of a feature are locked with all they need, by
  version and the hashes of their files, in the `requirements.txt` of its
  directory, for the image's Python (Debian's). They are installed with
  `--require-hashes`. `update-pins.py` moves a package only to a version
  that runs on that Python, and makes the lock anew with uv.
- The npm packages Excalidraw is built from are locked the same way in
  `docker/features/excalidraw/package-lock.json`, installed with `npm ci`
  and without running their scripts, and the lock is made anew with npm.
  The npm packages installed on their own (Claude Code, pyright, the
  TypeScript language server) need nothing that is not pinned with them,
  and are pinned by version.
- Go modules, gopls among them, are checked against the Go checksum
  database.
- The Chromium of the `playwright` feature is the build its pinned version
  names. Playwright downloads it over HTTPS and checks its size alone:
  there is no checksum of it to check.

- Debian packages are not pinned, they follow the release of the pinned
  base image. Nor are `gh` and `docker-ce-cli`, which come from the apt
  repositories of GitHub and Docker: the keys those are signed with are
  pinned by checksum, the versions are their latest.
