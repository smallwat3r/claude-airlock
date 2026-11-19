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
in the build context, as `COPY NAME/file ...`.

## Language servers

The launcher makes one plugin of the `claude-feat-lsp` lines, builds it
into the image and starts `claude` with it. So a session has
go-to-definition and find-references for the languages of its image
without a plugin being enabled on the host. The `python`, `go`, `cpp` and
`typescript` features have one.

## Rebuilds and pins

- The image tag is a hash of the generated Dockerfile. Changing the
  selection or editing a part rebuilds on the next start, and each feature
  set keeps its own image.
- Old images pile up, several GB each. `claude-airlock --prune` removes
  them all but the one your settings ask for now.
- Images, downloads and Python packages are pinned by digest, checksum or
  version. Claude Code's auto-updater is off, so upgrading means
  refreshing the pins:

```
docker/update-pins.py
```
