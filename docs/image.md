# The image

The image is built from three parts in `docker/`, in this order:
`base.Dockerfile` (what Claude Code needs, plus git, gh, Python with uv,
Node.js and a C toolchain), the features you select, then
`tail.Dockerfile`.

## Features

Each feature is one Dockerfile fragment in `docker/features/`. Some have a
directory of the same name, with files the fragment copies in.

| Feature | Adds |
| --- | --- |
| `ble` | tshark and scapy, for offline analysis of BLE captures |
| `cad` | OpenSCAD, admesh |
| `cpp` | cmake, clangd |
| `docker` | Docker CLI, for `CLAUDE_AIRLOCK_DOCKER_SOCKET` |
| `docs` | pandoc, poppler-utils, qpdf, gnuplot |
| `excalidraw` | `excalidraw-export`, which renders an [Excalidraw](https://excalidraw.com) scene to PNG or SVG offline, and takes the scene back out of one. Brings in `playwright` for its headless Chromium |
| `font` | fontforge, fonttools, ttfautohint, woff2, fontconfig and the common monospace fonts (DejaVu Sans Mono, Liberation Mono, Noto Mono, JetBrains Mono, Fira Code, Hack, Inconsolata, Anonymous Pro, Courier Prime, Mononoki, Go Mono) |
| `go` | Go, gopls |
| `kicad` | KiCad 9 with `kicad-cli`, the pcbnew Python module and the symbol and footprint libraries |
| `loadtest` | wrk, hey, for HTTP load testing |
| `media` | ffmpeg, ImageMagick, webp |
| `playwright` | Playwright (Python) with headless Chromium |
| `python` | mypy, ruff, black, pytest, ipython, pyright (Python 3 and uv are already in the base) |
| `reverse` | gdb-multiarch, binutils-multiarch, strace, ltrace (not on arm64), binwalk, squashfs-tools, xxd and the Python capstone, lief, pyelftools libraries |
| `rosbag` | mcap CLI, sqlite3 CLI and the Python rosbag libraries |
| `shell` | shellcheck, shfmt |
| `terraform` | Terraform, terraform-ls |
| `typescript` | typescript-language-server, `tsc` 6 |
| `typst` | Typst |

With no selection, every feature is built, which is large. Select a
subset in one of two ways. The environment variable wins over the file:

```
export CLAUDE_AIRLOCK_FEATURES="go typst"       # space or comma separated, empty for none

mkdir -p ~/.config/claude-airlock
printf 'go\ntypst\n' > ~/.config/claude-airlock/features.txt   # one per line, # for comments
```

## A feature of your own

Put a fragment in `~/.config/claude-airlock/features/NAME.Dockerfile`.
The name is lowercase letters, digits, `-` and `_`. The fragment runs as
root after the base, so `apt-get install` works. A file there with the
name of a bundled feature replaces it.

```dockerfile
# claude-feat: sqlite
# claude-feat-md: sqlite3 CLI
RUN apt-get update \
    && apt-get install -y --no-install-recommends sqlite3 \
    && rm -rf /var/lib/apt/lists/*
```

The comment lines the launcher reads:

| Line | Says |
| --- | --- |
| `# claude-feat: NAME` | The feature's name, for whoever reads the fragment. The launcher takes the name from the file |
| `# claude-feat-md: ...` | What it adds, one line per bullet. These go into the image's system-level CLAUDE.md, so Claude knows exactly what is installed |
| `# claude-feat-requires: other ...` | Features it needs, space separated. Selecting this one builds them too |
| `# claude-feat-lsp: {...}` | The language servers it installs, as a JSON object like the `lspServers` of a Claude Code plugin (see `docker/features/go.Dockerfile`) |

A fragment can copy files from a `NAME` directory next to it, as
`COPY NAME/file ...`. Name its Python packages in a `requirements.in`
there, and `update-pins.py` locks them into a `requirements.txt` beside
it. Install that with `--require-hashes`, as the bundled features do (see
`docker/features/python.Dockerfile`).

## Language servers

The launcher turns the `claude-feat-lsp` lines into one plugin, builds it
into the image and starts `claude` with it. So a session has
go-to-definition and find-references for the languages of its image,
without a plugin enabled on the host. The `python`, `go`, `cpp`,
`typescript` and `terraform` features have one.

## Rebuilds and pins

- The image tag is a hash of what the image is built from: the generated
  Dockerfile, the CLAUDE.md, the files of the feature directories and
  your home path. Changing any of them rebuilds on the next start, and
  each feature set keeps its own image.
- Old images pile up, several GB each. `claude-airlock --prune` removes
  all but the one your settings ask for now. One a container still uses
  is kept.
- Images and downloads are pinned by digest or checksum. Claude Code's
  auto-updater is off, so to upgrade you refresh the pins. This needs uv
  and npm on the host, and covers your own features too:

```
docker/update-pins.py
```

- The Python packages of a feature are locked in the `requirements.txt`
  of its directory, with everything they depend on, by version and file
  hash. The lock is for the image's Python (Debian's), and installed with
  `--require-hashes`. `update-pins.py` only moves a package to a version
  that runs on that Python, and makes the lock anew with uv.
- The npm packages Excalidraw is built from are locked the same way, in
  `docker/features/excalidraw/package-lock.json`. They are installed with
  `npm ci` without running their scripts, and the lock is made anew with
  npm.
- The npm packages installed on their own (Claude Code, pyright, the
  TypeScript language server, TypeScript) depend on nothing that is not
  pinned with them, and are pinned by version. TypeScript stays on 6,
  which the language server needs, so `update-pins.py` leaves it alone.
- Go modules, gopls among them, are checked against the Go checksum
  database.
- The Chromium of the `playwright` feature is the build its pinned version
  names. Playwright downloads it over HTTPS and only checks its size,
  there is no checksum to check.
- Debian packages are not pinned, they follow the release of the pinned
  base image. Nor are `gh` and `docker-ce-cli`, which come from the apt
  repositories of GitHub and Docker. The keys those are signed with are
  pinned by checksum, the versions are the latest.
