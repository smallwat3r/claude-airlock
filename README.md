# claude-airlock

> [!NOTE]
> claude-airlock is still under development. It works today, but settings
> and behaviour may change, sometimes in breaking ways. It is mostly
> developed on Linux. macOS should work too, but sees less daily use.

Run [Claude Code](https://claude.com/claude-code) in a hardened Docker
container that only has the current project mounted, and see everything
it does there. It works from any shell, and from editors that can launch
a custom `claude` program.

![The launcher on the host starts the session container, a capture sidecar
and a process sidecar that share one network namespace, and reads their
records and the transcript while the session runs, the egress proxy, the
Docker socket proxy, the SSH agent and the gVisor runtime are
opt-in](docs/img/architecture.excalidraw.png)

What you get:

- **A contained session.** Only the project is mounted, as your user, on a
  read-only root filesystem with all capabilities dropped. `.env` files
  read as empty, and Claude's own configuration is read-only. On Linux it
  can also run on [gVisor](docs/sandbox.md#gvisor), a kernel of its own.
- **A record of what it did.** Every connection, DNS lookup and process is
  recorded from outside the session, so the session cannot tamper with
  it. Its tool calls come from its transcript, which the launcher copies
  as it is written, and it flags any line changed or removed later.
  `--trace` shows it all.
- **A check when it ends.** The launcher warns when a session changed a
  file that runs commands on the host, such as a git hook or a Makefile.
- **Line mode.** Claude Code with a simpler UI that shows more than the
  native one, see [Line mode](#line-mode).
- **Opt-in doors.** An egress filter, the SSH agent and the Docker socket,
  each off until you switch it on.

Contents:

- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
  - [Login](#login)
  - [Settings](#settings)
  - [The config file](#the-config-file)
- [What the sandbox does](#what-the-sandbox-does)
- [Known limits](#known-limits)
- [Reviewing a session](#reviewing-a-session), with `--trace`
- [Line mode](#line-mode), Claude Code without its native UI
- [The image](#the-image) and its features
- [Statusline](#statusline)
- [Editor integration](#editor-integration)
- [Tests](#tests)

## Requirements

- Docker (Linux, or Docker Desktop on macOS)
- Python 3.13 or later for the launcher, standard library only

## Install

```
git clone https://github.com/smallwat3r/claude-airlock.git ~/code/claude-airlock
export PATH="$HOME/code/claude-airlock/bin:$PATH"
```

Or symlink the launcher into a directory already on your `PATH`. It
finds the rest of the checkout through the link:

```
ln -s ~/code/claude-airlock/bin/claude-airlock ~/.local/bin/claude-airlock
```

## Usage

```
cd ~/code/my-project
claude-airlock                       # builds the image on first use
claude-airlock -p "summarise this" < notes.txt   # piped, no TTY needed
```

Any other argument is passed on to `claude`.

- **Permissions.** The container is the sandbox, so `claude` runs with
  `--dangerously-skip-permissions` and does not ask before it uses a
  tool. `CLAUDE_AIRLOCK_ASK=1` makes it ask, and your own
  `--permission-mode` is left alone. [Known limits](#known-limits) says
  what a session can reach without asking.
- **Model.** It starts on Opus at high effort. `CLAUDE_AIRLOCK_MODEL` and
  `CLAUDE_AIRLOCK_EFFORT` change that, and your own `--model` or
  `--effort` wins.

The launcher's own options (`claude-airlock --help` lists them all, with
the settings):

```
# What a session gets
claude-airlock --add-dir ~/code/api  # mount a second project read-write
claude-airlock --add-dir-ro ~/code/lib   # mount reference code read-only
claude-airlock --worktree feature-x  # second session on its own git worktree
claude-airlock --shell               # bash in the same sandbox, to look around

# The image, see "The image"
claude-airlock --rebuild             # clean image rebuild, then exit
claude-airlock --prune               # delete all sandbox images but the current one
claude-airlock --dockerfile          # print the generated Dockerfile, then exit

# The egress filter, see docs/sandbox.md
claude-airlock --net-log             # domains the egress filter denied
claude-airlock --net-reload          # restart the egress filter

# What a session did, see "Reviewing a session"
claude-airlock --trace               # what the latest session here did
claude-airlock --trace list          # this project's sessions, latest first
claude-airlock --trace 3fa9 --verbose > trace.txt   # one session, in detail
claude-airlock --trace --json | jq 'select(.what == "net")'   # as JSON Lines
claude-airlock --trace --only bash,net   # just the commands and the network
claude-airlock --trace --failed      # just what went wrong
claude-airlock --trace --follow      # what the sessions here do, as they do it

# Claude Code's native UI instead of line mode, see "Line mode"
CLAUDE_AIRLOCK_LINE_MODE=0 claude-airlock  # or in the config file, for every session
```

### Login

A session uses the login of `claude` on the host. When either side renews
it, the other picks up the new one a moment later. On macOS the login is
in the Keychain, and the launcher reads and writes it there.

So log in with `claude` on the host. Or log in from a session with the
native UI, as [line mode](#line-mode) has no `/login`:

```
CLAUDE_AIRLOCK_LINE_MODE=0 claude-airlock   # then /login
```

### Settings

All optional, set in the environment or in [the config file](#the-config-file).
A switch takes `1` for on and `0` for off. Any other value, such as `true`,
stops the launcher, so a typo never leaves a restriction off.

What a session gets:

| Setting | Default | Effect |
| --- | --- | --- |
| `CLAUDE_AIRLOCK_EXTRA_DIRS=a:b` | none | Extra directories to mount, like repeated `--add-dir` |
| `CLAUDE_AIRLOCK_EXTRA_DIRS_RO=a:b` | none | The same read-only, like repeated `--add-dir-ro` |
| `CLAUDE_AIRLOCK_SHARED_DIR=~/scratch` | `~/claude-shared` if it exists | Scratch directory shared between sessions, empty for none |
| `CLAUDE_AIRLOCK_SHADOW="*.pem:.npmrc"` | none | More file names to hide, on top of the `.env` family |
| `CLAUDE_AIRLOCK_PROTECT="~/kit:docs"` | none | Paths that are read-only wherever they are mounted |
| `CLAUDE_AIRLOCK_RW_CONFIG` | `0` | `1` makes the protected parts of `~/.claude` (`settings.json`, `CLAUDE.md`, `hooks`...) writable |
| `CLAUDE_AIRLOCK_SHARED_HISTORY` | `0` | `1` lets a session see Claude Code's history of every project, not only its own |
| `CLAUDE_AIRLOCK_CACHE` | `1` | `~/.cache` persists per project. `0` makes it a tmpfs of at most 2g |
| `ANTHROPIC_API_KEY`, `GH_TOKEN` | unset | Passed through when set. `GH_TOKEN` is how `gh` logs in |

The doors, all closed by default:

| Setting | Default | Effect |
| --- | --- | --- |
| `CLAUDE_AIRLOCK_NET_FILTER` | `0` | `1` allows only the domains in `docker/allowed-domains.txt`, over HTTP, HTTPS and git over SSH |
| `CLAUDE_AIRLOCK_NET_ASK` | `0` | `1` makes line mode ask you before the filter refuses a host. A yes holds for that host and port until the session ends |
| `CLAUDE_AIRLOCK_SSH_AGENT` | `0` | `1` forwards your SSH agent, so git over SSH and `ssh` work with your keys |
| `CLAUDE_AIRLOCK_CONNECTORS` | `0` | `1` loads the connectors of your claude.ai account (Gmail, Google Drive...), with their tools in every request |
| `CLAUDE_AIRLOCK_DOCKER_SOCKET` | `0` | `1` allows `docker ps` and `docker logs` against the host, `full` adds `inspect`, `stats` and `top` |

What is recorded, for `--trace`:

| Setting | Default | Effect |
| --- | --- | --- |
| `CLAUDE_AIRLOCK_NET_LOG` | `1` | Records the network: every connection in and out, UDP sends, pings, name lookups, and how much went over each connection and when. `0` turns it off |
| `CLAUDE_AIRLOCK_PROC_LOG` | `1` | Records the processes that run, which one made each connection, the secret files they open, and the memory and CPU used. `0` turns it off |
| `CLAUDE_AIRLOCK_API_LOG` | `0` | `1` keeps every request Claude Code sends to the model and each answer, see [docs/trace.md](docs/trace.md#the-requests-to-the-model) |

How Claude Code runs:

| Setting | Default | Effect |
| --- | --- | --- |
| `CLAUDE_AIRLOCK_LINE_MODE` | `1` | Sessions run in [line mode](#line-mode). `0` gives Claude Code's native UI |
| `CLAUDE_AIRLOCK_ASK` | `0` | `1` makes Claude Code ask before it uses a tool, as it does outside the sandbox |
| `CLAUDE_AIRLOCK_MODEL=fable` | `opus` | The starting model, as `--model` takes it. Empty leaves it to Claude Code |
| `CLAUDE_AIRLOCK_EFFORT=xhigh` | `high` | The starting effort, as `--effort` takes it. Empty leaves it to Claude Code |
| `CLAUDE_AIRLOCK_INJECTION_STOP` | `0` | `1` makes line mode stop a turn when what it read looks forged, see [docs/line-mode.md](docs/line-mode.md#stopping-a-turn-for-what-it-read). `0` only flags it |
| `CLAUDE_AIRLOCK_TELEMETRY` | `0` | `1` lets Claude Code send usage events and crash reports |

The container and its image:

| Setting | Default | Effect |
| --- | --- | --- |
| `CLAUDE_AIRLOCK_FEATURES="go typst"` | `~/.config/claude-airlock/features.txt`, else every feature | Tools to build into the image, see [The image](#the-image) |
| `CLAUDE_AIRLOCK_MEMORY=32g` | `16g` | Memory limit. Below about 10g, `/tmp` and the other tmpfs shrink to fit in half of it |
| `CLAUDE_AIRLOCK_PIDS=1024` | `512` | Process limit |
| `CLAUDE_AIRLOCK_CPUS=4` | every CPU | CPU limit, fractions like `1.5` work too. At the limit a session runs slower, nothing is killed |
| `CLAUDE_AIRLOCK_RUNTIME=runsc-hostnet` | Docker's own | Container runtime, as registered in Docker. For gVisor see [docs/sandbox.md](docs/sandbox.md#gvisor) |

Each setting is described in detail in [docs/sandbox.md](docs/sandbox.md),
and the records in [docs/trace.md](docs/trace.md).

### The config file

To change a default for every session, put the same variables in
`~/.config/claude-airlock/config`, one per line:

```
# ~/.config/claude-airlock/config
CLAUDE_AIRLOCK_MEMORY=8g
CLAUDE_AIRLOCK_NET_FILTER=1
CLAUDE_AIRLOCK_SHARED_DIR=/home/me/scratch
```

- **The environment wins**, so one session can override the file. A
  variable set but empty counts as unset, except for
  `CLAUDE_AIRLOCK_FEATURES` and `CLAUDE_AIRLOCK_SHARED_DIR`, where empty
  means none, and `CLAUDE_AIRLOCK_MODEL` and `CLAUDE_AIRLOCK_EFFORT`,
  where empty leaves the choice to Claude Code.
- **Values are taken literally.** No quotes, no blanks around them, and
  comments go on a line of their own. A leading `~` is your home in the
  settings that take a path.
- **Mistakes stop the launcher**: a quoted value, an unknown name or one
  given twice. Taken as written, they would quietly hide or protect
  nothing.
- **Only your config directory is read**, never the project, which a
  session can write to.
- `CLAUDE_AIRLOCK_EXTRA_DIRS` and `CLAUDE_AIRLOCK_EXTRA_DIRS_RO` are not
  accepted there, as extra directories belong to one project.
- `CLAUDE_AIRLOCK_SHADOW` and `CLAUDE_AIRLOCK_PROTECT` add up: what the
  file and the environment name both count.

## What the sandbox does

What is mounted and how, what is read-only or hidden, how the container
is hardened, the check when a session ends, and the opt-in doors (the
egress filter, the SSH agent, the Docker socket) are all in
[docs/sandbox.md](docs/sandbox.md).

## Known limits

The sandbox limits what a session can reach. It does not make a
read-write project safe to trust blindly afterwards. Unless
`CLAUDE_AIRLOCK_ASK=1`, a session does not ask before it uses a tool, so
it can do all of this on its own, including when something it read told
it to:

- **Prompt injection is only flagged.** What a session reads is checked
  for signs of it (see [What it read](docs/trace.md#what-it-read)), but
  the check knows only a few ways of writing it, and the session has read
  the text either way. With `CLAUDE_AIRLOCK_INJECTION_STOP=1` line mode
  stops the turn for two of the signs. The native UI never stops.
- **Anything in the project can be changed**, including files that later
  run code on the host. The launcher warns about the ones it knows by
  name (see [the check](docs/sandbox.md#the-check-when-a-session-ends)),
  but it does not read them for you and its list is not complete: a
  script a Makefile calls, `node_modules`, or a build file it does not
  know are yours to review in the diff.
- **With the network open, a session reaches whatever the host listens
  on**, and the rest of your network. Only the egress filter stops that.
- **The login is in the sandbox.** A session can read it and use it
  elsewhere. It can also replace it, since renewals are carried to the
  host: a session can log the host's `claude` out, or into another
  account. Only what does not look like a login is kept from the host.
- **The egress allowlist limits where a session can send, not what.**
  GitHub, npm and Anthropic's API are on the list and accept uploads from
  anyone with a token. A session does not need yours: what it read can
  bring its own, to push to a repository or publish a package. With a
  forwarded SSH agent or a `GH_TOKEN` it can do so as you.
- **Secrets outside a shadowed file** (hard-coded, or in git history) are
  readable.

The narrower limits, on plugins, MCP servers, the history of other
projects and what the egress filter cannot tell apart, are in
[docs/sandbox.md](docs/sandbox.md#known-limits).

## Reviewing a session

`claude-airlock --trace` shows what the latest session of the project did,
in order: what it ran and why, what it wrote, and what it reached on the
network. `--trace --follow` shows it live. See
[docs/trace.md](docs/trace.md).

## Line mode

Sessions run in line mode by default: Claude Code with a simpler UI. You
get a prompt, and above it what the session does, as it does it, in the
lines of `--trace`. Why it is the default:

- **You see what a command did, not only that it ran.** Under each
  command are the connections it made, the process behind each, the files
  it changed and who allowed it. The native UI shows none of that.
- **It is the launcher's account, not the session's.** The network,
  resource use and doors are recorded from outside the sandbox, so the
  session cannot leave anything out.
- **Problems stand out.** Refused connections, failed commands, writes
  outside the project and possible prompt injections are in bold red
  capitals.
- **You see the cost.** Each step shows its tokens, each turn its time,
  price and network use, and the sandbox reports its memory and CPU every
  so often.
- **It works anywhere.** Lines are only added, never redrawn, so it reads
  the same in a terminal, an Emacs shell buffer or a file.

`CLAUDE_AIRLOCK_LINE_MODE=0` gives the native UI back. See
[docs/line-mode.md](docs/line-mode.md).

![Two turns in line mode at a terminal: how the sandbox was started, then
under each command the connections it made and the files it changed, an
edit with its diff, and the memory and CPU the sandbox
uses](docs/img/line-mode.png)

## The image

The image is built from `docker/base.Dockerfile`, the features you pick
and `docker/tail.Dockerfile`. [docs/image.md](docs/image.md) covers the
features, adding your own, the language servers and how versions are
pinned.

## Statusline

With the native UI, the statusline of your `~/.claude/settings.json`
works as it does on the host, its script is mounted read-only. Line mode
does not run it and shows its own status. See
[docs/sandbox.md](docs/sandbox.md#statusline).

## Editor integration

Point your editor's Claude Code integration at `claude-airlock` instead of
`claude`. For Emacs with
[claude-code.el](https://github.com/stevemolitor/claude-code.el):

```elisp
(setq claude-code-program (executable-find "claude-airlock"))
```

- Each claude-code.el buffer gets its own container name (from
  `CLAUDE_BUFFER_NAME`), so parallel sessions on one project work.
- The buffer runs in [line mode](#line-mode).
- No terminal emulator is needed, `claude-airlock` works the same from
  `M-x shell`.

## Tests

```
make check          # ruff, shellcheck, mypy and the tests, as CI runs them
make test K=trace   # the tests with trace in their name
make smoke          # the end-to-end test against a real Docker daemon
make upgrade        # refresh the pins, then rebuild the image
```

- **The unit tests** (`test/test_*.py`) run the launcher against a fake
  `docker` that records every call. They check the mounts, the shadowed
  files, the defaults, the tamper check, the records, `--trace` and line
  mode. pytest runs them in parallel, with fewer workers inside a sandbox
  to stay under its process limit.
- **The tools** (pytest, ruff, mypy) are the only dependencies, and only
  for the checks. `make` runs them through [uv](https://docs.astral.sh/uv/)
  at the versions and hashes in `uv.lock`. `uv run pytest test/test_trace.py`
  runs one file.
- **CI** runs the tests on Python 3.13 and the latest on Linux, the
  latest on macOS, and 3.13 with GNU readline, plus ruff, mypy,
  shellcheck and a small image build.
- **The smoke test** (`test/smoke/run.sh`) runs by hand on the host. It
  starts open, filtered and socket-proxy sessions in a throwaway project
  and checks the sandbox from the inside (`test/smoke/inside`) and what
  it left on the host (`test/smoke/checks`). Run it after changing the
  launcher, the Dockerfile parts or the sidecar configuration.
