# claude-airlock

> [!NOTE]
> claude-airlock is still under development. It works today, but expect
> changes, including breaking ones to settings and behaviour. It is mostly
> developed on Linux, macOS should work too but sees less daily use.

Run [Claude Code](https://claude.com/claude-code) inside a hardened Docker
container, with only the current project mounted, and see everything it
does there. Every connection and process of a session is recorded from
outside it, where the session cannot tamper with the record. You see them
as they happen, under the tool call that made them, and can review them
later. When the session ends, what it changed is checked. Works from any
shell, and from editors that can launch a custom `claude` program.

![The launcher on the host starts the session container, a capture sidecar
and a process sidecar that share one network namespace, and reads their
records and the transcript while the session runs, the egress proxy, the
Docker socket proxy, the SSH agent and the gVisor runtime are
opt-in](docs/img/architecture.excalidraw.png)

What you get:

- **A contained session.** Only the project is mounted, as your user, on a
  read-only root filesystem with all capabilities dropped. Secrets in
  `.env` files read as empty, and Claude's own configuration is read-only.
  On Linux it can run on [gVisor](docs/sandbox.md#gvisor), a kernel of its
  own, instead of the host's.
- **A record of what it did.** Every connection, DNS lookup and process is
  recorded from outside the session, so the session cannot tamper with
  it. Its tool calls come from its own transcript, which the launcher
  copies as it is written and flags when a line is later changed or
  removed. `--trace` shows it all.
- **A check when it ends.** The launcher warns when a session changed a
  file that runs commands on the host, a git hook or a Makefile say.
- **Line mode.** Claude Code with a simpler UI that shows more than the
  native one: a prompt, and above it what the session does as it does it.
  Under each command the connections it made and how they ended, the
  files it changed, who allowed it, what each step cost, how much memory
  and CPU the sandbox uses, and each use of an opt-in door.
- **Opt-in doors.** An egress filter, the SSH agent and the Docker socket,
  each off until you switch it on.

Contents:

- [Requirements](#requirements), [Install](#install) and [Usage](#usage),
  with the [settings](#settings)
- [What the sandbox does](#what-the-sandbox-does) and its
  [known limits](#known-limits)
- [Reviewing a session](#reviewing-a-session) with `--trace`
- [Line mode](#line-mode), Claude Code without its native UI
- [The image](#the-image) and its features
- [Statusline](#statusline), [Editor integration](#editor-integration)
  and [Tests](#tests)

## Requirements

- Docker (Linux, or Docker Desktop on macOS)
- Python 3.13 or later for the launcher, standard library only

## Install

```
git clone https://github.com/smallwat3r/claude-airlock.git ~/code/claude-airlock
export PATH="$HOME/code/claude-airlock/bin:$PATH"
```

Or leave `PATH` alone and symlink the launcher into a directory already on
it, it finds the rest of the checkout from where it really is:

```
ln -s ~/code/claude-airlock/bin/claude-airlock ~/.local/bin/claude-airlock
```

## Usage

```
cd ~/code/my-project
claude-airlock                       # builds the image on first use
claude-airlock -p "summarise this" < notes.txt   # piped, no TTY needed
```

Any other argument is forwarded to `claude`.

The container is the sandbox, so `claude` is started with
`--dangerously-skip-permissions` and does not ask before it uses a tool.
`CLAUDE_AIRLOCK_ASK=1` has it ask, and a `--permission-mode` of your own is
left as it is. [Known limits](#known-limits) says what a session can reach
without being asked.

The launcher's own options, `claude-airlock --help` lists them with the
settings:

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

# The egress filter, see "The opt-in doors"
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

# Claude Code's native UI in place of line mode, see "Line mode"
CLAUDE_AIRLOCK_LINE_MODE=0 claude-airlock  # or in the config file, for every session
```

### Login

A session has the login of `claude` on the host, and what either renews
is the other's a moment later. On macOS that login is in the Keychain,
where the launcher reads and writes it.

So log in with `claude` on the host. Or in a session, with the native UI,
as [line mode](#line-mode) has no `/login`:

```
CLAUDE_AIRLOCK_LINE_MODE=0 claude-airlock   # then /login
```

### Settings

All optional, set in the environment or in [the config file](#the-config-file).
A switch takes `1` for on and `0` for off. Any other value, such as `true`,
stops the launcher instead of quietly leaving a restriction off.

What a session gets:

| Setting | Default | Effect |
| --- | --- | --- |
| `CLAUDE_AIRLOCK_EXTRA_DIRS=a:b` | none | Extra directories to mount, as repeated `--add-dir` |
| `CLAUDE_AIRLOCK_EXTRA_DIRS_RO=a:b` | none | The same read-only, as repeated `--add-dir-ro` |
| `CLAUDE_AIRLOCK_SHARED_DIR=~/scratch` | `~/claude-shared` if it exists | Scratch directory shared between sessions, empty for none |
| `CLAUDE_AIRLOCK_SHADOW="*.pem:.npmrc"` | none | More file names to hide, on top of the `.env` family |
| `CLAUDE_AIRLOCK_PROTECT="~/kit:docs"` | none | Paths that are read-only wherever they are mounted |
| `CLAUDE_AIRLOCK_RW_CONFIG` | `0` | `1` makes the protected parts of `~/.claude` (`settings.json`, `CLAUDE.md`, `hooks`...) writable |
| `CLAUDE_AIRLOCK_SHARED_HISTORY` | `0` | `1` lets a session see Claude Code's history of every project, not only its own |
| `CLAUDE_AIRLOCK_CACHE` | `1` | `~/.cache` persists per project. `0` makes it a tmpfs of at most 2g |
| `ANTHROPIC_API_KEY`, `GH_TOKEN` | unset | Passed through when set, `GH_TOKEN` is how `gh` logs in |

The doors, all closed by default:

| Setting | Default | Effect |
| --- | --- | --- |
| `CLAUDE_AIRLOCK_NET_FILTER` | `0` | `1` allows only the domains in `docker/allowed-domains.txt`, over HTTP, HTTPS and git over SSH |
| `CLAUDE_AIRLOCK_NET_ASK` | `0` | `1` has the filter ask you in line mode before it refuses a host, a yes lets the request through and holds until the session ends |
| `CLAUDE_AIRLOCK_SSH_AGENT` | `0` | `1` forwards your SSH agent, so git over SSH and `ssh` work with your keys |
| `CLAUDE_AIRLOCK_CONNECTORS` | `0` | `1` loads the connectors of your claude.ai account (Gmail, Google Drive...), with their tools in every request |
| `CLAUDE_AIRLOCK_DOCKER_SOCKET` | `0` | `1` allows `docker ps` and `docker logs` against the host, `full` adds `inspect`, `stats` and `top` |

What is recorded, for `--trace`:

| Setting | Default | Effect |
| --- | --- | --- |
| `CLAUDE_AIRLOCK_NET_LOG` | `1` | Records every connection, what is sent by UDP or a ping, and every name looked up. `0` records nothing |
| `CLAUDE_AIRLOCK_PROC_LOG` | `1` | Records the processes that run, which of them made each connection, and the memory and CPU the session uses. `0` records nothing |

How Claude Code runs:

| Setting | Default | Effect |
| --- | --- | --- |
| `CLAUDE_AIRLOCK_LINE_MODE` | `1` | Sessions run in [line mode](#line-mode). `0` gives Claude Code's native UI |
| `CLAUDE_AIRLOCK_ASK` | `0` | `1` has Claude Code ask before it uses a tool, as it does outside the sandbox |
| `CLAUDE_AIRLOCK_INJECTION_STOP` | `0` | `1` has line mode stop a turn when what it read looks written to pass for the system or the user, see [docs/line-mode.md](docs/line-mode.md#stopping-a-turn-for-what-it-read). `0` flags it and goes on |
| `CLAUDE_AIRLOCK_TELEMETRY` | `0` | `1` lets Claude Code send usage events and crash reports |

The container and its image:

| Setting | Default | Effect |
| --- | --- | --- |
| `CLAUDE_AIRLOCK_FEATURES="go typst"` | `features.txt`, else every feature | Tools to build into the image, see [The image](#the-image) |
| `CLAUDE_AIRLOCK_MEMORY=32g` | `16g` | Memory limit. Below about 10g, `/tmp` and the other tmpfs shrink to fit in half of it |
| `CLAUDE_AIRLOCK_PIDS=1024` | `512` | Process limit |
| `CLAUDE_AIRLOCK_CPUS=4` | every CPU | CPU limit, a fraction like `1.5` works too. A session at its limit runs slower, nothing is ended |
| `CLAUDE_AIRLOCK_RUNTIME=runsc-hostnet` | Docker's own | Container runtime, as registered in Docker. For gVisor see [docs/sandbox.md](docs/sandbox.md#gvisor) |

The detail of each is in [docs/sandbox.md](docs/sandbox.md), of the two
records in [docs/trace.md](docs/trace.md).

### The config file

To change a default for every session, put the same variables in
`~/.config/claude-airlock/config`, one per line:

```
# ~/.config/claude-airlock/config
CLAUDE_AIRLOCK_MEMORY=8g
CLAUDE_AIRLOCK_NET_FILTER=1
CLAUDE_AIRLOCK_SHARED_DIR=/home/me/scratch
```

- The environment wins, so one session can override the file. A variable
  that is set but empty says nothing, the file is asked next, but for
  `CLAUDE_AIRLOCK_FEATURES` and `CLAUDE_AIRLOCK_SHARED_DIR`, where empty
  says none.
- Values are taken literally, without quotes. A leading `~` is your home
  directory in the settings that take a path. A value in quotes, or with
  blanks around it, stops the launcher: taken as it is, it would hide or
  protect nothing.
- A name given twice stops the launcher, as an unknown one does.
- The file is only read from your config directory, never from the
  project, which a session can write to.
- `CLAUDE_AIRLOCK_EXTRA_DIRS` and `CLAUDE_AIRLOCK_EXTRA_DIRS_RO` are not
  accepted there, extra directories belong to one project.
- `CLAUDE_AIRLOCK_SHADOW` and `CLAUDE_AIRLOCK_PROTECT` add up: what the file
  names and what the environment names both count.

## What the sandbox does

What a session is given and kept from: what is mounted and how, what is
read-only or hidden, the hardening of the container, the check of the files
that run code on the host when a session ends, and the opt-in doors (the SSH
agent, the Docker socket). See [docs/sandbox.md](docs/sandbox.md).

## Known limits

The sandbox contains what a session can reach, it does not make a
read-write project safe to trust blindly afterwards. A session is not asked
before it uses a tool unless `CLAUDE_AIRLOCK_ASK=1`, so all of this it can
do on its own, also when something it read told it to:

- What it reads is looked at for signs of that, and flagged (see
  [What it read](docs/trace.md#what-it-read)). The flag knows a few ways
  of writing: text in other words goes unflagged, and the session had
  read it either way. With `CLAUDE_AIRLOCK_INJECTION_STOP=1` line mode
  stops the turn for two of the signs, Claude Code's native UI stops
  for none.
- Anything in the project can be changed, including files that run code on
  the host later. The launcher warns about git's and Claude's own, and
  about the build files, hook managers and nested `CLAUDE.md` it knows by
  name (see [the check](docs/sandbox.md#the-check-when-a-session-ends)).
  It names them, it does not read them for you, and its list is not
  whole: a script a Makefile calls, what is in `node_modules`, and any
  build file it has no name for are still yours to review in the diff.
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
  It can replace it too: what a session writes as its login is carried to
  the host, as a renewal has to be, so a session can log the host's
  `claude` out, or into another account. Only what does not read as a
  login is kept from the host.
- The sandboxed sessions of every project share one `.claude.json`. An
  MCP server a session adds there is started by the next session of
  another project. The launcher says so when the session ends, it does
  not prevent it.
- The egress allowlist limits what a session can reach, not what it can
  send there. GitHub, npm and Anthropic's API, all on the list, take
  uploads from whoever holds a token, and a session needs none of yours:
  what it read can come with one of its own, to push to a repository or
  a gist, or to publish a package. With a forwarded SSH agent or a
  `GH_TOKEN` it does so as you.
- The filter goes by the name a connection asks the proxy for, and does
  not look into what is then sent over it. A name on the list that is
  served by a network of many sites (npm, PyPI and GitHub's files are)
  leads to that network's addresses, and a session can ask there for
  another site of the same network.
- Secrets that are not in a shadowed file (hard-coded, or in git history)
  are readable.
- What Python compiled of a project's modules (`__pycache__`) is run in
  the place of a module whose time and size it carries, and no diff
  shows it. A session can leave such a file. The launcher does not run
  its own from there, your tools still do: remove those directories
  before you run a project's Python on the host after a session you do
  not trust.
- Claude Code names the directory of a project's transcripts after its
  path, with every character that is no letter or digit as a dash. Two
  projects whose paths differ in such characters alone (`my-app` and
  `my_app`) share one, and a session of either reads what the other's
  sessions said and remember.

## Reviewing a session

`claude-airlock --trace` shows what the latest session of the project did, in
the order it happened: what it ran and why, what it wrote, and what it
reached on the network. `--trace --follow` shows it as it happens. See
[docs/trace.md](docs/trace.md).

## Line mode

A session runs in line mode by default: Claude Code with a simpler UI.
You get a prompt and, above it, what the session does in the lines of
`--trace`, as it happens. Why it is the default:

- **You see what a command did, not only that it ran.** Under each
  command are the connections made while it ran and how each ended, the
  files it changed, and who allowed it. The native UI shows none of
  that, a host an install reaches besides the registry goes unseen there.
- **It is the launcher's word, not the session's.** The network, the
  resource use and the doors are recorded from outside the sandbox, the
  session cannot leave them out.
- **What went wrong stands out.** A refused connection, a denied
  request, a failed command, a write outside the project and a possible
  prompt injection in what was read are in bold red and in capitals.
- **The cost is in sight.** Each step says the tokens it wrote and read,
  each turn its time and price, and the sandbox says every so often how
  much memory and CPU it uses.
- **It works anywhere.** Lines are only added, never redrawn, so it reads
  the same in a terminal, an Emacs shell buffer or a file, and scrolls
  back like any output.

`CLAUDE_AIRLOCK_LINE_MODE=0` gives the native UI back. See
[docs/line-mode.md](docs/line-mode.md).

![Two turns in line mode at a terminal: how the sandbox was started, then
under each command the connections it made and the files it changed, an
edit with its diff, and the memory and CPU the sandbox
uses](docs/img/line-mode.png)

## The image

The image is assembled from `docker/base.Dockerfile`, the features you pick
and `docker/tail.Dockerfile`. See [docs/image.md](docs/image.md) for the
features, how to add your own, the language servers and how versions are
pinned.

## Statusline

For Claude Code's native UI. The launcher has no statusline of its own
and adds none: the one of your `~/.claude/settings.json` works in the
sandbox as on the host. The file its command runs is mounted read-only
where the settings name it, whether it is the program
(`~/.claude/statusline.sh`) or the script an interpreter is given
(`bash ~/bin/statusline.sh`):

- It has to be a file of your home directory, named by its whole path.
  A command the image has (`npx some-statusline`) needs no mount.
- Only that file is mounted. What it runs has to be in the image (bash,
  `jq`, Python and Node.js are), and what it reads besides in a directory
  mounted with `CLAUDE_AIRLOCK_EXTRA_DIRS_RO`.
- A file whose name is one of secrets (`.env`, `.netrc`) is not mounted.
- Only the statusline of `~/.claude/settings.json` on the host, not one a
  project's settings name.
- It can show the sandbox from the variables a session has of how it was
  started, `env | grep CLAUDE_AIRLOCK_` in a session lists them: the name
  of the container, which is not set outside the sandbox, the network
  mode and the doors that are open.

[Line mode](#line-mode) does not run it. It shows a status of its own
above its prompt, made from what it knows of the session, with the
effort and the weekly limit of Fable while that is the model.

## Editor integration

Point your editor's Claude Code integration at `claude-airlock` instead of
`claude`. For Emacs with
[claude-code.el](https://github.com/stevemolitor/claude-code.el):

```elisp
(setq claude-code-program (executable-find "claude-airlock"))
```

- `CLAUDE_BUFFER_NAME`, which claude-code.el exports, gives parallel
  sessions on the same project distinct container names.
- That buffer runs in [line mode](#line-mode).
- No terminal emulator is needed: `claude-airlock` run from `M-x shell`
  works the same.

## Tests

```
make check          # ruff, shellcheck, mypy and the tests, as CI runs them
make test K=trace   # the tests with trace in their name
make smoke          # test/smoke/run.sh
make upgrade        # refresh the pins, then rebuild the image
```

- **The unit tests** (`test/test_*.py`, by topic) are run by pytest, side
  by side on every core, on fewer inside a sandbox to keep within its
  process limit. They run the launcher against a fake `docker`
  that records every call, and check what is mounted, shadowed and
  switched off by default, the tamper check, the records of a session,
  `--trace` and line mode.
- **The tools** (pytest, ruff, mypy) are the only dependencies, and only
  of the checks: `make` runs them through [uv](https://docs.astral.sh/uv/)
  at the versions and hashes of `uv.lock`, on a Python uv fetches when the
  machine has none recent enough. `uv run pytest test/test_trace.py` runs
  one file.
- **CI** runs them on Python 3.13 and the latest on Linux and on the
  latest on macOS, with ruff, mypy, shellcheck and a small image build.
- **The smoke test** (`test/smoke/run.sh`) is run by hand on the host
  against a real Docker daemon. It starts open, filtered and socket-proxy
  sessions in a throwaway project and checks the sandbox from the inside.
  The scripts that run inside a session are in `test/smoke/inside`, and
  the checks of what a session left on the host in `test/smoke/checks`.
  Run it after changing the launcher, the Dockerfile parts or the sidecar
  configuration, or after moving the checkout.
