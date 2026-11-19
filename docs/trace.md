# Reviewing a session

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
# instructions read
#   /home/me/.claude/CLAUDE.md (User)
#   /home/me/code/api/CLAUDE.md (Project)
# files written
#   /home/me/code/api/Makefile x2
# sandbox     claude-api under runc, memory 16g, processes 512, all CPUs, network open
# network
#   captured in claude-api from 10:02:11 to 10:31:40
#   tcp/https registry.npmjs.org (104.16.3.35):443 x4
#   tcp/postgres 10.0.0.7:5432 x1
#
# time                 who      what        details
2026-01-02 10:02:11  sandbox  started     claude-api under runc, image claude-code-sandbox:1a2b3c4d5e6f
2026-01-02 10:02:11  sandbox  started     limits: memory 16g, processes 512, all CPUs
2026-01-02 10:02:11  sandbox  started     network: open
2026-01-02 10:02:11  sandbox  started     recorded: connections, processes
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

That is how it looks in a file or a pipe: every line starts with when, who
and what, so any line `grep` finds says it all. On a terminal an event
says so once, its other lines are indented under it, and the result goes
through your pager.

## Options

| Option | Shows |
| --- | --- |
| `list` | The project's sessions, the latest first |
| `3fa9` | The session whose id starts so, instead of the latest |
| `--verbose` | Commands, diffs and replies whole, the output of every call, each step of the model, lookup and process, what the language server reported |
| `--only bash,net` | The events of the kinds named, by what the `what` column says |
| `--failed` | What went wrong: a call that failed or was not allowed to run, a write outside the project, a refused request or connection, a request the API did not answer, a lookup that stands out, what was taken out of the transcript, a line of it that cannot be read |
| `--json` | JSON Lines, see [As JSON](#as-json) |
| `--follow` | The sessions as they run, see [Following a session](#following-a-session) |

## Reading the lines

| Column | Values |
| --- | --- |
| `who` | `user`, `claude`, `agent` (a subagent), or `sandbox`: what the launcher recorded of the container from outside, not what the transcript says |
| `what` | `prompt`, `reply`, `command`, `step`, the tool (`bash`, `edit`, `write`, `read`, ...), `context`, `mode`, `model`, `api`, `compact`, `task` (see [Besides the calls](#besides-the-calls)), `started` (see [How the sandbox was started](#how-the-sandbox-was-started)), `net`, `dns`, `exec`, `listen`, `health`, `ssh-agent`, `docker`, `changed` (Claude Code no longer says something as [line mode](line-mode.md#how-it-works) reads it) or `transcript` (a line of it that cannot be read) |

- A command comes with the reason Claude gave for it (`why:`), how it
  ended and how many lines it put out.
- A command that changed files says which (`changed:`) and how many
  lines each gained and lost. See [What a command wrote](#what-a-command-wrote).
- A call says who allowed it when that was not the permission mode of
  the session: `allowed by you, once`, `allowed by a rule`.
- What went wrong is in capitals: `FAILED` for a call, `REFUSED by` for
  one that was not allowed to run, `INTERRUPTED` for one that was cut
  short, `OUTSIDE PROJECT` for a file written there, `DENIED` for a
  request the egress filter refused.
- A prompt typed while claude worked says so, claude was given it with
  the next result.
- Long commands, diffs and replies are cut to a few lines, and the output
  of a call is shown only when it failed. `--verbose` shows more.
- The same thing on the network several times in a row is one line with
  how often (`x4`).
- When several sessions of the project ran at the same time, the trace of
  one has what the others did on the network too, each of those lines
  starting with the name of its container (`[claude-api-2]`).

On a terminal the colours make what the session did out of your sight
stand out: commands are yellow, files it wrote magenta, the network cyan,
what went wrong bold red, and the conversation is dimmed. `NO_COLOR=1`
switches them off, `FORCE_COLOR=1` on wherever the output goes.

## What a command wrote

```
claude   bash   $ sed -i 's/go build .\/../go build .\/.../' Makefile && echo done >> ~/.bashrc
claude   bash   result: ok, 0.1s
claude   bash   changed: /home/me/code/api/Makefile (+1 -1)
claude   bash   changed: /home/me/.bashrc (+1 -0)  OUTSIDE PROJECT
```

- What changed in each file is not shown, the diff is in `--json`.
- Of a command that changed many files the first 50 are named, and how
  many more there are. `--verbose` names them all.

- These files are counted under `files written` in the header, and one
  outside the project is among what `--failed` keeps and what the
  launcher says [when a session ends](#when-a-session-ends).
- It is what Claude Code noticed of the command, not all a command can
  write: a file it had not seen before may be missing. The record of
  [what ran](#what-ran) says which processes there were.
- A result also says what an exit code means when that is no failure
  (`No matches found`), and where the output is kept when it was too
  long to give claude whole (`output kept:`).

## Besides the calls

Some lines tell of nothing claude did, they say why it did what it did:

```
claude   context  instructions: /home/me/.claude/CLAUDE.md (User, 1.2k chars)
claude   context  instructions: /home/me/code/api/CLAUDE.md (Project, 4.0k chars)
claude   context  MCP server instructions: github
claude   context  skills: 12 listed
claude   context  changed since claude read it: /home/me/code/api/main.go
claude   mode     permissions: bypassPermissions  was: default
claude   model    claude-opus-5-5, effort high  was: claude-fable-5-2, effort medium
claude   api      API error: No response from API, tried again after 0.5s (retry 1 of 10)
claude   compact  the conversation was compacted (auto), 152.3k tokens before
claude   task     completed: Agent "review" finished
```

| `what` | Says |
| --- | --- |
| `context` | What Claude Code put before the model next to the prompt: each file of instructions it read (a `CLAUDE.md`, its memory) with where it is from, the MCP servers that brought instructions, the skills it listed, a file that changed since claude read it. With `--verbose` what the language server reported after an edit |
| `mode` | The permission mode changed. The one the session started in is in the header |
| `model` | Another model, or another effort, than the request before |
| `api` | A request the API did not answer or refused, which Claude Code tried again |
| `compact` | The conversation was summed up to make room: from there on claude knows what came before by the summary |
| `task` | A subagent, or a command left to run, ended |

- A file of instructions steers a session as a prompt does, and a
  `Project` one came with the repository. The header lists them all
  (`instructions read`), a line comes when the set of them changes.
- With `--verbose` a step that could not read the conversation from the
  cache says so, with how much it read at full price and why when the
  transcript tells:

```
claude   step   754 tokens out, 405.1k in (372.4k new)  cache MISSED, 372.4k read anew: 107 thinking blocks dropped, model mismatch
```

## As JSON

`--json` gives the same events as JSON Lines, one object each, nothing
shortened, for `jq` or to load into a database:

```
{"session": "3fa9c0de-...", "time": "2026-01-02T10:02:41.120+01:00", "who": "claude", "what": "bash", "tool": "Bash", "input": {"command": "npm ci", "description": "Install the dependencies"}, "cwd": "/home/me/code/api", "failed": false, "output": "...", "seconds": 8.2}
{"session": "3fa9c0de-...", "time": "2026-01-02T10:02:42.480+01:00", "who": "sandbox", "what": "net", "protocol": "tcp/https", "name": "registry.npmjs.org", "address": "104.16.3.35", "port": 443}
```

Every object has `session`, `time`, `who` and `what`, the rest depends on
the event. What happened on the network also has `during`, the ids of the
tool calls running at that time.

## The network

The network lines come from two records the launcher keeps outside the
session, which can neither forge nor edit them:

| Record | Kept when | Holds |
| --- | --- | --- |
| The egress proxy's log | `CLAUDE_DOCKER_NET_FILTER=1` | What the session asked the proxy for: method, host, allowed or `DENIED`, the bytes each way and duration |
| The capture | Unless `CLAUDE_DOCKER_NET_LOG=0` | Every TCP connection whatever the protocol, what was sent by anything but TCP, and every name looked up |

The capture is taken by a sidecar that shares the session's network
namespace. It records where a connection went and how it ended, not what
was sent: of HTTPS neither the URL nor the content.

```
sandbox  net         tcp/https registry.npmjs.org (104.16.3.35):443  closed after 8.1s, 2 kB out, 41 MB in  during: $ npm ci
sandbox  net         tcp/postgres 10.0.0.7:5432  REFUSED  during: $ make test
sandbox  net         tcp/https api.anthropic.com (160.79.104.10):443  left open  (no call running)
sandbox  net         udp/https www.google.com (142.250.74.4):443  212 packets, 31 kB out
sandbox  dns         lookup 4a6f...3d.x.example.com TXT FLAGGED: an unusually long name
```

| On the line | Means |
| --- | --- |
| `closed after` | How long the connection was open, with the bytes each way |
| `REFUSED`, `NO ANSWER` | The other end refused, or did not answer |
| `during:` | The tool call that was running when the connection was made. By the clock, not proof |
| `(no call running)` | Claude Code itself (the API), or something a command left running |
| `by:` | The process that made the connection, see [What ran](#what-ran) |
| `FLAGGED` | A lookup that stands out: a very long name, or many different names under one parent. Data can be carried out that way, it is a prompt to look |

The name of a destination is what the session looked up or asked for, the
address is what was reached. Trust the address where the two matter.

## The transcript

The tool calls come from Claude Code's transcript, which is written from
inside the sandbox, so a session could rewrite its own. While a session
runs, the launcher copies what the transcript gains, and `--trace`
compares the two. The header says what came of it:

```
# transcript  as the launcher copied it (212 lines)
# transcript  CHANGED: 3 lines the launcher copied are gone or altered, they are shown as REMOVED
# transcript  as it is now, the launcher has no copy of it to compare
# transcript  REMOVED, it is no longer there: the 212 lines the launcher copied are shown as REMOVED
# transcript  NOT ALL COPIED: the launcher stops at 512 MB, what came later cannot be compared
# transcript  1 lines CANNOT BE READ, shown as UNREADABLE: what was done there is not told
```

- The third line is that of a session run outside the sandbox.
- All of [Besides the calls](#besides-the-calls), who allowed a call and
  what a command changed are the transcript's word too.
- A session that removed its transcript is still listed and traced, from
  the launcher's copy, for as long as that is kept.
- A line that holds no entry is not Claude Code's doing: half a line
  written ahead of an entry makes that entry unreadable. It is shown as
  `UNREADABLE`, with `--failed` too.
- The copy is made half a second or so after a line is written. One a
  session takes back within that moment is out of reach.
- The transcripts of subagents are copied and compared the same way.

## What ran

The transcript says what a tool call was, not what the command it ran went
on to do. Unless `CLAUDE_DOCKER_PROC_LOG=0`, a second sidecar notes each
process it sees in the session and which one holds each connection:

```
sandbox  net   tcp/https example.com (93.184.215.14):443  closed after 0.2s, 1 kB out, 2 kB in  by: [812] curl -sS https://example.com < bash < claude  during: $ make deploy
```

A socket that starts to wait for connections is a line too (`listen`),
with the process that holds it. One that waits on more than the session's
own loopback is `OPEN to its network`, where the other sessions that run
can reach it, those of other projects too.

```
sandbox  listen  tcp 0.0.0.0:8080  OPEN to its network  by: [812] node server.js < bash < claude
```

With `--verbose` every process is a line of its own (`exec`). The sidecar
looks 25 times a second, so a process that lived shorter than that can be
missed. The session can neither stop it nor reach its record.

The same sidecar notes how the session is doing (`health`), every 30
seconds: the memory it holds, the CPU it used since the line before (100%
is one CPU), its processes, any tmpfs that is half full or more, and its
largest process. The figures are those of the container's cgroup, read
from outside the session.

```
sandbox  health  mem 3.1g of 16g (19%)  cpu 240%  pids 87 of 512  top: [812] node 2g
sandbox  health  ALMOST OUT OF memory  mem 15g of 16g (93%)  cpu 96%  pids 91 of 512  waited for: memory 35%  top: [812] node 13g
sandbox  health  OUT OF MEMORY, a process was ended for it  gone since: [812] node 14g
```

Under [gVisor](sandbox.md#gvisor) there is no such sidecar. Processes are
not recorded, and the launcher records the memory and CPU use of the
session itself, along with the time it waited for memory, CPU or disk.

- A line comes out of turn when the session first uses 70% of its
  memory, its processes or a tmpfs (`running low on`), and 90% (`ALMOST
  OUT OF`). At 90%, and when it spent a tenth of the time waiting for
  memory (`STALLED`), the line is one of those `--failed` keeps.
- `waited for` is the share of the time something in the session stood
  still for want of memory, CPU or disk, as the kernel counts it. High
  use alone is often harmless, this says whether it hurt.
- `held back` is the time the session was slowed at `CLAUDE_DOCKER_CPUS`.
- When the kernel ends a process for want of memory it does not say
  which. `gone since` names the large ones that were there a second
  before and are not any more: the likely ones, not proof.
- The header of a trace sums it up: the most memory held, the CPU used
  on average and at most, and what else came near its limit.
- `--only health` shows these lines alone, `--json` has every figure,
  each tmpfs and the three largest processes.
- Memory is written as `CLAUDE_DOCKER_MEMORY` is, in units of 1024
  (`3.1g`, `512m`), so a figure can be held against the limit as it was
  set. What went over the network is in units of 1000 (`14 MB`), as
  network tools count.
- It takes cgroup v2. On a host with version 1 the lines are not there.

## How the sandbox was started

The settings of today are not those a session ran with, so the launcher
notes how it starts each session, and when it is over. A trace has it in
its header (`sandbox`) and as its first lines:

```
sandbox  started  claude-api under gVisor (runsc-hostnet), image claude-code-sandbox:1a2b3c4d5e6f
sandbox  started  limits: memory 8g, processes 512, cpus 4
sandbox  started  network: filtered to the allowed domains
sandbox  started  recorded: connections, memory and CPU use
sandbox  started  open: ssh-agent, docker:ps
sandbox  started  mounted: /home/me/code/lib (ro)
```

| Line | Says |
| --- | --- |
| The first | The container, the runtime it runs under (`gVisor (name)` under [gVisor](sandbox.md#gvisor), else the name of the runtime, `runc` as a rule) and its image |
| `limits` | `CLAUDE_DOCKER_MEMORY`, `CLAUDE_DOCKER_PIDS` and `CLAUDE_DOCKER_CPUS` as they were set |
| `network` | Whether `CLAUDE_DOCKER_NET_FILTER` was on |
| `recorded` | What the launcher kept of the session from outside it: its connections, its processes, or under gVisor its memory and CPU use alone |
| `open` | What was open that is closed by default: the SSH agent, the Docker socket, a writable `~/.claude` config, the history of other projects, the connectors, telemetry. Not there when nothing was |
| `mounted` | The directories mounted next to the project. Not there without any |

- It is of the session, not of the settings: the SSH agent is only named
  when the host had one to forward.
- A session that goes on in a new container (`--resume`) has a start for
  each, and so has each of several sessions that ran at the same time.
- `--trace --follow` shows a start when a session starts, line mode
  before the first prompt.

## The SSH agent and the Docker socket

A session started with `CLAUDE_DOCKER_SSH_AGENT=1` or `CLAUDE_DOCKER_SOCKET`
has each use of them noted by the launcher:

```
sandbox  ssh-agent   signed a login as git with SHA256:Xk3... (me@laptop)
sandbox  docker      POST /v1.47/containers/create 403  DENIED
```

## When a session ends

The launcher says what is worth a look, and is silent when there is
nothing:

```
claude-docker: of this session, claude-docker --trace has the rest:
  reached for the first time from this project:
    tcp/https transfer.example (203.0.113.9):443
  sent 14 MB to tcp/https gist.github.com (140.82.121.4):443
  refused by the egress filter:
    example.org:443 x3
  ran into its memory limit of 16g, what it ran was ended for it: CLAUDE_DOCKER_MEMORY sets the limit
  ran into its limit of processes 3 times, what it tried to start then did not: CLAUDE_DOCKER_PIDS sets the limit
  lookups that stand out:
    4a6f...3d.x.example.com: an unusually long name
  waited for connections, open to the other sessions on its network:
    tcp 0.0.0.0:8080
  written outside the project:
    /home/me/.bashrc
  the transcript of 3fa9c0de was changed: 3 lines the launcher copied are gone or altered
  the transcript of 3fa9c0de was removed, --trace shows the launcher's copy of it
  ssh agent 4 requests, 2 signatures
```

A destination is known by its name, which is the session's own word. An
upload is said from 10 MB to one destination on, not for the model's API.
Of a filtered session it is what the proxy's log says went up to each
host, a tunnel is logged when it closes.

## What is kept

The records are under `~/.local/state/claude-sandbox`, but for the proxy's
log:

| What | Holds | How much |
| --- | --- | --- |
| `claude-egress-log`, a Docker volume | The proxy's log | About 20 MB at most |
| `captures` | The capture of each session | A few kB each as a rule, the latest 100 |
| `processes` | What ran in each session, 20 MB each at most, of which 4 MB are kept for its connections | A few hundred kB each as a rule, the latest 100 |
| `transcripts` | The launcher's copy of each transcript | For 30 days |
| `net-sessions.jsonl` | A line per recorded session | The latest 1000 |
| `door-use.jsonl` | A line per use of the SSH agent and the Docker socket | The latest 5000 |
| `session-starts.jsonl` | How each session was started, and when it was over | The latest 2000 lines |
| `claude-code-changes.jsonl` | A line per change line mode found in what Claude Code says | The latest 1000 |
| `destinations.json` | What each project is known to reach | 2000 destinations per project |

The directory also holds what is not a record: the launcher's locks, the
lines typed in line mode, and `history`, what the sessions of each project
remember (see
[What is read-only or hidden](sandbox.md#what-is-read-only-or-hidden)).

## Following a session

`claude-docker --trace --follow`, run on the host in a second terminal,
shows the same lines while the sessions of the project run, until you
interrupt it. It needs nothing from the session and changes nothing about
it, so it can be started and stopped at any time.

```
# following   /home/me/code/api, until interrupted
# session     3fa9c0de-...  Fix the build
2026-01-02 10:02:41  claude   bash        [7] $ npm ci
2026-01-02 10:02:41  claude   bash        why: Install the dependencies
2026-01-02 10:02:42  sandbox  net         tcp/https registry.npmjs.org (104.16.3.35):443  during: [7] $ npm ci
2026-01-02 10:02:49  claude   bash        [7] result: ok, 8.2s, 14 lines out
```

- A tool call shows when it is issued, and its result on a line of its own
  when that comes. The two have the same number (`[7]`).
- The start of a session id follows that session alone.
- How the session is doing (`health`) shows every 30 seconds, and within
  about 10 seconds when a limit is near or a process was ended for want
  of memory. Line mode shows the same lines among what the session does.
- `--verbose`, `--json`, `--only` and `--failed` work as above:

```
claude-docker --trace --follow --json | jq -c 'select(.denied or .failed)'
```
