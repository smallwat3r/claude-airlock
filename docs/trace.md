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
# files written
#   /home/me/code/api/Makefile x2
# network
#   captured in claude-api from 10:02:11 to 10:31:40
#   tcp/https registry.npmjs.org (104.16.3.35):443 x4
#   tcp/postgres 10.0.0.7:5432 x1
#
# time                 who      what        details
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
| `--verbose` | Commands, diffs and replies whole, the output of every call, each step of the model, lookup and process |
| `--only bash,net` | The events of the kinds named, by what the `what` column says |
| `--failed` | What went wrong: a failed call, a write outside the project, a refused request or connection, a lookup that stands out, what was taken out of the transcript |
| `--json` | JSON Lines, see [As JSON](#as-json) |
| `--follow` | The sessions as they run, see [Following a session](#following-a-session) |

## Reading the lines

| Column | Values |
| --- | --- |
| `who` | `user`, `claude`, `agent` (a subagent), or `sandbox`: what the launcher recorded of the container from outside, not what the transcript says |
| `what` | `prompt`, `reply`, `command`, `step`, the tool (`bash`, `edit`, `write`, `read`, ...), `net`, `dns`, `exec`, `ssh-agent` or `docker` |

- A command comes with the reason Claude gave for it (`why:`), how it
  ended and how many lines it put out.
- What went wrong is in capitals: `FAILED` for a call, `OUTSIDE PROJECT`
  for a file written there, `DENIED` for a request the egress filter
  refused.
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
| The egress proxy's log | `CLAUDE_DOCKER_NET_FILTER=1` | What the session asked the proxy for: method, host, allowed or `DENIED`, bytes and duration |
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
```

- The last line is that of a session run outside the sandbox.
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

With `--verbose` every process is a line of its own (`exec`). The sidecar
looks 25 times a second, so a process that lived shorter than that can be
missed. The session can neither stop it nor reach its record.

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
  lookups that stand out:
    4a6f...3d.x.example.com: an unusually long name
  written outside the project:
    /home/me/.bashrc
  the transcript of 3fa9c0de was changed: 3 lines the launcher copied are gone or altered
  ssh agent 4 requests, 2 signatures
```

A destination is known by its name, which is the session's own word. An
upload is said from 10 MB to one destination on, not for the model's API
and not for a filtered session, where everything goes to the proxy.

## What is kept

The records are under `~/.local/state/claude-sandbox`, but for the proxy's
log:

| What | Holds | How much |
| --- | --- | --- |
| `claude-egress-log`, a Docker volume | The proxy's log | About 20 MB at most |
| `captures` | The capture of each session | A few kB each as a rule, the latest 100 |
| `processes` | What ran in each session | A few hundred kB each as a rule, the latest 100 |
| `transcripts` | The launcher's copy of each transcript | For 30 days |
| `net-sessions.jsonl` | A line per recorded session | The latest 1000 |
| `door-use.jsonl` | A line per use of the SSH agent and the Docker socket | The latest 5000 |
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
- `--verbose`, `--json`, `--only` and `--failed` work as above:

```
claude-docker --trace --follow --json | jq -c 'select(.denied or .failed)'
```
