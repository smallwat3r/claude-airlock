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

That is how it looks in a file or a pipe: plain text, every line starting
with when, who and what, so any line `grep` finds says it all. On a
terminal an event says so once, and its other lines are indented under it:

```
# time      who      what        details
# day         2026-01-02
10:02:30  user     prompt      fix the build
10:02:41  claude   bash        $ npm ci
                               why: Install the dependencies
                               result: ok, 8.2s, 14 lines out
10:02:42  sandbox  net         tcp/https registry.npmjs.org (104.16.3.35):443  x4
```

## Options

| Option | Shows |
| --- | --- |
| `list` | The project's sessions with when each last did something, the latest first |
| `3fa9` | The session whose id starts so, instead of the latest |
| `--verbose` | Commands, diffs and replies whole, the output of every call, each step of the model, lookup and process |
| `--only bash,net` | The events of the kinds named, by what the `what` column says |
| `--failed` | What went wrong, see below |
| `--json` | JSON Lines, see [As JSON](#as-json) |
| `--follow` | The sessions as they run, see [Following a session](#following-a-session) |

- `--failed` picks: a failed call, a write outside the project, a refused
  request, a connection that was refused or not answered, a lookup that
  stands out, a signature the SSH agent refused, and what was taken out of
  the transcript.
- `--only` and `--failed` work with `--json` and `--follow`. The header
  stays that of the whole session, and says what is shown.
- On a terminal the result goes through your pager.
- Sessions run outside the sandbox in the same directory are listed too,
  Claude Code keeps them in the same place.

## Reading the lines

| Column | Values |
| --- | --- |
| `who` | `user`, `claude`, `agent` (a subagent), or `sandbox`: what the launcher recorded of the container from outside, not what the transcript says |
| `what` | `prompt`, `reply`, `command` (what a command of Claude Code's said, `/model` for one), `step`, the tool (`bash`, `edit`, `write`, `read`, ...), `net`, `dns`, `exec`, `ssh-agent` or `docker` |

- A tool of an MCP server shows by its own name without the server's. A
  name longer than the column is cut (`notebooke~`), `--json` has it whole.
- A command comes with the reason Claude gave for it (`why:`), its working
  directory when that is not the project (`cwd:`), how it ended and how
  many lines it put out.
- What went wrong is in capitals: `FAILED` for a call, `OUTSIDE PROJECT`
  for a file written there, `DENIED` for a request the egress filter
  refused.
- Long commands, diffs and replies are cut to a few lines. What a command
  feeds to another through a here-document (`python3 - <<'EOF'`) is said to
  be so many lines.
- The output of a call is shown when it failed: its first 2 lines and its
  last 6, the end is where a command says what went wrong. `--verbose`
  shows the first and last 10 lines of every call, never all: one `cat`
  can put out thousands.
- The same thing on the network several times in a row is one line with
  how often (`x4`). Claude Code's own connections come by the dozen and
  would bury the one a command made.
- A transcript does not say which container wrote it. So when several
  sessions of the project ran at the same time, the trace of one has what
  the others did on the network too, and each of those lines starts with
  the name of its container (`[claude-api-2]`).

With `--verbose`, a `step` line comes ahead of what one answer of the model
did, and says what that answer used:

```
claude   step        1.4k tokens out (300 thinking), 182.0k in (2.0k new)
```

- Out is what the model wrote.
- In is what it read, the whole conversation so far.
- New is the part added since the step before: the results of the calls
  before it, and your prompt.
- The API counts by step, not by tool call, so calls issued together share
  one line. The header sums the steps up (`tokens`).

The colours on a terminal make what the session did out of your sight stand
out:

| Colour | What |
| --- | --- |
| Yellow | Commands |
| Magenta | Files it wrote |
| Cyan | The network |
| Blue | Pages it fetched or searched for with its tools |
| Bold red | What went wrong |
| Dimmed | The conversation, which you saw anyway |

A file or a pipe gets plain text. `NO_COLOR=1` switches the colours off and
`FORCE_COLOR=1` on wherever the output goes, for an Emacs shell buffer say.

## As JSON

`--json` gives the same events as JSON Lines, one object each, nothing
shortened, for `jq` or to load into a database:

```
{"session": "3fa9c0de-...", "time": "2026-01-02T10:02:41.120+01:00", "who": "claude", "what": "bash", "tool": "Bash", "input": {"command": "npm ci", "description": "Install the dependencies"}, "cwd": "/home/me/code/api", "failed": false, "output": "...", "seconds": 8.2}
{"session": "3fa9c0de-...", "time": "2026-01-02T10:02:42.480+01:00", "who": "sandbox", "what": "net", "protocol": "tcp/https", "name": "registry.npmjs.org", "address": "104.16.3.35", "port": 443}
```

Every object has `session`, `time`, `who` and `what`, then:

| Event | Fields |
| --- | --- |
| Prompt, reply | `text` |
| Step | `output_tokens`, `thinking_tokens`, `input_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`, as the API names them. The three input counts add up to what the step read |
| Tool call | `tool`, `id`, `input`, `cwd`, `failed`, `seconds`, `output`, and `outside_project` for a file it wrote |
| Connection | `protocol`, `address`, `port`, `source_port`, `name`. When the capture tells, `outcome` (`closed`, `open`, `refused` or `no answer`), and for a closed one `seconds`, `bytes_out`, `bytes_in`. When its process was seen, `process` (`pid`, `exe`, `argv`, `parents`) |
| Sent by another protocol | `protocol`, `address`, `port`, `name`, `packets`, `bytes_out` |
| Plain HTTP request | `protocol`, `method`, `url`, `address`, `port` |
| Proxy request | `protocol`, `method`, `url`, `port`, `denied`, `bytes`, `seconds` |
| Lookup | `name`, `type`, `addresses`, `error`, and `flagged` when it stands out |
| Process | `pid`, `ppid`, `exe`, `argv` |
| SSH agent | `did` (`sign`, `list` or `other`), `key`, `comment`, `what` |
| Docker socket | `method`, `path`, `status`, `denied` |

What happened on the network also has `during`, the ids of the tool calls
running at that time. What the launcher recorded of a container (a
connection, a request, a lookup, a process) has `container`, its name. An
entry that was taken out of the transcript has
`removed`.

## The network

The network lines come from two records the launcher keeps. The session
cannot forge or edit either, both are taken outside of it.

| Record | Kept when | Holds |
| --- | --- | --- |
| The egress proxy's log | `CLAUDE_DOCKER_NET_FILTER=1` | What the session asked the proxy for: method, host, allowed or `DENIED`, bytes and duration. HTTPS shows as the host, not the URL |
| The capture | Unless `CLAUDE_DOCKER_NET_LOG=0` | Every TCP connection whatever the protocol, what was sent by anything but TCP, and every name looked up. Over IPv4 and IPv6 |

The proxy's log is shared by all sessions, so the launcher notes the address
each session's container had and picks its requests by that.

How the capture works:

- The session's route out is not changed. A sidecar that owns its network
  namespace captures the packets that say where a connection goes and how
  it went: its start, the answer to it and its end, the DNS answers, the
  TLS hello and the request line of plain HTTP.
- Of what goes out by UDP or another protocol every packet is taken, there
  a conversation has no start to pick out. It is read for where it went and
  how long it was.
- It works with the filter too, where it shows what a session tried to
  reach around the proxy.
- The name of a destination comes from the DNS answers and the TLS hello,
  a connection to a bare address shows as the address. The address is what
  was reached, the name is what the session looked up or asked for: trust
  the address where the two matter.
- Not recorded: what was sent, so of HTTPS neither the URL nor the content,
  and what comes in other than by TCP or as an answer of the resolver.

A line of the network says more than where to:

```
sandbox  net         tcp/https registry.npmjs.org (104.16.3.35):443  closed after 8.1s, 2 kB out, 41 MB in  during: $ npm ci
sandbox  net         tcp/postgres 10.0.0.7:5432  REFUSED  during: $ make test
sandbox  net         http GET http://deb.debian.org/debian/InRelease  during: $ apt-get update
sandbox  net         tcp/https api.anthropic.com (160.79.104.10):443  left open  (no call running)
sandbox  net         udp/https www.google.com (142.250.74.4):443  212 packets, 31 kB out
sandbox  net         icmp 10.0.0.7  3 packets, 252 B out
sandbox  dns         lookup registry.npmjs.org A -> 104.16.3.35, 104.16.0.35
sandbox  dns         lookup nope.internal A FAILED: no such name
sandbox  dns         lookup 4a6f...3d.x.example.com TXT FLAGGED: an unusually long name
```

| On the line | Means |
| --- | --- |
| `closed after` | How long the connection was open, with the bytes each way. From its sequence numbers, nothing of what was sent is kept |
| `left open` | The capture ended before the connection did |
| `REFUSED`, `NO ANSWER` | The other end refused, or the first attempt had to be sent again |
| `during:` | The tool call that was running when the connection was made, the innermost of several. By the clock, not proof |
| `(no call running)` | Claude Code itself (the API, its telemetry), or something a command left running |
| `by:` | The process that made the connection and those it comes from, see [What ran](#what-ran). Not by the clock: it was seen to hold the socket |
| `udp/...`, `icmp` | What went out by another protocol than TCP, one line per destination at the time of the first packet. QUIC shows as `udp/https` |
| `http GET ...` | A request over plain HTTP, the one kind that can be read |
| `lookup` | The kind of record asked for and the addresses that came back, or what the resolver said went wrong. With `--verbose` |
| `FLAGGED` | A lookup that stands out, shown without `--verbose` |

A lookup is flagged when its name is longer than names are (over 100
characters, or 40 in one label), or when it is the 30th different name
under one parent. Data can be carried out in the names a session asks a
resolver for, which takes long names or many of them. Some services do
this on their own, it is a prompt to look.

## The transcript

The transcript is written from inside the sandbox, a session could rewrite
its own. So while a session runs, the launcher copies what the project's
transcripts gain to its state directory, half a second or so after it is
written, and `--trace` compares the two. The `transcript` line of the
header says what came of it:

```
# transcript  as the launcher copied it (212 lines)
# transcript  CHANGED: 3 lines the launcher copied are gone or altered, they are shown as REMOVED
# transcript  as it is now, the launcher has no copy of it to compare
```

- What the copy has and the transcript no longer does is shown where it
  happened, marked `REMOVED FROM THE TRANSCRIPT`. `--failed` picks it out.
- The last line is that of a session run outside the sandbox, or before
  copies were kept.
- Still out of reach: a line a session takes back within the moment before
  it is copied.
- A subagent has a transcript of its own, next to that of its session. What
  it did is in the trace by `agent`, its writes and calls count in the
  header, and its transcript is copied and compared the same way. A
  `subagents` line says so when a session had any:

```
# subagents   2, as the launcher copied them (41 lines)
# subagents   2, CHANGED: 1 lines the launcher copied are gone or altered, they are shown as REMOVED
```

## What ran

The transcript says what a tool call was, not what the command it ran went
on to do. Unless `CLAUDE_DOCKER_PROC_LOG=0`, a second sidecar joins the
session's process and network namespaces and notes, from `/proc`, each
process it sees and the processes that hold each TCP connection. `--trace`
ties a connection of the capture to its process by its ports:

```
sandbox  net   tcp/https example.com (93.184.215.14):443  closed after 0.2s, 1 kB out, 2 kB in  by: [812] curl -sS https://example.com < bash < claude  during: $ make deploy
```

With `--verbose` every process is a line of its own (`exec`), with its
program and its parent. The program is named as it really is (`exe`), what
a process calls itself is its own to choose.

What to know about the sidecar:

- It looks 25 times a second, it is not told: nothing short of privileges
  it should not have reports every start of a process. What lived shorter
  than that can be missed, and a connection without a `by:` falls back on
  `during:`.
- It comes up a moment after the session.
- It does not tie what goes out by UDP to a process.
- It runs as root without capabilities, so the session can neither stop it
  nor reach its record.
- It costs a few percent of one core.

## The SSH agent and the Docker socket

A session started with `CLAUDE_DOCKER_SSH_AGENT=1` or `CLAUDE_DOCKER_SOCKET`
has each use of them noted by the launcher:

```
sandbox  ssh-agent   listed the keys, 2 of them
sandbox  ssh-agent   signed a login as git with SHA256:Xk3... (me@laptop)
sandbox  ssh-agent   asked for a signature for git with SHA256:Xk3... (me@laptop)  REFUSED by the agent
sandbox  docker      GET /v1.47/containers/json 200
sandbox  docker      POST /v1.47/containers/create 403  DENIED
```

A signature says which key was asked and what for, as far as what was
signed tells: a login says as whom, to which host is the connection next
to it. The header counts both.

## When a session ends

The launcher says what is worth a look, next to its check of the files
that can run commands on the host:

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

- It is silent when there is nothing of this, and about the first recorded
  session of a project, whose destinations are all new.
- A destination is known by its name where it has one, addresses change
  too often to go by. The name is the session's own word: a session that
  wants to pass for a known name can, the trace has the address.
- An upload is said from 10 MB to one destination on. Not for the model's
  API, told by Anthropic's published addresses and not by name. And not
  for a filtered session, where everything goes to the proxy.

## What is kept

All of it under `~/.local/state/claude-sandbox`, but for the proxy's log:

| What | Holds | How much |
| --- | --- | --- |
| `claude-egress-log`, a Docker volume | The proxy's log, which so survives a proxy restart | Rotated past 10 MB when a filtered session starts, one rotated file kept, about 20 MB at most |
| `captures` | The capture of each session | A few kB each as a rule, the latest 100. One stops at 100,000 packets, about 100 MB at the very worst, and the trace says so |
| `net-sessions.jsonl` | A line per recorded session | The latest 1000 |
| `transcripts` | The launcher's copy of each transcript a sandboxed session wrote to | For 30 days, as long as Claude Code keeps its own by default. As large as the transcripts are, each up to 512 MB |
| `processes` | What ran in each session | A few hundred kB each as a rule and 20 MB at most, the latest 100 |
| `door-use.jsonl` | A line per use of the SSH agent and the Docker socket | The latest 5000 |
| `destinations.json` | What each project is known to reach | 2000 destinations per project |
| `names`, `proxies`, `sidecars.lock` | Not records: what the running launchers hold a lock on, so that two do not take the same container name, start the same proxy at once or remove one another still uses | Empty files |
| `agents`, `pending-checks`, `login-synced` | Not records: the sockets in front of the SSH agent, where each running session started from for the check when it ends, and the login the host and the sandbox last had in common | A few small files |
| `line-mode-history` | Not a record: the lines you typed in `--line-mode`, a file per project, for the arrow keys of the next one. Never mounted into a session | The latest 1000 lines |
| `history` | Not a record: what the sessions of each project remember, see [What is read-only or hidden](sandbox.md#what-is-read-only-or-hidden). The one part mounted into a session | As much as Claude Code writes |

- `docker volume rm claude-egress-log` (with the proxy removed) clears the
  proxy's log.
- A capture and a record of processes are copied out when the launcher
  returns. A launcher that is told to end (a killed Emacs buffer, a closed
  terminal, `kill`) stops its session first and then returns as after any
  session. The sidecars of a session that ended without it (`kill -9`, a
  crash) are collected by the next `claude-docker` launch.

## Following a session

`claude-docker --trace --follow`, run on the host in a second terminal, shows
the same lines while the sessions of the project run, until you interrupt
it:

```
# following   /home/me/code/api, until interrupted
# time                 who      what        details
# network     following the capture of claude-api
# 41 earlier events, see claude-docker --trace
# session     3fa9c0de-...  Fix the build
2026-01-02 10:02:41  claude   bash        [7] $ npm ci
2026-01-02 10:02:41  claude   bash        why: Install the dependencies
2026-01-02 10:02:42  sandbox  net         tcp/https registry.npmjs.org (104.16.3.35):443  during: [7] $ npm ci
2026-01-02 10:02:49  claude   bash        [7] result: ok, 8.2s, 14 lines out
```

It needs nothing from the session and changes nothing about it, so it can be
started and stopped at any time, before the session too.

Which sessions:

- It starts with the last 10 events of the latest session, then follows
  every session of the project that does something. One you start, resume
  or clear later is picked up, and a `# session` line says whose lines
  come next.
- The start of a session id follows that session alone.
- What the subagents of a followed session do shows with it, by `agent`:
  Claude Code keeps a transcript of each next to that of its session.

What differs from the trace of a session that is over:

- A tool call shows when it is issued, and its result on a line of its own
  when that comes. The two have the same number (`[7]`), which tells apart
  the results of calls that ran together.
- When something else came between the two, the result also names its call
  (`of: $ npm ci`). Always so with `--only` or `--failed`, where the call
  itself may not be shown.
- A connection shows with the name known when it was made, and what became
  of it on a line of its own when it does.
- A tunnel through the proxy is logged when it closes, so it shows then, at
  the time it began. A refused request shows at once.
- The uses of the SSH agent and of the Docker socket show as they are
  noted. Which process made a connection does not, `--trace` tells that
  once the session is over.
- Of a prompt or a reply only the first line is shown, with `--verbose`
  too: you are after what the session does, what it says is on its own
  screen.

`--verbose`, `--json`, `--only` and `--failed` work as above. With `--json`:

- A prompt or reply is there whole.
- A call and its result are two objects that share an `id`, with `stage`
  set to `call` or `result`.
- A connection has `stage` set to `open`, then `outcome`, and carries the
  id of the session that wrote last.

```
claude-docker --trace --follow --json | jq -c 'select(.denied or .failed)'
```
