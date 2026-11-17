# Line mode

A session runs in line mode by default: Claude Code without its
full-screen UI. Nothing else changes: `claude-docker` is run as before, with the
same arguments, and it is the same session in the same sandbox, recorded
and checked the same way. What you get is a prompt and, under it, what the
session does, in the lines `--trace` shows it in (see [Reading the
lines](trace.md#reading-the-lines)), the network included.

Claude Code's full-screen UI redraws itself as it goes, which takes a
terminal that keeps up with it and loses its place in one that does not.
Line mode only adds lines, as a line-mode terminal does.

What it shows that Claude Code's own UI does not, as it happens and under
the call that was running at the time (`during:`):

- Every connection the session opens, with its name and address, and how
  it ended when that went wrong (`REFUSED`, `NO ANSWER`), what it sends by
  UDP or ICMP, and plain HTTP requests, from the capture of its sidecar.
  A connection that closed as usual is not said again: Claude Code keeps
  its own open for minutes, and the end of each would bury the rest.
  `--trace` has them, with the bytes each way.
- With the egress filter, each request to the proxy, `DENIED` when refused.
- Lookups that stand out (`FLAGGED`).
- Each use of the SSH agent and of the Docker socket.
- What its subagents run and write, by `agent`.
- How long each call took, and per turn the time, tokens, cost and how
  full the context is.

Only this session's, not what the project's other sessions do at the same
time. Two things wait for `--trace` once the session is over: which
process made a connection (`by:`), and each process that ran.

- `CLAUDE_DOCKER_LINE_MODE=0 claude-docker` is one session with Claude
  Code's full-screen UI, and the setting in the config file gives it to
  every session. There, `claude-docker --line-mode` is one session in line
  mode.
- What has no conversation to show keeps running as it is: `-p`, a command
  of claude's (`claude-docker mcp list`), `--version`, and `--shell`.
- An editor that runs `claude-docker` in a terminal of its own gets line
  mode there too, see [Editor integration](../README.md#editor-integration).

```
# chat        /home/me/code/api, Ctrl-C interrupts a turn, Ctrl-D leaves
# time      who      what        details
> fix the build
# network     following the capture of claude-api
# day         2026-01-02
10:02:30  user     prompt      fix the build
10:02:41  claude   bash        [1] $ npm ci
                               why: Install the dependencies
allow bash $ npm ci? [y/a/N] y
10:02:42  sandbox  net         tcp/https registry.npmjs.org (104.16.3.35):443  during: [1] $ npm ci
10:02:49  claude   bash        [1] result: ok, 8.2s, 14 lines out
10:02:51  claude   reply
The build works again, `npm ci` had not been run since the lockfile changed.

# turn        21.3s, 1 call, 31.9k in, 412 out, $0.0412
# status      Opus 5.5 ctx:16% 5h:42% used 14:00 7d:10% used $0.04 [claude-api] net:filtered
# ready       claude has finished, waiting for your input
> /model sonnet
10:04:10  user     prompt      /model sonnet
10:04:10  claude   command
Set model to `Sonnet 5.5` for this session only

# turn        0.0s, 0 calls
# status      Opus 5.5 ctx:16% 5h:42% used 14:00 7d:10% used $0.04 [claude-api] net:filtered
# ready       claude has finished, waiting for your input
>
```

What it looks like:

- Lines are only ever added at the end. The one exception is the line you
  are typing, at a terminal: what is written meanwhile goes above it, and
  the line is written again under that. In a shell buffer of Emacs
  (`M-x shell`) or with the output in a file nothing is written twice.
- Every line has its time, a result says how long its call took, and the
  `turn` line how long the whole turn did, with the tokens it read and
  wrote, what it cost as claude counts it, how full the context is, and
  the model when it changed.
- Under it, the `ready` line says that claude has finished and the prompt
  is yours again, bright green in colour.
- Once you press Enter, the line you typed is written again in its place
  in reverse video, for what you said to stand out among what follows. In
  a shell buffer of Emacs, which shows what you typed itself, it is left
  as it is.
- Under a call, its `why:` line is what claude says it makes it for: the
  label bold and the reason in italics, in colour.
- A status heads the prompt, as a multi-line `PS1` would: the model, how
  full its context is, the limits of your account as far as claude says
  how much of them is used (yellow from 70%, red from 90%), what the
  session cost, and the sandbox: the container, the network mode, the
  doors that are open and the directories mounted next to the project.
  It stands above `> `, under what is written, and is written again in
  place when it changes. Each line you send keeps the status it was typed
  under. In a shell buffer of Emacs it is written with each prompt, and
  again when it changed. It is made again when a turn starts and ends,
  and with `/status`, which also says it in a line. Not above a question
  claude asks, nor above `. `. The model is the one that wrote the last
  reply, so `/model` shows from the next one. The `statusLine` command
  of your settings is for Claude Code's own screen and is not run here.
- At a terminal a reply is written line by line as claude makes it, from
  the left edge under a line that says when (`claude   reply`, bold and
  bright cyan in colour), and wrapped to the window. In
  a file it is written once it is whole, each line saying when and who as
  any other.
- In colour the Markdown of a reply is taken for what it means: code, in a
  block or between backticks, is green, headings and `**bold**` are bold,
  and the marks are left out. Without colour (a file, `NO_COLOR`) it is as
  claude wrote it. Code in a block is never wrapped.
- When claude takes no step for 5 seconds (no call made, no result back,
  nothing new started) a line says that the turn still runs, how long
  since that last step and what it waits for: `# working     35s, waiting
  for bash`, or `for claude` while it writes, `claude, thinking` while it
  thinks. At a terminal it is one line above the status, counted up in
  place every 5 seconds and gone with the next step. In a shell buffer of
  Emacs or a file it is written as a line, after 10 more seconds, 20, and
  so on up to a minute, the wait starting over with each step. What claude
  thinks is not shown, it does not say.
- What a subagent does shows as it does in a trace, by `agent`. Its start
  and its end are said (`# task        started: ...`), and so are a
  conversation being compacted, a request to the API that is tried again
  and a limit of the account that is near.

What you type:

- A line can be typed at any time. While a turn runs claude takes it up
  when it can: between two steps of that turn, or as a turn after it.
- When claude asks whether it may use a tool, `y` allows that one call and
  anything else refuses it. `a` allows it and what a line above the
  question names from now on: the rule Claude Code suggests for calls like
  it (`Bash(git status)`), which it then goes by itself, or where it has
  none to suggest every call of that tool. Until the session ends, and
  written to no settings. The terminal rings when a question is put, and
  when a turn that ran 30 seconds or more ends.
- A call whose line above was cut is shown whole first: the diff of an
  edit (in colour, what it takes out red and what it puts in green), a
  long command, the plan claude asks to go ahead with.
- The prompt is `> ` whatever the permission mode, `/mode` says which
  one it is.
- A question claude has for you lists its options, answered by number or
  in your own words.
- A line that was being typed when a question came is taken for the prompt
  it was meant as, not for the answer, and a line says so: at a terminal
  it stands after the question as if it were.
- Ctrl-C interrupts the turn that runs, a second one stops the session. At
  the prompt it drops the line. Ctrl-D, `/exit` or `/quit` leaves.
- A line that ends with a backslash takes the next one too, and so does
  Alt+Enter, with GNU readline. Shift+Enter does too once the terminal
  sends something of its own for it, most send Enter: `\e[13;2u` (iTerm2's
  CSI u mode, or a key mapped to it in kitty, WezTerm, Ghostty or foot),
  `\e[27;2;13~` (xterm's modifyOtherKeys) or Alt+Enter, what Claude Code's
  `/terminal-setup` maps it to. Lines pasted together are one prompt, at
  a terminal and in a shell buffer of Emacs alike, whether the terminal
  marks a paste or not. At a terminal a paste waits for Enter, so you
  can type on after it. In a shell buffer of Emacs, which sends nothing
  until Enter, a paste that does not end with a line break waits too. Tab completes
  the names of commands and of files (`@src/main.py`, which claude reads,
  an image too). The lines typed are kept for the next chat of the project.

| Line | Does |
| --- | --- |
| `/help` | Says what is in this table |
| `/model sonnet`, `/context`, `/usage`, `/compact`, `/clear`, your own commands and skills | Claude Code's commands that answer in text, as typed. What they say is shown as a reply is |
| `/mode plan` | Changes the permission mode, to any that Claude Code has (`default`, `acceptEdits`, `plan`...). `/mode` says which one it is in |
| `/resume`, `/resume 3fa9` | Leaves this session for an earlier one of the project, picked from a list or by the start of its id. It is another launch: this session is ended, recorded and checked first |
| `/mcp` | The MCP servers of the session and how each is |
| `/status`, `/statusline` | Says the status now, in place of Claude Code's own two, which are not there in line mode |
| `!make test` | Runs a command in the sandbox. Claude is not told and the transcript does not have it, the record of what ran does |

What to know:

- Arguments after `--line-mode` go to claude: `--permission-mode` and the like
  decide how often it asks, `--resume` and `--continue` which session it
  is. When you leave, a line says how to go on with the session.
- A prompt among those arguments is not taken, claude passes it over in
  this mode. Lines that are not typed are: `echo "fix the build" |
  claude-docker --line-mode` asks that and leaves, each line being a prompt, or
  the answer to what the one before led claude to ask.
- Something else claude asks its host for (a hook to be run, an MCP server
  that wants input) is refused, and a line says that it was asked.
- Of the network, the SSH agent and the Docker socket only what this
  session does is shown, not what the project's other sessions do.
- What is not there: the menus of Claude Code's screen (`/config`,
  `/permissions`, going back to an earlier point of the
  conversation), and its commands that open one, which answer that they are
  not available.
- Ctrl-C does not reach a command started with `!` once docker has let go
  of it, it runs on in the sandbox until it ends.

Claude Code runs in its print mode for this and speaks JSON Lines over its
standard input and output, the protocol of the Agent SDK. What the session
did, its calls, the network, its subagents, comes from the same records as
`--trace --follow`, so the two never disagree about it. What claude says,
its replies, is taken from the pipe as it is made: the transcript would
have it a moment late. The code is the `claude_sandbox/chat` package.
