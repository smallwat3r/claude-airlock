# Line mode

Line mode is Claude Code without its full-screen UI. You type at a prompt,
and under it the session writes what it does, in the lines `--trace` shows
it in (see [Reading the lines](trace.md#reading-the-lines)), the network
included.

It is the default. Nothing else changes: `claude-docker` takes the same
arguments, and it is the same session in the same sandbox, recorded and
checked the same way.

Why: Claude Code's full-screen UI redraws itself as it goes, which needs a
terminal that keeps up with it. Line mode only adds lines, so it works in
a terminal, a shell buffer of Emacs (`M-x shell`) or a file alike.

![A turn in line mode at a terminal. Under each command, in cyan, the
connections it made: the package registry and a second host during an
install, then a database that refuses the connection, in red, during a
test run that fails](line-mode.png)

The cyan lines are what Claude Code's own UI does not show: every
connection the session opens, under the command that was running at the
time. Here the install reaches a second host besides the registry, and the
tests fail because the database refuses the connection.

## An example

The same in text, with the egress filter on and a command of Claude Code's
after the turn:

```
# chat        /home/me/code/api, /help says what there is
# time      who      what        details
[claude-api] net:filtered
> fix the build
# network     following the capture of claude-api
# day         2026-01-02
10:02:30  user     prompt      fix the build
10:02:41  claude   bash        [1] $ npm ci
                               why: Install the dependencies
10:02:42  sandbox  net         tcp/https registry.npmjs.org (104.16.3.35):443  during: [1] $ npm ci
10:02:49  claude   bash        [1] result: ok, 8.2s, 14 lines out
10:02:51  claude   reply
The build works again, `npm ci` had not been run since the lockfile changed.

# turn        21.3s, 1 call, 31.9k in, 412 out, $0.0412
# ready       claude has finished, waiting for your input
Opus 5.5 ctx:16% 5h:42% used 14:00 7d:10% used $0.04 [claude-api] net:filtered
> /model sonnet
10:04:10  user     prompt      /model sonnet
10:04:10  claude   command
Set model to `Sonnet 5.5` for this session only

# ready       claude has finished, waiting for your input
Sonnet 5.5 ctx:16% 5h:42% used 14:00 7d:10% used $0.04 [claude-api] net:filtered
>
```

## What you type

A line can be typed at any time. While a turn runs, claude takes it up
when it can: between two steps of that turn, or as a turn after it.

| Key | Does |
| --- | --- |
| Enter | Sends the line |
| Ctrl-C | Interrupts the turn that runs, a second one stops the session. At the prompt it drops the line |
| Ctrl-D, `/exit`, `/quit` | Leaves. A line then says how to go on with the session |
| Tab | Completes the names of commands and of files (`@src/main.py`, which claude reads, an image too) |
| Up, Down | The lines typed before, kept from one chat of the project to the next |

| Line | Does |
| --- | --- |
| `/help` | Says what is in this table |
| `/model sonnet`, `/context`, `/usage`, `/compact`, `/clear`, your own commands and skills | Claude Code's commands that answer in text, as typed. What they say is shown as a reply is |
| `/mode plan` | Changes the permission mode, to any that Claude Code has (`default`, `acceptEdits`, `plan`...). `/mode` says which one it is in |
| `/resume`, `/resume 3fa9` | Leaves this session for an earlier one of the project, picked from a list or by the start of its id. It is another launch: this session is ended, recorded and checked first |
| `/mcp` | The MCP servers of the session and how each is, as claude said at the start of the last turn |
| `/status`, `/statusline` | Says the status now |
| `!make test` | Runs a command in the sandbox and shows what it writes, a line at a time. Claude is not told and the transcript does not have it, the record of what ran does |

Claude Code's menus are not there (`/config`, `/permissions`, going back to
an earlier point of the conversation). Its commands that open one answer
that they are not available.

### More than one line

- A line that ends with a backslash takes the next one too.
- Lines pasted together are one prompt. At a terminal a paste waits for
  Enter, so you can type on after it. A shell buffer of Emacs sends
  nothing until Enter either way.
- Alt+Enter starts a new line, with GNU readline.
- Shift+Enter does too, once the terminal sends something of its own for
  it. Most send Enter. What is understood: `\e[13;2u` (iTerm2's CSI u
  mode, or a key mapped to it in kitty, WezTerm, Ghostty or foot),
  `\e[27;2;13~` (xterm's modifyOtherKeys), and Alt+Enter, which is what
  Claude Code's `/terminal-setup` maps it to.

### When claude asks

When claude asks whether it may use a tool:

| Answer | Does |
| --- | --- |
| `y` | Allows that one call |
| `a` | Allows it, and from now on what the line above the question names: the rule Claude Code suggests for calls like it (`Bash(git status)`), or every call of that tool where it suggests none. Until the session ends, written to no settings |
| Anything else | Refuses it |

- A call whose line was cut is shown whole first: the diff of an edit, a
  long command, the plan claude asks to go ahead with.
- A question claude has for you lists its options. Answer by number, or in
  your own words.
- A line you were typing when a question came is not taken for the answer.
  A line says so, enter it or drop it (Ctrl-U) first.
- What the session does goes on being shown above a question that waits,
  a subagent that works on is not held up. Questions are put one at a
  time.
- The terminal rings when a question is put, and when a turn that ran 30
  seconds or more ends.

## What it shows

What the session does, as it happens:

- **Each tool call** when it is made, with the reason claude gives for it
  (`why:`), and its result with how long it took.
- **Each reply**, under a line that says when (`claude   reply`).
- **What its subagents run and write**, by `agent`, with when each starts
  and ends (`# task        started: ...`).
- **A conversation being compacted**, a request to the API that is tried
  again, and a limit of the account that is near.

What Claude Code's own UI does not show, each under the call that was
running at the time (`during:`):

- **Every connection** the session opens, with its name and address, and
  how it ended when that went wrong (`REFUSED`, `NO ANSWER`). Also what it
  sends by UDP or ICMP, and plain HTTP requests.
- **Each request to the egress filter**, `DENIED` when refused.
- **Lookups that stand out** (`FLAGGED`).
- **Each use of the SSH agent and of the Docker socket.**

Around a turn:

| Line | Says |
| --- | --- |
| `# working` | Claude took no step for 5 seconds: how long since the last one and what it waits for (`waiting for bash`, `for claude`, `claude, thinking`). What claude thinks is not shown |
| `# turn` | How long the turn took, its calls, the tokens it read and wrote, what it cost as claude counts it, how full the context is, and the model when it changed. Not for a command that used nothing (`/model sonnet`) |
| `# ready` | Claude has finished and the prompt is yours again |
| The status, above the prompt | The model, the permission mode when it is not the one the session started in (`mode:plan` always), how full the context is, the limits of your account (yellow from 70% used, red from 90%), what the session cost, and the sandbox: the container, the network mode, the doors that are open and the directories mounted next to the project |

What is left out, and where it is:

- A connection that closed as usual is not said again. Claude Code keeps
  its own open for minutes, and the end of each would bury the rest.
  `--trace` has them, with the bytes each way.
- Which process made a connection (`by:`) and each process that ran wait
  for `--trace`, once the session is over.
- What the project's other sessions do at the same time is not shown, of
  the network, the SSH agent and the Docker socket either.

About the status:

- Before the first turn it is the sandbox alone, claude has said nothing
  yet. It is made again when a turn starts and ends.
- The model is the one that wrote the last reply, so `/model` shows from
  the next one.
- Each line you send keeps the status it was typed under.
- It is not above a question claude asks.
- The `statusLine` command of your settings is for Claude Code's own
  screen and is not run here.

## Terminal, Emacs, file

Lines are only ever added at the end. The one exception is the line you
are typing at a terminal.

| | Terminal | Emacs shell buffer | File or pipe |
| --- | --- | --- | --- |
| Prompt | Stays at the bottom. What is written goes above it, and the line you are typing is written again under that | Written when a turn is over, with the `ready` line. A line can be typed without one | Written before each line read |
| Status | Above the prompt, written again in place when it changes | With each prompt | With each prompt |
| The line you sent | Written again in its place, bold and bright magenta | Left as Emacs shows it | Written once |
| Reply | Line by line as claude makes it, from the left edge, wrapped to the window | The same | Once it is whole, each line saying when and who |
| `# working` | One line above the status, counted up in place every 5 seconds | A line after 5 seconds, then after 10 more, 20, up to a minute | The same as Emacs |

In colour:

- The Markdown of a reply is taken for what it means: code is green,
  headings and `**bold**` are bold, and the marks are left out.
- The line over a reply is bold bright cyan, the `ready` line bright
  green.
- Under a call, the `why:` label is bold and the reason in italics.
- In the diff of an edit shown before a question, what it takes out is red
  and what it puts in green.

Without colour (a file, `NO_COLOR`) a reply is as claude wrote it. Code in
a block is never wrapped.

## Running it

- `CLAUDE_DOCKER_LINE_MODE=0 claude-docker` is one session with Claude
  Code's full-screen UI. The setting in the config file gives it to every
  session, and `claude-docker --line-mode` is then one session in line
  mode.
- Arguments go to claude: `--permission-mode` and the like decide how
  often it asks, `--resume` and `--continue` which session it is.
- A prompt among those arguments is not taken, claude passes it over in
  this mode.
- Lines that are not typed are prompts: `echo "fix the build" |
  claude-docker` asks that and leaves. Each line is a prompt, or the
  answer to what the one before led claude to ask.
- What has no conversation runs as it is: `-p`, a command of claude's
  (`claude-docker mcp list`), `--version`, and `--shell`.
- An editor that runs `claude-docker` in a terminal of its own gets line
  mode there too, see [Editor integration](../README.md#editor-integration).

## Limits

- Something else claude asks its host for (a hook to be run, an MCP server
  that wants input) is refused, and a line says that it was asked.
- While a command started with `!` runs, Ctrl-C is for it and not for
  claude's turn. It does not reach the command once docker has let go of
  it, which then runs on in the sandbox until it ends.
- What a `!` command writes shows when its line ends, so a progress bar
  that redraws itself shows late.

## How it works

Claude Code runs in its print mode and speaks JSON Lines over its standard
input and output, the protocol of the Agent SDK.

- What the session did (its calls, the network, its subagents) comes from
  the same records as `--trace --follow`, so the two never disagree.
- What claude says, its replies, is taken from the pipe as it is made. The
  transcript would have it a moment late.

The code is the `claude_sandbox/chat` package.
