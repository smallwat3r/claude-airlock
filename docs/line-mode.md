# Line mode

Line mode is Claude Code with a simpler UI. You type at a prompt, and the
session writes what it does above it, one line at a time, the network
included.

It is the default. Nothing else changes: `claude-docker` takes the same
arguments, and it is the same session in the same sandbox, recorded and
checked the same way.

![A turn in line mode at a terminal. Under each command, in cyan, the
connections it made: the package registry and a second host during an
install, then a database that refuses the connection, in red, during a
test run that fails](line-mode.png)

## Why

- **It shows more.** The cyan lines are what Claude Code's own UI does not
  show: every connection the session opens, under the command that was
  running at the time. Here the install reaches a second host besides the
  registry, and the tests fail because the database refuses the
  connection.
- **It works anywhere.** Claude Code's full-screen UI redraws itself as it
  goes, which needs a terminal that keeps up with it. Line mode only adds
  lines, so it works in a terminal, a shell buffer of Emacs (`M-x shell`)
  or a file alike.

## What it shows

- Each tool call, with the reason claude gives for it, and its result.
- Each reply, and what its subagents do.
- Every connection the session opens, and how it ended when that went
  wrong (`REFUSED`, `NO ANSWER`).
- Each request the egress filter refused (`DENIED`), and each use of the
  SSH agent and of the Docker socket.
- After a turn, how long it took and what it cost.
- Above the prompt, the status: the model, how full the context is, the
  limits of your account, and the sandbox with its network mode.

The lines are those of `--trace`, see
[Reading the lines](trace.md#reading-the-lines). `--trace` has the rest
once the session is over, such as which process made each connection.

## What you type

A line can be typed at any time, claude takes it up when it can.

| You type | Does |
| --- | --- |
| Enter | Sends the line |
| Ctrl-C | Interrupts the turn, a second one stops the session. While a `!COMMAND` runs, ends that command |
| Ctrl-D, `/exit`, `/quit` | Leaves |
| Tab | Completes the names of commands and of files (`@src/main.py`) |
| Up, Down | The lines typed before |
| `/help` | Says what there is |
| `/model`, `/context`, `/compact`, `/clear`, your own commands and skills | Claude Code's commands that answer in text, as typed |
| `/mode plan` | Changes the permission mode |
| `/resume` | Leaves this session for an earlier one of the project |
| `!make test` | Runs a command in the sandbox, claude is not told |

When claude asks whether it may use a tool, `y` allows that one call, `a`
allows calls like it until the session ends, and anything else refuses it.

Claude Code's menus are not there: `/config`, `/permissions`, and `/rewind`
(Esc twice), which undoes the last turns of the conversation and the edits
they made.

## Switching it off

`CLAUDE_DOCKER_LINE_MODE=0 claude-docker` is one session with Claude Code's
full-screen UI. With that setting in the config file every session has it,
and `claude-docker --line-mode` is then one session in line mode.

What has no conversation runs as it always did: `-p`, a command of
claude's (`claude-docker mcp list`), `--version` and `--shell`.

## How it works

Claude Code runs in its print mode and speaks JSON Lines over its standard
input and output, the protocol of the Agent SDK. What the session did
comes from the same records as `--trace --follow`, so the two never
disagree. The code is the `claude_sandbox/chat` package.
