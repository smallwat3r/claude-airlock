"""Line mode, Claude Code without its native UI
(CLAUDE_AIRLOCK_LINE_MODE, or --line-mode for one session): the same session
in the same sandbox, run with the same arguments. A prompt is read a line at a
time, and what the session does with it is written under it in the lines
of a trace, with what the launcher records of the network, the SSH agent
and the Docker socket (followed.py).

Claude Code's screen redraws itself and so needs a terminal that keeps up
with it. Here lines are added at the end and never changed, in a terminal
window, a shell buffer of Emacs or a file alike. The one exception is the
line being typed at a terminal, which is written again under what comes
meanwhile (console.py).

Claude Code runs in its print mode, where it speaks JSON Lines over its
standard input and output (pipe.py). That is how it is told a prompt, how
it asks whether a tool may be used (asking.py) and how it says that a
turn starts and is over (turn.py).

What is shown has two sources. What the session did, its tool calls,
what it reached on the network, what its subagents did, is taken from the
records --trace --follow reads (see follow.py), so a chat and a trace
never disagree about it. What claude says, its replies, is taken from the
pipe as it is made (reply.py): a chat is the one screen it has, and the
transcript would have it a moment late. Both are the session's own word,
cleaned before they are shown, and the id claude gives for its session is
not made a path of before it is seen to be one.

The conversation itself, the threads it takes and how it ends, is in
talk.py. What a chat does itself with a line (/mode, /resume, !COMMAND)
is in commands.py and shell.py, what it says of claude's doings besides
answering in notices.py. What claude says over the pipe is checked for
being what it should be in said.py."""

from .commands import Handover
from .pipe import CHAT_ARGS
from .status import Sandbox
from .talk import chat

__all__ = ["CHAT_ARGS", "Handover", "Sandbox", "chat"]
