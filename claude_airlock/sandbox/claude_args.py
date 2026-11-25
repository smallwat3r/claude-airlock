"""The arguments of claude as the launcher reads them: whether they start
a session or run one of claude's commands, whether they say how to go
about permissions, and how they are changed to resume another session."""

from __future__ import annotations

# The commands of claude that are not a session (claude mcp list), by
# which they are told when one is its first argument
CLAUDE_COMMANDS = (
    *("agents", "attach", "auth", "auto-mode", "doctor", "gateway", "import"),
    *("install", "logs", "mcp", "plugin", "plugins", "purge", "respawn", "rm"),
    *("setup-token", "stop", "kill", "ultrareview", "update", "upgrade"),
)
# What says how claude is to go about permissions, when the user does
PERMISSION_OPTIONS = (
    "--dangerously-skip-permissions",
    "--allow-dangerously-skip-permissions",
    "--permission-mode",
)
# What claude does without a conversation, and so without a screen to
# replace: with one of these among its arguments, or one of its commands
# as the first (claude mcp list), it is run as it is. A command that is
# not known yet shows as what it writes, see Agent of chat/pipe.py.
# Not --help, which is the launcher's own (see _parse_args of cli.py).
NO_CONVERSATION = ("-p", "--print", "-v", "--version", "--bg")


def _option_of(arg: str) -> str:
    """The option an argument gives, without the value it gives with =."""
    return arg.partition("=")[0]


def is_a_command(args: list[str]) -> bool:
    """Whether the arguments run a command of claude's rather than a
    session (claude mcp list): told by the first alone."""
    return bool(args) and args[0] in CLAUDE_COMMANDS


def says_permissions(args: list[str]) -> bool:
    """Whether the arguments say how claude is to go about permissions."""
    return any(_option_of(arg) in PERMISSION_OPTIONS for arg in args)


def has_a_conversation(args: list[str]) -> bool:
    """Whether claude, run with these arguments, has a conversation with
    its user, the one thing a chat can stand in for the screen of."""
    if any(_option_of(arg) in NO_CONVERSATION for arg in args):
        return False
    return not is_a_command(args)


def resumed_args(args: list[str], session: str) -> list[str]:
    """The arguments of claude for a session that is resumed, in place of
    what they said about which session to run."""
    kept: list[str] = []
    rest = iter(args)
    for arg in rest:
        option = _option_of(arg)
        if option in ("--continue", "-c", "--fork-session"):
            continue
        if option in ("--resume", "-r", "--session-id"):
            if "=" not in arg:
                value = next(rest, None)
                if value is not None and value.startswith("-"):
                    # --resume takes its value or none: this is the next option
                    kept.append(value)
            continue
        kept.append(arg)
    return [*kept, f"--resume={session}"]
