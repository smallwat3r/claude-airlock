"""The hooks a session ran, as its transcript tells of them: on which
event, the command, and how it ended. A hook runs a command of the
settings of the project or of a plugin with no tool call, so nothing else
in a trace says it ran. Claude Code notes each run in an attachment whose
kind says how it ended, and the hooks it ran as claude was to stop in a
summary of them all.

What a hook gave the model is looked at for the signs of planted.py, as
given.py does what a hook added to the context: a hook can come with the
project. Not what it said to the user alone, nor its decision on a call,
which the result of the call says (REFUSED by hook). The shape of each is
that of Claude Code's own, checked here all the same: a transcript is
written from inside the sandbox, see events.py."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..events import Event, Kind, Who, Wrong, clean, flat
from .brief import clip, lines_out, output_shown, shortened
from .calls import command_lines
from .entries import MOST_LISTED, counted, every, kept, seconds
from .given import hook_named
from .planted import Planted, flagged, planted

# The events on which what a hook wrote out is given to the model as
# Claude Code's own word: when the session started, and when a prompt was
# given or a command of the user's made one
GIVES_OUTPUT = frozenset({"SessionStart", "UserPromptSubmit", "UserPromptExpansion"})
# The subtype of the entry of the system that sums up the hooks run as
# claude was to stop, and what that is of when it names no event
STOP_SUMMARY = "stop_hook_summary"
STOP_EVENT = "Stop"


@dataclass(frozen=True)
class Ran:
    """A hook that ran, as an attachment tells of it: the event it ran on
    and its own name, its command, how long it took and its exit code
    when the attachment says, what it wrote out, why it ended as it did
    (why it blocked, what it stopped the session with, why it failed),
    what it said to the user, and what of it the model was given."""

    event: str
    name: str
    command: str = ""
    exit_code: int | None = None
    seconds: float | None = None
    stdout: str = ""
    stderr: str = ""
    reason: str = ""
    said: str = ""
    given: str = ""


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _joined(*texts: object) -> str:
    """The texts the model was given of a hook, one after the other."""
    return "\n".join(text for text in texts if isinstance(text, str) and text)


def _ran(attached: dict, /, **more: object) -> Ran:
    """What an attachment of any kind of a hook says of the run, with
    what one of its kind says more."""
    exit_code = attached.get("exitCode")
    values: dict = {
        "event": kept(attached.get("hookEvent")),
        "name": kept(attached.get("hookName")),
        "command": _text(attached.get("command")),
        "exit_code": exit_code if type(exit_code) is int else None,
        "seconds": seconds(attached.get("durationMs")),
        "stdout": _text(attached.get("stdout")),
        "stderr": _text(attached.get("stderr")),
    }
    return Ran(**{**values, **more})


def _succeeded(given: dict) -> Ran:
    """content: what it wrote out, which Claude Code gives the model on
    the events of GIVES_OUTPUT"""
    gives = kept(given.get("hookEvent")) in GIVES_OUTPUT
    return _ran(given, given=_text(given.get("content")) if gives else "")


def _blocked(given: dict) -> Ran:
    """blockingError.blockingError, blockingError.command: why it
    blocked what it ran on, and its command, both given to the model"""
    error = given.get("blockingError")
    about = error if isinstance(error, dict) else {}
    why, command = _text(about.get("blockingError")), _text(about.get("command"))
    return _ran(given, command=command, reason=why, given=_joined(why, command))


def _errored(given: dict) -> Ran:
    """content: why it could not be run"""
    return _ran(given, reason=_text(given.get("content")))


def _cancelled(given: dict) -> Ran:
    """timedOut, timeoutMs: whether it ran out of time, and of how much"""
    if given.get("timedOut") is not True:
        return _ran(given)
    limit = seconds(given.get("timeoutMs"))
    after = f" after {limit:.1f}s" if limit is not None else ""
    return _ran(given, reason=f"timed out{after}")


def _stopped(given: dict) -> Ran:
    """message: what it stopped the session with, given to the model"""
    message = _text(given.get("message"))
    return _ran(given, reason=message, given=message)


def _said(given: dict) -> Ran:
    """content: what it said to the user"""
    return _ran(given, said=_text(given.get("content")))


def _deferred(given: dict) -> Ran:
    """toolName: the call it held back until the session is resumed"""
    tool = flat(kept(given.get("toolName")))
    return _ran(given, reason=f"held back {tool or 'a call'} until resumed")


def _answered(given: dict) -> Ran:
    """response.systemMessage, response.hookSpecificOutput.additionalContext:
    what a hook run in the background answered with, given to the model"""
    response = given.get("response")
    answer = response if isinstance(response, dict) else {}
    specific = answer.get("hookSpecificOutput")
    added = specific.get("additionalContext") if isinstance(specific, dict) else None
    return _ran(given, given=_joined(answer.get("systemMessage"), added))


@dataclass(frozen=True)
class Ending:
    """How a hook ended, as an attachment of a kind says it: in the words
    of the trace, whether that is something gone wrong, and what reads
    the rest out of the attachment."""

    said: str
    wrong: bool
    read: Callable[[dict], Ran]


# Each kind of attachment that tells of a hook run, by its kind as Claude
# Code names it. One more is one more here.
ENDINGS = {
    "hook_success": Ending("ok", False, _succeeded),
    "hook_non_blocking_error": Ending("FAILED", True, _ran),
    "hook_blocking_error": Ending("BLOCKED", True, _blocked),
    "hook_error_during_execution": Ending("FAILED to run", True, _errored),
    "hook_cancelled": Ending("CANCELLED", True, _cancelled),
    "hook_stopped_continuation": Ending("STOPPED the session", True, _stopped),
    "hook_system_message": Ending("ok", False, _said),
    "hook_deferred_tool": Ending("DEFERRED", True, _deferred),
    "async_hook_response": Ending("ok", False, _answered),
}
# The kinds of attachment hook_event reads
HOOK_RUNS = frozenset(ENDINGS)


def _output_lines(ran: Ran, verbose: bool, wrong: bool) -> list[str]:
    """What a hook wrote out and to its errors, each under its label, as
    of a call: the ends of each when it went wrong, more of them with
    --verbose, see output_shown."""
    return [
        f"{label}: {line}"
        for label, text in (("out", ran.stdout), ("err", ran.stderr))
        for line in output_shown(clean(text).splitlines(), verbose, wrong)
    ]


def _read(given: dict) -> tuple[Ending, Ran] | None:
    """How a hook ended and what ran, as an attachment tells of it, none
    for an attachment that tells of no hook run."""
    kind = given.get("type")
    ending = ENDINGS.get(kind) if isinstance(kind, str) else None
    return None if ending is None else (ending, ending.read(given))


def hook_planted(given: dict) -> tuple[Planted, ...]:
    """The signs in what a hook gave the model, see planted.py, of an
    attachment of any kind: none for one that tells of no hook run."""
    read = _read(given)
    if read is None:
        return ()
    _, ran = read
    return planted(ran.given, _named(ran))


def _named(ran: Ran) -> str:
    """A hook as it is named, see hook_named, on one line."""
    return flat(hook_named(ran.event, ran.name)) or "a hook"


def _hook_lines(ran: Ran, named: str, verbose: bool) -> list[str]:
    """The lines that name a hook and its command, by the lines a shell
    reads it in (see command_lines), each on one line: the first few,
    all of them with verbose. The hook alone when it names no command."""
    if not ran.command:
        return [named]
    shown = clip([flat(line) for line in command_lines(ran.command)], verbose)
    return [f"{named}: $ {shown[0]}", *(f"$   {line}" for line in shown[1:])]


def _notes(ran: Ran, said: str) -> list[str]:
    """What the line of how a hook ended says: how, its exit code, how
    long it took and how much it wrote out, each when it is known."""
    notes = [said]
    if ran.exit_code is not None:
        notes.append(f"exit {ran.exit_code}")
    if ran.seconds is not None:
        notes.append(f"{ran.seconds:.1f}s")
    out = clean(ran.stdout).splitlines()
    if out:
        notes.append(lines_out(len(out)))
    return notes


def hook_event(given: dict, when: float, who: Who, verbose: bool) -> Event | None:
    """The event of a hook that ran, none for an attachment that tells of
    none: which hook on which event, its command, and how it ended,
    flagged when it blocked or stopped something or failed. What it wrote
    out with --verbose, and when it went wrong."""
    read = _read(given)
    if read is None:
        return None
    ending, ran = read
    said, wrong = ending.said, ending.wrong
    if not wrong and ran.exit_code not in (None, 0):
        # Of what ran, a code other than 0 is a failure
        said, wrong = "FAILED", True
    named = _named(ran)
    signs = planted(ran.given, named)
    event = Event(when, who, Kind.HOOK, _hook_lines(ran, named, verbose), {})
    event.say("result: " + ", ".join(_notes(ran, said)), alert=wrong)
    for label, text in (("why", ran.reason), ("said", ran.said)):
        if text:
            event.say(
                f"{label}: {shortened(flat(text))}", alert=wrong and label == "why"
            )
    if ran.given:
        event.say(f"given to claude: {len(ran.given)} chars")
    for sign in signs:
        event.say(sign.shown, alert=True)
    for line in _output_lines(ran, verbose, wrong):
        event.say(line, alert=wrong)
    if wrong or signs:
        event.went_wrong()
    event.fields = {
        "of": given["type"],
        "hook_event": ran.event,
        "hook_name": ran.name,
        "command": ran.command,
        "ended": said.lower(),
        "exit_code": ran.exit_code,
        "seconds": ran.seconds,
        "stdout": ran.stdout,
        "stderr": ran.stderr,
        "reason": ran.reason,
        "said": ran.said,
        "given": ran.given,
        **flagged(signs),
    }
    return event


def _hook_infos(entry: dict) -> list[tuple[str, float | None]]:
    """The command of each hook a summary names, with how long it ran."""
    return [
        (_text(info.get("command")), seconds(info.get("durationMs")))
        for info in every(entry.get("hookInfos"))
        if isinstance(info, dict)
    ]


def summary_planted(entry: dict) -> tuple[Planted, ...]:
    """The signs in what the hooks of a summary gave the model: each
    error of theirs, which Claude Code tells the model of as the reason
    claude may not stop."""
    errors = _joined(*every(entry.get("hookErrors")))
    return planted(errors, flat(kept(entry.get("hookLabel"))) or STOP_EVENT)


def summary_event(entry: dict, when: float, who: Who) -> Event:
    """The event of the hooks Claude Code ran as claude was to stop: how
    many and for how long, the command of each, every error of theirs,
    and whether they kept claude from stopping, which went wrong."""
    named = flat(kept(entry.get("hookLabel"))) or STOP_EVENT
    infos = _hook_infos(entry)
    count = counted(entry.get("hookCount")) or len(infos)
    took = seconds(entry.get("totalDurationMs"))
    line = f"{named}: {count} hook{'s' if count != 1 else ''} ran"
    event = Event(when, who, Kind.HOOK, [line + (f", {took:.1f}s" if took else "")], {})
    for command, spent in infos[:MOST_LISTED]:
        after = f"  ({spent:.1f}s)" if spent is not None else ""
        event.say(f"$ {shortened(flat(command))}{after}")
    if len(infos) > MOST_LISTED:
        event.say(f"$ ... {len(infos) - MOST_LISTED} more")
    errors = [text for text in every(entry.get("hookErrors")) if isinstance(text, str)]
    for error in errors[:MOST_LISTED]:
        event.say(f"error: {shortened(flat(error))}", alert=True)
    if len(errors) > MOST_LISTED:
        event.say(f"error: ... {len(errors) - MOST_LISTED} more", alert=True)
    stopped = entry.get("preventedContinuation") is True
    reason = _text(entry.get("stopReason"))
    if stopped:
        why = f": {shortened(flat(reason))}" if reason else ""
        event.say(f"result: STOPPED the session{why}", alert=True)
    signs = summary_planted(entry)
    for sign in signs:
        event.say(sign.shown, alert=True)
    if errors or stopped or signs:
        event.went_wrong(Wrong.PART)
    event.fields = {
        "of": STOP_SUMMARY,
        "hook_event": named,
        "count": count,
        "seconds": took,
        "commands": [command for command, _ in infos],
        "errors": errors,
        "stopped": stopped,
        "reason": reason,
        **flagged(signs),
    }
    return event
