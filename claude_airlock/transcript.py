"""Reading the transcript Claude Code keeps of each session in
~/.claude/projects (every prompt, reply, tool call and result) as events.
What an entry holds is read in entries.py, a tool call and how it ended
in calls.py, and what a transcript tells besides in told.py.

The transcript is written from inside the sandbox, so it is a convenience
for review and not an audit log, a session could rewrite its own. For the
same reason nothing in it is trusted here, see events.py, and no shape it
can be given stops the reading."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .brief import TALK_LINES, amount, between, clip, shortened
from .calls import (
    Outcome,
    call_event,
    call_label,
    outcome,
    tell_result,
)
from .entries import (
    INPUT_TOKENS,
    claude_of,
    content_blocks,
    is_prompt,
    local_time,
    step_tokens,
    step_usage,
)
from .events import Event, Kind, Stage, Who, clean, flat
from .files import UNREADABLE
from .told import Asides, typed_while_working

# A live walk of a transcript lets go of the oldest calls once this many
# wait for a result, and of the oldest steps it has shown
MOST_REMEMBERED = 10_000
# Of the call a result is named after, when other things came between
CALL_LABEL_WIDTH = 100
# How Claude Code records a command the user gave it (/model sonnet): its
# name and its arguments in tags, and what the command said in others
# Each is found by where it starts and where it then ends, see between
_COMMAND_NAME = ("<command-name>", "</command-name>")
_COMMAND_ARGS = ("<command-args>", "</command-args>")
_COMMAND_SAID = re.compile(r"<local-command-(stdout|stderr)>")
# A step that reads less than one in so many of what the step before read
# from the cache has missed it
MISS_SHARE = 2
# What is said ahead of a prompt that was typed while claude worked
TYPED_MEANWHILE = "(typed while claude worked)"


def command_said(content: str) -> list[str]:
    """What a command of Claude Code's said, each part it is recorded in:
    what it wrote to its output and to its errors, in their order."""
    parts: list[str] = []
    at = 0
    # The kinds that have no end from here on
    open_ended: set[str] = set()
    for opening in _COMMAND_SAID.finditer(content):
        kind = opening[1]
        if opening.start() < at or kind in open_ended:
            continue
        closing = f"</local-command-{kind}>"
        end = content.find(closing, opening.end())
        if end < 0:
            open_ended.add(kind)
            continue
        parts.append(content[opening.end() : end])
        at = end + len(closing)
    return parts


def as_typed(text: str) -> str:
    """A prompt as the user typed it: a command of Claude Code's is
    recorded as its name and arguments in tags, anything else as it is."""
    if not text.lstrip().startswith("<command-"):
        return text
    name = between(text, *_COMMAND_NAME)
    if name is None:
        return text
    args = between(text, *_COMMAND_ARGS) or ""
    return f"{name.strip()} {args.strip()}".strip()


def command_event(when: float, entry: dict, verbose: bool) -> Event | None:
    """What a command of Claude Code's said (/model, /context), which the
    model had no part in. None for an entry that holds nothing said."""
    content = entry.get("content")
    said = command_said(content) if isinstance(content, str) else []
    text = "\n".join(said).strip()
    lines = [line for line in clean(text).splitlines() if verbose or line.strip()]
    if not lines:
        return None
    details = clip(lines, verbose, TALK_LINES)
    return Event(when, Who.CLAUDE, Kind.COMMAND, details, {"text": text})


def talk_event(when: float, who: Who, block: dict, verbose: bool) -> Event | None:
    """A prompt or a reply, none for one without text."""
    said = clean(block.get("text", ""))
    text = (as_typed(said) if who is Who.USER else said).strip().splitlines()
    if not verbose:
        # Paragraph breaks would use up the preview
        text = [line for line in text if line.strip()]
    if not text:
        return None
    what = Kind.PROMPT if who is Who.USER else Kind.REPLY
    return Event(
        when, who, what, clip(text, verbose, TALK_LINES), {"text": block["text"]}
    )


def unreadable_event(when: float, entry: dict) -> Event:
    """A line of the transcript that holds no entry, see line_entry of
    files.py: what a session did there is not told, that it is so is.
    When is not known either, it is put where it was found."""
    text = entry.get("text")
    shown = shortened(flat(text if isinstance(text, str) else ""))
    details = [f"UNREADABLE line of the transcript: {shown}"]
    fields = {"unreadable_line": True, "text": text}
    return Event(when, Who.SANDBOX, Kind.TRANSCRIPT, details, fields)


def read_anew(used: dict[str, int], before: int) -> int:
    """How much of the conversation a step read at full price that the
    step before had left in the cache, 0 when the cache held: a step
    reads again what the one before read, and less than half of that
    from the cache is a miss. The conversation then changed near its
    start (another model, thinking that was dropped), or the cache was
    let go of over a pause. Before is what the step before read."""
    if used["cache_read_input_tokens"] * MISS_SHARE >= before:
        return 0
    return sum(used[kind] for kind in INPUT_TOKENS) - used["cache_read_input_tokens"]


def step_event(when: float, who: Who, usage: dict) -> Event | None:
    """What a step of the model used, none when that is nothing: the
    tokens it wrote, and the ones it read with how many of them are new
    since the step before, which is what the results it was given and the
    prompt took."""
    used = step_tokens(usage)
    read = sum(used[kind] for kind in INPUT_TOKENS)
    if not read and not used["output_tokens"]:
        return None
    thinking = used["thinking_tokens"]
    new = read - used["cache_read_input_tokens"]
    detail = (
        f"{amount(used['output_tokens'])} tokens out"
        + (f" ({amount(thinking)} thinking)" if thinking else "")
        + f", {amount(read)} in ({amount(new)} new)"
    )
    return Event(when, who, Kind.STEP, [detail], used)


@dataclass
class OpenCall:
    """A tool call that has no result yet."""

    who: Who
    # The cleaned name of the tool
    name: str
    # The entry the call is in, as far as its result needs it
    started: dict
    # What the call is shown by, to name it next to its result
    label: str
    # Its event, to add the result to. None in a live walk, where the
    # result is an event of its own.
    event: Event | None
    # Its number in a live walk, see Event
    number: int | None = None


@dataclass(frozen=True)
class WalkOptions:
    """How a transcript is walked, see Walk."""

    verbose: bool = False
    # Over a transcript as it is written, not one that is all there
    live: bool = False
    # Whether a live result always names its call, for when not every
    # event is shown
    name_results: bool = False
    # Whether what each step of the model used is told without verbose too
    steps: bool = False


class Walk:
    """Turns the entries of a transcript into events, an entry at a time
    and in their order: each prompt, reply and tool call, what a command
    of Claude Code's said, ahead of what a step of the model did, what
    the step used, and what the session was told or became besides, see
    told.py.

    There are two ways to walk. Over a transcript that is all there, a call
    and its result are one event: the result is added to the event of its
    call when it is found, and end marks the calls left without one. Live,
    over a transcript as it is written, events are shown as they come and
    cannot change later: a result is an event of its own, named after its
    call when something else came between the two (always with
    name_results, for when not every event is shown), and both carry the
    id of the call and its number. Of what is said only the first line is
    shown. What a live walk remembers is bounded, the transcript is the
    session's to write.

    What a step used is only told when verbose: it is the cost of the
    session, not what it did, and the header of a trace sums it up."""

    def __init__(
        self,
        project_dir: str,
        options: WalkOptions = WalkOptions(),
        usage: dict[str, dict] | None = None,
    ):
        self._project_dir = project_dir
        self._verbose = options.verbose
        # Whether what each step of the model used is told
        self._tell_steps = options.verbose or options.steps
        self._live = options.live
        self._name_results = options.name_results
        # How many calls a live walk has seen
        self._calls = 0
        # What each step used when that is known ahead, else the entry
        # that starts a step is taken at its word
        self._usage = usage or {}
        # An entry without a time of its own happened with the one before
        self._when = 0.0
        self._open: dict[str, OpenCall] = {}
        # The call shown last, when nothing of the session came after it
        self._last_call: str | None = None
        # The steps of the model whose usage was shown
        self._steps: dict[str, None] = {}
        # How much the last step of each read, which the next one of
        # theirs finds in the cache or has missed
        self._read: dict[Who, int] = {}
        self._asides = Asides(options.verbose)

    def take(self, entry: dict) -> list[Event]:
        """The events an entry adds."""
        kind = entry.get("type")
        if kind == UNREADABLE:
            return [unreadable_event(self._when, entry)]
        stamp = local_time(entry)
        self._when = stamp.timestamp() if stamp else self._when
        if kind == "system" and entry.get("subtype") == "local_command":
            return self._command(entry)
        if kind not in ("user", "assistant"):
            return self._aside(entry)
        by_claude = kind == "assistant"
        claude = claude_of(entry)
        events = self._step(claude, entry)
        if not by_claude:
            events += self._beside(self._asides.prompted(entry, self._when))
        for block in content_blocks(entry):
            part = block.get("type")
            if part == "text" and (by_claude or is_prompt(entry)):
                events += self._talk(claude if by_claude else Who.USER, block)
            elif part == "tool_use" and by_claude:
                events.append(self._call(claude, entry, block))
            elif part == "tool_result" and not by_claude:
                events += self._result(entry, block)
        return events

    def end(self) -> None:
        """Mark the calls that were left without a result."""
        for call in self._open.values():
            if call.event:
                tell_result(call.event, None, self._verbose)
        self._open.clear()

    def _remember(self, kept: dict) -> None:
        """Let go of the oldest of what a live walk keeps."""
        while self._live and len(kept) > MOST_REMEMBERED:
            del kept[next(iter(kept))]

    def _step(self, who: Who, entry: dict) -> list[Event]:
        """What the step an entry starts used, nothing for a later entry
        of the same step."""
        step = step_usage(entry) if self._tell_steps else None
        if not step or step[0] in self._steps:
            return []
        self._steps[step[0]] = None
        self._remember(self._steps)
        used = step_event(self._when, who, self._usage.get(*step))
        # Said with the step it is about, or not at all
        why = self._asides.dropped()
        if not used:
            return []
        anew = read_anew(used.fields, self._read.get(who, 0))
        self._read[who] = sum(used.fields[kind] for kind in INPUT_TOKENS)
        if anew:
            said = f"cache MISSED, {amount(anew)} read anew"
            used.notes.append(said + (f": {why}" if why else ""))
            used.fields = {**used.fields, "cache_missed": anew, "cache_missed_why": why}
        return [used]

    def _aside(self, entry: dict) -> list[Event]:
        """What an entry that is neither said nor done by the model adds:
        a line the user typed while claude worked, which is a prompt, and
        what told.py reads."""
        typed = typed_while_working(entry)
        if typed is None:
            events = self._asides.take(entry, self._when)
            if any(event.what == Kind.COMPACT for event in events):
                # What is read from here on is another conversation
                self._read.clear()
            return self._beside(events)
        blocks = content_blocks({"message": {"content": typed}})
        events = []
        for block in blocks:
            if block.get("type") != "text" or not isinstance(block.get("text"), str):
                continue
            for said in self._talk(Who.USER, block):
                said.tag = TYPED_MEANWHILE
                said.fields["queued"] = True
                events.append(said)
        return events

    def _beside(self, events: list[Event]) -> list[Event]:
        """Events that came between a call and its result: the result is
        then named after its call."""
        if events:
            self._last_call = None
        return events

    def _talk(self, who: Who, block: dict) -> list[Event]:
        return self._said(talk_event(self._when, who, block, self._whole))

    def _command(self, entry: dict) -> list[Event]:
        """What a command of Claude Code's said, as of anything said."""
        return self._said(command_event(self._when, entry, self._whole))

    @property
    def _whole(self) -> bool:
        """Whether what is said is shown whole. Live just its first line,
        when verbose too: whoever follows is after what the session does,
        what it says is on its own screen."""
        return self._verbose and not self._live

    def _said(self, said: Event | None) -> list[Event]:
        """Something said, which ends the call before it, live its first
        line alone."""
        if not said:
            return []
        if self._live:
            del said.details[1:]
        self._last_call = None
        return [said]

    def _call(self, who: Who, entry: dict, block: dict) -> Event:
        event = call_event(
            self._when, who, entry, block, self._project_dir, self._verbose
        )
        call = str(block.get("id"))
        name = event.fields["tool"]
        # Before the event has its number: a result shows that itself
        label = (call_label(event) or name)[:CALL_LABEL_WIDTH]
        started = {"timestamp": entry.get("timestamp")}
        if self._live:
            self._calls += 1
            event.number = self._calls
            event.fields = {"stage": Stage.CALL, **event.fields}
        kept = None if self._live else event
        self._open[call] = OpenCall(who, name, started, label, kept, event.number)
        self._remember(self._open)
        self._last_call = call
        return event

    def _result(self, entry: dict, block: dict) -> list[Event]:
        """How a call that was seen ended: added to its event, or live an
        event of its own. Nothing for the result of any other call."""
        call = str(block.get("tool_use_id"))
        issued = self._open.pop(call, None)
        if issued is None:
            return []
        ended = outcome(issued.started, entry, block, self._project_dir)
        if issued.event:
            self._ended(issued.event, ended)
            return []
        named = self._name_results or self._last_call != call
        self._last_call = None
        fields = {
            "stage": Stage.RESULT,
            "tool": issued.name,
            "id": call,
            **ended.fields(),
        }
        details = ["of: " + issued.label] if named else []
        event = Event(
            self._when, issued.who, issued.name.lower(), details, fields, issued.number
        )
        tell_result(event, ended, self._verbose)
        return [event]

    def _ended(self, event: Event, ended: Outcome) -> None:
        """Add how a call ended to its event."""
        tell_result(event, ended, self._verbose)
        # Whether it wrote outside the project stays the last value,
        # and is so when the call or what it ran did
        fields, found = event.fields, ended.fields()
        key = "outside_project"
        flags = [of.pop(key) for of in (fields, found) if key in of]
        fields.update(found)
        if flags:
            fields[key] = any(flags)


def transcript_events(
    entries: list[dict], project_dir: str, verbose: bool
) -> list[Event]:
    """The events of a transcript that is all there."""
    # As the last entry of a step has it, should an earlier one be short
    usage = dict(found for found in map(step_usage, entries) if found)
    walk = Walk(project_dir, WalkOptions(verbose), usage)
    events = [event for entry in entries for event in walk.take(entry)]
    walk.end()
    return events
