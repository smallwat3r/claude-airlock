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
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field

from ..events import Event, Kind, Stage, Who, Wrong, clean, flat
from ..files import UNREADABLE
from .brief import TALK_LINES, amount, between, clip, shortened
from .calls import call_event, call_label, tell_result
from .entries import (
    INPUT_TOKENS,
    calls_issued,
    claude_of,
    content_blocks,
    entry_times,
    is_prompt,
    kept,
    local_time,
    step_of,
    step_tokens,
    step_usage,
    tool_results,
)
from .outcomes import Outcome, outcome, said_source
from .told import Asides, typed_while_working

# A live walk of a transcript lets go of the oldest calls once this many
# wait for a result, and of the oldest steps it has shown
MOST_REMEMBERED = 10_000
# Of the call a result is named after, when other things came between
CALL_LABEL_WIDTH = 100
# What a result is named after when its call is nowhere to be found, and
# the tool it is then of, as a call without a name has it
NO_CALL = "a call the transcript does not have"
NO_TOOL = "?"
# What is said, live, of a call the model went on without a result of
WENT_ON = "result: none recorded, the session went on without one"
# What is said of a call under the id of one that waits for its result
REUSED_ID = "THE ID OF A CALL BEFORE IT, whose result it is not told with"
# Of the entries that are no event of a trace, how many kinds are named
# when they are counted, and how much of the name of one
UNTOLD_KINDS = 8
KIND_WIDTH = 40
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


def _command_event(when: float, entry: dict, verbose: bool) -> Event | None:
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


def _talk_event(when: float, who: Who, block: dict, verbose: bool) -> Event | None:
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


def _unreadable_event(when: float, entry: dict) -> Event:
    """A line of the transcript that holds no entry, see line_entry of
    files.py: what a session did there is not told, that it is so is.
    When is not known either, it is put where it was found."""
    text = entry.get("text")
    shown = shortened(flat(text if isinstance(text, str) else ""))
    details = [f"UNREADABLE line of the transcript: {shown}"]
    fields = {"unreadable_line": True, "text": text}
    return Event(
        when, Who.SANDBOX, Kind.TRANSCRIPT, details, fields, wrong=Wrong.THROUGHOUT
    )


def _untold_event(when: float, entries: list[dict]) -> Event:
    """Entries of a transcript that add to no event, as one that counts
    them by their kind: a step in which the model only thought, a title,
    a mode or a model with nothing before it to have changed from. Said
    of those that were taken out of a transcript (see taken_out_events),
    where nothing is to go without a word. Each is whole in --json."""
    kinds = Counter(flat(entry.get("type", "?"))[:KIND_WIDTH] for entry in entries)
    named = [f"{count} {kind}" for kind, count in kinds.most_common(UNTOLD_KINDS)]
    if len(kinds) > UNTOLD_KINDS:
        named.append("...")
    count = "1 line that is" if len(entries) == 1 else f"{len(entries)} lines that are"
    detail = f"{count} no event of a trace ({', '.join(named)}), see --json"
    return Event(when, Who.SANDBOX, Kind.TRANSCRIPT, [detail], {"entries": entries})


def _read_anew(used: dict[str, int], before: int) -> int:
    """How much of the conversation a step read at full price that the
    step before had left in the cache, 0 when the cache held: a step
    reads again what the one before read, and less than half of that
    from the cache is a miss. The conversation then changed near its
    start (another model, thinking that was dropped), or the cache was
    let go of over a pause. Before is what the step before read."""
    if used["cache_read_input_tokens"] * MISS_SHARE >= before:
        return 0
    return sum(used[kind] for kind in INPUT_TOKENS) - used["cache_read_input_tokens"]


def _step_event(when: float, who: Who, usage: dict) -> Event | None:
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
    # What it and its result are tied by in a live walk, see Event.link
    link: str = ""
    # Where what it reads is said to be from, see said_source
    source: str = ""


def _open_call(event: Event, entry: dict, block: dict, whole: bool) -> OpenCall:
    """A call as its result needs it, by its event, the entry it is in
    and the call itself. Its result is added to the event when the two
    are told as a whole, and is an event of its own when not."""
    name = event.fields["tool"]
    # Before the event has what it is tied by: a result shows that itself
    label = (call_label(event) or name)[:CALL_LABEL_WIDTH]
    started = {"timestamp": entry.get("timestamp")}
    source = said_source(block.get("input"))
    added_to = event if whole else None
    return OpenCall(event.who, name, started, label, added_to, source=source)


def _side_of(who: Who, entry: dict) -> tuple[Who, str]:
    """Whose side of a conversation an entry is of: claude's, or that of
    one subagent, which Claude Code names in each entry of its."""
    return who, kept(entry.get("agentId"))


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
    # Whether the lines of the events are for anyone to read. They are not
    # as JSON Lines, which has the values alone: what takes long to lay
    # out and is no value, the diff of an Edit, is then left out.
    lines: bool = True


@dataclass(frozen=True)
class OtherPart:
    """Of a transcript that lines were taken out of, the part a walk is
    not over: what is left of it for a walk over what was taken out, and
    the other way round. A call can be in one part and its result in the
    other, and neither is to go untold for it."""

    # Each call there by its id, with the entry it is in: a result that
    # has no call where it is walked is named after the one found here
    calls: dict[str, tuple[dict, dict]] = field(default_factory=dict)
    # Each result there the same way, for a walk over what was taken
    # out: a call left without a result ended as the one found here says.
    # None for a walk over what is left, which is told as it is.
    results: dict[str, tuple[dict, dict]] = field(default_factory=dict)


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

    Live, the walk of a subagent's transcript is given agents, where it
    takes the number of its subagent from when it has its first event:
    every event of it then says which subagent it is of (a3), and its
    calls are numbered after that (a3.1). Several subagents run side by
    side, each in a transcript of its own that counts its calls from 1,
    as that of their session does.

    Live, a call is taken to run until its result comes. One whose
    result never does is told as that when the model takes its next
    step, which it does once it has the results of the last: the session
    was ended while the call ran, and went on later. Told by the ids of
    the steps, since several calls of one step run side by side: an entry
    that names no step tells nothing of the kind.

    No result goes untold where a transcript is all there. One whose call
    is not ahead of it is an event of its own as a live one is, named
    after its call: a second result of a call that had one, the result of
    a call in the other part of a transcript that lines were taken out of
    (see OtherPart), and one whose call is nowhere, which says so.

    What a step used is only told when verbose: it is the cost of the
    session, not what it did, and the header of a trace sums it up."""

    def __init__(
        self,
        project_dir: str,
        options: WalkOptions = WalkOptions(),
        usage: dict[str, dict] | None = None,
        other: OtherPart | None = None,
        agents: Iterator[int] | None = None,
    ):
        self._project_dir = project_dir
        self._verbose = options.verbose
        # Whether what each step of the model used is told
        self._tell_steps = options.verbose or options.steps
        self._live = options.live
        self._name_results = options.name_results
        self._diffed = options.lines
        self._other = other or OtherPart()
        # How many results were added to the event of their call: an
        # entry that gives no event may have told of something all the
        # same, see taken_out_events
        self.added = 0
        # How many calls a live walk has seen
        self._calls = 0
        # Where the walk of a subagent's transcript takes the number of
        # its subagent from, and that number once it has one
        self._agents = agents
        self._agent: int | None = None
        # What each step used when that is known ahead, else the entry
        # that starts a step is taken at its word
        self._usage = usage or {}
        # An entry without a time of its own happened with the one before
        self._when = 0.0
        self._open: dict[str, OpenCall] = {}
        # Live, the calls that had a result, by their ids: what else comes
        # as the result of one is told as a result of its own
        self._answered: dict[str, OpenCall] = {}
        # How many calls came under the id of one that waits for its result
        self._reused = 0
        # The call shown last, when nothing of the session came after it
        self._last_call: str | None = None
        # The steps of the model whose usage was shown
        self._steps: dict[str, None] = {}
        # Live, the step each side of the conversation is at, claude and
        # each subagent, with the calls it issued in that step
        self._at: dict[tuple[Who, str], tuple[str, list[str]]] = {}
        # How much the last step of each read, which the next one of
        # theirs finds in the cache or has missed
        self._read: dict[Who, int] = {}
        self._asides = Asides(options.verbose)

    def take(self, entry: dict) -> list[Event]:
        """The events an entry adds, each of a subagent's transcript
        that is followed said to be of that subagent, see Walk."""
        events = self._taken(entry)
        if self._agents is not None and events:
            of_agent = self._of_agent()
            for event in events:
                event.link = event.link or of_agent
        return events

    def _of_agent(self) -> str:
        """What the events of a subagent's transcript are tied by: the
        number of the subagent, taken when its first event comes."""
        if self._agents is None:
            return ""
        if self._agent is None:
            self._agent = next(self._agents)
        return f"a{self._agent}"

    def _link(self) -> str:
        """What the call a live walk saw last and its result are tied
        by: how many calls it has seen, of a subagent after the number
        of the subagent."""
        of_agent = self._of_agent()
        return f"{of_agent}.{self._calls}" if of_agent else str(self._calls)

    def _taken(self, entry: dict) -> list[Event]:
        kind = entry.get("type")
        if kind == UNREADABLE:
            return [_unreadable_event(self._when, entry)]
        stamp = local_time(entry)
        self._when = stamp.timestamp() if stamp else self._when
        if kind == "system" and entry.get("subtype") == "local_command":
            return self._command(entry)
        if kind not in ("user", "assistant"):
            return self._aside(entry)
        by_claude = kind == "assistant"
        claude = claude_of(entry)
        events = self._went_on(claude, entry) + self._step(claude, entry)
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
        """Mark the calls that were left without a result. Not one whose
        result the other part of the transcript has (see OtherPart): it
        ended as that says."""
        for call, issued in self._open.items():
            if not issued.event:
                continue
            found = self._other.results.get(call)
            if found is None:
                tell_result(issued.event, None, self._verbose)
                continue
            ended = outcome(
                issued.started, *found, self._project_dir, issued.name, issued.source
            )
            self._ended(issued.event, ended)
        self._open.clear()

    def _remember(self, kept: dict) -> None:
        """Let go of the oldest of what a live walk keeps."""
        while self._live and len(kept) > MOST_REMEMBERED:
            del kept[next(iter(kept))]

    def _went_on(self, who: Who, entry: dict) -> list[Event]:
        """Live, the calls the model went on without: those it issued in
        the step before the one an entry starts that have no result yet,
        each as an event in the place of its result, see Walk. Nothing
        for a later entry of the same step, and for one that names none.
        A call stays known all the same, should a result of it come."""
        step = step_of(entry)
        if not self._live or not step:
            return []
        side = _side_of(who, entry)
        before, issued = self._at.get(side, ("", []))
        if before == step:
            return []
        self._at[side] = (step, [])
        self._remember(self._at)
        # Those still without a result, each by its id
        left = ((name, self._open.get(name)) for name in issued)
        return [
            Event(
                self._when,
                call.who,
                call.name.lower(),
                ["of: " + call.label, WENT_ON],
                {"stage": Stage.RESULT, "tool": call.name, "id": name},
                call.link,
                call=True,
            )
            for name, call in left
            if call
        ]

    def _step(self, who: Who, entry: dict) -> list[Event]:
        """What the step an entry starts used, nothing for a later entry
        of the same step."""
        step = step_usage(entry) if self._tell_steps else None
        if not step or step[0] in self._steps:
            return []
        self._steps[step[0]] = None
        self._remember(self._steps)
        used = _step_event(self._when, who, self._usage.get(*step))
        # Said with the step it is about, or not at all
        why = self._asides.dropped()
        if not used:
            return []
        anew = _read_anew(used.fields, self._read.get(who, 0))
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
            if any(event.kind is Kind.COMPACT for event in events):
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
        return self._said(_talk_event(self._when, who, block, self._whole))

    def _command(self, entry: dict) -> list[Event]:
        """What a command of Claude Code's said, as of anything said."""
        return self._said(_command_event(self._when, entry, self._whole))

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
            self._when,
            who,
            entry,
            block,
            self._project_dir,
            self._verbose,
            self._diffed,
        )
        call = str(block.get("id"))
        issued = _open_call(event, entry, block, whole=not self._live)
        key = call
        if self._waits(call):
            # A transcript is the session's to add to: a call it wrote
            # under the id of one that runs would take its result, and
            # the call before would be told with none. Kept apart, it is
            # told with none itself, and said to be so.
            self._reused += 1
            key = f"{call}\0{self._reused}"
            event.say(REUSED_ID, alert=True)
            event.went_wrong()
        if self._live:
            self._calls += 1
            event.link = issued.link = self._link()
            event.fields = {"stage": Stage.CALL, **event.fields}
            # Of the step its side is at, when the entry names it
            _, in_step = self._at.get(_side_of(who, entry), ("", []))
            if step_of(entry) and len(in_step) < MOST_REMEMBERED:
                in_step.append(key)
        self._open[key] = issued
        self._remember(self._open)
        # A result that comes is not this call's, and is named
        self._last_call = call if key == call else None
        return event

    def _waits(self, call: str) -> bool:
        """Whether a call of that id waits for its result."""
        issued = self._open.get(call)
        return issued is not None and (self._live or issued.event is not None)

    def _issued(self, call: str, entry: dict) -> OpenCall | None:
        """The call a result is of, by its id and the entry of the
        result. Live it is let go of with its result, and kept among
        those answered, for what else comes as its result: a session can
        write one ahead of the real one, which says the call failed.
        There is none for a result whose call was not seen: that is of
        before the following began. Else it is kept, for what else comes
        as its result, and a call that was not seen is known all the
        same, see _elsewhere."""
        if self._live:
            issued = self._open.pop(call, None) or self._answered.get(call)
            if issued is not None:
                self._answered[call] = issued
                self._remember(self._answered)
            return issued
        issued = self._open.get(call)
        if issued is None:
            # Kept as the others are: found once, however many results
            # are given as its own
            issued = self._open[call] = self._elsewhere(call, entry)
        return issued

    def _elsewhere(self, call: str, entry: dict) -> OpenCall:
        """A call that is not ahead of its result in what is walked, as
        far as the result needs it: the one of that id in the other part
        of the transcript (see OtherPart), named as its event names it,
        or one that is nowhere, of which the result alone says by whom
        it is."""
        found = self._other.calls.get(call)
        if found is None:
            return OpenCall(claude_of(entry), NO_TOOL, {}, NO_CALL, None)
        issued, block = found
        # For what it is named by, not for its lines
        event = call_event(
            self._when,
            claude_of(issued),
            issued,
            block,
            self._project_dir,
            verbose=False,
            diffed=False,
        )
        return _open_call(event, issued, block, whole=False)

    def _result(self, entry: dict, block: dict) -> list[Event]:
        """How a call ended: added to its event, or an event of its own
        where there is none to add it to, which is so live, of a call
        that had a result before, and of one this walk has not seen (see
        _issued). Live nothing for the result of a call that was not
        seen."""
        call = str(block.get("tool_use_id"))
        issued = self._issued(call, entry)
        if issued is None:
            return []
        ended = outcome(
            issued.started,
            entry,
            block,
            self._project_dir,
            issued.name,
            issued.source,
        )
        if issued.event:
            self._ended(issued.event, ended)
            # Once: what else comes as its result is told apart
            issued.event = None
            return []
        # Always where a transcript is all there: such a result is far
        # from its call, or has none
        named = not self._live or self._name_results or self._last_call != call
        self._last_call = None
        fields = {
            "stage": Stage.RESULT,
            "tool": issued.name,
            "id": call,
            **ended.fields(),
        }
        details = ["of: " + issued.label] if named else []
        event = Event(
            self._when,
            issued.who,
            issued.name.lower(),
            details,
            fields,
            issued.link,
            call=True,
        )
        tell_result(event, ended, self._verbose)
        return [event]

    def _ended(self, event: Event, ended: Outcome) -> None:
        """Add how a call ended to its event."""
        self.added += 1
        tell_result(event, ended, self._verbose)
        # Whether it wrote outside the project stays the last value,
        # and is so when the call or what it ran did
        fields, found = event.fields, ended.fields()
        key = "outside_project"
        flags = [of.pop(key) for of in (fields, found) if key in of]
        fields.update(found)
        if flags:
            fields[key] = any(flags)


def _steps_used(entries: list[dict]) -> dict[str, dict]:
    """What each step of the model used, by its id: as the last entry of
    a step has it, should an earlier one be short."""
    return dict(found for found in map(step_usage, entries) if found)


def left_events(
    entries: list[dict], gone: list[dict], project_dir: str, options: WalkOptions
) -> list[Event]:
    """The events of a transcript as it is now, next to the entries that
    were taken out of it: a result whose call is among those is named
    after it."""
    other = OtherPart(calls_issued(gone))
    walk = Walk(project_dir, options, _steps_used(entries), other)
    events = [event for entry in entries for event in walk.take(entry)]
    walk.end()
    return events


def taken_out_events(
    gone: list[dict], left: list[dict], project_dir: str, options: WalkOptions
) -> list[Event]:
    """The events of the entries that were taken out of a transcript,
    next to what is left of it. A result that was taken out or altered
    is named after its call, which may be left, and a call that was is
    told with its result, which may be left too. Then one event for the
    entries that add to none (see _untold_event), at the time of the
    first: nothing that was taken out goes without a word."""
    if not gone:
        return []
    other = OtherPart(calls_issued(left), tool_results(left))
    walk = Walk(project_dir, options, _steps_used(gone), other)
    events: list[Event] = []
    untold: list[dict] = []
    for entry in gone:
        added = walk.added
        found = walk.take(entry)
        events += found
        if not found and walk.added == added:
            untold.append(entry)
    walk.end()
    if untold:
        times = entry_times(untold) or entry_times(gone)
        when = times[0].timestamp() if times else 0.0
        events.append(_untold_event(when, untold))
    return events
