"""What a transcript holds besides the conversation and the tool calls.

What Claude Code put before the model next to the prompt: the instruction
files it read (each CLAUDE.md), the instructions of MCP servers, the
skills it listed, the texts of given.py, a file that changed behind the
model's back, what a language server reported, the hooks it ran (see
hooks.py), and a prompt that did not come from the user. And what became
of the session itself: its permission mode, its model, a request the API
did not answer, a conversation that was compacted, a task of its that
ended or fired, what it saved to its memory or published, and that it can
be driven from claude.ai.

None of it is something the model did, all of it says why it did what it
did. Like the rest of a transcript it is written from inside the sandbox,
so nothing of it is trusted, see events.py, and what is kept of it while
a transcript is followed is bounded."""

from __future__ import annotations

import dataclasses
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from ..events import Event, Kind, Who, Wrong, clean, flat
from .brief import PREVIEW_WIDTH, TALK_LINES, amount, between, clip, shortened
from .entries import (
    MOST_LISTED,
    Origin,
    block_text,
    claude_of,
    counted,
    every,
    kept,
    listed,
    message_content,
    origin_of,
    seconds,
    text_blocks,
)
from .given import GIVEN, GIVING, Given, digest_of, scanned, texts_read
from .hooks import HOOK_RUNS, STOP_SUMMARY, hook_event, summary_event
from .planted import Planted, flagged, planted

# What a line of a language server's report is about, in the order of the
# LSP's severities as Claude Code names them
SEVERITIES = ("Error", "Warning", "Info", "Hint")
# The mode in which a line typed while claude works is a prompt
PROMPT_MODE = "prompt"
# Where the instructions the user gave every session are from, as Claude
# Code names it: those are the host's own and read-only in the sandbox.
# Any other file of instructions came with the project or was written in
# a session.
OWN_INSTRUCTIONS = frozenset({"Managed", "User"})
# The kind of the event that tells of the files read as instructions, and
# of the one that tells what Claude Code said in the place of a prompt.
# Each kind is a name given here, never a value of the transcript.
INSTRUCTIONS = "instructions"
# What Claude Code attaches for a file of instructions it read later on
NESTED = "nested_memory"
# Of those, and of the texts of given.py, how many are remembered as they
# were last told: what one says again is told once
MOST_REMEMBERED = 1000
TOLD = "told"
# The mode of a queued command that tells of a task that ended, and the
# origin of a prompt that does, which tells of it in a tag of that name.
# A prompt of that origin without the tag is one a task of the schedule
# fired with.
TASK_NOTIFICATION = "task-notification"
TASK_TAG = f"<{TASK_NOTIFICATION}>"
# What starts the line of a prompt that came from outside the session
NOT_FROM_YOU = "NOT FROM YOU"


class Read(Protocol):
    """Something read into the conversation: a file of instructions, or
    a text of given.py."""

    @property
    def line(self) -> str: ...

    @property
    def fields(self) -> dict: ...

    @property
    def planted(self) -> tuple[Planted, ...]: ...


def names(value: object) -> list[str]:
    """The names in a list a transcript gives, each on one line."""
    return [
        flat(name)[:PREVIEW_WIDTH] for name in listed(value) if isinstance(name, str)
    ]


@dataclass(frozen=True)
class Instructions:
    """A file of instructions Claude Code read into the conversation: a
    CLAUDE.md, a rule, its memory. The kind is where Claude Code says it
    is from: Managed, User, Project, Local, AutoMem."""

    path: str
    kind: str
    # How long it is, in characters
    size: int
    # The signs that it was written to turn the session against the
    # user, of a file that is not the user's own, see planted.py
    planted: tuple[Planted, ...] = ()
    # What its content is told from another by, see digest_of
    digest: bytes = b""

    @property
    def line(self) -> str:
        """How it is told."""
        about = f"{flat(self.path)} ({flat(self.kind)}, {amount(self.size)} chars)"
        return f"instructions: {about}"

    @property
    def fields(self) -> dict:
        about = {"path": self.path, "type": self.kind, "chars": self.size}
        return {**about, **flagged(self.planted)}


def _instructions_planted(
    kind: str, content: object, path: str = ""
) -> tuple[Planted, ...]:
    """The signs in a file read as instructions (see planted.py), each
    with the file it is in, none for one of the user's own."""
    return () if kind in OWN_INSTRUCTIONS else planted(content, path)


def _instructions_given(given: dict) -> list:
    """The files an attachment gives as read as instructions: all those of
    the instructions of a session, or the one Claude Code read later, as
    the model read a file in its directory (a CLAUDE.md below the top of
    the project), which the attachment names as its own when it does not
    say. All of them: a file past those shown is looked at all the same,
    a repository can come with a file of instructions past any count."""
    kind = given.get("type")
    if kind == NESTED:
        read = given.get("content")
        if not isinstance(read, dict):
            return []
        return [{"path": given.get("path"), **read}]
    return every(given.get("files")) if kind == INSTRUCTIONS else []


def files_read(given: dict) -> list[tuple[Instructions, object]]:
    """The files an entry says were read as instructions, each as it is
    told without the signs it shows, and its content to look for them
    in: what is read again is known so before it is looked at."""
    files = []
    for file in _instructions_given(given):
        if not isinstance(file, dict) or not isinstance(file.get("path"), str):
            continue
        kind, content = kept(file.get("type")) or "?", file.get("content")
        size = len(content) if isinstance(content, str) else 0
        read = Instructions(kept(file["path"]), kind, size, digest=digest_of(content))
        files.append((read, content))
    return files


def scanned_file(read: Instructions, content: object) -> Instructions:
    """A file of instructions as it is told, with the signs it shows."""
    signs = _instructions_planted(read.kind, content, read.path)
    return dataclasses.replace(read, planted=signs)


def attachment(entry: dict) -> dict:
    """What Claude Code attached to the conversation in an entry, empty
    for an entry that is no attachment."""
    given = entry.get("attachment") if entry.get("type") == "attachment" else None
    return given if isinstance(given, dict) else {}


def typed_while_working(entry: dict) -> object:
    """What the user typed while claude worked, when an entry is that:
    text or blocks of it, none for any other entry. Such a line is given
    to the model with the next result, and is in no entry of the user's.
    Not what Claude Code queued in their name (isMeta), nor what did not
    come from them, see told_events."""
    given = attachment(entry)
    if given.get("type") != "queued_command" or given.get("commandMode") != PROMPT_MODE:
        return None
    if given.get("isMeta") or not origin_of(given).users:
        return None
    return given.get("prompt")


def _origin_said(origin: Origin) -> str:
    """Where a prompt that is not the user's came from, as it is said:
    its kind and who it names as having sent it."""
    sender = f" {shortened(flat(origin.sender))}" if origin.sender else ""
    return f"{shortened(flat(origin.kind))}{sender}"


def told_planted(origin: Origin, said: object) -> tuple[Planted, ...]:
    """The signs in a prompt that came from outside the session, see
    planted.py, none for one that did not: another session or a server
    can write anything, and the model takes it in as it takes a prompt."""
    return planted(block_text(said), _origin_said(origin)) if origin.outside else ()


def _prompt_given(entry: dict) -> tuple[Origin, object] | None:
    """The prompt an entry gives the model, with where it came from: of
    the user's side its text blocks (see text_blocks), or what was queued
    while claude worked. None for an entry that gives none."""
    given = attachment(entry)
    if given.get("type") == "queued_command":
        return origin_of(given), given.get("prompt")
    if entry.get("type") != "user":
        return None
    return origin_of(entry), text_blocks(message_content(entry))


def entry_told_planted(entry: dict) -> tuple[Planted, ...]:
    """The signs in what an entry gave the model as a prompt from outside
    the session, see _prompt_given."""
    prompt = _prompt_given(entry)
    return () if prompt is None else told_planted(*prompt)


def told_from_outside(entries: list[dict]) -> Counter[str]:
    """How many prompts came from outside the session, by where they came
    from, see Origin."""
    found = (_prompt_given(entry) for entry in entries)
    return Counter(prompt[0].kind for prompt in found if prompt and prompt[0].outside)


def _task_event(said: object, when: float, who: Who) -> Event:
    """A task that ended, as Claude Code tells the model of it: how, and
    what it was."""
    text = clean(said) if isinstance(said, str) else ""
    status = flat((between(text, "<status>", "</status>") or "ended").strip())
    summary = flat((between(text, "<summary>", "</summary>") or "").strip())
    line = shortened(f"{status}: {summary}" if summary else status)
    fields = {"status": status, "summary": summary, "text": said}
    return Event(when, who, Kind.TASK, [line], fields)


def told_events(
    origin: Origin,
    said: object,
    when: float,
    who: Who,
    verbose: bool,
    live: bool = False,
) -> list[Event]:
    """A prompt the user did not give, see Origin: what Claude Code made
    itself, as it told the model, a task that ended as that, and what
    came from outside the session as a prompt that is flagged, with its
    kind, who sent it, and the signs it shows. Of its text the first
    lines, all of them with verbose, and live the first alone, as of a
    prompt. None for a prompt of the user's, and for one without text."""
    if origin.users:
        return []
    if origin.kind == TASK_NOTIFICATION and TASK_TAG in block_text(said):
        return [_task_event(block_text(said), when, who)]
    # Else the prompt a task of the schedule fired with, as it is, or
    # what Claude Code told in another way of its own
    text = clean(block_text(said)).strip().splitlines()
    whole = verbose and not live
    lines = text if whole else [line for line in text if line.strip()]
    if not lines:
        return []
    fields: dict = {"origin": origin.kind, "from": origin.sender, "text": said}
    if origin.claude_codes:
        first = f"told ({_origin_said(origin)}): {shortened(lines[0])}"
        fields = {"kind": TOLD, **fields}
        return [Event(when, who, Kind.CONTEXT, [first], fields)]
    shown = [shortened(lines[0])] if live else clip(lines, whole, TALK_LINES)
    signs = told_planted(origin, said)
    first = f"{NOT_FROM_YOU} ({_origin_said(origin)}): {shown[0]}"
    event = Event(when, who, Kind.PROMPT, [first, *shown[1:]], {})
    event.alerts.add(0)
    for sign in signs:
        event.say(sign.shown, alert=True)
    event.fields = {**fields, "not_from_you": True, **flagged(signs)}
    event.went_wrong()
    return [event]


def instructions_read(entries: list[dict]) -> list[str]:
    """Each file the session read as instructions, for the header of a
    trace: they steer a session as a prompt does, and one of them may
    have come with the project."""
    files = {
        (flat(file.path), flat(file.kind))
        for entry in entries
        for file, _ in files_read(attachment(entry))
    }
    lines = ["instructions read"] if files else []
    shown = sorted(files)[:MOST_LISTED]
    lines += [f"  {shortened(path)} ({kind[:PREVIEW_WIDTH]})" for path, kind in shown]
    if len(files) > len(shown):
        lines.append(f"  ... {len(files) - len(shown)} more")
    return lines


def _read_event(
    read: Sequence[Read],
    fields: dict,
    more: Callable[[int], str],
    when: float,
    who: Who,
) -> Event:
    """The event of what was read into the conversation, with the fields
    of what it is: each named, no more than MOST_LISTED of them and how
    many more there are (the line more says for that count), and the
    signs of every one, past those named too."""
    signs = flagged(sign for one in read for sign in one.planted)
    event = Event(when, who, Kind.CONTEXT, [], {**fields, **signs})
    if signs:
        event.went_wrong()
    named, rest = read[:MOST_LISTED], read[MOST_LISTED:]
    for one in named:
        event.say(one.line)
        for sign in one.planted:
            event.say(sign.shown, alert=True)
    if rest:
        event.say(more(len(rest)))
    for sign in (sign for one in rest for sign in one.planted):
        event.say(sign.shown, alert=True)
    return event


def _instructions_event(
    files: tuple[Instructions, ...], when: float, who: Who
) -> Event:
    """The event of files read as instructions."""
    fields = {"kind": INSTRUCTIONS, "files": [file.fields for file in files]}
    return _read_event(
        files, fields, lambda rest: f"instructions: ... {rest} more files", when, who
    )


def _given_event(texts: tuple[Given, ...], when: float, who: Who) -> Event:
    """The event of texts an attachment put before the model, all of one
    kind."""
    first = texts[0]
    fields = {
        "kind": GIVEN,
        "of": first.kind,
        "texts": [text.fields for text in texts],
    }
    return _read_event(
        texts, fields, lambda rest: f"{first.what}: ... {rest} more", when, who
    )


def _diagnostic_lines(file: dict) -> list[str]:
    """What a language server reported of one file: how many of each
    severity, then each message with its line."""
    found = [d for d in listed(file.get("diagnostics")) if isinstance(d, dict)]
    by_severity = [
        (severity, sum(d.get("severity") == severity for d in found))
        for severity in SEVERITIES
    ]
    counts = ", ".join(f"{n} {severity}" for severity, n in by_severity if n)
    lines = [f"diagnostics: {flat(file.get('uri', '?'))}: {counts or len(found)}"]
    for diagnostic in found:
        position = diagnostic.get("range")
        start = position.get("start") if isinstance(position, dict) else None
        line = counted(start.get("line")) if isinstance(start, dict) else None
        # A language server counts lines from 0
        at = f" line {line + 1}" if line is not None else ""
        severity = flat(diagnostic.get("severity", "?"))[:PREVIEW_WIDTH]
        said = shortened(flat(diagnostic.get("message", "")))
        lines.append(f"  {severity}{at}: {said}")
    return lines


class Asides:
    """Turns the entries of a transcript that are neither said nor done by
    the model into events, an entry at a time. What repeats is said once:
    Claude Code writes down the instructions and the mode of a session
    again and again, an event is what changed.

    What a language server reported is only told when verbose, it comes
    after every edit."""

    def __init__(self, verbose: bool, live: bool = False):
        self._verbose = verbose
        # Whether the transcript is followed as it is written, see Walk
        self._live = live
        # Each as it was last told, without the signs it shows: what is
        # given again is known so before it is looked at for them
        self._instructions: tuple[Instructions, ...] = ()
        self._nested: dict[str, Instructions] = {}
        self._given: dict[tuple[str, str], Given] = {}
        self._skills: tuple[int, tuple[str, ...]] = (0, ())
        self._mode = ""
        # The model and the effort last asked for, by what asked
        self._models: dict[str, tuple[str, str]] = {}
        # Why the model was last made to think anew, until a step is told
        self._dropped = ""
        # The pull request and the Remote Control session last named:
        # Claude Code names them again whenever it writes what it knows
        # of the session
        self._linked = ""
        self._bridge = ""

    def take(self, entry: dict, when: float) -> list[Event]:
        """The events an entry adds, none for one that is not an aside."""
        kind = entry.get("type")
        given, readers = entry, OF_THE_SESSION
        if kind == "attachment":
            given, readers = attachment(entry), ATTACHED
            kind = given.get("type")
        elif kind == "system":
            readers, kind = OF_THE_SYSTEM, entry.get("subtype")
        reader = readers.get(kind) if isinstance(kind, str) else None
        if reader is None:
            return []
        return reader(self, given, when, claude_of(entry))

    def prompted(self, entry: dict, when: float) -> list[Event]:
        """A prompt says the permission mode it was given in: an event
        when that is another than before."""
        return self._mode_set(entry, when, Who.CLAUDE)

    def dropped(self) -> str:
        """Why the model was made to think anew since the step before,
        empty when it was not: said once, with the step it cost."""
        why, self._dropped = self._dropped, ""
        return why

    def _instructions_read(self, given: dict, when: float, who: Who) -> list[Event]:
        """The files of instructions of the session: told when the set
        is new or one of them says other than it did, and looked at for
        signs then."""
        read = files_read(given)
        files = tuple(file for file, _ in read)
        if not files or files == self._instructions:
            return []
        self._instructions = files
        told = tuple(scanned_file(file, content) for file, content in read)
        return [_instructions_event(told, when, who)]

    def _nested_read(self, given: dict, when: float, who: Who) -> list[Event]:
        """A file of instructions Claude Code read later on, on top of
        those of the session: told when it is new or says other than it
        did, and looked at for signs then."""
        read = files_read(given)
        if not read or self._nested.get(read[0][0].path) == read[0][0]:
            return []
        file, content = read[0]
        _remember(self._nested, file.path, file)
        return [_instructions_event((scanned_file(file, content),), when, who)]

    def _texts_given(self, given: dict, when: float, who: Who) -> list[Event]:
        """Texts an attachment put before the model: told when one is new
        or says other than it did, and looked at for signs then, those it
        gives again are not."""
        new = [
            (text, said)
            for text, said in texts_read(given)
            if self._given.get((text.kind, text.source)) != text
        ]
        for text, _ in new:
            _remember(self._given, (text.kind, text.source), text)
        told = tuple(scanned(text, said) for text, said in new)
        return [_given_event(told, when, who)] if told else []

    def _server_instructions(self, given: dict, when: float, who: Who) -> list[Event]:
        added, removed = (
            names(given.get("addedNames")),
            names(given.get("removedNames")),
        )
        lines = []
        if added:
            lines.append("MCP server instructions: " + ", ".join(added))
        if removed:
            lines.append("MCP server instructions gone: " + ", ".join(removed))
        # Not named removed: that is what an event says of itself when it
        # was taken out of the transcript, see removed_events of trace.py
        fields = {"kind": "mcp_instructions", "added": added, "gone": removed}
        return [Event(when, who, Kind.CONTEXT, lines, fields)] if lines else []

    def _skills_listed(self, given: dict, when: float, who: Who) -> list[Event]:
        skills = names(given.get("names"))
        number = counted(given.get("skillCount")) or len(skills)
        listed = (number, tuple(skills))
        if not number or listed == self._skills:
            return []
        self._skills = listed
        more = "" if given.get("isInitial", True) else " more"
        line = f"skills: {number}{more} listed"
        if self._verbose and skills:
            line += ": " + ", ".join(skills)
        fields = {"kind": "skills", "count": number, "names": skills}
        return [Event(when, who, Kind.CONTEXT, [line], fields)]

    def _told(self, given: dict, when: float, who: Who) -> list[Event]:
        """What Claude Code told the model in the place of a prompt: that
        a task ended, or anything else it has a mode for, and what came
        from elsewhere than the user, by where it came from (see
        told_events). Not a line the user typed, which is a prompt, see
        typed_while_working."""
        mode = flat(given.get("commandMode") or "?")[:PREVIEW_WIDTH]
        said = given.get("prompt")
        origin = origin_of(given)
        if mode == TASK_NOTIFICATION:
            return [_task_event(said, when, who)]
        if not origin.users:
            events = told_events(origin, said, when, who, self._verbose, self._live)
            for event in events:
                event.fields["queued"] = True
            return events
        first = _first_line(said)
        line = f"told ({mode})" + (f": {first}" if first else "")
        # The mode under a name of its own: it is the session's to give,
        # and as the kind it could pass for one of those here, which are
        # the launcher's and say what else an event holds
        fields = {"kind": TOLD, "mode": mode, "text": said}
        return [Event(when, who, Kind.CONTEXT, [line], fields)]

    def _file_changed(self, given: dict, when: float, who: Who) -> list[Event]:
        path = given.get("filename")
        if not isinstance(path, str):
            return []
        line = f"changed since claude read it: {flat(path)}"
        fields = {"kind": "edited_file", "path": path, "snippet": given.get("snippet")}
        return [Event(when, who, Kind.CONTEXT, [line], fields)]

    def _diagnostics(self, given: dict, when: float, who: Who) -> list[Event]:
        files = [file for file in listed(given.get("files")) if isinstance(file, dict)]
        if not self._verbose or not files:
            return []
        lines = [line for file in files for line in _diagnostic_lines(file)]
        fields = {"kind": "diagnostics", "files": files}
        return [Event(when, who, Kind.CONTEXT, lines, fields)]

    def _thinking_dropped(self, given: dict, _when: float, _who: Who) -> list[Event]:
        dropped = given.get("newlyDropped")
        about = dropped if isinstance(dropped, dict) else {}
        blocks = counted(about.get("blockCount"))
        why = flat(about.get("reason") or "").replace("_", " ")[:PREVIEW_WIDTH]
        if blocks:
            said = f"{blocks} thinking block{'s' if blocks > 1 else ''} dropped"
            self._dropped = f"{said}, {why}" if why else said
        return []

    def _api_error(self, entry: dict, when: float, who: Who) -> list[Event]:
        """A request the API did not answer, or answered with an error,
        which Claude Code tries again."""
        error = entry.get("error")
        about = error if isinstance(error, dict) else {"message": error}
        said = about.get("formatted") or about.get("message")
        why = (
            shortened(flat(said))
            if isinstance(said, str) and said
            else "no reason given"
        )
        line = f"API error: {why}"
        fields: dict = {"error": why}
        wait = seconds(entry.get("retryInMs"))
        attempt, most = (
            counted(entry.get("retryAttempt")),
            counted(entry.get("maxRetries")),
        )
        if wait is not None:
            line += f", tried again after {wait:.1f}s"
            fields["retry_in"] = wait
        if attempt:
            line += f" (retry {attempt}" + (f" of {most})" if most else ")")
            fields.update(retry=attempt, retries=most)
        return [Event(when, who, Kind.API, [line], fields, wrong=Wrong.THROUGHOUT)]

    def _compacted(self, entry: dict, when: float, who: Who) -> list[Event]:
        """The conversation was summed up to make room: what the model
        knows of what came before is from then on the summary."""
        given = entry.get("compactMetadata") or entry.get("compact_metadata")
        about = given if isinstance(given, dict) else {}
        trigger = flat(about.get("trigger") or "")[:PREVIEW_WIDTH]
        before = counted(about.get("preTokens", about.get("pre_tokens")))
        line = "the conversation was compacted" + (f" ({trigger})" if trigger else "")
        if before:
            line += f", {amount(before)} tokens before"
        fields = {"trigger": trigger or None, "pre_tokens": before}
        return [Event(when, who, Kind.COMPACT, [line], fields)]

    def _mode_set(self, entry: dict, when: float, _who: Who) -> list[Event]:
        """The permission mode of the session, an event when it is another
        than before: what the session was started in is in the header."""
        mode = kept(entry.get("permissionMode"))
        if not mode or entry.get("isSidechain"):
            return []
        was, self._mode = self._mode, mode
        if not was or was == mode:
            return []
        line = f"permissions: {shortened(flat(mode))}  was: {shortened(flat(was))}"
        return [Event(when, Who.CLAUDE, Kind.MODE, [line], {"mode": mode, "was": was})]

    def _requested(self, entry: dict, when: float, who: Who) -> list[Event]:
        """A request to the API says which model it asks and how hard it
        is to think: an event when that is another than the request
        before of the same kind asked for."""
        params = entry.get("params")
        if not isinstance(params, dict):
            return []
        config = params.get("output_config")
        effort = kept(config.get("effort")) if isinstance(config, dict) else ""
        asked = (kept(params.get("model")), effort)
        source = kept(entry.get("querySource"))
        was = self._models.get(source)
        if not asked[0] or (was is None and len(self._models) >= MOST_LISTED):
            return []
        self._models[source] = asked
        if was is None or was == asked:
            return []
        line = f"{_model_shown(*asked)}  was: {_model_shown(*was)}"
        fields = {
            "model": asked[0],
            "effort": asked[1] or None,
            "was_model": was[0],
            "was_effort": was[1] or None,
            "source": source,
        }
        return [Event(when, who, Kind.MODEL, [line], fields)]

    def _hook_ran(self, given: dict, when: float, who: Who) -> list[Event]:
        """A hook that ran, see hooks.py."""
        event = hook_event(given, when, who, self._verbose)
        return [event] if event else []

    def _stop_hooks(self, entry: dict, when: float, who: Who) -> list[Event]:
        """The hooks Claude Code ran as claude was to stop, see hooks.py."""
        return [summary_event(entry, when, who)]

    def _scheduled(self, entry: dict, when: float, who: Who) -> list[Event]:
        """A task of the session's schedule that fired: a turn that no
        user started, with the prompt it was given."""
        cron = shortened(flat(kept(entry.get("cron"))))
        prompt = _first_line(entry.get("prompt"))
        line = "scheduled task fired" + (f" ({cron})" if cron else "")
        fields = {
            "task_id": kept(entry.get("taskId")),
            "cron": kept(entry.get("cron")),
            "prompt": entry.get("prompt"),
        }
        return [
            Event(
                when, who, Kind.TASK, [f"{line}: {prompt}" if prompt else line], fields
            )
        ]

    def _memory_saved(self, entry: dict, when: float, who: Who) -> list[Event]:
        """Files Claude Code wrote to its memory, which a later session
        of the project is given."""
        paths = [
            path for path in every(entry.get("writtenPaths")) if isinstance(path, str)
        ]
        if not paths:
            return []
        lines = [f"saved: {shortened(flat(path))}" for path in paths[:MOST_LISTED]]
        if len(paths) > MOST_LISTED:
            lines.append(f"saved: ... {len(paths) - MOST_LISTED} more")
        return [Event(when, who, Kind.MEMORY, lines, {"paths": paths})]

    def _bridged(self, entry: dict, when: float, who: Who) -> list[Event]:
        """Remote Control was switched on: whoever has the claude.ai
        account can drive the session from there, a phone too, at the
        address it gives. Gone wrong throughout."""
        url = kept(entry.get("url"))
        line = "REMOTE CONTROL is on, the session can be driven from claude.ai"
        line += f": {shortened(flat(url))}" if url else ""
        return [
            Event(when, who, Kind.REMOTE, [line], {"url": url}, wrong=Wrong.THROUGHOUT)
        ]

    def _bridge_session(self, entry: dict, when: float, who: Who) -> list[Event]:
        """The Remote Control session the session is joined to, as Claude
        Code names it whenever it writes what it knows of the session:
        told when it is another than before, gone wrong throughout but
        when it was let go of."""
        bridge = kept(entry.get("bridgeSessionId"))
        if bridge == self._bridge:
            return []
        was, self._bridge = self._bridge, bridge
        if not bridge:
            line = f"remote control ended: {shortened(flat(was))}"
            return [
                Event(
                    when, who, Kind.REMOTE, [line], {"bridge_session": "", "was": was}
                )
            ]
        line = f"REMOTE CONTROL session: {shortened(flat(bridge))}"
        fields = {"bridge_session": bridge, "was": was}
        return [Event(when, who, Kind.REMOTE, [line], fields, wrong=Wrong.THROUGHOUT)]

    def _published(self, entry: dict, when: float, who: Who) -> list[Event]:
        """A change the session had published for review, a pull request
        created or pushed to, as Claude Code noted it: where, and how."""
        about = {
            key: kept(entry.get(key))
            for key in ("provider", "url", "repo", "identifier", "action", "branch")
        }
        named = [about["action"], about["repo"], about["identifier"]]
        if about["branch"]:
            named.append(f"branch {about['branch']}")
        said = ", ".join(shortened(flat(one)) for one in named if one)
        line = f"{shortened(flat(about['url'])) or '?'}" + (
            f" ({said})" if said else ""
        )
        return [Event(when, who, Kind.PUBLISHED, [line], about)]

    def _pr_linked(self, entry: dict, when: float, who: Who) -> list[Event]:
        """The pull request the session is linked to, as Claude Code names
        it whenever it writes what it knows of the session: told when it
        is another than before."""
        url = kept(entry.get("prUrl"))
        if not url or url == self._linked:
            return []
        self._linked = url
        number, repo = counted(entry.get("prNumber")), kept(entry.get("prRepository"))
        named = ([f"#{number}"] if number is not None else []) + (
            [repo] if repo else []
        )
        said = shortened(flat(", ".join(named)))
        line = f"pull request: {shortened(flat(url))}" + (f" ({said})" if said else "")
        fields = {"url": url, "number": number, "repository": repo}
        return [Event(when, who, Kind.PUBLISHED, [line], fields)]

    def _denied(self, entry: dict, when: float, who: Who) -> list[Event]:
        """A call the permissions refused, as Claude Code noted it apart
        from its result: of which tool, and why. Gone wrong throughout."""
        tool = kept(entry.get("tool_name"))
        why = entry.get("decision_reason") or entry.get("message")
        reason = shortened(flat(why)) if isinstance(why, str) and why else ""
        line = f"permission DENIED: {shortened(flat(tool)) or '?'}"
        fields = {
            # Not named tool: no other event than a call has that, see
            # call_event of calls.py
            "denied_tool": tool,
            "call": kept(entry.get("tool_use_id")),
            "reason": why if isinstance(why, str) else None,
        }
        line += f": {reason}" if reason else ""
        return [Event(when, who, Kind.MODE, [line], fields, wrong=Wrong.THROUGHOUT)]

    def _fell_back(self, entry: dict, when: float, who: Who) -> list[Event]:
        """Claude Code went on with another model than the one asked for:
        when that one failed, or refused the request, which is gone
        wrong."""
        was, model = kept(entry.get("originalModel")), kept(entry.get("fallbackModel"))
        trigger = kept(entry.get("trigger"))
        refused = (
            entry.get("subtype") == "model_refusal_fallback" or trigger == "refusal"
        )
        line = f"{shortened(flat(model)) or '?'}  was: {shortened(flat(was)) or '?'}"
        category = kept(entry.get("apiRefusalCategory"))
        if refused:
            line += ", the model REFUSED the request" + (
                f" ({shortened(flat(category))})" if category else ""
            )
        elif trigger:
            line += f", fell back: {shortened(flat(trigger))}"
        fields = {
            "model": model,
            "was_model": was,
            "trigger": trigger,
            "refused": refused,
            "category": category or None,
        }
        event = Event(when, who, Kind.MODEL, [line], fields)
        if refused:
            event.alerts.add(0)
            event.went_wrong()
        return [event]


# What reads the entries of each kind that Asides tells of: of an
# attachment, of the system, and of the session itself, each by its kind
# as Claude Code names it. One more is one more here, and see untold_kinds
# of transcript.py for those that are known to tell nothing.
type Reader = Callable[[Asides, dict, float, Who], list[Event]]
ATTACHED: dict[str, Reader] = {
    INSTRUCTIONS: Asides._instructions_read,
    NESTED: Asides._nested_read,
    "mcp_instructions_delta": Asides._server_instructions,
    "skill_listing": Asides._skills_listed,
    "queued_command": Asides._told,
    "edited_text_file": Asides._file_changed,
    "diagnostics": Asides._diagnostics,
    "thinking_drop": Asides._thinking_dropped,
    **dict.fromkeys(GIVING, Asides._texts_given),
    **dict.fromkeys(HOOK_RUNS, Asides._hook_ran),
}
OF_THE_SYSTEM: dict[str, Reader] = {
    "api_error": Asides._api_error,
    "compact_boundary": Asides._compacted,
    STOP_SUMMARY: Asides._stop_hooks,
    "scheduled_task_fire": Asides._scheduled,
    "memory_saved": Asides._memory_saved,
    "bridge_status": Asides._bridged,
    "code_change_published": Asides._published,
    "permission_denied": Asides._denied,
    "model_fallback": Asides._fell_back,
    "model_refusal_fallback": Asides._fell_back,
}
OF_THE_SESSION: dict[str, Reader] = {
    "permission-mode": Asides._mode_set,
    "api-request": Asides._requested,
    "pr-link": Asides._pr_linked,
    "bridge-session": Asides._bridge_session,
}


def _first_line(said: object) -> str:
    """The first line of a text a transcript gives, cut to the width of
    a preview, empty for what is no text."""
    text = clean(said).strip() if isinstance(said, str) else ""
    return shortened((text.splitlines() or [""])[0])


def _remember[K, V](remembered: dict[K, V], key: K, value: V) -> None:
    """Keep what was last told of something, forgetting the oldest past
    MOST_REMEMBERED: what is forgotten is told again."""
    remembered.pop(key, None)
    remembered[key] = value
    while len(remembered) > MOST_REMEMBERED:
        del remembered[next(iter(remembered))]


def _model_shown(model: str, effort: str) -> str:
    said = shortened(flat(model))
    return f"{said}, effort {shortened(flat(effort))}" if effort else said
