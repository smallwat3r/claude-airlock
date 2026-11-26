"""What a transcript holds besides the conversation and the tool calls.

What Claude Code put before the model next to the prompt: the instruction
files it read (each CLAUDE.md), the instructions of MCP servers, the
skills it listed, a file that changed behind the model's back, what a
language server reported. And what became of the session itself: its
permission mode, its model, a request the API did not answer, a
conversation that was compacted, a task of its that ended.

None of it is something the model did, all of it says why it did what it
did. Like the rest of a transcript it is written from inside the sandbox,
so nothing of it is trusted, see events.py, and what is kept of it while
a transcript is followed is bounded."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..events import Event, Kind, Who, Wrong, clean, flat
from .brief import PREVIEW_WIDTH, amount, between, shortened
from .entries import MOST_LISTED, claude_of, counted, every, kept, listed, seconds
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
# Of those, how many are remembered as they were last told: what one
# says again is told once
MOST_NESTED = 1000
TOLD = "told"

type Reader = Callable[[dict, float, Who], list[Event]]


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

    @property
    def shown(self) -> str:
        return f"{flat(self.path)} ({flat(self.kind)}, {amount(self.size)} chars)"

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


def instruction_files(given: dict, scan: bool = True) -> tuple[Instructions, ...]:
    """The files an entry says were read as instructions, each with the
    signs it shows unless told not to look: for what only names them."""
    files = []
    for file in _instructions_given(given):
        if not isinstance(file, dict) or not isinstance(file.get("path"), str):
            continue
        kind, content = kept(file.get("type")) or "?", file.get("content")
        size = len(content) if isinstance(content, str) else 0
        path = kept(file["path"])
        signs = _instructions_planted(kind, content, path) if scan else ()
        files.append(Instructions(path, kind, size, signs))
    return tuple(files)


def attachment(entry: dict) -> dict:
    """What Claude Code attached to the conversation in an entry, empty
    for an entry that is no attachment."""
    given = entry.get("attachment") if entry.get("type") == "attachment" else None
    return given if isinstance(given, dict) else {}


def typed_while_working(entry: dict) -> object:
    """What the user typed while claude worked, when an entry is that:
    text or blocks of it, none for any other entry. Such a line is given
    to the model with the next result, and is in no entry of the user's."""
    given = attachment(entry)
    if given.get("type") != "queued_command" or given.get("commandMode") != PROMPT_MODE:
        return None
    return given.get("prompt")


def instructions_read(entries: list[dict]) -> list[str]:
    """Each file the session read as instructions, for the header of a
    trace: they steer a session as a prompt does, and one of them may
    have come with the project."""
    files = {
        (flat(file.path), flat(file.kind))
        for entry in entries
        for file in instruction_files(attachment(entry), scan=False)
    }
    lines = ["instructions read"] if files else []
    shown = sorted(files)[:MOST_LISTED]
    lines += [f"  {shortened(path)} ({kind[:PREVIEW_WIDTH]})" for path, kind in shown]
    if len(files) > len(shown):
        lines.append(f"  ... {len(files) - len(shown)} more")
    return lines


def _instructions_event(
    files: tuple[Instructions, ...], when: float, who: Who
) -> Event:
    """The event of files read as instructions: each named, no more than
    MOST_LISTED of them and how many more there are, and the signs of
    every one, past those named too."""
    fields = {
        "kind": INSTRUCTIONS,
        "files": [file.fields for file in files],
        **flagged(sign for file in files for sign in file.planted),
    }
    event = Event(when, who, Kind.CONTEXT, [], fields)
    if any(file.planted for file in files):
        event.went_wrong()
    named, rest = files[:MOST_LISTED], files[MOST_LISTED:]
    for file in named:
        event.say(f"instructions: {file.shown}")
        for sign in file.planted:
            event.say(sign.shown, alert=True)
    if rest:
        event.say(f"instructions: ... {len(rest)} more files")
    for sign in (sign for file in rest for sign in file.planted):
        event.say(sign.shown, alert=True)
    return event


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

    def __init__(self, verbose: bool):
        self._verbose = verbose
        self._instructions: tuple[Instructions, ...] = ()
        self._nested: dict[str, Instructions] = {}
        self._skills: tuple[int, tuple[str, ...]] = (0, ())
        self._mode = ""
        # The model and the effort last asked for, by what asked
        self._models: dict[str, tuple[str, str]] = {}
        # Why the model was last made to think anew, until a step is told
        self._dropped = ""
        self._attached: dict[str, Reader] = {
            INSTRUCTIONS: self._instructions_read,
            NESTED: self._nested_read,
            "mcp_instructions_delta": self._server_instructions,
            "skill_listing": self._skills_listed,
            "queued_command": self._told,
            "edited_text_file": self._file_changed,
            "diagnostics": self._diagnostics,
            "thinking_drop": self._thinking_dropped,
        }
        self._of_the_system: dict[str, Reader] = {
            "api_error": self._api_error,
            "compact_boundary": self._compacted,
        }
        self._of_the_session: dict[str, Reader] = {
            "permission-mode": self._mode_set,
            "api-request": self._requested,
        }

    def take(self, entry: dict, when: float) -> list[Event]:
        """The events an entry adds, none for one that is not an aside."""
        kind = entry.get("type")
        given, readers = entry, self._of_the_session
        if kind == "attachment":
            given, readers = attachment(entry), self._attached
            kind = given.get("type")
        elif kind == "system":
            readers, kind = self._of_the_system, entry.get("subtype")
        reader = readers.get(kind) if isinstance(kind, str) else None
        if reader is None:
            return []
        return reader(given, when, claude_of(entry))

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
        files = instruction_files(given)
        if not files or files == self._instructions:
            return []
        self._instructions = files
        return [_instructions_event(files, when, who)]

    def _nested_read(self, given: dict, when: float, who: Who) -> list[Event]:
        """A file of instructions Claude Code read later on, on top of
        those of the session: told when it is new or says other than it
        did."""
        files = instruction_files(given)
        if not files or self._nested.get(files[0].path) == files[0]:
            return []
        self._nested[files[0].path] = files[0]
        while len(self._nested) > MOST_NESTED:
            del self._nested[next(iter(self._nested))]
        return [_instructions_event(files, when, who)]

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
        a task ended, or anything else it has a mode for. Not a line the
        user typed, which is a prompt, see typed_while_working."""
        mode = flat(given.get("commandMode") or "?")[:PREVIEW_WIDTH]
        said = given.get("prompt")
        text = clean(said) if isinstance(said, str) else ""
        if mode != "task-notification":
            first = (text.strip().splitlines() or [""])[0]
            first = shortened(first)
            line = f"told ({mode})" + (f": {first}" if first else "")
            # The mode under a name of its own: it is the session's to
            # give, and as the kind it could pass for one of those here,
            # which are the launcher's and say what else an event holds
            fields = {"kind": TOLD, "mode": mode, "text": said}
            return [Event(when, who, Kind.CONTEXT, [line], fields)]
        status = flat((between(text, "<status>", "</status>") or "ended").strip())
        summary = flat((between(text, "<summary>", "</summary>") or "").strip())
        line = shortened(f"{status}: {summary}" if summary else status)
        fields = {"status": status, "summary": summary, "text": said}
        return [Event(when, who, Kind.TASK, [line], fields)]

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


def _model_shown(model: str, effort: str) -> str:
    said = shortened(flat(model))
    return f"{said}, effort {shortened(flat(effort))}" if effort else said
