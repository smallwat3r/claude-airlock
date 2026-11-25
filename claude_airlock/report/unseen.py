"""The commands of a transcript that no process was seen of.

The watcher of a session looks, it is not told (see procwatch.py): a
process that lived shorter than the time between two looks is not in its
record, and neither is what that process started and waited for. A trace
then has the command, from the transcript, and nothing of what it ran,
which reads the same as a command that ran nothing more. So a command in
whose time the record has no process at all says so.

By the clock, the record does not say which command a process is of: a
command is held against the processes first seen from when it was issued
to when its result came. Another process first seen in that time, of a
command that ran next to it or of Claude Code's own, passes for one of
its, and the command then goes without the line. The line is true where
it is said, it is not said of every command it is true of.

Not said where the record cannot tell: of a command issued before the
watcher was up or after it ran out of room for processes, and of one in
whose time another session of the project ran whose record cannot tell.
Nor of a command that was not let run, or of one without a result, which
is not known to have run at all. A trace says it, not what follows a
session as it runs: the record stays in the sidecar until the session is
over."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from ..events import Event, Stage
from ..recording.processes import ProcessRecord
from ..recording.records import TracedSession

# The tool whose calls run a command
COMMAND_TOOL = "Bash"
# How long before a command was issued and after its result came a process
# of it may have been noted: the watcher notes a process at its next look,
# and the times of the two are each taken as they are written down
NOTED_WITHIN = 0.25
# What such a command is marked with among its values, and the line that
# says it
UNSEEN = "unseen"
SAID = "processes: none seen while it ran"


def ran_between(event: Event) -> tuple[float, float] | None:
    """From when to when the command of an event ran, as its transcript
    has it, none for what is no command known to have run: what is no
    call, another tool, a call that was not let run, and one without a
    result or whose result is said to have come before it. An event that
    is the result alone (see Walk) is of when that came, and its command
    ran up to then."""
    fields = event.fields
    seconds = fields.get("seconds")
    if not event.call or fields.get("tool") != COMMAND_TOOL or fields.get("refused"):
        return None
    if seconds is None or seconds < 0:
        return None
    if fields.get("stage") == Stage.RESULT:
        return event.when - seconds, event.when
    return event.when, event.when + seconds


def seen(
    start: float, end: float, watched: Sequence[tuple[TracedSession, ProcessRecord]]
) -> bool | None:
    """Whether a process was noted while a command ran from start to end,
    by any of the records of the sessions that ran then: a transcript does
    not say which container wrote it. None when one of them cannot tell,
    the command may be that session's, and when none ran then."""
    answers = []
    for session, record in watched:
        if end < session.start or session.until < start:
            continue
        if start < session.start or session.until < end:
            # Not all of the command's time is this session's
            return None
        answers.append(record.noted_processes(start, end, NOTED_WITHIN))
    return any(answers) if answers and None not in answers else None


def mark_unseen(
    events: Iterable[Event], watched: Sequence[tuple[TracedSession, ProcessRecord]]
) -> int:
    """Say of each command no process was seen of that it is one, in its
    lines and among its values. Returns how many there are."""
    marked = 0
    for event in events:
        ran = ran_between(event)
        if ran is None or seen(*ran, watched) is not False:
            continue
        event.fields[UNSEEN] = True
        event.say(SAID)
        marked += 1
    return marked


def unseen_summary(count: int) -> list[str]:
    """The line of the header on the commands no process was seen of,
    none without any."""
    if not count:
        return []
    commands = "command" if count == 1 else "commands"
    return [f"  {count} {commands} ran with no process seen, see --only bash"]
