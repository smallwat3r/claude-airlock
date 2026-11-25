"""The uses of the SSH agent and of the Docker socket that doors.py
noted, as --trace and the lines said when a session ends show them."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable

from ..events import Event, Who, Wrong, flat
from ..recording.doors import BY_LAUNCHER, UNRECORDED, AgentUse, Door, read_uses
from ..settings import Host


def unrecorded(said: dict) -> dict[str, int] | None:
    """How many uses of each kind a line of the record says were counted
    and not noted one by one, none for a line that is a use. Without a
    count yet in the line that says it began, see SessionUses."""
    counted = said.get(UNRECORDED)
    if not counted:
        return None
    if not isinstance(counted, dict):
        return {}
    return {
        str(kind): number
        for kind, number in counted.items()
        if isinstance(number, int) and number > 0
    }


def _unrecorded_event(when: float, door: str, counted: dict[str, int]) -> Event:
    """That a session used a door more than is noted use by use, which
    is how one would be rid of the record of what it did before."""
    if counted:
        each = ", ".join(f"{number} {kind}" for kind, number in sorted(counted.items()))
        detail = f"{sum(counted.values())} more uses NOT RECORDED one by one: {each}"
    else:
        detail = "more uses than are recorded one by one, counted from here"
    fields = {UNRECORDED: counted, "error": "not recorded one by one"}
    return Event(
        when, Who.SANDBOX, door, [flat(detail)], fields, wrong=Wrong.THROUGHOUT
    )


def _ssh_agent_event(when: float, said: dict) -> Event:
    """A request to the SSH agent: a signature, the list of the keys, or
    another the launcher refused."""
    refused = bool(said.get("refused"))
    did = said.get("did")
    if did == AgentUse.SIGN.value:
        comment = f" ({said['comment']})" if said.get("comment") else ""
        detail = (
            f"signed {said.get('what', 'something')} with {said.get('key')}{comment}"
        )
        if refused:
            detail = "asked for " + detail[len("signed ") :]
    elif did == AgentUse.LIST.value:
        detail = f"listed the keys, {said.get('keys', 0)} of them"
    else:
        detail = str(said.get("what", "sent a request"))
    fields = {
        key: said[key] for key in ("did", "key", "comment", "keys") if key in said
    }
    if "what" in said:
        # What was signed or asked for, which the record names what: an
        # event has that name for what it is, the use of a door
        fields["request"] = said["what"]
    if refused:
        by = "launcher" if said.get("by") == BY_LAUNCHER else "agent"
        detail += f"  REFUSED by the {by}"
        fields["error"] = f"refused by the {by}"
    wrong = Wrong.THROUGHOUT if refused else Wrong.NO
    return Event(
        when, Who.SANDBOX, Door.SSH_AGENT.value, [flat(detail)], fields, wrong=wrong
    )


def _docker_event(when: float, said: dict) -> Event:
    """A call to the Docker socket, through the socket proxy."""
    status = said.get("status")
    denied = status == 403
    detail = f"{said.get('method')} {said.get('path')} {status}"
    fields = {
        "method": said.get("method"),
        "path": said.get("path"),
        "status": status,
        "denied": denied,
    }
    if denied:
        detail += "  DENIED"
    wrong = Wrong.THROUGHOUT if denied else Wrong.NO
    return Event(
        when, Who.SANDBOX, Door.DOCKER.value, [flat(detail)], fields, wrong=wrong
    )


# How the use of each door is shown, by the door
DOOR_EVENTS: dict[str, Callable[[float, dict], Event]] = {
    Door.SSH_AGENT.value: _ssh_agent_event,
    Door.DOCKER.value: _docker_event,
}


def use_event(said: dict) -> Event | None:
    """A use of a door as an event, none for a line that is not one. The
    record is the launcher's own, what it holds was still chosen by a
    session: it is cleaned like the rest."""
    door = str(said.get("door"))
    shown = DOOR_EVENTS.get(door)
    if shown is None:
        return None
    when = float(said["t"])
    counted = unrecorded(said)
    if counted is not None:
        return _unrecorded_event(when, door, counted)
    return shown(when, said)


def door_events(
    host: Host, start: float, end: float, session: str | None = None
) -> tuple[list[tuple[str, str]], list[Event]]:
    """What this project's sessions did through the doors between two
    times, as summary rows (each door with what it was used for) and as
    events. Of one session when it is named: a transcript does not say
    which container wrote it, the launcher of a session knows."""
    uses = read_uses(host, start, end, session)
    events = [event for event in map(use_event, uses) if event]
    one_by_one = [event for event in events if UNRECORDED not in event.fields]
    by_door = Counter(event.what for event in one_by_one)
    # What was counted and not noted, by the door
    more: Counter[str] = Counter()
    for event in events:
        more[event.what] += sum(event.fields.get(UNRECORDED, {}).values())
    rows = []
    agent, docker = by_door[Door.SSH_AGENT.value], by_door[Door.DOCKER.value]
    if agent:
        signed = sum(
            event.fields.get("did") == AgentUse.SIGN.value
            and "error" not in event.fields
            for event in one_by_one
        )
        said = f"{agent} requests, {signed} signatures"
        rows.append(("ssh agent", said + _not_recorded(more[Door.SSH_AGENT.value])))
    if docker:
        denied = sum(bool(event.fields.get("denied")) for event in one_by_one)
        denials = f", {denied} DENIED" if denied else ""
        said = f"{docker} calls{denials}"
        rows.append(("docker", said + _not_recorded(more[Door.DOCKER.value])))
    return rows, events


def _not_recorded(more: int) -> str:
    """What a summary row says of the uses that were only counted."""
    return f", {more} more NOT RECORDED one by one" if more else ""
