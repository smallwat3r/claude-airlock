"""The uses of the SSH agent and of the Docker socket that doors.py
noted, as --trace and the lines said when a session ends show them."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable

from .doors import BY_LAUNCHER, read_uses
from .events import Event, Who, clean
from .settings import Host


def ssh_agent_event(when: float, said: dict) -> Event:
    """A request to the SSH agent: a signature, the list of the keys, or
    another the launcher refused."""
    refused = bool(said.get("refused"))
    did = said.get("did")
    if did == "sign":
        comment = f" ({said['comment']})" if said.get("comment") else ""
        detail = (
            f"signed {said.get('what', 'something')} with {said.get('key')}{comment}"
        )
        if refused:
            detail = "asked for " + detail[len("signed ") :]
    elif did == "list":
        detail = f"listed the keys, {said.get('keys', 0)} of them"
    else:
        detail = str(said.get("what", "sent a request"))
    fields = {
        key: said[key]
        for key in ("did", "key", "comment", "what", "keys")
        if key in said
    }
    if refused:
        by = "launcher" if said.get("by") == BY_LAUNCHER else "agent"
        detail += f"  REFUSED by the {by}"
        fields["error"] = f"refused by the {by}"
    return Event(when, Who.SANDBOX, "ssh-agent", [clean(detail)], fields)


def docker_event(when: float, said: dict) -> Event:
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
    return Event(when, Who.SANDBOX, "docker", [clean(detail)], fields)


# How the use of each door is shown, by the door
DOOR_EVENTS: dict[str, Callable[[float, dict], Event]] = {
    "ssh-agent": ssh_agent_event,
    "docker": docker_event,
}


def use_event(said: dict) -> Event | None:
    """A use of a door as an event, none for a line that is not one. The
    record is the launcher's own, what it holds was still chosen by a
    session: it is cleaned like the rest."""
    shown = DOOR_EVENTS.get(str(said.get("door")))
    return shown(float(said["t"]), said) if shown else None


def door_events(
    host: Host, start: float, end: float, session: str | None = None
) -> tuple[list[tuple[str, str]], list[Event]]:
    """What this project's sessions did through the doors between two
    times, as summary rows (each door with what it was used for) and as
    events. Of one session when it is named: a transcript does not say
    which container wrote it, the launcher of a session knows."""
    uses = read_uses(host, start, end, session)
    events = [event for event in map(use_event, uses) if event]
    by_door = Counter(event.what for event in events)
    rows = []
    if by_door["ssh-agent"]:
        signed = sum(
            event.fields.get("did") == "sign" and "error" not in event.fields
            for event in events
        )
        rows.append(
            ("ssh agent", f"{by_door['ssh-agent']} requests, {signed} signatures")
        )
    if by_door["docker"]:
        denied = sum(bool(event.fields.get("denied")) for event in events)
        denials = f", {denied} DENIED" if denied else ""
        rows.append(("docker", f"{by_door['docker']} calls{denials}"))
    return rows, events
