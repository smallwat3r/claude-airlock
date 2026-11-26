"""What a session sent as its capture saw it go (see uploads.py of
recording), as events: each upload with where it went, how much and for
how long, to the model's API and to anywhere else. A request to the model
is one, so the requests of a session show from outside it, whatever the
session says of them, and so does a push or a file it sent somewhere.

And next to that the requests a session says it made, when what Claude
Code sends is kept (see api_events.py): for each the upload to the
model's API that carried it and the connection that went over, and the
uploads there that no request accounts for. The first is the session's
own word, the second the launcher's. Put side by side, a request says
where it was seen from outside, and what went to the model with no
request noted for it does not go without a word. A request is looked for
by when Claude Code wrote it out, which is when it sent it, and by how
long it is: an upload is taken for it when it began about then and has
that much in it that no request before it took. Two requests sent at
once over one connection are one upload, which both are then said to be
in.

What this does not tell: what an upload held, the capture keeps no more
of it than its headers. Nor where an upload of a session behind the
egress filter went, its packets all go to the proxy: each is an upload
to the proxy, and none is known to be a request to the model."""

from __future__ import annotations

from datetime import datetime

from ..events import Event, Kind, Who
from ..recording.capture import parts_cut_short
from ..recording.pcap import Capture
from ..recording.uploads import ELSEWHERE_PART, UPLOADS_PART, Upload
from .net_events import name_container, name_processes
from .recorded import Recorded
from .shown import over, reached, size

# Seconds an upload can end before its request says it was written out
# and still be its own, for what the two clocks are apart, and seconds it
# can begin after: a connection may have to be made first
EARLY = 1.0
LATE = 5.0
# Seconds an upload is looked for before a request was written out: one
# that began earlier and still went on then holds other requests too
LONGEST = 60.0
# The share of a request's length an upload has to have left for it
FITS = 0.5
# What is said of a request no upload was seen for, and of an upload no
# request was noted for
NOT_SEEN = "wire: no upload of its size seen"
UNNOTED = "no request noted for it"


class Wire:
    """What captures saw go to the model's API, given out to the
    requests that account for it: each request is placed once, in the
    order the requests were made, and takes its length of the upload it
    is placed in."""

    def __init__(self) -> None:
        # How much of each upload the requests placed in it took. By
        # what the upload is, a capture keeps each for as long as it is
        self._taken: dict[int, int] = {}

    def _left(self, upload: Upload) -> int:
        return upload.sent - self._taken.get(id(upload), 0)

    def _found(self, capture: Capture, asked: float, sent: int) -> Upload | None:
        """The upload a request written out at a time is in, none when
        none was seen then that has room for it. One no request took of
        before any other, and the one nearest to its length."""
        about_then = [
            upload
            for upload in capture.uploads.between(asked - LONGEST, asked + LATE)
            if upload.ended >= asked - EARLY and self._left(upload) >= sent * FITS
        ]
        if not about_then:
            return None
        return min(
            about_then,
            key=lambda upload: (
                id(upload) in self._taken,
                abs(self._left(upload) - sent),
            ),
        )

    def place(self, event: Event, capture: Capture) -> None:
        """Say of a request where the capture of its session saw it go.
        Nothing of one that does not say when it was written out, nor
        when the capture did not take what is sent to the model."""
        asked = event.fields.get("asked")
        if event.kind is not Kind.REQUEST or not isinstance(asked, float):
            return
        if UPLOADS_PART not in capture.part_packets:
            return
        sent = event.fields.get("sent") or 0
        upload = self._found(capture, asked, sent)
        if upload is None:
            # Not of a part that stopped: what came later is missing
            if UPLOADS_PART not in parts_cut_short(capture):
                event.notes.append(NOT_SEEN)
                event.fields["wire"] = None
            return
        shared = id(upload) in self._taken
        self._taken[id(upload)] = self._taken.get(id(upload), 0) + (sent or upload.sent)
        connection = capture.connection_of(upload.key, upload.began)
        opened = (
            f"the connection of {_clock(connection.when)}"
            if connection
            else "a connection not seen to open"
        )
        among = "with another request in " if shared else ""
        event.notes.append(
            f"wire: {among}{size(upload.sent)} at {_clock(upload.began)} on {opened}"
        )
        event.fields["wire"] = {
            **_upload_fields(upload),
            "shared": shared,
            "opened": connection.when if connection else None,
        }

    def unaccounted(self, capture: Capture) -> list[Upload]:
        """The uploads to the model's API that no request was placed in,
        those long enough to be worth a line."""
        return [
            upload
            for upload in capture.uploads.all
            if upload.sized and id(upload) not in self._taken
        ]


def _clock(when: float) -> str:
    return f"{datetime.fromtimestamp(when):%H:%M:%S}"


def _upload_fields(upload: Upload) -> dict[str, object]:
    source_port, address, port = upload.key
    return {
        "address": address,
        "port": port,
        "source_port": source_port,
        "at": upload.began,
        "seconds": upload.seconds,
        "bytes": upload.sent,
    }


def upload_event(
    capture: Capture, upload: Upload, to_model: bool, unnoted: bool = False
) -> Event:
    """An upload as an event: where it went, how much and for how long,
    and whether that was the model's API. Unnoted, it is said that no
    request was noted for it, of one to the model by a session whose
    requests are: not said to be wrong, Claude Code asks that host for
    more than the model."""
    source_port, address, port = upload.key
    detail = (
        f"{reached(capture, address, port, 'tcp', upload.began)}"
        f"  upload of {size(upload.sent)} in {upload.seconds:.1f}s"
    )
    if unnoted:
        detail += f", {UNNOTED}"
    fields: dict[str, object] = {
        "protocol": over("tcp", port),
        "name": capture.name_of(address, upload.began),
        "address": address,
        "port": port,
        "source_port": source_port,
        "upload": True,
        "model_api": to_model,
        "bytes_out": upload.sent,
        "seconds": upload.seconds,
        **({"unnoted": True} if unnoted else {}),
    }
    return Event(upload.began, Who.SANDBOX, Kind.NET, [detail], fields)


def on_the_wire(
    events: list[Event], recorded: Recorded
) -> tuple[list[tuple[str, str]], list[Event]]:
    """What the captures of some sessions saw them send, next to the
    requests among some events. Each request is placed in the capture of
    the session it is of, by its container and its time, and the uploads
    no request was placed in are given as events, each with the process
    that made its connection where that is known: those to the model's
    API, and those to anywhere else. Of a session whose requests are
    noted, the first are the uploads no request accounts for, and said
    to be. Of any other they are all there is to tell of its requests.
    With what that comes to as summary rows, none when no capture took
    what a session sends."""
    captured = [
        (found.session, found.capture)
        for found in recorded.captured
        if found.capture
        and {UPLOADS_PART, ELSEWHERE_PART} & found.capture.part_packets.keys()
    ]
    if not captured:
        return [], []
    wire = Wire()
    requests = [
        event
        for event in events
        if event.kind is Kind.REQUEST and isinstance(event.fields.get("asked"), float)
    ]
    for event in sorted(requests, key=lambda event: event.fields["asked"]):
        asked = event.fields["asked"]
        for session, capture in captured:
            ran_then = session.start - EARLY <= asked <= session.until + LATE
            if ran_then and session.name == event.fields.get("container"):
                wire.place(event, capture)
                break
    # The sessions whose requests are noted, by their containers
    noted = {event.fields.get("container") for event in requests}
    others: list[Event] = []
    for session, capture in captured:
        unnoted = session.name in noted
        found = [
            upload_event(capture, upload, to_model=True, unnoted=unnoted)
            for upload in wire.unaccounted(capture)
        ]
        found += [
            upload_event(capture, upload, to_model=False)
            for upload in capture.elsewhere.all
            if upload.sized
        ]
        found.sort(key=lambda event: event.when)
        record = recorded.processes_of(session)
        if record:
            name_processes(found, record)
        name_container(found, session.name, recorded.several)
        others += found
    return _summary(requests, others), others


def _summary(requests: list[Event], others: list[Event]) -> list[tuple[str, str]]:
    """The rows that sum up what was seen on the wire: of the requests
    that are noted how many were seen there, the uploads to the model's
    API that are no request of those, and what was sent anywhere else,
    each when there is any."""
    rows = []
    seen = sum(bool(event.fields.get("wire")) for event in requests)
    unseen = sum(event.fields.get("wire", 0) is None for event in requests)
    unnoted = sum(bool(event.fields.get("unnoted")) for event in others)
    if requests:
        said = f"{seen} seen on the wire"
        if unseen:
            said += f", {unseen} NOT SEEN there"
        if unnoted:
            said += f", {unnoted} uploads to the model's API with no request noted"
        rows.append(("requests", said))
    for to_model, where in ((True, "to the model's API"), (False, "elsewhere")):
        some = [
            event
            for event in others
            if event.fields["model_api"] is to_model and not event.fields.get("unnoted")
        ]
        if some:
            sent = sum(event.fields["bytes_out"] for event in some)
            rows.append(("uploads", f"{len(some)} {where}, {size(sent)} sent"))
    return rows
