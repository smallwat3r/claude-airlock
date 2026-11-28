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

And what came back from the model's API after each upload there (see
answers.py of recording): how long the answer took to begin, how much it
was and for how long it came.

An upload, what came back for it and the request it carried are tied by
one number, which starts with that of their connection (see links.py):
the three are lines of different times, with others between them.

Of a session behind the egress filter every packet goes to the proxy.
Where an upload went is then told by what its connection first asked the
proxy for (CONNECT), which the capture has: an upload over a tunnel to
the model's host is one to the model, and a request is placed among
those. The name is what the session asked the proxy for, and the proxy
is what connects to it. What came back through the proxy is not told
apart, a filtered session has no answers here.

What this does not tell: what an upload or an answer held, the capture
keeps no more of them than their headers."""

from __future__ import annotations

import functools
import math
from dataclasses import dataclass

from ..events import Event, Kind, Who, flat
from ..recording.answers import Answer
from ..recording.capture import parts_cut_short
from ..recording.model_api import is_model_host
from ..recording.pcap import Capture
from ..recording.uploads import ELSEWHERE_PART, UPLOADS_PART, Upload, began_between
from ..settings import EGRESS_PORT
from .links import Links, links_of
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


def asked_for(capture: Capture, upload: Upload) -> str:
    """What the connection of an upload first asked a proxy to connect
    it to (host:port), empty when it asked for no such thing."""
    connection = capture.connection_of(upload.key, upload.began)
    return connection.asked if connection else ""


def tunnel_to_model(port: int, asked: str) -> bool:
    """Whether a connection to a port that asked a proxy for something
    is a tunnel through the egress proxy to the model's host."""
    host = asked.rpartition(":")[0]
    return port == EGRESS_PORT and is_model_host(host.lower())


def _tunnelled_to_model(capture: Capture, upload: Upload) -> bool:
    """Whether an upload went over a tunnel through the egress proxy to
    the model's host, by what its connection asked the proxy for."""
    return tunnel_to_model(upload.key[2], asked_for(capture, upload))


@dataclass(frozen=True)
class Sent:
    """What a capture saw a session send, told apart: to the model, and
    to anywhere else, each in the order it began. Of a session behind
    the egress filter the first are those sent over a tunnel to the
    model's host, see _tunnelled_to_model. Of any other, those sent to
    the addresses of the model's API, which is the part of the capture
    they are in: a name is not taken for it there, the session can ask
    any proxy it reaches for any name. With links, the numbers the
    connections of the capture are told by, see links_of."""

    capture: Capture
    filtered: bool = False
    links: Links | None = None

    @property
    def taken(self) -> bool:
        """Whether the capture took what is sent to the model at all."""
        part = ELSEWHERE_PART if self.filtered else UPLOADS_PART
        return part in self.capture.part_packets

    @property
    def cut_short(self) -> bool:
        """Whether what is sent to the model was not all taken, or
        cannot all be told to be that: behind the egress filter it takes
        the start of each connection, which says what the proxy was
        asked for."""
        cut = parts_cut_short(self.capture)
        if self.filtered:
            return ELSEWHERE_PART in cut or "tcp" in cut
        return UPLOADS_PART in cut

    def to_model(self, upload: Upload) -> bool:
        return self.filtered and _tunnelled_to_model(self.capture, upload)

    @functools.cached_property
    def _tunnelled(self) -> list[Upload]:
        """Of a session behind the egress filter, what went to the model,
        in the order it began: told apart once, as the capture is now,
        and not again for each request placed. It sends everything to
        the proxy, as many uploads as it likes."""
        return [
            upload for upload in self.capture.elsewhere.all if self.to_model(upload)
        ]

    def model_between(self, start: float, end: float) -> list[Upload]:
        """What began to go to the model between two times."""
        to_model = self._tunnelled if self.filtered else self.capture.uploads.all
        return began_between(to_model, start, end)

    @property
    def model(self) -> list[Upload]:
        return self.model_between(-math.inf, math.inf)

    @property
    def others(self) -> list[Upload]:
        return [
            upload for upload in self.capture.elsewhere.all if not self.to_model(upload)
        ]


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

    def _found(self, seen: Sent, asked: float, sent: int) -> Upload | None:
        """The upload a request written out at a time is in, none when
        none was seen then that has room for it. One no request took of
        before any other, and the one nearest to its length."""
        about_then = [
            upload
            for upload in seen.model_between(asked - LONGEST, asked + LATE)
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

    def place(self, event: Event, seen: Sent) -> None:
        """Say of a request where the capture of its session saw it go.
        Nothing of one that does not say when it was written out, nor
        when the capture did not take what is sent to the model. Nor of
        one whose length is not known, its body withheld or not found,
        which is marked unmeasured instead, see _summary: any upload
        would have room for it, and one written out by the session would
        pass for seen."""
        asked = event.fields.get("asked")
        if event.kind is not Kind.REQUEST or not isinstance(asked, float):
            return
        if not seen.taken:
            return
        sent = event.fields.get("sent")
        if not isinstance(sent, int) or isinstance(sent, bool) or sent <= 0:
            event.fields["unmeasured"] = True
            return
        capture = seen.capture
        upload = self._found(seen, asked, sent)
        if upload is None:
            # Not of a part that stopped: what came later is missing
            if not seen.cut_short:
                event.notes.append(NOT_SEEN)
                event.fields["wire"] = None
            return
        shared = id(upload) in self._taken
        self._taken[id(upload)] = self._taken.get(id(upload), 0) + sent
        connection = capture.connection_of(upload.key, upload.began)
        among = "with another request in " if shared else ""
        # By the number of the upload, which its answer has too, and
        # the line of its connection the start of it
        tied = links_of(seen.links).of_upload(capture, upload)
        unseen = "" if connection else " on a connection not seen to open"
        event.notes.append(f"wire: {among}[{tied}] {size(upload.sent)}{unseen}")
        event.fields["wire"] = {
            **_upload_fields(upload),
            "shared": shared,
            "opened": connection.when if connection else None,
        }

    def unaccounted(self, seen: Sent) -> list[Upload]:
        """The uploads to the model's API that no request was placed in,
        those long enough to be worth a line."""
        return [
            upload
            for upload in seen.model
            if upload.sized and id(upload) not in self._taken
        ]


def is_upload(event: Event) -> bool:
    """Whether an event is of something long sent over a connection, see
    upload_event."""
    return event.kind is Kind.NET and event.fields.get("upload") is True


def to_the_model(event: Event) -> bool:
    """Whether an event is of what was sent to the model's API or came
    back from it, see upload_event and answer_event."""
    return event.kind is Kind.NET and event.fields.get("model_api") is True


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
    capture: Capture,
    upload: Upload,
    to_model: bool,
    unnoted: bool = False,
    links: Links | None = None,
) -> Event:
    """An upload as an event: where it went, how much and for how long,
    and whether that was the model's API. Unnoted, it is said that no
    request was noted for it, of one to the model by a session whose
    requests are: not said to be wrong, Claude Code asks that host for
    more than the model. Tied to its connection and to what came back
    for it by its number, with links those the capture is told by."""
    source_port, address, port = upload.key
    connection = capture.connection_of(upload.key, upload.began)
    asked = connection.asked if connection else ""
    detail = reached(capture, address, port, "tcp", upload.began)
    if asked:
        detail += f"  asked for {flat(asked)}"
    detail += f"  upload of {size(upload.sent)} in {upload.seconds:.1f}s"
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
        **({"asked": asked} if asked else {}),
        # When its connection was made, which its process is known by
        **({"opened": connection.when} if connection else {}),
        **({"unnoted": True} if unnoted else {}),
    }
    tied = links_of(links).of_upload(capture, upload)
    return Event(upload.began, Who.SANDBOX, Kind.NET, [detail], fields, tied)


def answer_event(capture: Capture, answer: Answer, links: Links | None = None) -> Event:
    """What came back from the model's API after an upload, as an event
    at the time it began: how much, for how long, and how long after the
    upload it began. The rest of one that was quiet for a while says it
    is that. Which upload it is to is said by its number, that of the
    upload, with links those the capture is told by."""
    source_port, address, port = answer.key
    connection = capture.connection_of(answer.key, answer.began)
    where = reached(capture, address, port, "tcp", answer.began)
    about = f"{size(answer.received)} in {answer.seconds:.1f}s"
    if answer.rest:
        detail = f"{where}  the rest of its answer, {about}"
    else:
        detail = (
            f"{where}  answer of {about}, began {answer.waited:.1f}s after its upload"
        )
    fields: dict[str, object] = {
        "protocol": over("tcp", port),
        "name": capture.name_of(address, answer.began),
        "address": address,
        "port": port,
        "source_port": source_port,
        "answer": True,
        "model_api": True,
        "bytes_in": answer.received,
        "seconds": answer.seconds,
        "waited": answer.waited,
        "upload_at": answer.upload.began,
        # When its connection was made, which its process is known by
        **({"opened": connection.when} if connection else {}),
        **({"rest": True} if answer.rest else {}),
    }
    tied = links_of(links).of_upload(capture, answer.upload)
    return Event(answer.began, Who.SANDBOX, Kind.NET, [detail], fields, tied)


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
        (found.session, Sent(found.capture, bool(found.session.ip), found.links))
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
        for session, seen in captured:
            ran_then = session.start - EARLY <= asked <= session.until + LATE
            if ran_then and session.name == event.fields.get("container"):
                wire.place(event, seen)
                break
    # The sessions whose requests are noted, by their containers
    noted = {event.fields.get("container") for event in requests}
    others: list[Event] = []
    for session, seen in captured:
        capture = seen.capture
        unnoted = session.name in noted
        tied = links_of(seen.links)
        found = [
            upload_event(capture, upload, True, unnoted, tied)
            for upload in wire.unaccounted(seen)
        ]
        found += [
            upload_event(capture, upload, False, links=tied)
            for upload in seen.others
            if upload.sized
        ]
        found += [answer_event(capture, answer, tied) for answer in capture.answers.all]
        found.sort(key=lambda event: event.when)
        record = recorded.processes_of(session)
        if record:
            name_processes(found, record)
        name_container(found, session.name, recorded.several)
        others += found
    return _summary(requests, others), others


def _summary(requests: list[Event], others: list[Event]) -> list[tuple[str, str]]:
    """The rows that sum up what was seen on the wire: of the requests
    that are noted how many were seen there, and how many were not looked
    for there, those of no length that is known, the uploads to the
    model's API that are no request of those, and what was sent anywhere
    else, each when there is any."""
    rows = []
    seen = sum(bool(event.fields.get("wire")) for event in requests)
    unseen = sum(event.fields.get("wire", 0) is None for event in requests)
    unmeasured = sum(bool(event.fields.get("unmeasured")) for event in requests)
    unnoted = sum(bool(event.fields.get("unnoted")) for event in others)
    if requests:
        said = f"{seen} seen on the wire"
        if unseen:
            said += f", {unseen} NOT SEEN there"
        if unmeasured:
            said += f", {unmeasured} not looked for (their length is not known)"
        if unnoted:
            said += f", {unnoted} uploads to the model's API with no request noted"
        rows.append(("requests", said))
    uploads = [event for event in others if event.fields.get("upload")]
    for to_model, where in ((True, "to the model's API"), (False, "elsewhere")):
        some = [
            event
            for event in uploads
            if event.fields["model_api"] is to_model and not event.fields.get("unnoted")
        ]
        if some:
            sent = sum(event.fields["bytes_out"] for event in some)
            rows.append(("uploads", f"{len(some)} {where}, {size(sent)} sent"))
    answers = [event for event in others if event.fields.get("answer")]
    if answers:
        came = sum(event.fields["bytes_in"] for event in answers)
        whole = sum(not event.fields.get("rest") for event in answers)
        rows.append(("answers", f"{whole} from the model's API, {size(came)} received"))
    return rows
