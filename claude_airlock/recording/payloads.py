"""What a packet carries, of the three kinds that are read: a DNS message,
the hello of TLS with the name of the server, and a plain HTTP request.
And of the first bytes a connection sends, what they say is spoken on it.

Each is the session's to write, or written to it: what is not what it is
read as raises NotThis or reads as nothing."""

from __future__ import annotations

import socket
from dataclasses import dataclass

from ..reader import Cursor, NotThis

# The methods a plain HTTP request starts with, by their first four bytes
HTTP_METHODS = ("GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT")
DNS_IS_RESPONSE = 0x8000
DNS_ERROR_CODE = 0x000F
# The two top bits of a length that is a pointer to the rest of a name
DNS_POINTER = 0xC0
# The kinds of record that are named, the others show as their number,
# and of those the two that hold an address
DNS_RECORDS = {
    1: "A",
    5: "CNAME",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
}
DNS_ADDRESS_FAMILIES = {1: socket.AF_INET, 28: socket.AF_INET6}
# What a resolver says went wrong, by the code in its answer
DNS_ERRORS = {
    1: "malformed query",
    2: "server failure",
    3: "no such name",
    5: "refused",
}
# What a lookup says that was asked and never answered
NO_ANSWER = "no answer"
# A name cannot have more labels than this, a longer walk is a loop
DNS_MOST_LABELS = 127
TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
# The major version every record of TLS starts with, after its type
TLS_MAJOR = 0x03
# The extensions of a hello that are read: the name of the server, and
# what the client offers to speak once the connection is made
TLS_SERVER_NAME = 0
TLS_ALPN = 16
# No more of what a hello offers to speak is kept than this, nor of each
MOST_OFFERED = 8
OFFERED_LENGTH = 32
# What the first bytes a connection sends are told as, see spoken
TLS, HTTP, SSH, OTHER = "tls", "http", "ssh", "other"
# How a client that speaks HTTP/2 without TLS and without asking first
# begins, which is no method of HTTP
HTTP2_PREFACE = b"PRI * HTTP/2"
SSH_BANNER = b"SSH-"
# From this many bytes on, what starts as none of the three is another
# protocol: the longest of what they start with
TOLD_BY = len(HTTP2_PREFACE)


@dataclass(frozen=True)
class Lookup:
    """An answer of the resolver: for which name and kind of record it
    was asked, the addresses it gave, and what it said went wrong."""

    when: float
    name: str
    kind: str
    addresses: tuple[str, ...]
    error: str


def _dns_name(message: bytes, at: Cursor) -> str:
    """The name at a cursor in a DNS message, the cursor left after it.
    A name can end in a pointer to the rest of it, elsewhere in the
    message, which is followed without moving the cursor further."""
    labels: list[str] = []
    reader = at
    for _ in range(DNS_MOST_LABELS):
        length = reader.number(1)
        if length & DNS_POINTER == DNS_POINTER:
            target = (length & ~DNS_POINTER) << 8 | reader.number(1)
            reader = Cursor(message, target)
        elif length == 0:
            return ".".join(labels)
        else:
            labels.append(reader.take(length).decode("ascii", "replace"))
    raise NotThis


@dataclass(frozen=True)
class DnsMessage:
    """A DNS message as it is read: its id, whether it is a response, the
    kind of record it is about (by number) and the lookup it makes, with
    the addresses a response gives and the error it reports."""

    id: int
    response: bool
    asked: int
    lookup: Lookup


def dns_message(when: float, message: bytes, answered: bool = True) -> DnsMessage:
    """A DNS query or response as a lookup: the name and kind of record it
    is about, and of a response the addresses it gives and the error it
    reports. A response that was captured only in part, as one longer than
    the capture takes is, gives the addresses that came before the cut.
    Without answered the addresses are not read, for what first asks which
    question a response is to: they are what takes long to read, and a
    session can send any number of answers nobody asked for. Raises
    NotThis for anything that is not about exactly one name."""
    reader = Cursor(message)
    ident = reader.number(2)
    flags, questions, answers = (reader.number(2) for _ in range(3))
    reader.skip(4)  # the counts of the two other sections
    if questions != 1:
        raise NotThis
    name = _dns_name(message, reader)
    asked = reader.number(2)
    reader.skip(2)  # the class asked for
    if not name:
        raise NotThis
    response = bool(flags & DNS_IS_RESPONSE)
    addresses = []
    try:
        for _ in range(answers if response and answered else 0):
            _dns_name(message, reader)
            kind = reader.number(2)
            reader.skip(6)  # class, time to live
            data = reader.take(reader.number(2))
            family = DNS_ADDRESS_FAMILIES.get(kind)
            if family is not None:
                try:
                    addresses.append(socket.inet_ntop(family, data))
                except (OSError, ValueError):
                    continue
    except NotThis:
        pass
    code = flags & DNS_ERROR_CODE if response else 0
    error = DNS_ERRORS.get(code, f"error {code}") if code else ""
    kind_asked = DNS_RECORDS.get(asked, f"type {asked}")
    lookup = Lookup(when, name, kind_asked, tuple(addresses), error)
    return DnsMessage(ident, response, asked, lookup)


def dns_answer(when: float, message: bytes) -> Lookup:
    """A DNS response as a lookup, see dns_message. Raises NotThis for
    anything else, a query too."""
    found = dns_message(when, message)
    if not found.response:
        raise NotThis
    return found.lookup


def unanswered(asked: float, key: tuple[int, str, int]) -> Lookup:
    """The lookup of a query that never had an answer: when it was sent,
    for which name and kind of record."""
    _, name, kind = key
    return Lookup(asked, name, DNS_RECORDS.get(kind, f"type {kind}"), (), NO_ANSWER)


def http_request(payload: bytes) -> tuple[str, str, str] | None:
    """The method, target and Host header of a plain HTTP request, none
    for a payload that does not start as one."""
    lines = payload.split(b"\r\n")
    start = lines[0].split(b" ")
    if len(start) != 3 or not start[2].startswith(b"HTTP/"):
        return None
    method, target = (part.decode("ascii", "replace") for part in start[:2])
    if method not in HTTP_METHODS:
        return None
    host = ""
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        if name.lower() == b"host":
            host = value.strip().decode("ascii", "replace")
            break
    return method, target, host


@dataclass(frozen=True)
class Hello:
    """The hello of a TLS client as far as it is read: the server name it
    asks for, empty without one, what it offers to speak once connected
    (ALPN), and whether all of its extensions were there to be read. One
    that was cut short, by the capture or by the packet it came in, may
    name a server past the cut."""

    name: str
    offered: tuple[str, ...]
    whole: bool


def _offered(listed: bytes) -> tuple[str, ...]:
    """What an ALPN extension lists, see MOST_OFFERED."""
    found: list[str] = []
    reader = Cursor(listed)
    reader.skip(2)  # the length of the list
    while reader.rest() and len(found) < MOST_OFFERED:
        name = reader.take(reader.number(1))
        found.append(name[:OFFERED_LENGTH].decode("ascii", "replace"))
    return tuple(found)


def tls_hello(record: bytes) -> Hello | None:
    """The hello of a TLS client, none for anything else and for one cut
    before its extensions begin."""
    hello = Cursor(record)
    try:
        if hello.number(1) != TLS_HANDSHAKE:
            return None
        hello.skip(4)  # record version and length
        if hello.number(1) != TLS_CLIENT_HELLO:
            return None
        hello.skip(3 + 2 + 32)  # handshake length, version, random
        hello.skip(hello.number(1))  # session id
        hello.skip(hello.number(2))  # cipher suites
        hello.skip(hello.number(1))  # compression methods
        end = hello.number(2)
        end += hello.at
    except NotThis:
        return None
    name = ""
    offered: tuple[str, ...] = ()
    try:
        while hello.at < end:
            kind, length = hello.number(2), hello.number(2)
            extension = hello.take(length)
            if kind == TLS_SERVER_NAME and not name:
                named = Cursor(extension)
                named.skip(3)  # list length, name type
                name = named.take(named.number(2)).decode("ascii", "replace")
            elif kind == TLS_ALPN and not offered:
                offered = _offered(extension)
    except NotThis:
        return Hello(name, offered, whole=False)
    return Hello(name, offered, whole=True)


def spoken(payload: bytes) -> str:
    """What a connection speaks, going by the first bytes sent on it: TLS,
    HTTP, SSH, OTHER for what starts as none of them, and nothing when
    there are too few bytes to tell. The bytes are the session's to
    choose: this tells a connection that is not what its port says from
    one that is, not one made to look like it."""
    if payload[:1] == bytes([TLS_HANDSHAKE]) and len(payload) > 5:
        if payload[1] == TLS_MAJOR and payload[5] == TLS_CLIENT_HELLO:
            return TLS
        return OTHER
    if payload.startswith(SSH_BANNER):
        return SSH
    if payload.startswith(HTTP2_PREFACE):
        return HTTP
    if any(payload.startswith(method.encode() + b" ") for method in HTTP_METHODS):
        return HTTP
    return OTHER if len(payload) >= TOLD_BY else ""
