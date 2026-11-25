"""What a packet carries, of the three kinds that are read: a DNS message,
the hello of TLS with the name of the server, and a plain HTTP request.

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
TLS_SERVER_NAME = 0


@dataclass(frozen=True)
class Lookup:
    """An answer of the resolver: for which name and kind of record it
    was asked, the addresses it gave, and what it said went wrong."""

    when: float
    name: str
    kind: str
    addresses: tuple[str, ...]
    error: str


def dns_name(message: bytes, at: Cursor) -> str:
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
    name = dns_name(message, reader)
    asked = reader.number(2)
    reader.skip(2)  # the class asked for
    if not name:
        raise NotThis
    response = bool(flags & DNS_IS_RESPONSE)
    addresses = []
    try:
        for _ in range(answers if response and answered else 0):
            dns_name(message, reader)
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


def tls_server_name(record: bytes) -> str:
    """The server name a TLS client hello asks for. Empty for anything
    else, and for a hello without one or longer than what was captured."""
    try:
        hello = Cursor(record)
        if hello.number(1) != TLS_HANDSHAKE:
            return ""
        hello.skip(4)  # record version and length
        if hello.number(1) != TLS_CLIENT_HELLO:
            return ""
        hello.skip(3 + 2 + 32)  # handshake length, version, random
        hello.skip(hello.number(1))  # session id
        hello.skip(hello.number(2))  # cipher suites
        hello.skip(hello.number(1))  # compression methods
        hello.skip(2)  # length of the extensions
        while True:
            kind, length = hello.number(2), hello.number(2)
            if kind == TLS_SERVER_NAME:
                hello.skip(3)  # list length, name type
                return hello.take(hello.number(2)).decode("ascii", "replace")
            hello.skip(length)
    except NotThis:
        return ""
