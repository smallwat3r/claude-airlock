"""What a packet carries, of the three kinds that are read: a DNS message,
the hello of TLS with the name of the server, and a plain HTTP request.
And of the first bytes a connection sends, what they say is spoken on it.

Each is the session's to write, or written to it: what is not what it is
read as raises NotThis or reads as nothing."""

from __future__ import annotations

import dataclasses
import socket
import struct
from dataclasses import dataclass, field

from ..reader import Cursor, NotThis

# The methods a plain HTTP request starts with, by their first four bytes
HTTP_METHODS = ("GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT")
DNS_IS_RESPONSE = 0x8000
DNS_ERROR_CODE = 0x000F
# The header of a DNS message, read in one go: its id, its flags, how many
# questions and answers it has, then the counts of the two other sections.
# What is shorter than it is no message.
_DNS_HEADER = struct.Struct("!HHHH4x")
DNS_HEADER = _DNS_HEADER.size
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
# A name cannot have more labels than this, a longer walk is a loop. It is
# also all the labels and pointers followed in a message: of one name
# alone, that of the question, those of the answers are passed over
# without following theirs
DNS_MOST_LABELS = 127
# No more of a name is kept than this, its labels and the dots between
# them: DNS allows no longer, and a session can send what it likes, of
# which each byte can take four to write (see dns_label). Of one that is
# longer its last labels are kept, the domain it goes to, after CUT_NAME.
DNS_LONGEST_NAME = 255
CUT_NAME = "..."
# The bytes of a label that are written after a backslash, as dig does:
# they mean something in a name written out
DNS_ESCAPED = frozenset(b'.\\"();@$')
# The bytes a host name is made of: letters, digits, the hyphen, and the
# underscore of a service (_dmarc, _sip._tcp)
HOST_BYTES = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
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
class Name:
    """A name a DNS message asks about, as it is read from its bytes:
    written as dig writes it (see dns_label), its labels so written, how
    many bytes it and its longest label are on the wire, and whether all
    of it is what a host name is made of (see HOST_BYTES). Of a name
    longer than DNS_LONGEST_NAME the text and the labels are of its last
    labels alone, what it is made of and how long it is of all of it."""

    text: str
    labels: tuple[str, ...]
    length: int
    longest: int
    plain: bool

    @classmethod
    def of(cls, raw: list[bytes]) -> Name:
        """The name of labels as they came."""
        length = sum(map(len, raw)) + max(len(raw) - 1, 0)
        # The last labels that fit, each with the dot ahead of it
        first, size = len(raw), -1
        while first and size + len(raw[first - 1]) + 1 <= DNS_LONGEST_NAME:
            first -= 1
            size += len(raw[first]) + 1
        labels = tuple(map(dns_label, raw[first:]))
        text = ".".join(labels)
        return cls(
            CUT_NAME + text if first else text,
            labels,
            length,
            max(map(len, raw), default=0),
            not any(label.translate(None, HOST_BYTES) for label in raw),
        )


@dataclass(frozen=True)
class Lookup:
    """An answer of the resolver: for which name and kind of record it
    was asked, the addresses it gave, and what it said went wrong."""

    when: float
    name: str
    kind: str
    addresses: tuple[str, ...]
    error: str


def _dns_labels(message: bytes, at: Cursor) -> list[bytes]:
    """The labels of the name at a cursor in a DNS message, the cursor
    left after it. A name can end in a pointer to the rest of it,
    elsewhere in the message, which is followed without moving the cursor
    further. No more labels and pointers than DNS_MOST_LABELS in all."""
    labels: list[bytes] = []
    reader = at
    for _ in range(DNS_MOST_LABELS):
        length = reader.number(1)
        if length & DNS_POINTER == DNS_POINTER:
            target = (length & ~DNS_POINTER) << 8 | reader.number(1)
            reader = Cursor(message, target)
        elif length == 0:
            return labels
        else:
            labels.append(reader.take(length))
    raise NotThis


def _pass_name(at: Cursor) -> None:
    """Move a cursor past the name it is at in a DNS message, without
    following a pointer it ends in: where the name goes on is not read.
    The name of each answer is, for one, and a session can have it go
    through a long chain of pointers."""
    for _ in range(DNS_MOST_LABELS):
        length = at.number(1)
        if length & DNS_POINTER == DNS_POINTER:
            at.skip(1)
            return
        if length == 0:
            return
        at.skip(length)
    raise NotThis


def _shown_byte(byte: int) -> str:
    if byte in DNS_ESCAPED:
        return "\\" + chr(byte)
    if 0x21 <= byte <= 0x7E:
        return chr(byte)
    return f"\\{byte:03d}"


# How each byte of a label is written, see dns_label, and those that are
# written as they are
_LABEL_BYTES = tuple(_shown_byte(byte) for byte in range(256))
_PLAIN = bytes(byte for byte in range(256) if _LABEL_BYTES[byte] == chr(byte))


def dns_label(raw: bytes) -> str:
    """A label of a name as dig writes it, so that no two are written
    the same: a byte that is no printable letter of ASCII as a backslash
    and its number in three digits (\\032 for a space), a dot, a
    backslash and the others that mean something in a name after a
    backslash. Letters keep their case. A session can carry anything out
    in the names it looks up, a resolver passes them on: read as text
    they would all look alike. For showing alone, what a name is made of
    is told by Name."""
    if not raw.translate(None, _PLAIN):
        # As a rule: one that has nothing to be written otherwise
        return raw.decode("ascii")
    return "".join(_LABEL_BYTES[byte] for byte in raw)


@dataclass(frozen=True)
class DnsMessage:
    """A DNS message as it is read: its id, whether it is a response, the
    kind of record it is about (by number) and the lookup it makes, with
    the error a response reports and without the addresses it gives, see
    answered. With the name as it was read (see Name), and the message
    itself, where its answers start and how many it says there are."""

    id: int
    response: bool
    asked: int
    lookup: Lookup
    named: Name
    message: bytes = field(repr=False, compare=False)
    answers_at: int = field(default=0, repr=False)
    answers: int = field(default=0, repr=False)

    def answered(self) -> Lookup:
        """Its lookup with the addresses its answers give, as far as they
        go: one that was captured only in part gives those that came
        before the cut."""
        if not self.response:
            return self.lookup
        addresses: list[str] = []
        reader = Cursor(self.message, self.answers_at)
        try:
            for _ in range(self.answers):
                _pass_name(reader)
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
        return dataclasses.replace(self.lookup, addresses=tuple(addresses))


def dns_message(when: float, message: bytes) -> DnsMessage:
    """A DNS query or response as a lookup: the name and kind of record it
    is about, and of a response the error it reports. Not the addresses
    a response gives, for what first asks which question a response is
    to: they are what takes long to read, and a session can send any
    number of answers nobody asked for. They are read from it once it is
    one that was asked, see DnsMessage.answered. Raises NotThis for
    anything that is not about exactly one name."""
    try:
        ident, flags, questions, answers = _DNS_HEADER.unpack_from(message)
    except struct.error:
        raise NotThis from None
    if questions != 1:
        raise NotThis
    reader = Cursor(message, DNS_HEADER)
    labels = _dns_labels(message, reader)
    asked = reader.number(2)
    reader.skip(2)  # the class asked for
    if not labels:
        raise NotThis
    response = bool(flags & DNS_IS_RESPONSE)
    code = flags & DNS_ERROR_CODE if response else 0
    error = DNS_ERRORS.get(code, f"error {code}") if code else ""
    kind_asked = DNS_RECORDS.get(asked, f"type {asked}")
    named = Name.of(labels)
    lookup = Lookup(when, named.text, kind_asked, (), error)
    return DnsMessage(
        ident, response, asked, lookup, named, message, reader.at, answers
    )


def unanswered(query: Lookup) -> Lookup:
    """The lookup of a query that never had an answer, by that of the
    query: when it was sent, for which name and kind of record."""
    return dataclasses.replace(query, addresses=(), error=NO_ANSWER)


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

    @property
    def told(self) -> bool:
        """Whether it says all it could: the name of its server, or that
        it names none."""
        return bool(self.name) or self.whole


def _offered(listed: bytes) -> tuple[str, ...]:
    """What an ALPN extension lists, see MOST_OFFERED."""
    found: list[str] = []
    reader = Cursor(listed)
    reader.skip(2)  # the length of the list
    while reader.rest() and len(found) < MOST_OFFERED:
        name = reader.take(reader.number(1))
        found.append(name[:OFFERED_LENGTH].decode("ascii", "replace"))
    return tuple(found)


def _handshake(sent: bytes) -> bytes:
    """What the records of TLS handshake that some bytes start with hold,
    one after the other, as far as the bytes go: a message of the
    handshake can be cut into as many records as its sender likes, each
    with a length of its own, and a server joins them. Read as one, the
    header of the next record would be taken for what the message holds,
    which is the sender's to make read as anything. Empty when they do not
    start with such a record."""
    records = Cursor(sent)
    held: list[bytes] = []
    try:
        while records.rest() and records.number(1) == TLS_HANDSHAKE:
            records.skip(2)  # version
            length = records.number(2)
            fragment = sent[records.at : records.at + length]
            held.append(fragment)
            records.skip(len(fragment))
    except NotThis:
        pass
    return b"".join(held)


def tls_hello(sent: bytes) -> Hello | None:
    """The hello of a TLS client that some bytes start with, see
    _handshake, none for anything else and for one cut before its
    extensions begin. Read within the length it says it has."""
    handshake = _handshake(sent)
    if len(handshake) < 4 or handshake[0] != TLS_CLIENT_HELLO:
        return None
    hello = Cursor(handshake[4 : 4 + int.from_bytes(handshake[1:4], "big")])
    try:
        hello.skip(2 + 32)  # version, random
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
