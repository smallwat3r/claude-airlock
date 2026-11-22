"""A capture file (pcap, as tcpdump writes it) as the frames it holds,
read in one go or as it grows."""

from __future__ import annotations

import struct
from collections.abc import Iterator
from pathlib import Path

# A pcap file starts with one of these, which gives its byte order and what
# its timestamps count in: microseconds or nanoseconds
PCAP_FORMATS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e9),
    b"\xa1\xb2\xc3\xd4": (">", 1e6),
    b"\xa1\xb2\x3c\x4d": (">", 1e9),
}
PCAP_HEADER = 24
PCAP_RECORD_HEADER = 16
PCAP_READ_SIZE = 1 << 16
# The longest frame tcpdump writes, a longer one means a damaged file
PCAP_LONGEST_FRAME = 262144


class PcapReader:
    """Reads a capture (pcap, as tcpdump writes it) piece by piece, as a
    file read in one go or one still being written. Ends at the first thing
    that is not as it should be, what is fed after that is dropped."""

    def __init__(self) -> None:
        self._pending = bytearray()
        # Byte order, timestamp units per second and link type, from the
        # header of the file
        self._format: tuple[str, float, int] | None = None
        self._ended = False

    def feed(self, data: bytes) -> Iterator[tuple[float, int, bytes]]:
        """Take in the next bytes of the capture and give the frames they
        complete: when each was captured, the link type of the file and
        the frame. A frame cut off at the end waits for the rest of it."""
        if self._ended:
            return
        self._pending += data
        if self._format is None:
            if len(self._pending) < PCAP_HEADER:
                return
            start = bytes(self._pending[:PCAP_HEADER])
            del self._pending[:PCAP_HEADER]
            if start[:4] not in PCAP_FORMATS:
                self._end()
                return
            byte_order, per_second = PCAP_FORMATS[start[:4]]
            (link_type,) = struct.unpack_from(byte_order + "I", start, 20)
            self._format = (byte_order, per_second, link_type)
        byte_order, per_second, link_type = self._format
        at = 0
        while len(self._pending) - at >= PCAP_RECORD_HEADER:
            seconds, fraction, length, _ = struct.unpack_from(
                byte_order + "IIII", self._pending, at
            )
            if length > PCAP_LONGEST_FRAME:
                self._end()
                return
            end = at + PCAP_RECORD_HEADER + length
            if len(self._pending) < end:
                break
            frame = bytes(self._pending[at + PCAP_RECORD_HEADER : end])
            at = end
            yield seconds + fraction / per_second, link_type, frame
        del self._pending[:at]

    def _end(self) -> None:
        self._ended = True
        self._pending.clear()


def pcap_frames(path: Path) -> Iterator[tuple[float, int, bytes]]:
    """The frames of a capture file: when each was captured, the link type
    of the file and the frame. Ends at the first thing that is not as it
    should be, as a file cut off by a stopped tcpdump is. Raises OSError
    when the file cannot be read."""
    reader = PcapReader()
    with open(path, "rb") as file:
        while True:
            data = file.read(PCAP_READ_SIZE)
            if not data:
                return
            yield from reader.feed(data)
