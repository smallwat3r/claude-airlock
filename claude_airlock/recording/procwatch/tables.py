"""The TCP sockets of the session's network namespace as the kernel lists
them, and the processes that hold them, by what their descriptors link
to."""

from __future__ import annotations

import functools
import ipaddress
import os
import sys
from collections.abc import Sequence
from typing import NamedTuple

from .addresses import is_loopback, unmapped

TCP_LISTEN = "0A"
# How many addresses are known as text at a time: every look reads the same
# few again, and a session that reaches many has them worked out again
MOST_ADDRESSES_KNOWN = 4096


@functools.lru_cache(maxsize=MOST_ADDRESSES_KNOWN)
def address(encoded: str) -> str:
    """An address as /proc/net/tcp and tcp6 write it: each four bytes of
    it as one number in the machine's own byte order. One of IPv4 inside
    IPv6 as the IPv4 address it is, as it goes over the wire. Remembered,
    every look reads the same few again."""
    words = [encoded[at : at + 8] for at in range(0, len(encoded), 8)]
    packed = b"".join(int(word, 16).to_bytes(4, sys.byteorder) for word in words)
    return unmapped(ipaddress.ip_address(packed))


Sockets = dict[tuple[int, str, int], str]
# No more sockets of each kind are kept from one look than this: some 300
# bytes each, and a session can open as many as it likes
MOST_SOCKETS = 20_000


class Tables(NamedTuple):
    """The TCP sockets of one look, see sockets: the connections, those
    that wait for one, and whether some were passed over for being more
    than MOST_SOCKETS."""

    connected: Sockets
    waiting: Sockets
    passed_over: bool


def _socket(line: str) -> tuple[tuple[int, str, int], str, bool] | None:
    """A socket as a line of /proc/net/tcp or tcp6 has it: by its own
    port, the address and the port at the other end, or for one that
    waits for connections its port and the address it waits on, then its
    inode and whether it waits. None for a line that says none, or one
    that was let go of, which is told before any address is read: a
    session can leave as many of those in the table as it likes, every
    connection it closes waits there a while."""
    # The inode is the tenth field, what follows it is not read
    parts = line.split(None, 10)
    try:
        local, remote, state, inode = parts[1], parts[2], parts[3], parts[9]
    except IndexError:
        return None
    if inode == "0":
        # Let go of
        return None
    try:
        on, port = local.rsplit(":", 1)
        to, to_port = remote.rsplit(":", 1)
        waits = state == TCP_LISTEN
        if waits:
            key = (int(port, 16), address(on), 0)
        else:
            key = (int(port, 16), address(to), int(to_port, 16))
    except ValueError:
        return None
    return key, inode, waits


# Where the kernel lists the TCP sockets of the network namespace
TCP_TABLES = ("/proc/net/tcp", "/proc/net/tcp6")


def sockets(tables: Sequence[str] = TCP_TABLES) -> Tables:
    """The TCP sockets of the network namespace, each with its inode, from
    one read of each table, the kernel takes its time over them, a line at
    a time: the connections, each by its own port, the address and the
    port at the other end, and the sockets that wait for connections, each
    by its port and the address it waits on. Not the connections on the
    session's own loopback, which nothing asks who made (see
    Watch._look_at_connections of watcher.py), and no more of each kind
    than MOST_SOCKETS."""
    connected: Sockets = {}
    waiting: Sockets = {}
    passed_over = False
    for table in tables:
        try:
            with open(table, encoding="ascii", errors="replace") as lines:
                # Its heading
                next(lines, None)
                for line in lines:
                    found = _socket(line)
                    if found is None:
                        continue
                    key, inode, waits = found
                    kept = waiting if waits else connected
                    if not waits and not watched(key):
                        continue
                    if len(kept) >= MOST_SOCKETS:
                        passed_over = True
                        continue
                    kept[key] = inode
        except OSError:
            continue
    return Tables(connected, waiting, passed_over)


def watched(connection: tuple[int, str, int]) -> bool:
    """Whether a connection is one the processes of are looked for: one
    with another end, and not on the session's own loopback, which no
    capture has, so nothing asks who made it, and of which a session can
    make as many as it likes without the network."""
    _, to, to_port = connection
    return bool(to_port) and not is_loopback(to)


class Holders:
    """Finds the processes that hold sockets, by what their descriptors
    link to."""

    def __init__(self) -> None:
        # Whether the descriptors of any process could be read at all
        self.readable = False

    def of(self, inodes: set[str], pids: list[int]) -> dict[str, list[int]]:
        wanted = {f"socket:[{inode}]": inode for inode in inodes}
        found: dict[str, list[int]] = {}
        for pid in pids:
            directory = f"/proc/{pid}/fd"
            try:
                descriptors = os.listdir(directory)
            except OSError:
                continue
            self.readable = True
            for descriptor in descriptors:
                try:
                    inode = wanted.get(os.readlink(f"{directory}/{descriptor}"))
                except OSError:
                    continue
                if inode is not None and pid not in found.setdefault(inode, []):
                    found[inode].append(pid)
        return found


def started_last(pids: Sequence[int]) -> int:
    """Of the processes that hold a socket, as the watcher lists them in
    the order they started (see Watch._by_start of watcher.py), the one
    started last. Not the highest id, ids start over once they reach the
    most there can be."""
    return pids[-1]
