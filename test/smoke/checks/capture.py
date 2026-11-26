"""Checks that the capture of a smoke session holds what inside/capture.sh
did: a TCP connection, a lookup of example.com and a UDP datagram. And
that what it tells of the connection of curl is what curl did: TLS, with
a hello for the name it looked up, which nothing is noted of.

Usage: capture.py CAPTURE_PREFIX"""

from __future__ import annotations

import sys

from records import only_file, require

from claude_airlock.recording.capture import read_parts

# The main file, the other parts of the capture are next to it
capture = read_parts(only_file(sys.argv[1], ".pcap"))
connected = {(made.address, made.port) for made in capture.connections}
require(("1.1.1.1", 53) in connected, connected)
require("example.com" in capture.names.values(), capture.names)
sent = {(flow.transport, flow.address, flow.port) for flow in capture.flows}
require(("udp", "1.1.1.1", 9999) in sent, sent)
https = [made for made in capture.connections if made.port == 443]
spoken = [(made.speaks, made.hello.name if made.hello else None) for made in https]
require(("tls", "example.com") in spoken, spoken)
require(not capture.noticed, [what for _, what, _ in capture.noticed])
require(not capture.inbound, [made.address for made in capture.inbound])
# What curl sent is in the part that has all the session sends
require("elsewhere" in capture.part_packets, capture.part_packets)
