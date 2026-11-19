"""Checks that the capture of a smoke session holds what inside/capture.sh
did: a TCP connection, a lookup of example.com and a UDP datagram.

Usage: capture.py CAPTURE_PREFIX"""

from __future__ import annotations

import sys

from records import only_file, require

from claude_sandbox.pcap import read_capture

capture = read_capture(only_file(sys.argv[1]))
connected = {(made.address, made.port) for made in capture.connections}
require(("1.1.1.1", 53) in connected, connected)
require("example.com" in capture.names.values(), capture.names)
sent = {(flow.transport, flow.address, flow.port) for flow in capture.flows}
require(("udp", "1.1.1.1", 9999) in sent, sent)
