#!/usr/bin/env python3
"""What a session sends to the model's API as the capture sees it, and
the requests it says it made placed next to that: which upload each was
in, on which connection, and the uploads no request accounts for."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from unittest import mock

import pytest
from harness import LauncherTest, follow, pcap, prompts_at, records
from test_capture import answer, ipv4, ipv6, pcap_file, tcp, tcp_header, udp

from claude_airlock.events import Event, Kind
from claude_airlock.recording import api_calls, uploads
from claude_airlock.recording import capture as capture_module
from claude_airlock.recording.pcap_file import PcapReader
from claude_airlock.report import api_events, wire
from claude_airlock.report.layout import Layout
from claude_airlock.report.net_events import capture_events
from claude_airlock.report.recorded import Recorded

API = "160.79.104.10"
CONTAINER = "claude-proj"
# The connection the packets of tcp() are of
KEY = (40443, API, 443)
type Frames = list[tuple[float, bytes, bool]]


def sent(when: float, length: int, sequence: int, port: int = 443) -> Frames:
    """The packets of something sent to the model's API in one go, from
    a place in the stream of its connection."""
    frames: Frames = []
    at = 0
    while at < length:
        some = min(10_000, length - at)
        packet = tcp(API, port, 0x18, b"x" * some, sequence=sequence + at)
        frames.append((when + len(frames) * 0.001, packet, True))
        at += some
    return frames


def opened(when: float, port: int = 443) -> Frames:
    """What starts a connection to the model's API, and the answer."""
    return [(when, tcp(API, port), True), (when + 0.01, answer(API, port), False)]


def request(asked: float, length: int, **more: object) -> Event:
    """A request as it is noted, written out at a time and so long."""
    said = {"t": asked + 3, "session": CONTAINER, "asked": asked, "sent": length}
    event = api_events.call_event({"answered": True, **said, **more})
    assert event is not None
    return event


class WireTest(LauncherTest):
    @pytest.fixture(autouse=True)
    def a_moment(self, sandbox: None) -> None:
        # A whole second, the times of a capture are written to a millionth
        self.now = float(int(time.time()))

    def captured(
        self,
        main: Frames,
        sent_to_the_model: Frames | None,
        sent_elsewhere: Frames | None = None,
    ) -> pcap.Capture:
        """What a capture of those packets says, with the part of what
        was sent to the model, and that of what was sent anywhere else,
        unless there is none."""
        directory = Path(self.cleanup.enter_context(tempfile.TemporaryDirectory()))
        file = directory / "c.pcap"
        file.write_bytes(pcap_file(main, asked=False))
        parts = (
            (uploads.UPLOADS_PART, sent_to_the_model),
            (uploads.ELSEWHERE_PART, sent_elsewhere),
        )
        for name, frames in parts:
            if frames is not None:
                part = directory / f"c.pcap.{name}"
                part.write_bytes(pcap_file(frames, asked=False))
        return capture_module.read_parts(file)

    def clock(self, when: float) -> str:
        return f"{datetime.fromtimestamp(when):%H:%M:%S}"

    def test_what_is_sent_without_a_pause_is_one_upload(self):
        now = self.now
        frames = [
            *sent(now, 25_000, 1),
            # After a pause, the next one
            *sent(now + 2, 8_000, 25_001),
            # And what keeps the connection going in between is none of
            # the length of a request
            *sent(now + 5, 40, 33_001),
        ]
        found = self.captured(opened(now - 1), frames).uploads.all
        assert [(upload.sent, upload.sized) for upload in found] == [
            (25_000, True),
            (8_000, True),
            (40, False),
        ]
        assert [upload.key for upload in found] == [KEY] * 3
        assert (found[0].began, found[0].ended) == (now, now + 0.002)

    def test_a_packet_sent_again_is_not_counted_twice(self):
        now = self.now
        again = sent(now + 0.1, 10_000, 1)
        frames = [*sent(now, 20_000, 1), *again, *sent(now + 0.2, 5_000, 20_001)]
        (upload,) = self.captured(opened(now - 1), frames).uploads.all
        assert upload.sent == 25_000

    def test_a_packet_the_capture_missed_is_counted_by_the_next(self):
        now = self.now
        whole = sent(now, 30_000, 1)
        (upload,) = self.captured(opened(now - 1), [whole[0], whole[2]]).uploads.all
        assert upload.sent == 30_000

    def test_another_connection_from_the_same_port_starts_anew(self):
        now = self.now
        frames = [*sent(now, 5_000, 1), *sent(now + 60, 6_000, 3_000_000_000)]
        first, second = self.captured(opened(now - 1), frames).uploads.all
        assert (first.sent, second.sent) == (5_000, 6_000)
        # Wherever its stream starts, before where the last one got to too
        frames = [*sent(now, 5_000, 3_000_000_000), *sent(now + 60, 6_000, 1)]
        first, second = self.captured(opened(now - 1), frames).uploads.all
        assert (first.sent, second.sent) == (5_000, 6_000)

    def test_each_connection_has_its_own_uploads(self):
        now = self.now
        frames = [*sent(now, 5_000, 1), *sent(now + 0.0005, 7_000, 1, port=8443)]
        found = self.captured(opened(now - 1), sorted(frames)).uploads
        assert sorted(upload.sent for upload in found.all) == [5_000, 7_000]
        assert [upload.sent for upload in found.on(KEY, now - 1, now + 1)] == [5_000]

    def test_only_what_the_session_sends_is_an_upload(self):
        back = ipv4(6, API, "172.20.0.5", tcp_header(40443, 0x18, 443) + b"y" * 900)
        capture = self.captured(opened(self.now), [(self.now + 1, back, False)])
        assert capture.uploads.all == []
        assert capture.part_packets[uploads.UPLOADS_PART] == 1

    def test_the_part_takes_what_is_sent_to_the_model_and_nothing_else(self):
        if not shutil.which("tcpdump"):
            pytest.skip("no tcpdump here")
        elsewhere, unsampled = "198.51.100.7", (3 << 30) + 65536
        v6 = tcp_header(443, 0x18) + b"x" * 50
        wanted = [
            tcp(API, 443, 0x18, b"x" * 1400, sequence=unsampled),
            tcp("160.79.105.200", 443, 0x10, b"x", sequence=unsampled),
            ipv6(6, "fd00::5", "2607:6bc0::10", v6),
        ]
        others = [
            (tcp(API, 443, 0x10, b"", sequence=unsampled), True),
            (tcp(API, 443), True),
            (tcp(elsewhere, 443, 0x18, b"x" * 1400, sequence=unsampled), True),
            (tcp("160.79.106.1", 443, 0x18, b"x" * 10, sequence=unsampled), True),
            (ipv4(17, "172.20.0.5", API, udp(443)), True),
            (ipv6(6, "fd00::5", "2001:db8::1", v6), True),
            (ipv6(6, "fd00::5", "2607:6bc0::10", tcp_header(443, 0x10)), True),
            # What the model's API sends back
            (ipv4(6, API, "172.20.0.5", tcp_header(40443, 0x18, 443) + b"y"), False),
        ]
        frames = [(1.0 + at, packet, True) for at, packet in enumerate(wanted)]
        frames += [(50.0 + at, *other) for at, other in enumerate(others)]
        *_, to_the_model, elsewhere = capture_module.PARTS
        assert to_the_model.name == uploads.UPLOADS_PART
        assert elsewhere.name == uploads.ELSEWHERE_PART
        taken = {}
        with tempfile.TemporaryDirectory() as directory:
            whole, kept = Path(directory, "all.pcap"), Path(directory, "kept.pcap")
            whole.write_bytes(pcap_file(frames, link_type=113, asked=False))
            for part in (to_the_model, elsewhere):
                subprocess.run(
                    ["tcpdump", "-r", str(whole), "-w", str(kept), part.filter],
                    check=True,
                    capture_output=True,
                )
                taken[part.name] = [
                    frame[16:] for _, _, frame in PcapReader().feed(kept.read_bytes())
                ]
        assert taken[to_the_model.name] == wanted
        # And the other part what carries something to anywhere else: to
        # an address next to the model's too, and never what comes back
        # or goes to the model
        assert taken[elsewhere.name] == [others[2][0], others[3][0], others[5][0]]

    def test_the_part_is_kept_next_to_the_capture_of_its_session(self):
        main, part = self.work / "capture.pcap", self.work / "uploads.pcap"
        main.write_bytes(pcap_file(opened(self.now), asked=False))
        part.write_bytes(pcap_file(sent(self.now + 1, 9_000, 1), asked=False))
        result = self.launch(
            CLAUDE_AIRLOCK_NET_LOG="1",
            FAKE_CAPTURE=str(main),
            FAKE_CAPTURE_UPLOADS=str(part),
        )
        assert result.status == 0, result.stderr
        # Taken of every session that is captured, with its headers alone
        sidecar = result.sidecar("claude-proj.capture")
        assert sidecar[-2:] == [
            capture_module.UPLOADS_FILTER,
            capture_module.ELSEWHERE_FILTER,
        ]
        for started in (
            'tcpdump $common -s 160 -w /uploads.pcap "$5" &\nuploads=$!\n',
            'tcpdump $common -s 160 -w /elsewhere.pcap "$6" &\nelsewhere=$!\n',
        ):
            assert started in capture_module.CAPTURE_SCRIPT
        (kept,) = Path(self.host.captures_dir).glob(f"*.pcap.{uploads.UPLOADS_PART}")
        (upload,) = capture_module.read_parts(kept.with_suffix("")).uploads.all
        assert upload.sent == 9_000
        # And goes with it when it is let go of
        kept.with_suffix("").unlink()
        capture_module.CaptureSidecar.for_session("s", "p").pruned(kept.parent)
        assert not kept.exists()

    def test_a_request_is_placed_in_the_upload_that_carried_it(self):
        now = self.now
        capture = self.captured(
            opened(now - 30), [*sent(now, 80_000, 1), *sent(now + 9, 81_000, 80_001)]
        )
        first, second = request(now - 0.2, 79_500), request(now + 8.9, 80_600)
        placer = wire.Wire()
        placer.place(first, capture)
        placer.place(second, capture)
        connection = f"on the connection of {self.clock(now - 30)}"
        assert first.notes == [f"wire: 80 kB at {self.clock(now)} {connection}"]
        assert second.notes == [f"wire: 81 kB at {self.clock(now + 9)} {connection}"]
        assert first.fields["wire"] == {
            "address": API,
            "port": 443,
            "source_port": 40443,
            "at": now,
            "seconds": 0.007,
            "bytes": 80_000,
            "shared": False,
            "opened": now - 30,
        }
        assert placer.unaccounted(capture) == []

    def test_two_requests_sent_at_once_are_in_one_upload(self):
        now = self.now
        capture = self.captured(opened(now - 30), sent(now, 130_000, 1))
        claudes, subagents = request(now - 0.1, 90_000), request(now, 39_000)
        placer = wire.Wire()
        placer.place(claudes, capture)
        placer.place(subagents, capture)
        assert claudes.notes[0].startswith("wire: 130 kB at")
        assert subagents.notes[0].startswith("wire: with another request in 130 kB")
        assert subagents.fields["wire"]["shared"] is True

    def test_a_request_takes_the_upload_of_its_length_not_the_nearest(self):
        now = self.now
        frames = [*sent(now, 300, 1), *sent(now + 1, 60_000, 301)]
        capture = self.captured(opened(now - 30), frames)
        asked = request(now - 0.1, 59_000)
        wire.Wire().place(asked, capture)
        assert asked.fields["wire"]["bytes"] == 60_000

    def test_a_request_no_upload_was_seen_for_is_said_to_have_none(self):
        now = self.now
        capture = self.captured(opened(now - 30), sent(now, 60_000, 1))
        placer = wire.Wire()
        # Long before, and at the time of an upload a tenth its length
        early, large = request(now - 300, 59_000), request(now, 600_000)
        placer.place(early, capture)
        placer.place(large, capture)
        for event in (early, large):
            assert event.notes == [wire.NOT_SEEN]
            assert event.fields["wire"] is None
        (left,) = placer.unaccounted(capture)
        assert left.sent == 60_000

    def test_nothing_is_said_of_a_capture_without_that_part(self):
        now = self.now
        asked = request(now, 59_000)
        wire.Wire().place(asked, self.captured(opened(now - 30), None))
        assert asked.notes == []
        assert "wire" not in asked.fields
        # Nor of a request that does not say when it was written out
        unknown = api_events.call_event({"t": now, "session": CONTAINER, "sent": 5})
        wire.Wire().place(unknown, self.captured(opened(now), sent(now, 60_000, 1)))
        assert unknown.notes == []

    def test_nothing_is_said_missing_of_a_part_that_stopped(self):
        now = self.now
        capture = self.captured(opened(now - 30), sent(now, 60_000, 1))
        capture.part_packets[uploads.UPLOADS_PART] = capture_module.PACKET_LIMIT
        asked = request(now + 100, 59_000)
        wire.Wire().place(asked, capture)
        assert asked.notes == []

    def test_a_connection_says_how_many_uploads_went_over_it(self):
        now = self.now
        frames = [
            *sent(now, 60_000, 1),
            *sent(now + 5, 61_000, 60_001),
            *sent(now + 9, 30, 121_001),
        ]
        ended = (now + 20, tcp(API, 443, 0x11, sequence=121_031), True)
        capture = self.captured([*opened(now - 30), ended], frames)
        (event,) = capture_events(capture, verbose=False)
        assert event.details[0].endswith(", 2 uploads")
        assert event.fields["uploads"] == 2
        # Nothing of one that nothing was sent over
        (quiet,) = capture_events(self.captured(opened(now), []), verbose=False)
        assert "uploads" not in quiet.details[0]
        assert "uploads" not in quiet.fields

    def traced(
        self, main: Frames, sent_to_the_model: Frames, sent_elsewhere: Frames = ()
    ) -> None:
        """Leave the capture of a session of the project that ran around
        now, as its launcher does when it ends."""
        captures = Path(self.host.captures_dir)
        captures.mkdir(parents=True)
        name = "claude-proj.capture-1.pcap"
        (captures / name).write_bytes(pcap_file(main, asked=False))
        parts = (
            (uploads.UPLOADS_PART, sent_to_the_model),
            (uploads.ELSEWHERE_PART, sent_elsewhere),
        )
        for part, frames in parts:
            file = captures / f"{name}.{part}"
            file.write_bytes(pcap_file(list(frames), asked=False))
        session = records.TracedSession(
            CONTAINER,
            self.host.project_dir,
            self.now - 60,
            capture=name,
            end=self.now + 60,
        )
        records.record_traced_session(self.host, session)

    def note(self, asked: float, length: int, **more: object) -> None:
        call = api_calls.Call(answered=True, asked=asked, sent=length, model="m")
        said = {**call.as_note(), **more}
        api_calls.call_record(self.host).add(self.host.project_dir, CONTAINER, **said)

    def test_the_trace_places_the_requests_and_shows_what_is_left(self):
        now = self.now
        frames = [
            *sent(now - 20, 80_000, 1),
            # Sent to the model with nothing noted for it
            *sent(now - 10, 12_000, 80_001),
        ]
        self.traced(opened(now - 30), frames)
        self.note(now - 20.1, 79_000)
        self.note(now - 5, 70_000)
        self.write_transcript("0a", prompts_at(now - 40, now + 40))
        stdout = self.launch("--trace").stdout
        connection = f"on the connection of {self.clock(now - 30)}"
        for expected in (
            "# requests    2 to the model, 149 kB sent, the bodies of 2 NOT KEPT",
            (
                "# requests    1 seen on the wire, 1 NOT SEEN there,"
                " 1 uploads to the model's API with no request noted"
            ),
            f"bodies NOT KEPT  wire: 80 kB at {self.clock(now - 20)} {connection}\n",
            f"bodies NOT KEPT  {wire.NOT_SEEN}\n",
            (
                f"sandbox  net         tcp/https {API}:443  upload of 12 kB in 0.0s,"
                " no request noted for it\n"
            ),
            f"tcp/https {API}:443  left open, 2 uploads  (no call running)\n",
        ):
            assert expected in stdout, stdout
        only = self.launch("--trace", "--only", "request", "--json").stdout
        first, second = map(json.loads, only.splitlines())
        assert first["wire"]["bytes"] == 80_000
        assert second["wire"] is None

    def test_a_request_of_another_container_is_not_placed_in_this_capture(self):
        now = self.now
        self.traced(opened(now - 30), sent(now - 20, 80_000, 1))
        recorded = Recorded.between(self.host, now - 40, now + 40)
        other = request(now - 20, 79_000, session="claude-other")
        rows, left = wire.on_the_wire([other], recorded)
        assert other.notes == []
        # Nor is its upload said to be without a request: none is noted
        # of this container
        assert rows == [
            ("requests", "0 seen on the wire"),
            ("uploads", "1 to the model's API, 80 kB sent"),
        ]
        assert [event.kind for event in left] == [Kind.NET]
        assert left[0].details[0].endswith("upload of 80 kB in 0.0s")
        assert left[0].fields["container"] == CONTAINER
        assert "\x1b" not in "".join(Layout().events(left))

    def test_without_requests_noted_the_trace_shows_each_upload(self):
        now = self.now
        frames = [*sent(now - 20, 80_000, 1), *sent(now - 10, 12_000, 80_001)]
        # And what is no request: too short to be one
        frames += sent(now - 5, 300, 92_001)
        self.traced(opened(now - 30), frames)
        self.write_transcript("0a", prompts_at(now - 40, now + 40))
        stdout = self.launch("--trace").stdout
        for expected in (
            "# uploads     2 to the model's API, 92 kB sent\n",
            f"sandbox  net         tcp/https {API}:443  upload of 80 kB in 0.0s\n",
            f"sandbox  net         tcp/https {API}:443  upload of 12 kB in 0.0s\n",
            f"tcp/https {API}:443  left open, 2 uploads  (no call running)\n",
        ):
            assert expected in stdout, stdout
        assert "# requests" not in stdout
        assert "upload of 300 B" not in stdout
        only = self.launch("--trace", "--only", "net", "--json").stdout
        upload = json.loads(only.splitlines()[1])
        assert (upload["upload"], upload["bytes_out"]) == (True, 80_000)
        assert (upload["source_port"], upload["address"]) == (40443, API)
        assert "unnoted" not in upload

    def test_what_is_sent_anywhere_else_is_an_upload_too(self):
        now, there = self.now, "198.51.100.7"

        def pushed(when: float, length: int, sequence: int) -> Frames:
            packet = tcp(there, 22, 0x18, b"x" * length, sequence=sequence)
            return [(when, packet, True)]

        main = [
            *opened(now - 30),
            (now - 28, tcp(there, 22), True),
            (now - 27.9, answer(there, 22), False),
        ]
        elsewhere = [*pushed(now - 12, 50_000, 1), *pushed(now - 3, 200, 50_001)]
        capture = self.captured(main, sent(now - 20, 80_000, 1), elsewhere)
        assert [upload.sent for upload in capture.uploads.all] == [80_000]
        assert [upload.sent for upload in capture.elsewhere.all] == [50_000, 200]
        # A connection says how many, whichever part has them
        ssh = capture_events(capture, verbose=False)[1]
        assert ssh.details == [f"tcp/ssh {there}:22  left open, 1 uploads"]
        self.traced(main, sent(now - 20, 80_000, 1), elsewhere)
        bash = {"type": "tool_use", "id": "c1", "name": "Bash"}
        bash["input"] = {"command": "git push"}
        done = {"type": "tool_result", "tool_use_id": "c1", "content": "ok"}
        stamps = [prompts_at(when)[0]["timestamp"] for when in (now - 13, now - 11)]
        steps = [
            {
                "type": "assistant",
                "timestamp": stamps[0],
                "message": {"content": [bash]},
            },
            {"type": "user", "timestamp": stamps[1], "message": {"content": [done]}},
        ]
        self.write_transcript(
            "0a", [*prompts_at(now - 40), *steps, *prompts_at(now + 40)]
        )
        stdout = self.launch("--trace").stdout
        for expected in (
            "# uploads     1 to the model's API, 80 kB sent\n",
            "# uploads     1 elsewhere, 50 kB sent\n",
            # Of the call it was sent during, as a connection is: not
            # what goes to the model, which no call makes
            f"tcp/ssh {there}:22  upload of 50 kB in 0.0s  during: $ git push\n",
            f"tcp/https {API}:443  upload of 80 kB in 0.0s\n",
        ):
            assert expected in stdout, stdout
        assert "upload of 200 B" not in stdout
        # A request is never placed in what went anywhere else
        asked = request(now - 12, 50_000)
        wire.Wire().place(asked, capture)
        assert asked.notes == [wire.NOT_SEEN]

    def test_an_upload_is_followed_once_it_is_over(self):
        tail = follow.CaptureTail(f"{CONTAINER}.capture", verbose=False)
        long_ago, just_now = self.now - 60, time.time()
        frames = [
            *sent(long_ago, 80_000, 1),
            *sent(long_ago + 5, 200, 80_001),
            # Still going on, as far as can be told
            *sent(just_now, 9_000, 80_201),
        ]
        pushed = tcp("198.51.100.7", 22, 0x18, b"x" * 30_000, sequence=1)
        tail.capture = self.captured(
            opened(self.now - 90), frames, [(long_ago + 9, pushed, True)]
        )
        event, elsewhere = tail._uploads_over()
        assert elsewhere.details == ["tcp/ssh 198.51.100.7:22  upload of 30 kB in 0.0s"]
        assert elsewhere.fields["model_api"] is False
        assert event.details == [f"tcp/https {API}:443  upload of 80 kB in 0.0s"]
        assert (event.when, event.fields["model_api"]) == (long_ago, True)
        assert tail._uploads_over() == []
        with mock.patch.object(follow, "UPLOAD_OVER", -60.0):
            (last,) = tail._uploads_over()
        assert last.fields["bytes_out"] == 9_000

    def test_a_request_is_placed_as_it_is_followed(self):
        now = self.now
        follower = follow.Follower(self.host, verbose=False, container=CONTAINER)
        tail = follow.CaptureTail(f"{CONTAINER}.capture", verbose=False)
        tail.capture = self.captured(opened(now - 30), sent(time.time(), 80_000, 1))
        follower._captures[(tail.sidecar, now - 60)] = tail
        time.sleep(0.01)
        self.note(time.time(), 79_000)
        found = follow.Round()
        follower._poll_notes(found)
        ((_, event),) = found.events
        assert event.notes[0].startswith("wire: 80 kB at ")
        assert event.notes[0].endswith(f"on the connection of {self.clock(now - 30)}")
