"""The protocol trace.

It exists to answer "why are these two nodes talking to each other?", and it
sits on the hot path of every incoming and outgoing packet. The two constraints
that matter: it must **never** record a payload, and it must never be able to
kill the receive loop it observes.
"""
import json
import os
import stat
import time

import pytest

from src import trace as trace_mod
from src.trace import Trace


class _Packet:
    """A packet reduced to what the trace looks at."""

    def __init__(self, type_=0x01, payload=b"secret payload", ttl=64,
                 src=b"\x11" * 20, dst=b"\x22" * 20):
        self.type = type_
        self.payload = payload
        self.ttl = ttl
        self.src_id = src
        self.dst_id = dst


class TestOffByDefault:
    def test_a_fresh_trace_records_nothing(self):
        trace = Trace()
        assert trace.status()["running"] is False
        trace.record("in", _Packet(), 80)
        assert trace.status()["events"] == 0

    def test_starting_is_what_enables_it(self):
        trace = Trace()
        trace.start(seconds=5)
        trace.record("in", _Packet(), 80)
        assert trace.status()["events"] == 1


class TestNoPayloadEverLeaves:
    """The header is already visible to every relay; the payload is precisely
    what this project exists to protect. A debug tool is no reason."""

    def test_the_payload_is_nowhere_in_what_is_kept(self):
        trace = Trace()
        trace.start(seconds=5)
        secret = b"THE-PLAINTEXT-NOBODY-MAY-SEE"
        trace.record("in", _Packet(payload=secret), 80)
        blob = json.dumps(trace.export())
        assert "THE-PLAINTEXT" not in blob
        assert secret.hex() not in blob

    def test_an_event_carries_only_header_facts(self):
        trace = Trace()
        trace.start(seconds=5)
        trace.record("out", _Packet(), 80)
        event = trace.events()[0]
        assert set(event) == {"at", "direction", "type", "bytes", "ttl",
                              "peer", "src", "dst"}

    def test_node_ids_are_kept_short(self):
        trace = Trace()
        trace.start(seconds=5)
        trace.record("in", _Packet(src=b"\xab" * 20), 80)
        assert len(trace.events()[0]["src"]) == trace_mod._ID_CHARS


class TestBounds:
    def test_the_ring_never_grows_past_its_size(self):
        trace = Trace()
        trace.start(seconds=30, events=100)
        for _ in range(500):
            trace.record("in", _Packet(), 80)
        status = trace.status()
        assert status["events"] == 100
        assert status["dropped"] >= 400

    def test_a_request_for_more_than_the_maximum_is_capped(self):
        trace = Trace()
        trace.start(seconds=10, events=10 ** 9)
        assert trace.status()["capacity"] == trace_mod.MAX_EVENTS

    def test_a_request_for_an_endless_trace_is_capped(self):
        """A trace that runs until someone remembers it is a leak with a
        friendly name."""
        trace = Trace()
        trace.start(seconds=10 ** 9)
        assert trace.status()["seconds_left"] <= trace_mod.MAX_SECONDS

    def test_it_stops_on_its_own_when_the_time_is_up(self):
        trace = Trace()
        trace.start(seconds=1)
        trace._stops_at = time.monotonic() - 1      # as if the time had run out
        trace.record("in", _Packet(), 80)
        assert trace.status()["running"] is False

    def test_unknown_message_types_cannot_grow_the_totals_without_end(self):
        trace = Trace()
        trace.start(seconds=30, events=200)
        for kind in range(2000):
            trace.record("in", _Packet(type_=kind % 1024), 80)
        assert len(trace._totals) <= 512


class TestNeverBreaksTheLink:
    """Losing a trace line is nothing; losing the receive loop is a security
    bug."""

    def test_a_packet_missing_its_fields_does_not_raise(self):
        trace = Trace()
        trace.start(seconds=5)

        class Broken:
            type = 1
            # ni ttl, ni src_id, ni dst_id

        trace.record("in", Broken(), 80)          # must not raise
        assert trace.status()["dropped"] == 1

    def test_a_packet_type_that_is_not_an_integer_does_not_raise(self):
        trace = Trace()
        trace.start(seconds=5)

        class Weird:
            type = object()
            ttl = 1
            src_id = b""
            dst_id = b""

        trace.record("in", Weird(), 80)
        assert trace.status()["events"] <= 1


class TestSummary:
    def test_the_rate_uses_the_recording_window_not_the_burst(self):
        """A 30 s trace containing a half-second burst describes half a second
        of traffic in thirty — dividing by the burst would announce a rate the
        link never sustained."""
        trace = Trace()
        trace.start(seconds=60)
        trace._started_at = time.time() - 60
        for _ in range(10):
            trace.record("in", _Packet(), 1000)
        trace.stop()
        summary = trace.summary()
        assert summary["window_seconds"] >= 59
        assert summary["rows"][0]["bytes_per_second"] < 200

    def test_rows_are_ordered_by_volume(self):
        trace = Trace()
        trace.start(seconds=30)
        trace.record("in", _Packet(type_=0x01), 100)
        for _ in range(5):
            trace.record("in", _Packet(type_=0x04), 15000)
        rows = trace.summary()["rows"]
        assert rows[0]["type"] != rows[1]["type"]
        assert rows[0]["bytes"] > rows[1]["bytes"]

    def test_names_come_from_the_table_it_was_given(self):
        trace = Trace()
        trace.start(seconds=5, names={0x04: "FOUND_NODE"})
        trace.record("in", _Packet(type_=0x04), 80)
        trace.record("in", _Packet(type_=0x77), 80)
        types = {row["type"] for row in trace.summary()["rows"]}
        assert "FOUND_NODE" in types and "0x77" in types


class TestOnDisk:
    def test_a_written_trace_is_owner_only(self, tmp_path):
        """A trace names who this node keeps company with, and when."""
        trace = Trace()
        trace.start(seconds=5)
        trace.record("in", _Packet(), 80)
        path = str(tmp_path / "trace.json")
        trace.write(path)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_what_is_written_is_valid_json_without_payload(self, tmp_path):
        trace = Trace()
        trace.start(seconds=5)
        trace.record("in", _Packet(payload=b"NEVER-WRITTEN"), 80)
        path = str(tmp_path / "trace.json")
        trace.write(path)
        with open(path) as handle:
            document = json.load(handle)
        assert document["format"] == "nmesh-trace-1"
        assert "NEVER-WRITTEN" not in json.dumps(document)

    def test_no_temporary_file_is_left_behind(self, tmp_path):
        trace = Trace()
        trace.start(seconds=5)
        path = str(tmp_path / "trace.json")
        trace.write(path)
        assert not os.path.exists(path + ".tmp")
