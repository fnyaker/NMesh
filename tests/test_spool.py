"""
Store-and-forward primitives: Bundle container, record framing, spool transport.

Focus on the hostile-medium contract: corruption, truncation and tampering are
detected and rejected (Bundle) or skipped with resync (record stream), and no
hostile bytes crash the parser.
"""
import asyncio
import hashlib
import os
import random
import struct
import tempfile

import pytest

from src.spool import Bundle, BundleError, write_bundle, read_bundle, _HEADER, _MAGIC
from src.spool_transport import (
    SpoolTransport, _parse_records, _REC, _REC_MAGIC,
)
from src.packet import Packet
from src.node import DATA
from src.node_id import NodeID
from src.crypto import SessionKey
from tests.conftest import make_node


def _pkt(payload: bytes = b"hi", t: int = 0x01) -> bytes:
    return Packet.create(t, os.urandom(20), os.urandom(20), payload).pack()


def _record(payload: bytes) -> bytes:
    import zlib
    return _REC.pack(_REC_MAGIC, len(payload), zlib.crc32(payload) & 0xFFFFFFFF) + payload


# ---------------------------------------------------------------------------
# Bundle container
# ---------------------------------------------------------------------------

class TestBundle:
    def test_roundtrip(self):
        pkts = [_pkt(b"a"), _pkt(b"b" * 100), _pkt(b"")]
        assert Bundle.unpack(Bundle.pack(pkts)) == pkts

    def test_empty(self):
        assert Bundle.unpack(Bundle.pack([])) == []

    def test_truncation_rejected(self):
        blob = Bundle.pack([_pkt(), _pkt()])
        for cut in (1, len(blob) // 2, len(blob) - 1):
            with pytest.raises(BundleError):
                Bundle.unpack(blob[:cut])

    def test_tamper_rejected(self):
        blob = bytearray(Bundle.pack([_pkt(b"secret")]))
        blob[_HEADER.size + 6] ^= 0xFF   # flip a body byte
        with pytest.raises(BundleError):
            Bundle.unpack(bytes(blob))

    def test_bad_magic(self):
        blob = bytearray(Bundle.pack([_pkt()]))
        blob[0] ^= 0xFF
        with pytest.raises(BundleError):
            Bundle.unpack(bytes(blob))

    def test_declared_count_too_large(self):
        # A valid-checksum bundle that lies about its packet count.
        body = _HEADER.pack(_MAGIC, 1, 10 ** 9)
        blob = body + hashlib.sha256(body).digest()
        with pytest.raises(BundleError):
            Bundle.unpack(blob)

    def test_trailing_garbage(self):
        body = _HEADER.pack(_MAGIC, 1, 0) + b"\x00\x00\x00\x03abc" + b"junk"
        blob = body + hashlib.sha256(body).digest()
        with pytest.raises(BundleError):
            Bundle.unpack(blob)

    def test_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "b.bundle")
            pkts = [_pkt(b"x"), _pkt(b"y")]
            write_bundle(path, pkts)
            assert read_bundle(path) == pkts
            # corrupt the file on disk → rejected on read
            with open(path, "r+b") as f:
                f.seek(-1, os.SEEK_END)
                f.write(b"\x00")
            with pytest.raises(BundleError):
                read_bundle(path)

    def test_fuzz_never_crashes(self):
        rng = random.Random(0xB0A7)
        for _ in range(5000):
            data = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 300)))
            try:
                out = Bundle.unpack(data)
            except BundleError:
                continue
            assert isinstance(out, list)


# ---------------------------------------------------------------------------
# Record stream framing (spool file)
# ---------------------------------------------------------------------------

class TestRecordParsing:
    def test_two_records(self):
        stream = _record(b"one") + _record(b"two")
        payloads, consumed = _parse_records(stream)
        assert payloads == [b"one", b"two"]
        assert consumed == len(stream)

    def test_partial_record_waits(self):
        full = _record(b"complete") + _record(b"partial")
        cut = full[:-3]  # last record truncated
        payloads, consumed = _parse_records(cut)
        assert payloads == [b"complete"]
        assert consumed == len(_record(b"complete"))  # partial not consumed

    def test_corrupt_crc_resyncs(self):
        good = _record(b"good")
        bad = bytearray(_record(b"bad"))
        bad[-1] ^= 0xFF  # break the payload → CRC fails
        stream = bytes(bad) + good
        payloads, _ = _parse_records(stream)
        assert b"good" in payloads

    def test_garbage_prefix_skipped(self):
        stream = b"\x00\x01\x02garbage" + _record(b"payload")
        payloads, _ = _parse_records(stream)
        assert payloads == [b"payload"]

    def test_fuzz_never_crashes(self):
        rng = random.Random(0x5900)
        for _ in range(5000):
            data = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 400)))
            payloads, consumed = _parse_records(data)
            assert isinstance(payloads, list)
            assert 0 <= consumed <= len(data)


# ---------------------------------------------------------------------------
# SpoolTransport bidirectional roundtrip over a directory (no node, no socket)
# ---------------------------------------------------------------------------

class TestSpoolTransport:
    async def test_bidirectional_roundtrip(self):
        with tempfile.TemporaryDirectory() as link:
            client = SpoolTransport()
            await client.connect(link)
            # find the session dir the client created and bind a server to it
            sess = [n for n in os.listdir(link) if n.startswith("sess-")][0]
            server = SpoolTransport()
            server._bind_server(os.path.join(link, sess))
            server._ensure_out()

            p1 = Packet.create(0x01, os.urandom(20), os.urandom(20), b"c2s")
            await client.send(p1)
            got = await server.receive()
            assert got.pack() == p1.pack()

            p2 = Packet.create(0x02, os.urandom(20), os.urandom(20), b"s2c")
            await server.send(p2)
            got2 = await client.receive()
            assert got2.pack() == p2.pack()

            await client.close()
            await server.close()

    async def test_survives_corruption_between_valid(self):
        with tempfile.TemporaryDirectory() as link:
            client = SpoolTransport()
            await client.connect(link)
            sess = [n for n in os.listdir(link) if n.startswith("sess-")][0]
            server = SpoolTransport()
            server._bind_server(os.path.join(link, sess))

            # Write a good record, then raw garbage, then another good record,
            # directly into the client's outbound file.
            import zlib
            good1 = _record(Packet.create(0x01, os.urandom(20), os.urandom(20), b"first").pack())
            junk = b"\xde\xad\xbe\xef" * 5
            good2 = _record(Packet.create(0x01, os.urandom(20), os.urandom(20), b"second").pack())
            with open(os.path.join(link, sess, "c2s.spool"), "wb") as f:
                f.write(good1 + junk + good2)

            first = await server.receive()
            second = await server.receive()
            assert first.payload == b"first"
            assert second.payload == b"second"
            await client.close()
            await server.close()


# ---------------------------------------------------------------------------
# Sneakernet: A and C never meet online. A pre-shares an E2E session with C,
# produces an encrypted DATA packet, packs it into a Bundle carried on a
# removable medium, and C decrypts it after import.
# ---------------------------------------------------------------------------

class TestSneakernet:
    async def test_offline_data_delivery(self):
        node_a, _ = await make_node()
        node_c, fake_c = await make_node()

        shared = os.urandom(32)
        node_a._e2e_sessions[node_c.id] = SessionKey(shared)
        node_c._e2e_sessions[node_a.id] = SessionKey(shared)

        # A produces an encrypted DATA packet destined for C (offline, no route).
        pkt = Packet.create_encrypted(
            DATA, node_a.id.raw, node_c.id.raw, b"carried by pigeon",
            node_a._e2e_sessions[node_c.id],
        )

        with tempfile.TemporaryDirectory() as da, tempfile.TemporaryDirectory() as dc:
            out_path = os.path.join(da, "carry.bundle")
            write_bundle(out_path, [pkt.pack()])
            # "carry" the file to another machine
            carried = os.path.join(dc, "carry.bundle")
            with open(out_path, "rb") as f, open(carried, "wb") as g:
                g.write(f.read())
            raw_packets = read_bundle(carried)

        # C imports: an authenticated peer feeds the carried packets in.
        peer_c = node_c._peers[0]
        peer_c.authenticated_id = node_a.id
        peer_c.session = SessionKey(os.urandom(32))
        for raw in raw_packets:
            await node_c._handle_packet(peer_c, Packet.unpack(raw))

        src, data = await asyncio.wait_for(node_c.receive_data(), timeout=1.0)
        assert src == node_a.id
        assert data == b"carried by pigeon"

        await node_a.stop()
        await node_c.stop()
