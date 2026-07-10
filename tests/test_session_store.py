"""
Opt-in E2E session persistence.

Covers the at-rest security contract (encrypted, tied to identity, hostile-file
tolerant) and the end-to-end value: a node restart resumes sessions and can
still decrypt with the restored key.
"""
import os
import random
import tempfile

import pytest

from src.node import MeshNode, DATA
from src.node_id import NodeID
from src.crypto import CryptoIdentity, SessionKey
from src.session_store import SessionStore
from src.packet import Packet
from tests.conftest import make_manager, make_node


def _peer_id() -> NodeID:
    return NodeID.from_public_key(CryptoIdentity().dsa_public_key)


# ---------------------------------------------------------------------------
# SessionStore unit
# ---------------------------------------------------------------------------

class TestSessionStore:
    def test_roundtrip(self):
        ident = CryptoIdentity()
        n1, n2 = _peer_id(), _peer_id()
        with tempfile.TemporaryDirectory() as d:
            store = SessionStore(os.path.join(d, "s"), ident)
            store.save(
                {n1: SessionKey(os.urandom(32))},
                {n2: os.urandom(48)},
                {n2: os.urandom(32)},
                {n1: [b"queued-a", b"queued-b"]},
            )
            st = store.load()
            assert n1 in st.e2e_sessions
            assert n2 in st.pending_kem and len(st.pending_kem[n2]) == 48
            assert n2 in st.pending_nonce
            assert st.pending_data[n1] == [b"queued-a", b"queued-b"]

    def test_encrypted_at_rest(self):
        ident = CryptoIdentity()
        secret_key = SessionKey(os.urandom(32))
        marker = secret_key.key_bytes
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s")
            SessionStore(path, ident).save({_peer_id(): secret_key}, {}, {}, {})
            with open(path, "rb") as f:
                blob = f.read()
            assert marker not in blob             # key not sitting in plaintext
            assert marker.hex().encode() not in blob

    def test_tamper_yields_empty(self):
        ident = CryptoIdentity()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s")
            SessionStore(path, ident).save({_peer_id(): SessionKey(os.urandom(32))}, {}, {}, {})
            blob = bytearray(open(path, "rb").read())
            blob[-1] ^= 0xFF
            with open(path, "wb") as f:
                f.write(blob)
            assert SessionStore(path, ident).load().e2e_sessions == {}

    def test_wrong_identity_cannot_read(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s")
            SessionStore(path, CryptoIdentity()).save(
                {_peer_id(): SessionKey(os.urandom(32))}, {}, {}, {})
            # A different identity derives a different at-rest key → no access.
            assert SessionStore(path, CryptoIdentity()).load().e2e_sessions == {}

    def test_missing_file_empty(self):
        with tempfile.TemporaryDirectory() as d:
            st = SessionStore(os.path.join(d, "nope"), CryptoIdentity()).load()
            assert st.e2e_sessions == {} and st.pending_data == {}

    def test_fuzz_load_never_crashes(self):
        ident = CryptoIdentity()
        rng = random.Random(0x5E55)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s")
            for _ in range(1000):
                with open(path, "wb") as f:
                    f.write(bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 200))))
                st = SessionStore(path, ident).load()   # must never raise
                assert isinstance(st.e2e_sessions, dict)


# ---------------------------------------------------------------------------
# Node restart: session survives and still decrypts
# ---------------------------------------------------------------------------

class TestNodeRestart:
    async def test_session_survives_restart(self):
        with tempfile.TemporaryDirectory() as d:
            idp = os.path.join(d, "id.key")
            ssp = os.path.join(d, "sessions")
            peer = _peer_id()
            shared = os.urandom(32)

            node1 = MeshNode(make_manager(), identity_path=idp, session_store_path=ssp)
            node1._e2e_sessions[peer] = SessionKey(shared)
            node1._persist_state()
            await node1.stop()

            # Restart with the same identity + store.
            node2 = MeshNode(make_manager(), identity_path=idp, session_store_path=ssp)
            assert peer in node2._e2e_sessions
            assert node2._e2e_sessions[peer].key_bytes == SessionKey(shared).key_bytes

            # The restored key still decrypts a packet the peer encrypted.
            pkt = Packet.create_encrypted(DATA, peer.raw, node2.id.raw,
                                          b"after restart", SessionKey(shared))
            p = node2._peers[0] if node2._peers else await node2._inject_peer(_Dummy())
            p.authenticated_id = peer
            p.session = SessionKey(os.urandom(32))
            await node2._handle_packet(p, pkt)
            src, data = await node2.receive_data()
            assert (src, data) == (peer, b"after restart")
            await node2.stop()

    async def test_disabled_by_default(self):
        # No session_store_path → nothing persisted, no store object.
        node, _ = await make_node()
        assert node._session_store is None
        node._persist_state()  # no-op, must not raise
        await node.stop()

    async def test_routing_survives_restart(self):
        # Known peers (direct-link recovery) are restored after a restart, so
        # the node can rebuild links without re-invitation.
        with tempfile.TemporaryDirectory() as d:
            idp = os.path.join(d, "id.key")
            ssp = os.path.join(d, "sessions")
            peer = _peer_id()
            dsa_pub = CryptoIdentity().dsa_public_key

            node1 = MeshNode(make_manager(), identity_path=idp, session_store_path=ssp)
            node1._routing.add(peer, ["tcp://198.51.100.7:9000"], dsa_pub)
            node1._persist_state()
            await node1.stop()

            node2 = MeshNode(make_manager(), identity_path=idp, session_store_path=ssp)
            entry = node2._routing.get(peer)
            assert entry is not None
            assert "tcp://198.51.100.7:9000" in entry.addresses
            assert entry.dsa_pub == dsa_pub
            await node2.stop()


class _Dummy:
    def __init__(self):
        self.on_connect = None
    async def connect(self, a): ...
    async def listen(self, a): ...
    async def send(self, p): ...
    async def close(self): ...
    async def receive(self):
        import asyncio
        await asyncio.Event().wait()
