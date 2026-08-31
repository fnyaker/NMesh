"""
Names that survive a restart.

A pseudo used to live only in memory, so every reboot blanked every label the
node had learned and — when no configuration file carried it — its own name too.
What is proved here is the cache: claims written down, re-verified on the way
back in, this node's own name re-adopted, and a hostile file buying nothing.
"""
import os
import tempfile

import pytest

from src.crypto import CryptoIdentity
from src.node import MeshNode
from src.node_id import NodeID
from src.pseudo_dir import build_claim, parse_claim
from src.session_store import PseudoStore, MAX_STORED_CLAIMS
from tests.conftest import make_manager


def _claim(identity, pseudo, ts=1000):
    return build_claim(pseudo, identity.dsa_public_key, identity.sign, ts)


def _node(directory, identity_path, pseudo=None):
    return MeshNode(transport_manager=make_manager(),
                    identity_path=identity_path,
                    pseudo_store_path=os.path.join(directory, "node.names"),
                    pseudo=pseudo)


# ---------------------------------------------------------------------------
# The store
# ---------------------------------------------------------------------------

class TestPseudoStore:
    def test_roundtrip(self):
        identity = CryptoIdentity()
        raw = _claim(CryptoIdentity(), "alice")
        with tempfile.TemporaryDirectory() as directory:
            store = PseudoStore(os.path.join(directory, "names"), identity)
            store.save([raw])
            assert store.load() == [raw]

    def test_missing_file_is_an_empty_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            store = PseudoStore(os.path.join(directory, "absent"), CryptoIdentity())
            assert store.load() == []

    def test_a_tampered_file_yields_nothing(self):
        identity = CryptoIdentity()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "names")
            store = PseudoStore(path, identity)
            store.save([_claim(CryptoIdentity(), "alice")])
            blob = bytearray(open(path, "rb").read())
            blob[-1] ^= 0xFF
            open(path, "wb").write(bytes(blob))
            assert store.load() == []

    def test_another_identity_cannot_read_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "names")
            PseudoStore(path, CryptoIdentity()).save([_claim(CryptoIdentity(), "a")])
            assert PseudoStore(path, CryptoIdentity()).load() == []

    def test_the_number_of_claims_is_bounded(self):
        identity = CryptoIdentity()
        claims = [_claim(CryptoIdentity(), f"name{i}")
                  for i in range(MAX_STORED_CLAIMS + 5)]
        with tempfile.TemporaryDirectory() as directory:
            store = PseudoStore(os.path.join(directory, "names"), identity)
            store.save(claims)
            kept = store.load()
            assert len(kept) == MAX_STORED_CLAIMS
            # The tail survives: the book hands claims over least-recently-used
            # first, so the names still in use are the ones worth keeping.
            assert kept == claims[-MAX_STORED_CLAIMS:]


# ---------------------------------------------------------------------------
# The node
# ---------------------------------------------------------------------------

class TestRestart:
    async def test_a_learned_name_survives(self):
        stranger = CryptoIdentity()
        stranger_id = NodeID.from_public_key(stranger.dsa_public_key)
        raw = _claim(stranger, "Alice Ada")
        with tempfile.TemporaryDirectory() as directory:
            key = os.path.join(directory, "node.key")
            node = _node(directory, key)
            try:
                node._pseudo_book.offer(parse_claim(raw, node._identity.verify), raw)
                node._write_pseudos_now()
            finally:
                await node.stop()
            again = _node(directory, key)
            try:
                assert again.pseudo_of(stranger_id) == "Alice Ada"
            finally:
                await again.stop()

    async def test_our_own_name_survives_without_a_configuration_file(self):
        with tempfile.TemporaryDirectory() as directory:
            key = os.path.join(directory, "node.key")
            node = _node(directory, key)
            try:
                node.set_pseudo("Alice Ada")
                node._write_pseudos_now()
            finally:
                await node.stop()
            again = _node(directory, key)
            try:
                assert again.pseudo == "Alice Ada"
                assert again.pseudo_of(again.id) == "Alice Ada"
            finally:
                await again.stop()

    async def test_a_configured_name_still_wins_over_the_cached_one(self):
        # The file is the operator's declaration; editing it by hand has to
        # take effect, cache or no cache.
        with tempfile.TemporaryDirectory() as directory:
            key = os.path.join(directory, "node.key")
            node = _node(directory, key)
            try:
                node.set_pseudo("Old")
                node._write_pseudos_now()
            finally:
                await node.stop()
            again = _node(directory, key, pseudo="New")
            try:
                assert again.pseudo == "New"
            finally:
                await again.stop()

    async def test_a_renamed_node_keeps_moving_its_timestamp_forward(self):
        # Peers keep the newest claim per node and drop the rest, so a claim
        # signed after a restart must be newer than the one before it.
        with tempfile.TemporaryDirectory() as directory:
            key = os.path.join(directory, "node.key")
            node = _node(directory, key)
            try:
                node.set_pseudo("First")
                before = node._pseudo_book.ts_of(node.id.raw)
                node._write_pseudos_now()
            finally:
                await node.stop()
            again = _node(directory, key)
            try:
                again.set_pseudo("Second")
                assert again._pseudo_book.ts_of(again.id.raw) > before
            finally:
                await again.stop()

    async def test_a_forged_claim_on_disk_is_refused(self):
        # The file is not a trusted input: a name is believed because it is
        # signed, not because it was on our own disk.
        stranger = CryptoIdentity()
        node_id = NodeID.from_public_key(stranger.dsa_public_key)
        forged = bytearray(_claim(stranger, "Alice Ada"))
        forged[-1] ^= 0xFF                     # break the signature
        with tempfile.TemporaryDirectory() as directory:
            key = os.path.join(directory, "node.key")
            node = _node(directory, key)
            try:
                PseudoStore(os.path.join(directory, "node.names"),
                            node._identity).save([bytes(forged)])
            finally:
                await node.stop()
            again = _node(directory, key)
            try:
                assert again.pseudo_of(node_id) == ""
            finally:
                await again.stop()

    async def test_no_store_no_file(self):
        # A node given no path writes nothing and still runs.
        node = MeshNode(transport_manager=make_manager())
        try:
            node.set_pseudo("Alice")
            assert node.pseudo == "Alice"
        finally:
            await node.stop()
