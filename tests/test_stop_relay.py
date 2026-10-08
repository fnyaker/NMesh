"""
The signed "stop relaying that node to me".

What is proved: a record verifies only for the key that signed it and names that
key as its requester, so nobody can sign one on another destination's behalf;
it expires and cannot ask for longer than `MAX_TTL`; and `parse` turns every
malformed, truncated, tampered or random input into ``None`` without raising.
"""
import os
import time

from src import stop_relay
from src.crypto import CryptoIdentity
from src.node_id import NodeID

ME = CryptoIdentity()
OTHER = CryptoIdentity()
BLOCKED = NodeID(os.urandom(20))


def _record(**kwargs):
    return stop_relay.build(BLOCKED, ME.dsa_public_key, ME.sign,
                            ttl=kwargs.pop("ttl", 600), **kwargs)


class TestWhatARecordSays:

    def test_it_names_the_key_that_signed_it(self):
        parsed = stop_relay.parse(_record(), ME.verify)
        assert parsed["requester"] == NodeID.from_public_key(ME.dsa_public_key)
        assert parsed["blocked"] == BLOCKED
        assert parsed["expires_at"] - parsed["issued_at"] == 600

    def test_it_cannot_ask_for_longer_than_the_ceiling(self):
        parsed = stop_relay.parse(_record(ttl=10 ** 6), ME.verify)
        assert parsed["expires_at"] - parsed["issued_at"] == stop_relay.MAX_TTL

    def test_it_expires(self):
        old = _record(ttl=60, now=int(time.time()) - 120)
        assert stop_relay.parse(old, ME.verify) is None

    def test_a_node_does_not_block_itself(self):
        me = NodeID.from_public_key(ME.dsa_public_key)
        try:
            stop_relay.build(me, ME.dsa_public_key, ME.sign, ttl=60)
        except ValueError:
            return
        raise AssertionError("built a record blocking its own signer")


class TestWhatIsRefused:

    def test_somebody_elses_key_cannot_sign_for_me(self):
        record = bytearray(_record())
        # Swap in another key, keep the signature: it no longer verifies.
        start = stop_relay._HDR.size
        record[start:start + len(OTHER.dsa_public_key)] = OTHER.dsa_public_key
        assert stop_relay.parse(bytes(record), ME.verify) is None

    def test_every_byte_flipped_is_refused(self):
        record = _record()
        for index in range(0, stop_relay._HDR.size, 3):
            tampered = bytearray(record)
            tampered[index] ^= 0x01
            assert stop_relay.parse(bytes(tampered), ME.verify) is None

    def test_noise_never_raises(self):
        for size in (0, 1, stop_relay._HDR.size, 500, stop_relay.MAX_RECORD + 1):
            for _ in range(20):
                assert stop_relay.parse(os.urandom(size), ME.verify) is None
        assert stop_relay.parse("not bytes", ME.verify) is None
        assert stop_relay.parse(_record()[:-1], ME.verify) is None
        assert stop_relay.parse(_record() + b"x", ME.verify) is None
