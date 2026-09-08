import pytest
from src.packet import _nonce as packet_nonce
from src.packet import Packet, PacketError

SRC  = bytes(range(20))
DST  = bytes(range(20, 40))
NONCE   = bytes(range(12))
GCM_TAG = bytes(range(16))
PAYLOAD = b"hello mesh"

def make_packet(**kwargs) -> Packet:
    defaults = dict(
        version=1, type=0x01, ttl=64,
        src_id=SRC, dst_id=DST, msg_id=0,
        nonce=NONCE, gcm_tag=GCM_TAG,
        payload=PAYLOAD,
    )
    defaults.update(kwargs)
    return Packet(**defaults)


class TestPackUnpack:
    def test_roundtrip_preserves_fields(self):
        p = make_packet()
        p2 = Packet.unpack(p.pack())
        assert p.pack() == p2.pack()

    def test_pack_size(self):
        p = make_packet()
        assert len(p.pack()) == 79 + len(PAYLOAD)

    def test_empty_payload(self):
        p = make_packet(payload=b"")
        assert Packet.unpack(p.pack()).pack() == p.pack()

    def test_max_payload(self):
        p = make_packet(payload=b"x" * 60000)
        assert Packet.unpack(p.pack()).pack() == p.pack()

    def test_unpack_too_short(self):
        with pytest.raises(PacketError):
            Packet.unpack(b"\x00" * 10)


class TestMsgId:
    def test_reproducible(self):
        p = make_packet()
        assert p.compute_msg_id() == p.compute_msg_id()

    def test_fits_64bits(self):
        assert make_packet().compute_msg_id() <= 0xFFFFFFFFFFFFFFFF

    def test_different_payload_different_id(self):
        p1 = make_packet(payload=b"aaa")
        p2 = make_packet(payload=b"bbb")
        assert p1.compute_msg_id() != p2.compute_msg_id()

    def test_ttl_ignored(self):
        p1 = make_packet(ttl=10)
        p2 = make_packet(ttl=20)
        assert p1.compute_msg_id() == p2.compute_msg_id()


class TestValidation:
    @pytest.mark.parametrize("field,value", [
        ("src_id",  b"\x00" * 19),
        ("src_id",  b"\x00" * 21),
        ("dst_id",  b"\x00" * 19),
        ("dst_id",  b"\x00" * 21),
        ("nonce",   b"\x00" * 11),
        ("nonce",   b"\x00" * 13),
        ("gcm_tag", b"\x00" * 15),
        ("gcm_tag", b"\x00" * 17),
    ])
    def test_wrong_size_raises(self, field, value):
        with pytest.raises(PacketError):
            make_packet(**{field: value})

    def test_payload_too_large(self):
        with pytest.raises(PacketError):
            make_packet(payload=b"x" * 60001)


class TestBuildingAPacketCheaply:
    """`create` is on the send path of every packet this node emits, and since
    a link can be probed ten times a second it is on a hot one. Two things came
    out of it, and neither may cost a property.

    It used to build the packet **twice** — one instance purely to ask it for
    its own id, then the one it kept — and draw twelve random bytes from the
    kernel each time."""

    def test_the_id_is_the_same_whether_or_not_there_is_a_packet(self):
        p = Packet.create(0x01, b"\x11" * 20, b"\x22" * 20, b"payload")
        assert p.msg_id == p.compute_msg_id()
        assert p.msg_id == Packet.msg_id_over(
            1, 0x01, b"\x11" * 20, b"\x22" * 20, p.nonce, bytes(16), b"payload")

    def test_the_id_still_binds_every_field_it_did(self):
        """Anti-amplification rests on this: a relay must not be able to change
        the content and keep the id."""
        base = dict(version=1, type=0x01, src_id=b"\x11" * 20,
                    dst_id=b"\x22" * 20, nonce=b"\x00" * 12,
                    gcm_tag=b"\x00" * 16, payload=b"body")
        first = Packet.msg_id_over(**base)
        for field, other in (("type", 0x02), ("src_id", b"\x33" * 20),
                             ("dst_id", b"\x44" * 20), ("nonce", b"\x01" * 12),
                             ("gcm_tag", b"\x01" * 16), ("payload", b"bodz"),
                             ("version", 2)):
            assert Packet.msg_id_over(**{**base, field: other}) != first, field

    def test_the_nonce_never_repeats_across_a_block_boundary(self):
        """Drawn in blocks now. A slice of a CSPRNG draw is CSPRNG output, so
        this buys a syscall and never a shortcut — but a repeat would be a
        `msg_id` collision, so it is checked rather than assumed."""
        seen = {packet_nonce() for _ in range(50000)}
        assert len(seen) == 50000

    def test_two_identical_payloads_get_different_ids(self):
        """What the nonce is *for* on an unencrypted control packet: without it
        two identical PINGs would share an id and the second could be dropped
        as a replay."""
        args = (0x01, b"\x11" * 20, b"\x22" * 20, b"same")
        assert Packet.create(*args).msg_id != Packet.create(*args).msg_id

    def test_the_pool_is_safe_to_share(self):
        """Handing out a slice is a read-modify-write on module state, and
        CPython promises nothing about that. Every caller today is on the event
        loop — but "nothing calls this off the loop" is the kind of invariant
        nobody re-checks when they add a thread, and the cost of being wrong is
        two packets sharing a nonce, therefore a `msg_id`, therefore a
        legitimate packet dropped somewhere down the mesh as a replay."""
        import threading
        drawn, guard = [], threading.Lock()

        def hammer():
            mine = [packet_nonce() for _ in range(5000)]
            with guard:
                drawn.extend(mine)

        threads = [threading.Thread(target=hammer) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(drawn) == 40000
        assert len(set(drawn)) == 40000

    def test_the_pool_is_dropped_in_a_forked_child(self):
        """Or both sides of the fork hand out the same bytes, each believing
        them fresh."""
        import src.packet as packet
        before = packet_nonce()
        packet._reset_nonce_pool()
        assert packet._nonce_pool == b"" and packet._nonce_at == 0
        assert packet_nonce() != before
