import pytest
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
