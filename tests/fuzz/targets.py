"""
What the fuzzer aims at: every parser a peer's bytes reach, with its contract.

``allowed`` is the contract as the code states it — "raises ``TicketError``,
never anything else", "``None`` for anything that does not check out". A target
whose contract is ``None`` allows nothing. A signature check is answered "yes"
(``_trust_all``) so the fuzzer gets past it to what follows: that is the input
an authenticated adversary, who can sign whatever it likes, gets to send.

Seeds are valid encodings built by the tree's own encoders, so mutation starts
inside the format rather than at its first length check.
"""
from __future__ import annotations

import functools
import json
import struct
import time
import zlib

from src import (accusation, app_auth, app_package, app_perms, console_feed,
                 core_release, features, join_ticket, key_share, lan_discovery,
                 pkg_dir, pseudo_dir, revocation, stop_relay, stun)
from src.apps import call, fleet_provision
from src.cert import Certificate
from src.control import frame
from src.crypto import CryptoIdentity
from src.mesh import codecs
from src.node_id import NodeID
from src.packet import Packet, PacketError
from src.transports import bundle, spool

from .engine import Target


def _trust_all(*_args, **_kwargs) -> bool:
    return True


@functools.lru_cache(maxsize=1)
def _identity() -> CryptoIdentity:
    return CryptoIdentity()


def _sign(message: bytes) -> bytes:
    return _identity().sign(message)


def _pub() -> bytes:
    return _identity().dsa_public_key


def _node() -> NodeID:
    return NodeID.from_public_key(_pub())


def _seeds(builder):
    """Each builder run once. One that fails raises: a seed that silently stops
    building is a target silently fuzzed from nothing."""
    return lambda: [build() for build in builder()]


# -- the core's wire formats ------------------------------------------------

def _packet_seeds():
    src, dst = b"\x01" * 20, b"\x02" * 20
    return [lambda t=t: Packet(1, t, 8, src, dst, None, b"\x00" * 12, b"\x00" * 16,
                               b"payload").pack() for t in (1, 2, 3, 7, 9)]


def _cert():
    return _identity().self_signed_cert()


def _handshake_seeds():
    return [lambda: codecs._encode_handshake(b"k" * 1184, _pub(), [], b"s" * 64),
            lambda: codecs._encode_handshake(b"k" * 1184, _pub(), [_cert()], b"s" * 64)]


def _ack_seeds():
    return [lambda: codecs._encode_handshake_ack(b"c" * 64, _pub(), [_cert()], _cert(),
                                                 b"s" * 64)]


def _cert_seeds():
    return [lambda: _cert().serialize()]


def _chain_seeds():
    return [lambda: codecs._encode_chain([_cert(), _cert()])]


def _addresses_seeds():
    return [lambda: codecs._encode_addresses(["tcp://192.0.2.1:9000",
                                              "udp://[2001:db8::1]:9001"])]


def _punch_seeds():
    return [lambda: codecs._encode_punch_request(b"\x03" * 20, 9001),
            lambda: codecs._encode_punch_relay(b"\x03" * 20, "192.0.2.1:9001", "x"),
            lambda: codecs._build_punch_probe(b"\x03" * 20, b"n" * 16, b"s" * 32),
            lambda: codecs._build_punch_ack(b"\x03" * 20, b"n" * 16, b"s" * 32)]


def _decode_punch(data: bytes):
    codecs._decode_punch_request(data)
    codecs._decode_punch_relay(data)
    codecs._parse_punch_probe(data)
    codecs._parse_punch_ack(data)


def _seek_seeds():
    return [lambda: codecs._encode_seek(int(time.time()) + 60, b"h" * 32, _pub(), b"t" * 16)]


def _entries_seeds():
    return [lambda: codecs._encode_entries([])]


def _hints_seeds():
    return [lambda: codecs._encode_cert_hints([b"p" * 32, b"q" * 32])]


def _decode_hints(data: bytes):
    codecs._decode_cert_hints(data)


def _decode_entries(data: bytes):
    codecs._decode_entries(data, resolve=lambda _fingerprint: None)


def _decode_ping_tail(data: bytes):
    codecs._decode_ping_tail(data, 0)


def _features_seeds():
    return [lambda: features.encode(["mlo", "speedtest", "x_custom"])]


def _bundle_seeds():
    return [lambda: bundle.Bundle.pack([b"one", b"two" * 30])]


def _bundle_unpack(data: bytes):
    bundle.Bundle.unpack(data)


def _spool_seeds():
    def record(payload: bytes) -> bytes:
        return spool._REC.pack(spool._REC_MAGIC, len(payload), zlib.crc32(payload)) + payload
    return [lambda: record(b"hello") + record(b"world" * 10)]


def _spool_parse(data: bytes):
    spool._parse_records(data)


# -- the signed planes ------------------------------------------------------

def _claim_seeds():
    return [lambda: pseudo_dir.build_claim("alice", _pub(), _sign),
            lambda: pseudo_dir.encode_claims([pseudo_dir.build_claim("bob", _pub(), _sign)])]


def _parse_claim(data: bytes):
    pseudo_dir.parse_claim(data, _trust_all)
    for claim in pseudo_dir.decode_claims(data):
        pseudo_dir.parse_claim(claim, _trust_all)


def _accusation_seeds():
    return [lambda: accusation.build(NodeID(b"\x05" * 20), _pub(), _sign)]


def _revocation_seeds():
    return [lambda: revocation.build(NodeID(b"\x05" * 20), _pub(), _sign)]


def _stop_relay_seeds():
    return [lambda: stop_relay.build(NodeID(b"\x05" * 20), _pub(), _sign, ttl=600)]


def _assertion_seeds():
    return [lambda: app_auth.make_assertion(_identity(), b"\x07" * 8, audience=b"\x08" * 20,
                                            purpose="fleet.enrol").serialize()]


def _key_share_seeds():
    return [lambda: key_share.build_offer(b"o" * 16, b"\x01" * 20, b"\x02" * 20, _pub(),
                                          _sign, label="ops")]


def _pkg_record_seeds():
    return [lambda: pkg_dir.build_record(1, "demo", "1.0.0", b"r" * pkg_dir.RELEASE_KEY_LEN, b"s" * pkg_dir.SRC_LEN,
                                         _pub(), _sign)]


def _core_release_seeds():
    return [lambda: core_release.build_release(
        core_release.build_package({"src/version.py": b'__version__ = "9.9.9"\n'}),
        "9.9.9", _pub(), _sign)]


def _app_release_seeds():
    return [lambda: app_package.build_release(b"k" * 32, "a" * 64, "demo", "1.0.0",
                                              _pub(), _sign)[0]]


def _key_share(data: bytes):
    key_share.parse_offer(data, b"\x01" * 20, b"\x02" * 20, _trust_all)
    key_share.parse_accept(data, b"\x01" * 20, b"\x02" * 20, _trust_all,
                           lambda _pub: b"\x01" * 20)


def _pkg_record(data: bytes):
    pkg_dir.parse_record(data, _trust_all)
    for record in pkg_dir.decode_records(data):
        pkg_dir.parse_record(record, _trust_all)


def _core_release(data: bytes):
    core_release.parse_release(data, _trust_all)


def _app_release(data: bytes):
    app_package.parse_release(data, _trust_all)


def _app_manifest(data: bytes):
    app_package.parse_manifest(data)
    app_package.parse_root(data)


def _app_package_seeds():
    return [lambda: app_package.build("demo", "1.0.0", {"main.py": b"print(1)\n"})[1]]


# -- the control plane and the edges ----------------------------------------

def _frame_seeds():
    return [lambda: frame.encode({"op": "node.state", "params": {"full": True}, "id": "1"}),
            lambda: frame.encode({"ok": True, "result": {"a": [1, 2]}, "id": "1"})]


def _frame_decode(data: bytes):
    for decode in (frame.decode_request, frame.decode_reply):
        try:
            decode(data)
        except frame.FrameError:
            pass


def _ticket_seeds():
    return [lambda: join_ticket.encode("192.0.2.1", 9000, b"s" * join_ticket.SEED_BYTES,
                                       time.time() + 300).encode()]


def _ticket_decode(data: bytes):
    join_ticket.decode(data.decode("utf-8", "replace"))


def _preauth(data: bytes):
    try:
        document = json.loads(data)
    except ValueError:
        return
    fleet_provision.parse_preauth(document)


def _preauth_seeds():
    def build():
        document, _token = fleet_provision.make_preauth(
            _node().raw, _pub(), capabilities=["full"], join_uris=["tcp://192.0.2.1:9000"],
            join_code="abc", label="box")
        return json.dumps(document).encode()
    return [build]


def _app_perms(data: bytes):
    try:
        document = json.loads(data)
    except ValueError:
        return
    app_perms.parse_manifest(document)


def _stun_seeds():
    txn = b"\x11" * 12
    attr = struct.pack("!HHBBH", stun._STUN_ATTR_XOR_MAPPED_ADDR, 8, 0, 1,
                       9000 ^ (stun._STUN_MAGIC_COOKIE >> 16)) + struct.pack(
        "!I", 0xC0000201 ^ stun._STUN_MAGIC_COOKIE)
    return [lambda: struct.pack("!HHI", stun._STUN_BINDING_RESPONSE, len(attr),
                                stun._STUN_MAGIC_COOKIE) + txn + attr]


def _stun_parse(data: bytes):
    stun._parse_binding_response(data, b"\x11" * 12)


def _lan_seeds():
    return [lambda: lan_discovery._encode_answer(b"\x09" * 20, ["tcp://192.0.2.1:9000"])]


def _call_seeds():
    return [lambda: call.encode_header(call.AudioFormat(48000, 1, 2), 960)]


def _have_seeds():
    return [lambda: b"managed:1a2b3c4d,jobs:00ff00ff,log:deadbeef"]


def _permission_seeds():
    return [lambda: json.dumps({"name": "demo", "permissions": ["node.state", "chat.send"],
                                "remote": ["node.state"]}).encode()]


def _ping_tail_seeds():
    return [lambda: codecs._encode_ping_tail(1500, 42)]


def _console_have(data: bytes):
    console_feed.parse_have(data.decode("utf-8", "replace"))


TARGETS = [
    # The core: what any peer, authenticated or not, can put on a link.
    Target("packet", lambda d: Packet.unpack(d), (PacketError,), _seeds(_packet_seeds)),
    Target("handshake", codecs._decode_handshake, (ValueError,), _seeds(_handshake_seeds),
           max_len=16384),
    Target("handshake_ack", codecs._decode_handshake_ack, (ValueError,), _seeds(_ack_seeds),
           max_len=16384),
    Target("certificate", Certificate.deserialize, (ValueError,), _seeds(_cert_seeds)),
    Target("chain", codecs._decode_chain, (ValueError,), _seeds(_chain_seeds),
           max_len=16384),
    Target("addresses", codecs._decode_addresses, (ValueError,), _seeds(_addresses_seeds)),
    Target("entries", _decode_entries, (ValueError,), _seeds(_entries_seeds)),
    Target("seek", codecs._decode_seek, (), _seeds(_seek_seeds)),
    Target("punch", _decode_punch, (), _seeds(_punch_seeds)),
    Target("cert_hints", _decode_hints, (), _seeds(_hints_seeds)),
    Target("ping_tail", _decode_ping_tail, (ValueError,), _seeds(_ping_tail_seeds)),
    Target("features", features.decode, (), _seeds(_features_seeds)),
    Target("bundle", _bundle_unpack, (bundle.BundleError,), _seeds(_bundle_seeds)),
    Target("spool", _spool_parse, (), _seeds(_spool_seeds), max_len=8192),
    # The signed planes, past their signature: what a peer that signs can send.
    Target("pseudo_claim", _parse_claim, (), _seeds(_claim_seeds)),
    Target("accusation", lambda d: accusation.parse(d, _trust_all), (),
           _seeds(_accusation_seeds)),
    Target("revocation", lambda d: revocation.parse(d, _trust_all), (),
           _seeds(_revocation_seeds)),
    Target("stop_relay", lambda d: stop_relay.parse(d, _trust_all), (),
           _seeds(_stop_relay_seeds)),
    Target("assertion", app_auth.parse_assertion, (), _seeds(_assertion_seeds)),
    Target("key_share", _key_share, (), _seeds(_key_share_seeds)),
    Target("pkg_record", _pkg_record, (), _seeds(_pkg_record_seeds)),
    Target("core_release", _core_release, (core_release.ReleaseError,),
           _seeds(_core_release_seeds), max_len=16384),
    Target("app_release", _app_release, (app_package.AppPackageError,),
           _seeds(_app_release_seeds), max_len=16384),
    Target("app_manifest", _app_manifest, (app_package.AppPackageError,),
           _seeds(_app_package_seeds)),
    # The edges: the control plane, an invitation pasted in, a file a
    # provisioner left, a STUN server's answer, a LAN neighbour, a call.
    Target("control_frame", _frame_decode, (), _seeds(_frame_seeds)),
    Target("join_ticket", _ticket_decode, (join_ticket.TicketError,), _seeds(_ticket_seeds)),
    Target("preauth", _preauth, (), _seeds(_preauth_seeds)),
    Target("app_permissions", _app_perms, (app_perms.ManifestError,),
           _seeds(_permission_seeds)),
    Target("stun", _stun_parse, (), _seeds(_stun_seeds)),
    Target("lan_answer", lan_discovery._decode_answer, (), _seeds(_lan_seeds)),
    Target("call_header", call.decode_header, (), _seeds(_call_seeds)),
    Target("console_have", _console_have, (), _seeds(_have_seeds)),
]

BY_NAME = {target.name: target for target in TARGETS}
