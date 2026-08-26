"""
Chat social layer — profiles and groups on the wire.

A capturing stub client stands in for the connector: we assert the bytes the
app emits, and feed it inbound payloads to drive its handlers. Everything is
app-level (no node).

Names are conspicuously absent from all of it. A pseudo is the node's, carried
in a signed claim; chat neither sends one nor believes one sent to it, and the
tests below hold that line.
"""
import asyncio
import struct

import pytest

from src.apps.chat import (
    ChatApp, ProfileReceived, GroupMessage, GroupInvited,
    _PROFILE, _GROUP_INVITE, _GROUP_TEXT,
    GROUP_ID_LEN, MSG_ID_LEN,
)
from src.node_id import NodeID


def _profile_body(bio=b"", avatar=b""):
    return bytes([_PROFILE]) + struct.pack("!H", len(bio)) + bio + avatar

ME = NodeID(bytes([0x01]) * 20)
B = NodeID(bytes([0x02]) * 20)
C = NodeID(bytes([0x03]) * 20)


class StubClient:
    def __init__(self):
        self.sent = []           # list[(NodeID, bytes)]
    async def send(self, target, payload):
        self.sent.append((target, payload))
    async def recv(self):
        await asyncio.Event().wait()
    async def close(self):
        pass


def _app():
    return ChatApp(StubClient(), node_id=ME)


async def _next(app, kind, timeout=2.0):
    ev = await asyncio.wait_for(app.next_event(), timeout=timeout)
    assert isinstance(ev, kind), f"expected {kind.__name__}, got {ev}"
    return ev


class TestSend:
    async def test_send_profile(self):
        app = _app()
        app.state.set_profile(bio="hi", avatar=b"AV")
        await app.send_profile(B)
        assert app._client.sent[-1] == (B, _profile_body(b"hi", b"AV"))

    async def test_create_group_invites_members(self):
        app = _app()
        app.state.add_contact(B.raw.hex())
        gid = await app.create_group("team", [B])
        # Roster is us + B, stored locally…
        assert set(app.state.group_members(gid.hex())) == {ME.raw.hex(), B.raw.hex()}
        # …and B got a GROUP_INVITE (we don't invite ourselves).
        targets = [t for t, _ in app._client.sent]
        assert B in targets and ME not in targets
        inv = next(p for t, p in app._client.sent if t == B)
        assert inv[0] == _GROUP_INVITE and inv[1:1 + GROUP_ID_LEN] == gid

    async def test_send_group_text_fans_out_excluding_self(self):
        app = _app()
        gid = bytes([0x09]) * GROUP_ID_LEN
        app.state.add_group(gid.hex(), "g", [ME.raw.hex(), B.raw.hex(), C.raw.hex()])
        await app.send_group_text(gid, "hi all")
        targets = sorted(t.raw.hex() for t, _ in app._client.sent)
        assert targets == sorted([B.raw.hex(), C.raw.hex()])   # not ME
        _, payload = app._client.sent[0]
        assert payload[0] == _GROUP_TEXT
        assert payload[1:1 + GROUP_ID_LEN] == gid
        # gid | mid(16) | reply_to(16) | text
        assert payload[1 + GROUP_ID_LEN + MSG_ID_LEN + GROUP_ID_LEN:] == b"hi all"


class TestReceive:
    async def test_profile_learned(self):
        app = _app()
        app._dispatch(B, _profile_body(b"bob's bio", b"BOBAV"))
        ev = await _next(app, ProfileReceived)
        assert ev.bio == "bob's bio" and ev.avatar == b"BOBAV"
        assert app.state.get_avatar(B.raw.hex()) == b"BOBAV"

    async def test_a_profile_cannot_carry_a_name(self):
        # The old format put a pseudo first. Replayed here, those bytes are read
        # as a bio length and the message is dropped — but the point is the
        # stronger one: there is nowhere in a profile for a name to go, so a
        # peer cannot tell us what to call it.
        app = _app()
        legacy = (bytes([_PROFILE]) + struct.pack("!H", 3) + b"bob"
                  + struct.pack("!H", 2) + b"hi")
        app._dispatch(B, legacy)
        assert app.state.known.get(B.raw.hex(), {}).get("pseudo", "") != "bob"

    async def test_group_invite_adds_group(self):
        app = _app()
        gid = bytes([0x07]) * GROUP_ID_LEN
        name = b"squad"
        roster = [ME, B, C]
        body = (bytes([_GROUP_INVITE]) + gid + struct.pack("!H", len(name)) + name
                + struct.pack("!H", len(roster)) + b"".join(n.raw for n in roster))
        app._dispatch(B, body)
        ev = await _next(app, GroupInvited)
        assert ev.name == "squad" and len(ev.members) == 3
        assert set(app.state.group_members(gid.hex())) == {ME.raw.hex(), B.raw.hex(), C.raw.hex()}

    async def test_group_text_emitted(self):
        app = _app()
        gid = bytes([0x07]) * GROUP_ID_LEN
        mid = b"\x05" * MSG_ID_LEN
        body = bytes([_GROUP_TEXT]) + gid + mid + bytes(GROUP_ID_LEN) + b"yo group"
        app._dispatch(B, body)
        ev = await _next(app, GroupMessage)
        assert ev.group_id == gid and ev.src == B and ev.text == "yo group" and ev.mid == mid


class TestHostile:
    async def test_malformed_group_invite_dropped(self):
        app = _app()
        for bad in (b"", bytes([_GROUP_INVITE]), bytes([_GROUP_INVITE]) + b"\x00" * 5,
                    bytes([_GROUP_INVITE]) + bytes(GROUP_ID_LEN) + struct.pack("!H", 9999)):
            app._dispatch(B, bad)   # must not raise
        assert app.state.groups == {}

    async def test_group_invite_member_count_bounded(self):
        app = _app()
        gid = bytes(GROUP_ID_LEN)
        # Claims 65535 members but carries none → rejected on the length check.
        body = (bytes([_GROUP_INVITE]) + gid + struct.pack("!H", 0)
                + struct.pack("!H", 65535))
        app._dispatch(B, body)
        assert app.state.groups == {}
