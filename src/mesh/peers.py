"""
A link to one peer, and the pieces that describe one.

``_Peer`` is a *link*, not a node — a node may hold several at once,
which is why every counter it keeps is named for the link. Beside it:
``RelayedTransport``, the core's own transport (a link that is another
node carrying frames), and ``_PunchState``, one hole-punch in flight.
"""

import asyncio
import os
import time

from ..transports import medium
from ..crypto import SessionKey
from ..metrics import Counters, LinkQuality
from .constants import *  # noqa: F401,F403
from ..node_id import NodeID
from .messages import RELAY_CARRY
from ..packet import Packet
from ..transport import BaseTransport


# ---------------------------------------------------------------------------
# Peer state
# ---------------------------------------------------------------------------

class _Peer:

    def __init__(self, transport: BaseTransport, is_client_side: bool = False) -> None:
        self.transport = transport
        self.session: SessionKey | None = None
        self.pending_kem_secret: bytes | None = None
        self.join_code: str | None = None
        self.pending_challenge: bytes | None = None
        self.received_challenge: bytes | None = None
        self.authenticated_id: NodeID | None = None
        # Who this link proved to be, whether or not we went on to serve it.
        # `authenticated_id` is only set for a link we keep; one refused because
        # it answered as somebody else — or as us — has still proved an identity
        # (the signature over our own challenge), and that is the one thing that
        # tells the dialler "wrong address" from "nobody answered".
        self.answered_as: NodeID | None = None
        # The challenge on this link named our own id. Not proof of anything —
        # nothing has authenticated yet — so it names the dial outcome for an
        # operator and never strikes an address off. See `_handle_challenge`.
        self.claimed_self: bool = False
        self.invite_accepted: bool = False
        self.invite_sent: bool = False
        # Our code came back rejected. Read only by the join that presented it,
        # to tell an operator the one thing that goes wrong most: a code is used
        # once and expires. The far end chose to send that byte, so keeping it
        # discloses nothing new — throwing it away only cost the person holding
        # a dead ticket any way of finding out.
        self.invite_refused: bool = False
        # We presented an invitation code on THIS link and it was accepted.
        # Only then may the answer's issued certificate make its self-signed
        # root a root of ours: the alternative — believing whoever we happen to
        # have dialled — is a trust anchor anybody we contact can plant. See
        # `_handle_handshake_ack`, and Docs/Architecture/security.md.
        self.joined_by_invite: bool = False
        self.is_client_side: bool = is_client_side
        # A link used only to relay for others (SEEK / RELAY_CARRY) — we do not
        # try to authenticate to it, so its unsolicited CHALLENGE is ignored.
        self.relay_only: bool = False
        # A second link to a node we already reach, opened to measure it
        # (address steering). It is a duplicate on purpose and the pass that
        # opened it closes the loser, so the duplicate reaper leaves it alone.
        self.probation: bool = False
        self.remote_addr: str | None = None   # dialled URI, for routing/reconnect
        # When this link stopped being served. Non-zero means everything that
        # arrives is dropped without a word — the link stays open and quiet
        # rather than closing, so the far end cannot tell "I have been found
        # out" from "the network is bad today", and keeps spending its effort
        # on a socket that leads nowhere. Cleared only by the link ending.
        self.tarpit_until: float = 0.0
        # What this peer said it can speak, and what that leaves us both able to
        # use. `None` — not an empty set — means it has said nothing, which is a
        # node from before the negotiation existed and must keep working exactly
        # as it did. Absence is never read as refusal (see `features.py`).
        self.features: frozenset | None = None
        self.agreed: frozenset | None = None
        # What the behavioural sweep reads. Three integers, incremented in the
        # receive loop and nowhere else: everything they feed is computed later,
        # on a timer that already runs. A detector that costs the hot path
        # anything has already done more damage than what it detects.
        self.undeclared: int = 0        # messages of a plane it said it lacks
        self.found_entries: int = 0     # routing candidates it has handed us
        self.found_self: int = 0        # …of which it named itself
        # Rule E2: answers we could hold beside other peers' answers to the
        # same question, and how many of them shared almost nothing with any of
        # them. Incremented once per lookup round, never per packet.
        self.answers_judged: int = 0
        self.answers_disjoint: int = 0
        self._invite_failures: int = 0
        self._invite_lockout_ts: float = 0.0
        # Handshakes this link has been allowed to make us verify. A joiner
        # legitimately needs more than one (the invite exchange re-drives it,
        # and a lost packet is retried), but not without end: the work is a
        # post-quantum verification per certificate plus one for the handshake
        # itself, and nothing above this handler is authenticated.
        self._handshake_attempts: int = 0
        self.dsa_pub: bytes = b""
        self._malformed: int = 0
        # Liveness / round-trip: set when we PING, cleared+measured on the PONG.
        self.ping_sent_at: float | None = None
        self.last_rtt: float | None = None
        self.quality = LinkQuality()  # latency spread and probe loss
        # -- the keepalive accord (see mlo.py) ------------------------------
        # What the peer proposed, and what that leaves the two of us held to.
        # `None` — not a default window — means it has proposed nothing, which
        # is a node from before this existed and keeps the classic cadence.
        self.ka_window: tuple | None = None
        self.ka_accord: tuple | None = None
        # When the accord last moved. A proposal crosses the link at the speed
        # of the link, so nothing is held against a peer for a short while
        # afterwards (`_KA_GRACE`).
        self.ka_accord_at: float = 0.0
        # The gap it last announced before its next probe, and what we last
        # asked it for. A request is cancelled by the peer announcing the
        # accord's floor: that is the one refusal the protocol allows, and it
        # is what keeps "I want the fast lane back" from looking like silence.
        self.ka_next_ms: int | None = None
        self.ka_asked_ms: int | None = None
        self.ka_asked_at: float = 0.0
        # What the far end asked *us* for, and when. Only ever slower than what
        # we were doing — a request can never make this node spend more (see
        # `_handle_ka_request`) — and it lapses at `_KA_TOLD_TTL` rather than
        # holding for ever: a request is a "go quiet for now", and a peer that
        # still wants it says so again.
        self.ka_told_ms: int | None = None
        self.ka_told_at: float = 0.0
        # What this link was last told about where we are, and when. `None` is
        # "nothing yet", which no advertised set can equal — so the first probe
        # on a link always carries the addresses.
        self.addrs_sent: tuple | None = None
        self.addrs_sent_at: float = 0.0
        # When this link is next probed. A fresh one is due at the classic
        # interval, exactly as it was when one interval served every link; what
        # moves it in is the sweep deciding this link has a twin worth
        # measuring against.
        self.ka_due: float = time.monotonic() + _LINK_KEEPALIVE_INTERVAL
        # …and what cadence that role calls for. Written by `_update_bundles`
        # on the sweep and read per probe: deciding it per probe would walk
        # every link to find out whether this one has a twin — ten times a
        # second, per link.
        self.ka_wanted_ms: int | None = None
        # Counters the behaviour sweep reads (rules K1–K3). Integers bumped in
        # the two handlers, never anything computed there.
        self.ka_outside: int = 0
        self.ka_ignored: int = 0
        self.ka_impossible: int = 0
        self.connected_at: float = time.monotonic()
        self.counters = Counters()   # per-link throughput
        self.total = None            # node-wide Counters, set by the node
        # Node-wide Trace, set by the node alongside `total`. None (or disabled)
        # costs one attribute test per packet, which is the point: this sits on
        # the hot path of every packet in and out.
        self.trace = None
        # Invoked when the receive loop exits on its own (dead link or abuse),
        # so the node can prune this peer. Cleared on intentional stop().
        self.on_dead = None
        # Invoked when a *frame* would not decode. The link's own counter below
        # is all this object can keep, and `CLAUDE.md` is explicit that a count
        # kept per link is a count a peer sheds by reconnecting — so the node
        # hangs its identity-wide book here. Set by `MeshNode._new_peer`; a peer
        # nobody owns simply counts locally, which is the honest fallback.
        self.on_abuse = None
        self._task: asyncio.Task | None = None

    async def start(self, on_packet) -> None:
        self._task = asyncio.create_task(self._run(on_packet))

    async def _run(self, on_packet) -> None:
        try:
            await self._loop(on_packet)
        finally:
            cb = self.on_dead
            if cb is not None:
                self.on_dead = None
                try:
                    await cb(self)
                except Exception:
                    pass

    async def _loop(self, on_packet) -> None:
        while True:
            try:
                packet = await self.transport.receive()
            except asyncio.CancelledError:
                raise
            except (asyncio.IncompleteReadError, ConnectionError, OSError, EOFError):
                return  # link is dead — exit so the node reaps this peer
            except Exception:
                # Malformed frame on a still-live link (e.g. bad length prefix,
                # oversized payload). One bad packet must never kill the link:
                # drop it, count the abuse, and keep serving. Persistent garbage
                # is treated as hostile and the peer is cut.
                self._charge_identity()
                if self.note_abuse():
                    return
                continue
            # …and what came back has to *be* a packet. Everything below counts
            # its length, traces it and hands it to a handler, all three of
            # which assumed one — so a transport answering `None` raised
            # outside this guard, took the link down and left an unretrieved
            # task behind it. A medium that answers nonsense is charged for it
            # exactly like a frame that would not decode (`src/transports/medium.py`).
            packet = medium.received(packet)
            if packet is None:
                self._charge_identity()
                if self.note_abuse():
                    return
                continue
            nbytes = _HEADER_BYTES + len(packet.payload)
            self.counters.on_in(nbytes)
            if self.total is not None:
                self.total.on_in(nbytes)
            if self.trace is not None:
                self.trace.record("in", packet, nbytes, self.authenticated_id)
            try:
                await on_packet(self, packet)
            except asyncio.CancelledError:
                raise
            except Exception:
                pass  # malformed payload or handler bug — drop, loop continues

    def _charge_identity(self) -> None:
        """Tell the node a frame would not decode, so the *identity* is charged.

        Every other violation in this product goes through
        `MeshNode._charge_abuse`, which charges the link **and** the node's
        reputation book. Frames that fail to decode were the exception: they
        were counted here, on the link, and nowhere else — so an authenticated
        peer could send noise up to the cut, reconnect, and start again, for
        ever, without its standing ever moving. That is exactly the shape
        `CLAUDE.md` names when it says a count is kept per identity and not per
        link.

        Never raises: this is the receive loop, and a bookkeeping failure must
        not be a way to end one."""
        hook = self.on_abuse
        if hook is None or self.authenticated_id is None:
            return          # nothing better than the link counter to charge
        try:
            hook(self)
        except Exception:                       # noqa: BLE001 — never the reason
            pass

    def note_handshake_attempt(self) -> bool:
        """Claim one handshake attempt on this link. False once they run out."""
        self._handshake_attempts += 1
        return self._handshake_attempts <= _MAX_HANDSHAKE_ATTEMPTS

    def note_abuse(self) -> bool:
        """Count one thing this peer did that a correct node never does, and say
        whether it has now earned being cut.

        The receive loop counts frames it could not even decode; handlers count
        what decoded but was a lie — a claim signed by nobody, a name in a form
        the protocol forbids. Both are the same judgement ("this peer is not
        playing the protocol") so both feed the same counter, and the console
        shows it under one heading."""
        self._malformed += 1
        return self._malformed > _MAX_MALFORMED

    async def send(self, packet: Packet) -> None:
        await self.transport.send(packet)
        nbytes = _HEADER_BYTES + len(packet.payload)
        self.counters.on_out(nbytes)
        if self.total is not None:
            self.total.on_out(nbytes)
        if self.trace is not None:
            self.trace.record("out", packet, nbytes, self.authenticated_id)

    async def stop(self) -> None:
        self.on_dead = None  # intentional shutdown — do not trigger reaping
        if self._task:
            self._task.cancel()
            # Bounded. A cancelled receive task normally dies at once, but when
            # the cancellation lands on a read future that was already cancelled
            # the task is left flagged "cancelling", waiting for a wake-up that
            # never comes — and stop() waited with it, forever (seen roughly one
            # teardown in three with several peers). Closing the transport below
            # tears the link down regardless, so give up waiting and finish.
            try:
                async with asyncio.timeout(_PEER_STOP_TIMEOUT):
                    await self._task
            except (asyncio.CancelledError, TimeoutError, Exception):
                pass
        await self.transport.close()


# ---------------------------------------------------------------------------
# Relayed transport — a virtual link tunnelled through a relay
# ---------------------------------------------------------------------------

class RelayedTransport(BaseTransport):
    """A BaseTransport that carries mesh packets to a *remote* node through a
    *relay* link, by wrapping each outgoing packet in a RELAY_CARRY and letting
    the relay route it. Incoming packets are fed by the node when a RELAY_CARRY
    addressed to us and originating from ``remote`` is unwrapped.

    This lets the entire existing invite/handshake run, unchanged, between two
    nodes that share no direct link — the relay only sees signed ciphertext."""

    def __init__(self, node: 'MeshNode', remote: NodeID, via: '_Peer') -> None:
        super().__init__()
        self._node = node
        self._remote = remote
        self._via = via
        # Bounded: `feed` is reached from `_handle_relay_carry`, which runs
        # *before* the authentication gates, so an unauthenticated peer that
        # knows the seeker's id can push into this. A relayed handshake is a
        # handful of packets; anything past that is not a handshake.
        self._queue: asyncio.Queue = asyncio.Queue(_RELAY_QUEUE_MAX)
        self._closed = False

    async def connect(self, address: str) -> None:  # never dialled directly
        ...

    async def listen(self, address: str) -> None:
        ...

    async def send(self, packet: Packet) -> None:
        if self._closed:
            raise ConnectionError("relayed transport closed")
        carrier = Packet.create(RELAY_CARRY, self._node.id.raw,
                                self._remote.raw, packet.pack(), ttl=_SEEK_TTL)
        await self._via.send(carrier)

    def feed(self, inner: Packet) -> None:
        if self._closed:
            return
        try:
            self._queue.put_nowait(inner)
        except asyncio.QueueFull:
            pass       # the tunnel is not a buffer — drop, the join retries

    async def receive(self) -> Packet:
        while True:
            if self._closed:
                raise ConnectionError("relayed transport closed")
            # asyncio.timeout, not wait_for: on a path that must stay
            # cancellable, wait_for can swallow the outer cancellation when the
            # inner get completes in the same loop step, and the receive task
            # then never dies (gotchas.md §3b).
            try:
                async with asyncio.timeout(1.0):
                    return await self._queue.get()
            except asyncio.TimeoutError:
                continue

    def remote_ip(self) -> str | None:
        return None

    async def close(self) -> None:
        self._closed = True


# ---------------------------------------------------------------------------
# Hole-punching state
# ---------------------------------------------------------------------------

class _PunchState:
    """Tracks an in-progress NAT hole-punch attempt."""

    def __init__(self, target: NodeID, remote_udp_addr: str,
                 my_udp_addr: str) -> None:
        self.target = target
        self.remote_udp_addr = remote_udp_addr   # peer's public UDP addr (from relay)
        self.my_udp_addr = my_udp_addr           # our public UDP addr (observed by relay)
        self.probes_sent: int = 0
        self.probes_received: int = 0
        self.ack_received: bool = False
        self.deadline: float = 0.0
        self.completed: bool = False   # hole open, mesh handshake handed off
        self.nonce: bytes = os.urandom(16)
        self.peer_nonce: bytes | None = None


__all__ = [
    "RelayedTransport",
    "_Peer",
    "_PunchState",
]
