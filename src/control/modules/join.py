"""
The ``join`` module: the ways in, and the ways this node offers one.

Four of them, and they differ in what has to travel and who carries it: a code
typed from one screen to another, a compact **ticket** that carries the address
with it, a **block** for a node that cannot reach this one directly, and the
manual exchange when neither end can dial the other. Only the first two and the
small block are here — the relay and connect blocks are 32 kB by their own
ceiling (`node._RELAY_BLOCK_MAX_LEN`), which is larger than a frame carries,
and they are pasted into the console of the machine you are sitting at anyway.

**Minting is local.** A code this node issues lets somebody into *its* network,
which is a credential rather than a setting — and the fleet already has a
capability for asking a node you manage to mint one (`invite`, and the node
that will honour the code is the node that makes it). Leaving `join.invite`
local means the `manage` right does not quietly include it.

**Joining travels**, because pointing a machine you manage at a network is what
provisioning one *is*, and because the node bounds the wait itself: it answers
when the session is up, not when the socket opens — reporting a socket as
success once told an operator "Joined" for a join that was about to be refused.
"""
from __future__ import annotations

from ... import join_ticket
from ... import qr
from ..context import on_loop
from ..errors import ControlError
from ..params import param
from ..plane import operation

_READ = 10.0
# Joining waits for the session rather than for the socket, and the node bounds
# that round itself. Sized to fit what the relay carries, so a node somebody
# manages can be pointed at a network from the console that manages it.
_JOIN = 15.0
# An invitation block is base64 JSON with a fresh code and the addresses this
# node advertises — small, unlike the relay block, which is why this one is
# here (`node._JOIN_BLOCK_MAX_LEN`).
_BLOCK = 8192


class JoinModule:
    """Codes, tickets and blocks — in, and out."""

    NAME = "join"

    OPERATIONS = (
        operation("network", "Join a network with an address and a code",
                  [param("uri", "line", required=False, default=""),
                   param("code", "text", required=False, default=""),
                   param("ticket", "text", required=False, default="")],
                  changes=True, remote=True, timeout=_JOIN),
        operation("invite", "Mint an invitation code to this node's network",
                  changes=True, timeout=_READ),
        operation("ticket", "Mint a compact join ticket, with its QR",
                  # The ticket's own ceiling, not a second opinion about it: a
                  # silly lifetime is clamped to the longest one a ticket may
                  # have, because the ticket format owns that number.
                  [param("ttl", "count", required=False, default=0,
                         limit=int(join_ticket.MAX_TTL))],
                  changes=True, timeout=_READ),
        operation("block", "A shareable invitation block for one node",
                  changes=True, timeout=_READ),
        operation("use_block", "Join from an invitation block",
                  [param("block", "text")],
                  changes=True, remote=True, timeout=_JOIN),
    )

    def __init__(self, context) -> None:
        self._context = context

    @property
    def _node(self):
        return self._context.node

    def _ask(self, coro, timeout: float):
        try:
            return self._context.ask(coro, timeout)
        except ControlError:
            raise
        except (TypeError, ValueError) as exc:
            raise ControlError("bad_request", str(exc)[:200]) from None
        except Exception as exc:
            raise ControlError("failed", f"{type(exc).__name__}") from None

    # -- getting in --------------------------------------------------------

    def op_network(self, uri: str, code: str, ticket: str) -> dict:
        """A ticket is the same join, with the address and the code travelling
        together instead of separately — so it is decoded here and the one
        implementation below does the joining."""
        if ticket:
            if uri or code:
                raise ControlError("bad_request",
                                   "a ticket carries both; do not send either")
            try:
                parsed = join_ticket.decode(ticket)
            except join_ticket.TicketError as exc:
                raise ControlError("bad_request", str(exc)[:200]) from None
            uri, code = parsed["uri"], parsed["code"]
        if not uri or not code:
            raise ControlError("bad_request", "an address and a code are required")
        result = self._ask(self._node.console_join(uri, code), _JOIN)
        if not result.get("ok"):
            # The node names which of the five ways it failed; the page shows
            # that rather than "join failed", because they are not the same
            # problem and not the same fix.
            raise ControlError("unavailable",
                               str(result.get("reason") or "the join failed")[:200],
                               {"detail": str(result.get("detail") or "")[:200]})
        return result

    def op_use_block(self, block: str) -> dict:
        if not block or len(block) > _BLOCK:
            raise ControlError("bad_request", "that is not an invitation block")
        return {"ok": True, **self._ask(
            on_loop(self._node.console_join_block, block), _JOIN)}

    # -- letting somebody in ----------------------------------------------

    def op_invite(self) -> dict:
        return {"code": self._ask(on_loop(self._node.generate_invite), _READ)}

    def op_block(self) -> dict:
        return {"block": self._ask(on_loop(self._node.console_invite_block),
                                   _READ)}

    def op_ticket(self, ttl: int) -> dict:
        """A ticket, and the QR beside it.

        The QR is rendered from the string just made — there is no operation
        that turns arbitrary text into a QR code, because nothing would need
        one."""
        try:
            ticket = self._ask(
                on_loop(self._node.issue_join_ticket,
                        join_ticket.clamp_ttl(ttl)), _READ)
        except ControlError as exc:
            # Not reachable from the open internet is a *state*, not a bad
            # argument: say why, rather than handing over a ticket that cannot
            # work.
            if exc.code == "bad_request":
                raise ControlError("conflict", exc.message) from None
            raise
        # The code travels inside the ticket; repeating it in the answer would
        # only put the same secret in one more place.
        ticket.pop("code", None)
        try:
            ticket["qr_svg"] = qr.svg_for(ticket["ticket"])
        except qr.QRError:
            ticket["qr_svg"] = ""
        return ticket
