"""
The ``trust`` module: who this node vouches for, and what it holds against whom.

Six operations that were six routes, each with its own two lines of validation.
What they have in common is the reason they are here at all: **trust is local,
named and revocable**, so every one of them is an operator saying something
about *this* node's own opinion — never a fact arriving from the network.

They are reachable from a console managing this node, because that is what
managing a node means: the operator who provisioned a machine is the one who
decides which roots it accepts and whose reports it counts. What none of them
does is let the *network* decide any of it — a peer cannot ask for any of this;
only somebody holding the fleet's ``manage`` right, granted by a human here.

The certificate is the one long argument in the whole plane: 14 kB of hex,
declared as ``hex`` rather than as text so it is what it claims to be before the
node is asked to parse it.
"""
from __future__ import annotations

from ..context import on_loop
from ..errors import ControlError
from ..params import param
from ..plane import operation

_READ = 10.0
# A self-signed certificate as hex. The ceiling is generous against today's
# ML-DSA-65 (about 14 kB) without approaching what one frame carries.
_CERT_HEX = 20000


class TrustModule:
    """This node's anchors, memberships and grudges."""

    NAME = "trust"

    OPERATIONS = (
        operation("add", "Trust another node's self-signed root certificate",
                  [param("cert", "hex", limit=_CERT_HEX)],
                  changes=True, remote=True, timeout=_READ),
        operation("untrust", "Stop trusting an anchor",
                  [param("node", "node")],
                  changes=True, remote=True, timeout=_READ),
        operation("revoke", "Take back a membership this node issued",
                  [param("node", "node"),
                   param("reason", "count", required=False, default=0)],
                  changes=True, remote=True, timeout=_READ),
        operation("forgive", "Drop everything held against a node",
                  [param("node", "node")],
                  changes=True, remote=True, timeout=_READ),
        operation("accept_change", "That was me: clear one noticed change",
                  [param("node", "node")],
                  changes=True, remote=True, timeout=_READ),
        operation("witness", "Count a node's abuse reports as if we saw them",
                  [param("node", "node"),
                   param("remove", "flag", required=False, default=False)],
                  changes=True, remote=True, timeout=_READ),
    )

    def __init__(self, context) -> None:
        self._context = context

    def _did(self, refusal: str, call, *args) -> dict:
        """Run one of the node's console actions and phrase its "no".

        Every one of these answers with a bool, and a false is the caller's
        mistake in each case — but not the *same* mistake, which is why the
        sentence is the caller's to read and is written per operation. "This
        node would not accept that" sends an operator looking at the node; "it
        does not hold that anchor" tells them what happened."""
        if not self._context.ask(on_loop(call, *args), _READ):
            raise ControlError("bad_request", refusal)
        return {"ok": True}

    def op_add(self, cert: str) -> dict:
        return self._did("that is not a certificate this node will accept",
                         self._context.node.console_add_root, cert)

    def op_untrust(self, node: str) -> dict:
        return self._did("this node does not hold that anchor",
                         self._context.node.console_remove_root, node)

    def op_revoke(self, node: str, reason: int) -> dict:
        return self._did("this node did not issue that membership",
                         self._context.node.console_revoke_member, node,
                         int(reason))

    def op_forgive(self, node: str) -> dict:
        return self._did("nothing is held against that node",
                         self._context.node.console_forgive, node)

    def op_accept_change(self, node: str) -> dict:
        return self._did("nothing was noticed about that node",
                         self._context.node.console_accept_change, node)

    def op_witness(self, node: str, remove: bool) -> dict:
        call = (self._context.node.console_remove_witness if remove
                else self._context.node.console_add_witness)
        return self._did(
            "that node is not a witness here" if remove
            else "this node cannot take that node as a witness", call, node)
