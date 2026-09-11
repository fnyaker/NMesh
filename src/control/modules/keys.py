"""
The ``keys`` module: the publisher keys this node can sign with.

A passphrase crosses this boundary — the sender's to unlock what it is
offering, the recipient's to keep what it accepts — and that is what decides
where these operations may be reached from. **Only the overview travels.** A
secret is typed at the machine that will hold it: an operator managing a node
can see which keys it has and which offers are in flight, and nothing else here.
That is not a guess about what is safe to relay, it is the same sentence
`Docs/AppAuth`-adjacent code has made all along — :mod:`src.key_share` exists
because there is no long-term encryption key to seal a secret to, so the
recipient produces one **when a human accepted**, and consent is structural
rather than checked.

Nothing here writes a passphrase down. The node holds the recipient's just long
enough for the grant to land, and drops it either way.
"""
from __future__ import annotations

from ...key_share import KeyShareError
from ...publisher_key import PublisherKeyError
from ..context import on_loop
from ..errors import ControlError
from ..params import MAX_ID_HEX, param
from ..plane import operation

_READ = 10.0
# Making a key is one scrypt and a write; offering or accepting one is a mesh
# round trip with a human at the other end of the decision, not of the call.
_WORK = 60.0


class KeysModule:
    """Make one, adopt one, hand one over — and see what is in flight."""

    NAME = "keys"

    OPERATIONS = (
        operation("overview", "Keys held here, and the offers either way",
                  remote=True, timeout=_READ),
        operation("create", "Make a signing key, kept under a passphrase",
                  [param("passphrase", "secret"),
                   param("label", "text", required=False, default="")],
                  changes=True, timeout=_WORK),
        operation("adopt", "Take an existing key file into this node's store",
                  [param("path", "line"), param("passphrase", "secret"),
                   param("label", "text", required=False, default="")],
                  changes=True, timeout=_WORK),
        operation("offer", "Offer a key held here to another node",
                  [param("node", "node"),
                   param("key", "hex", limit=MAX_ID_HEX),
                   param("passphrase", "secret"), param("confirm", "flag"),
                   param("label", "text", required=False, default="")],
                  changes=True, timeout=_WORK),
        operation("accept", "Accept an offered key under a passphrase of your own",
                  [param("offer", "hex", limit=MAX_ID_HEX),
                   param("passphrase", "secret"), param("confirm", "flag")],
                  changes=True, timeout=_WORK),
        operation("refuse", "Let an offer lapse",
                  [param("offer", "hex", limit=MAX_ID_HEX)],
                  changes=True, timeout=_READ),
        operation("forget", "Drop a key from this node",
                  [param("key", "hex", limit=MAX_ID_HEX),
                   param("confirm", "flag")],
                  changes=True, timeout=_READ),
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
        except (KeyShareError, PublisherKeyError, TypeError, ValueError) as exc:
            # The key layer's own sentence — "that is not a key file", "the
            # passphrase does not unlock it", "there is nowhere to keep it" —
            # which is exactly what whoever typed it needs to read, and always
            # about what they did rather than about this machine.
            raise ControlError("bad_request", str(exc)[:200]) from None
        except Exception as exc:
            raise ControlError("failed", f"{type(exc).__name__}") from None

    def _confirmed(self, confirm: bool) -> None:
        if confirm is not True:
            raise ControlError("bad_request", "confirmation required")

    # -- what is here ------------------------------------------------------

    def op_overview(self) -> dict:
        return self._ask(on_loop(self._node.key_share_overview), _READ)

    # -- making and adopting ----------------------------------------------

    def op_create(self, passphrase: str, label: str) -> dict:
        if not passphrase:
            raise ControlError("bad_request", "a passphrase is required")
        return {"ok": True, "key": self._ask(
            on_loop(self._node.create_publisher_key, passphrase, label), _WORK)}

    def op_adopt(self, path: str, passphrase: str, label: str) -> dict:
        if not path or not passphrase:
            raise ControlError("bad_request", "a path and a passphrase are required")
        return {"ok": True, "key": self._ask(
            on_loop(self._node.import_publisher_key, path, passphrase, label),
            _WORK)}

    # -- handing one over --------------------------------------------------

    def op_offer(self, node: str, key: str, passphrase: str, confirm: bool,
                 label: str) -> dict:
        self._confirmed(confirm)
        if not passphrase:
            raise ControlError("bad_request", "a passphrase is required")
        key_path = self._ask(on_loop(self._node.publisher_key_path, key), _READ)
        if key_path is None:
            raise ControlError("not_found", "no such publisher key")
        return {"ok": True, "offer": self._ask(
            self._node.offer_publisher_key(node, key_path, passphrase,
                                           label=label), _WORK)}

    def op_accept(self, offer: str, passphrase: str, confirm: bool) -> dict:
        self._confirmed(confirm)
        if not passphrase:
            raise ControlError("bad_request", "a passphrase is required")
        return {"ok": True, **self._ask(
            self._node.accept_publisher_key(offer, passphrase), _WORK)}

    def op_refuse(self, offer: str) -> dict:
        if not self._ask(on_loop(self._node.refuse_publisher_key, offer), _READ):
            raise ControlError("not_found", "no such offer")
        return {"ok": True}

    def op_forget(self, key: str, confirm: bool) -> dict:
        self._confirmed(confirm)
        if not self._ask(on_loop(self._node.forget_publisher_key, key), _READ):
            raise ControlError("not_found", "this node holds no such key")
        return {"ok": True}
