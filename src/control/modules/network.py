"""
The ``network`` module: how this node is reachable, and what it does about it.

Everything an operator changes about *addressing* rather than about the mesh:
whether a link may move to a better address of the same node, how priority and
latency share the choice, what a bundle of two links is judged on, whether the
LAN is listened to, which URIs are bound, and "look at the network again".

Two rules run through all of it.

**Applied first, remembered second.** Every setting is applied to the running
node and only then written to the configuration file, so a value the node
refuses never reaches the file — the next start would refuse it too, with
nobody at the keyboard to read why. The file is best effort by design: a node
started without one still applies the change and simply will not remember it,
and the answer says so.

**Partial, deliberately.** ``network.mlo`` takes seven numbers and applies the
ones it was given. One field typed wrong must not throw away the six typed with
it, which is the same rule the transports' own settings follow.

None of it decides who may talk to this node — that is the trust module and the
handshake. This is where it listens and how it chooses between the ways it is
already reachable.
"""
from __future__ import annotations

from ..context import on_loop
from ..errors import ControlError
from ..params import param
from ..plane import operation
from .settings import write_settings

_SET = 10.0
# A probe to every peer, or opening a listener: real work on the loop, still
# bounded by the node itself.
_PROBE = 12.0
# The four cadence bounds, in the order the node reports them back.
_KEEPALIVE = ("fast_min", "fast_max", "slow_min", "slow_max")


def _optional(name: str, kind: str, **extra):
    """A field that means "leave this alone" when it is absent.

    ``None`` rather than a default value: a partial update has to be able to
    tell "not given" from "given as what it already was", or every call would
    silently rewrite the six fields it did not mention."""
    return param(name, kind, required=False, default=None, **extra)


class NetworkModule:
    """Addressing, reachability and the shape of a bundle."""

    NAME = "network"

    OPERATIONS = (
        operation("probe", "Ask peers whether this node is reachable",
                  changes=True, remote=True, timeout=_PROBE),
        operation("recheck", "Look at the attached networks again",
                  changes=True, remote=True, timeout=_SET),
        operation("dynamic", "Move a link to a better address of the same node",
                  [param("enabled", "flag")],
                  changes=True, remote=True, timeout=_SET),
        operation("balance", "How priority and latency share the choice (0-100)",
                  [param("value", "count")],
                  changes=True, remote=True, timeout=_SET),
        operation("mlo", "Multi-link operation, and the cadence it may use",
                  [_optional("always", "flag"), _optional("skew_ms", "count"),
                   _optional("drop_percent", "count"),
                   _optional("keepalive_fast_min", "count"),
                   _optional("keepalive_fast_max", "count"),
                   _optional("keepalive_slow_min", "count"),
                   _optional("keepalive_slow_max", "count")],
                  changes=True, remote=True, timeout=_SET),
        operation("punch", "Try to open a path through a NAT",
                  [param("enabled", "flag")],
                  changes=True, remote=True, timeout=_SET),
        operation("punch_keepalive", "Keep an opened path from closing again",
                  [param("enabled", "flag")],
                  changes=True, remote=True, timeout=_SET),
        operation("punch_open", "Open one path to an address, by hand",
                  [param("host", "line"), param("port", "count")],
                  changes=True, remote=True, timeout=_PROBE),
        operation("discovery", "Listen for nodes on the local network",
                  [param("enabled", "flag")],
                  changes=True, remote=True, timeout=_SET),
        operation("udp", "Start or stop the UDP listener",
                  [param("action", "choice", choices=("start", "stop")),
                   _optional("port", "count")],
                  changes=True, remote=True, timeout=_SET),
        operation("listen", "Bind another URI",
                  [param("uri", "line")],
                  changes=True, remote=True, timeout=_SET),
        operation("unlisten", "Stop listening on a URI",
                  [param("uri", "line")],
                  changes=True, remote=True, timeout=_SET),
    )

    def __init__(self, context) -> None:
        self._context = context

    @property
    def _node(self):
        return self._context.node

    def _remember(self, name: str, value) -> None:
        """Best effort, and never the reason a change fails."""
        write_settings(self._context.config_path, {name: value})

    def _apply(self, call, *args, timeout: float = _SET):
        try:
            return self._context.ask(on_loop(call, *args), timeout)
        except ControlError:
            raise
        except (TypeError, ValueError) as exc:
            # The node's own sentence about the value it was given. It is the
            # caller's mistake, and it is the one thing they need to read.
            raise ControlError("bad_request", str(exc)[:200]) from None
        except Exception as exc:
            raise ControlError("failed", f"{type(exc).__name__}") from None

    # -- reachability ------------------------------------------------------

    def op_probe(self) -> dict:
        sent = self._context.ask(self._node.probe_reachability(), _PROBE)
        return {"ok": True, "sent": sent}

    def op_recheck(self) -> dict:
        return {"ok": bool(self._apply(self._node.console_recheck_net))}

    # -- how a link is chosen ---------------------------------------------

    def op_dynamic(self, enabled: bool) -> dict:
        self._apply(self._node.set_dynamic_address, enabled)
        self._remember("dynamic_address", enabled)
        return {"ok": True, "enabled": enabled}

    def op_balance(self, value: int) -> dict:
        applied = self._apply(self._node.set_transport_balance, value)
        self._remember("transport_balance", applied)
        # Read back on the loop like everything else: the order this produced
        # is the answer, and reading it from this thread would be reading a
        # list another coroutine may be halfway through rebuilding.
        return {"ok": True, "value": applied,
                "preference": self._apply(self._node.transport_preference)}

    def op_mlo(self, always, skew_ms, drop_percent, keepalive_fast_min,
               keepalive_fast_max, keepalive_slow_min, keepalive_slow_max) -> dict:
        if always is not None:
            self._apply(self._node.set_mlo_always, always)
            self._remember("mlo_always", always)
        judged = {name: value for name, value in
                  (("skew_ms", skew_ms), ("drop_percent", drop_percent))
                  if value is not None}
        if judged:
            applied = self._apply(
                lambda: self._node.set_mlo_settings(**judged))
            for name, value in applied.items():
                self._remember(f"mlo_{name}", value)
        cadence = {name: value for name, value in
                   zip(_KEEPALIVE, (keepalive_fast_min, keepalive_fast_max,
                                    keepalive_slow_min, keepalive_slow_max))
                   if value is not None}
        if cadence:
            bounds = self._apply(lambda: self._node.set_keepalive_bounds(
                **{f"{name}_ms": value for name, value in cadence.items()}))
            for name, value in zip(_KEEPALIVE, bounds.as_tuple()):
                self._remember(f"keepalive_{name}_ms", value)
        return {"ok": True, "mlo": self._apply(self._node.mlo_status)}

    # -- holes through a NAT ----------------------------------------------

    def op_punch(self, enabled: bool) -> dict:
        return {"ok": True, "enabled": self._apply(
            self._node.console_set_punch_enabled, enabled)}

    def op_punch_keepalive(self, enabled: bool) -> dict:
        return {"ok": True, "keepalive": self._apply(
            self._node.console_set_punch_keepalive, enabled)}

    def op_punch_open(self, host: str, port: int) -> dict:
        result = self._apply(self._node.console_open_hole, host, int(port),
                             timeout=_PROBE)
        return {"ok": True, **(result if isinstance(result, dict) else {})}

    # -- what is listened to ----------------------------------------------

    def op_discovery(self, enabled: bool) -> dict:
        started = (self._node.start_lan_discovery() if enabled
                   else self._node.stop_lan_discovery())
        try:
            self._context.ask(started, _SET)
        except ControlError:
            raise
        except Exception as exc:
            raise ControlError("failed", str(exc)[:200]) from None
        return {"ok": True, "enabled": enabled}

    def op_udp(self, action: str, port) -> dict:
        if action == "stop":
            self._run(self._node.console_stop_udp())
        else:
            # No port is not a default here: the node decides what "the UDP
            # port" is, and inventing one would bind something nobody asked for.
            if port is None:
                raise ControlError("bad_request", "a port is required to start")
            self._run(self._node.console_start_udp(int(port)))
        return {"ok": True}

    def op_listen(self, uri: str) -> dict:
        self._run(self._node.console_add_listen(uri))
        return {"ok": True}

    def op_unlisten(self, uri: str) -> dict:
        if not self._run(self._node.console_remove_listen(uri)):
            raise ControlError("not_found", "this node does not listen on that")
        return {"ok": True}

    def _run(self, coro):
        """A coroutine of the node's, with its refusals phrased for a caller."""
        try:
            return self._context.ask(coro, _SET)
        except ControlError:
            raise
        except (TypeError, ValueError) as exc:
            raise ControlError("bad_request", str(exc)[:200]) from None
        except Exception as exc:
            raise ControlError("failed", f"{type(exc).__name__}") from None
