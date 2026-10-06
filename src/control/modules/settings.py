"""
The ``config`` and ``transports`` modules: what this node is set to.

Both write the same file, and until now three different pieces of the console
each loaded it, merged it over the defaults and wrote it back — the settings
form, the pseudo, the transport fields, plus one live toggle at a time. Four
copies of "load, merge, save", which is four chances for one of them to write a
file the node would then refuse to start on. There is one here
(:func:`write_settings`), and the console's remaining routes use it too.

Nothing about the *meaning* of a value is decided in this module.
``config.apply_edits`` validates a setting and ``TransportManager.configure``
validates a transport field; they are the authority, and a plane that
second-guessed them would be a second, quieter set of rules.

**Applied first, stored second** for a transport: a value the transport refuses
must never reach the file, or the next start would refuse it too — with nobody
at the keyboard to read why. And the file is best effort by design: a node
started without one still applies the change to the running process, it simply
will not remember it, and the answer says so rather than letting the page imply
otherwise.
"""
from __future__ import annotations

import inspect

from ... import config as node_config
from ... import power
from ... import transport as transport_option
from ... import updater
from ..context import on_loop
from ..errors import ControlError
from ..params import param
from ..plane import operation

_FILE = 10.0            # reading or writing the configuration file
_CONFIGURE = 10.0       # applying one transport's settings on the loop
_LIVE = 15.0            # applying a whole form to the running node

# How the live settings reach the node, in groups. A group is applied in one
# call because its members only make sense together: the four keepalive bounds
# are sorted into shape by `mlo.clamp_bounds`, so moving them one at a time
# would clamp each against the old neighbours and land somewhere neither the
# old nor the new set describes. `tests/test_config_live.py` holds the union of
# these to `config.LIVE` exactly — a setting marked live with nothing applying
# it would be a console promising what the node never does.
_KEEPALIVE = ("keepalive_fast_min_ms", "keepalive_fast_max_ms",
              "keepalive_slow_min_ms", "keepalive_slow_max_ms")
_MLO = ("mlo_skew_ms", "mlo_drop_percent")
_UPDATES = {"update_check_minutes": "check_minutes",
            "update_when_active": "when_active",
            "release_quorum": "quorum",
            "release_auto_publish": "auto_publish",
            "recommend_version": "recommend"}
# Read from the file each time it is needed (`updater.update_branch`), so
# writing the file is the whole of applying it.
_FROM_FILE = ("update_branch",)
LIVE_GROUPS = (_KEEPALIVE, _MLO, tuple(_UPDATES), _FROM_FILE,
               ("punch_keepalive",), ("lan_discovery",),
               ("transport_balance",), ("dynamic_address",),
               ("mlo_always",), ("pseudo",), ("no_abuse_gossip",))


async def apply_live(node, values: dict, changed) -> tuple[dict, list]:
    """Put the ``changed`` live settings into force. ``(adjusted, problems)``.

    ``adjusted`` is what the node actually took where that differs from what
    was asked (keepalive bounds sorted into shape), so the file can record what
    is running rather than what was typed. A setting the node refuses is a
    problem named for the form, never an exception: one refusal must not leave
    the rest of a form half applied with nothing said."""
    changed = set(changed) & node_config.LIVE
    adjusted: dict = {}
    problems: list = []

    async def attempt(label, call):
        try:
            result = call()
            if inspect.isawaitable(result):
                result = await result
            return result
        except Exception as exc:                    # noqa: BLE001 — reported
            problems.append(f"{label}: {str(exc)[:120] or type(exc).__name__}")
            return None

    if changed & set(_KEEPALIVE):
        bounds = await attempt("keepalive", lambda: node.set_keepalive_bounds(
            **{name[len("keepalive_"):]: values[name] for name in _KEEPALIVE}))
        if bounds is not None:
            adjusted.update(zip(_KEEPALIVE, bounds.as_tuple()))
    if changed & set(_MLO):
        judged = await attempt("mlo", lambda: node.set_mlo_settings(
            skew_ms=values["mlo_skew_ms"],
            drop_percent=values["mlo_drop_percent"]))
        if judged:
            adjusted.update({"mlo_skew_ms": judged["skew_ms"],
                             "mlo_drop_percent": judged["drop_percent"]})
    if changed & set(_UPDATES):
        await attempt("updates", lambda: node.set_update_policy(
            **{_UPDATES[name]: values[name] for name in _UPDATES}))
    if "mlo_always" in changed:
        await attempt("mlo_always", lambda: node.set_mlo_always(values["mlo_always"]))
    if "dynamic_address" in changed:
        await attempt("dynamic_address",
                      lambda: node.set_dynamic_address(values["dynamic_address"]))
    if "transport_balance" in changed:
        await attempt("transport_balance",
                      lambda: node.set_transport_balance(values["transport_balance"]))
    if "punch_keepalive" in changed:
        await attempt("punch_keepalive",
                      lambda: node.console_set_punch_keepalive(values["punch_keepalive"]))
    if "lan_discovery" in changed:
        await attempt("lan_discovery", lambda: (
            node.start_lan_discovery() if values["lan_discovery"]
            else node.stop_lan_discovery()))
    if "no_abuse_gossip" in changed:
        await attempt("no_abuse_gossip",
                      lambda: node.set_abuse_gossip(not values["no_abuse_gossip"]))
    if "pseudo" in changed:
        adopted = await attempt("pseudo", lambda: node.set_pseudo(values["pseudo"]))
        if adopted is not None:
            adjusted["pseudo"] = adopted
    return adjusted, problems


def load_merged(path: str):
    """``(values over the defaults, problems)`` — read on every call.

    Never cached: the file can be edited by hand, and a page showing what the
    node was started with rather than what the file now says would be actively
    misleading."""
    values, problems = node_config.load(path)
    merged = node_config.defaults()
    merged.update(values)
    return merged, problems


def write_settings(path: str, updates: dict):
    """Merge ``updates`` into the file. ``(saved, problem)``, never raises.

    The single "remember this" for the whole product. Best effort: the change
    has already been applied to the running node by whoever called, and losing
    it on the next start is worth *saying*, never worth refusing the change
    over."""
    if not path:
        return False, "not stored — this node has no configuration file"
    try:
        merged, _problems = load_merged(path)
        merged.update(updates)
        node_config.save(path, merged)
    except OSError as exc:
        return False, f"could not write the configuration: {exc.strerror or 'error'}"
    except Exception as exc:
        return False, str(exc)[:200]
    return True, ""


class ConfigModule:
    """The node's configuration file, as the settings page edits it."""

    NAME = "config"

    OPERATIONS = (
        operation("get", "The configuration file, its values and its problems",
                  remote=True, timeout=_FILE),
        operation("save", "Apply what a running node can take, write the file",
                  [param("settings", "document")],
                  changes=True, remote=True, timeout=_LIVE),
        operation("profile", "Move to one of the ten consumption/performance steps",
                  [param("step", "count")],
                  changes=True, remote=True, timeout=_LIVE),
    )

    def __init__(self, context) -> None:
        self._context = context

    def op_get(self) -> dict:
        path = self._context.config_path
        if not path:
            return {"available": False,
                    "reason": "this node was not started from a configuration file",
                    "profiles": power.describe()}
        merged, problems = load_merged(path)
        return {"available": True,
                "path": path,
                "settings": node_config.public(merged),
                "problems": problems[:16],
                "profile": power.match(merged),
                "profiles": power.describe(),
                "restart_required": False,
                "can_restart": updater.restart_possible()[0]}

    def op_save(self, settings: dict) -> dict:
        """Every field validated before anything is applied or written.

        A rejected value leaves the stored one alone, so one bad entry in a
        form can never produce a file the node would refuse to start on. What
        a running node can take (`config.LIVE`) is applied to it first; the
        rest waits for a restart, and the answer names those so the page can
        say so beside each one rather than once for the whole form."""
        path = self._context.config_path
        if not path:
            raise ControlError(
                "conflict", "this node was not started from a configuration file")
        before, _problems = load_merged(path)
        merged, rejected = node_config.apply_edits(before, settings)
        if rejected:
            # The sentence *and* the list: a form has to mark the two fields
            # that were wrong and leave the rest of what was typed alone.
            raise ControlError("bad_request", "some settings were refused",
                               {"rejected": rejected[:16]})
        return self._commit(path, before, merged)

    def op_profile(self, step: int) -> dict:
        """One step of the consumption/performance bar: a set of live settings
        chosen together, applied and remembered like any other edit."""
        path = self._context.config_path
        try:
            values = power.values_for(step)
        except ValueError as exc:
            raise ControlError("bad_request", str(exc)) from None
        if not path:
            # Still applied: a node with no file can be told how to behave, it
            # simply will not remember it — and the answer says so.
            merged = node_config.defaults()
            merged.update(values)
            _adjusted, problems = self._apply(merged, values)
            return {"saved": False, "profile": int(step), "applied": sorted(values),
                    "problems": problems,
                    "note": "not stored — this node has no configuration file"}
        before, _problems = load_merged(path)
        merged = dict(before)
        merged.update(values)
        answer = self._commit(path, before, merged)
        answer["profile"] = power.match(merged)
        return answer

    def _apply(self, merged: dict, changed):
        return self._context.ask(
            apply_live(self._context.node, merged, changed), _LIVE)

    def _commit(self, path: str, before: dict, merged: dict) -> dict:
        """Applied first, stored second — the rule every other setting here
        follows — and the restart list is only what actually changed."""
        changed = {name for name in node_config.SETTINGS
                   if merged.get(name) != before.get(name)}
        live = sorted(changed & node_config.LIVE)
        waiting = sorted(changed - node_config.LIVE)
        problems: list = []
        if live:
            adjusted, problems = self._apply(merged, live)
            merged.update(adjusted)
        try:
            node_config.save(path, merged)
        except OSError as exc:
            raise ControlError(
                "failed",
                f"could not write the configuration: {exc.strerror or 'error'}") from None
        return {"saved": True, "path": path,
                "applied": live, "pending": waiting, "problems": problems[:16],
                "restart_required": bool(waiting),
                "can_restart": updater.restart_possible()[0]}


class TransportsModule:
    """What every registered transport takes, and what it is set to.

    The console renders this without knowing a single transport: a medium added
    tomorrow gets a form for free, and one that declares nothing simply does not
    appear. That is the flexibility principle showing up in the management
    plane — the plane knows about *schemes*, never about TCP."""

    NAME = "transports"

    OPERATIONS = (
        operation("options", "What each registered transport declares",
                  remote=True, timeout=_FILE),
        operation("save", "Apply one transport's settings, then store them",
                  [param("scheme", "text"), param("values", "document")],
                  changes=True, remote=True, timeout=_CONFIGURE),
    )

    def __init__(self, context) -> None:
        self._context = context

    @property
    def _manager(self):
        return self._context.node._transport_manager

    def _declaration(self, scheme: str, name: str) -> dict:
        """One field's declaration, for writing its value back as text."""
        for entry in self._manager.options().get(scheme, []):
            if entry["name"] == name:
                return entry
        return {"kind": "text"}

    def op_options(self) -> dict:
        try:
            declared = self._manager.options()
        except Exception:
            declared = {}
        return {"transports": [{"scheme": scheme, "options": fields}
                               for scheme, fields in declared.items()],
                "persisted": bool(self._context.config_path)}

    def op_save(self, scheme: str, values: dict) -> dict:
        try:
            result = self._context.ask(
                on_loop(self._manager.configure, scheme[:32], values), _CONFIGURE)
        except ControlError:
            raise
        except Exception as exc:
            raise ControlError("bad_request", str(exc)[:200]) from None
        saved, note = self._store()
        return {"ok": not result["rejected"],
                "applied": dict(result["applied"]),
                "rejected": result["rejected"],
                "persisted": saved, "note": note}

    def _store(self):
        """Write what is not at its default into the configuration file."""
        path = self._context.config_path
        if not path:
            return False, "not stored — this node has no configuration file"
        try:
            manager = self._manager
            rendered = {
                scheme: {name: transport_option.as_text(
                    self._declaration(scheme, name), value)
                    for name, value in fields.items()}
                for scheme, fields in manager.settings().items()}
        except Exception as exc:
            return False, f"could not read the settings back: {type(exc).__name__}"
        return write_settings(path, {"transports": rendered})
