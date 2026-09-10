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

from ... import config as node_config
from ... import transport as transport_option
from ... import updater
from ..context import on_loop
from ..errors import ControlError
from ..params import param
from ..plane import operation

_FILE = 10.0            # reading or writing the configuration file
_CONFIGURE = 10.0       # applying one transport's settings on the loop


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
        operation("save", "Write the configuration file",
                  [param("settings", "document")],
                  changes=True, remote=True, timeout=_FILE),
    )

    def __init__(self, context) -> None:
        self._context = context

    def op_get(self) -> dict:
        path = self._context.config_path
        if not path:
            return {"available": False,
                    "reason": "this node was not started from a configuration file"}
        merged, problems = load_merged(path)
        return {"available": True,
                "path": path,
                "settings": node_config.public(merged),
                "problems": problems[:16],
                "restart_required": False,
                "can_restart": updater.restart_possible()[0]}

    def op_save(self, settings: dict) -> dict:
        """Every field validated before anything is written.

        A rejected value leaves the stored one alone, so one bad entry in a
        form can never produce a file the node would refuse to start on.
        Nothing is applied live — the node reads this at startup, and the
        answer says so rather than letting the page imply otherwise."""
        path = self._context.config_path
        if not path:
            raise ControlError(
                "conflict", "this node was not started from a configuration file")
        merged, _problems = load_merged(path)
        merged, rejected = node_config.apply_edits(merged, settings)
        if rejected:
            # The sentence *and* the list: a form has to mark the two fields
            # that were wrong and leave the rest of what was typed alone.
            raise ControlError("bad_request", "some settings were refused",
                               {"rejected": rejected[:16]})
        try:
            node_config.save(path, merged)
        except OSError as exc:
            raise ControlError(
                "failed",
                f"could not write the configuration: {exc.strerror or 'error'}") from None
        return {"saved": True, "path": path, "restart_required": True,
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
