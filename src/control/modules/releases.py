"""
The ``releases`` module: the node's own code, and whose signature it accepts.

The most sensitive surface in the project after the identity itself, and the
one place where the plane's answer to "may a remote console do this?" is a firm
no for almost everything. Two separate reasons, and both are worth writing
down because they look like the same reason and are not.

**What a node accepts is pinned by a human at that node.** ``MeshNode.trust_publisher``
says it in its own docstring: *the only way a key enters this list is here — an
operator acting locally, never a packet*. A console reached over the mesh is not
a packet, but it is not somebody at that machine either, and the fleet's
``manage`` right is "drive that node's console" — not "decide what may replace
its program". Updating a node somebody manages has its own capability and its
own path (``update``, see `Docs/Apps/fleet`), which reports progress instead of
holding a call open. So pinning, unpinning, endorsing and arming automatic
installs stay local.

**And the rest would not fit anyway.** Publishing signs a whole tree (five
minutes), installing fetches and replaces it (seven), and checking GitHub is
forty seconds. The relay carries fifteen. An operation declaring more than
``REMOTE_BUDGET`` *and* ``remote`` is refused at declaration, so this is not a
rule anybody has to remember.

What does travel is the one read: **what this node holds, what it has pinned,
and what it is watching**. An operator managing a machine needs to see that
without being able to change it.
"""
from __future__ import annotations

from ... import updater
from ...core_release import ReleaseError
from ..context import on_loop
from ..errors import ControlError
from ..params import MAX_ID_HEX, param
from ..plane import operation

_READ = 10.0
_CHECK = 40.0            # asking GitHub: a network round trip we do not bound
_PUBLISH = 300.0         # packing and signing the installed tree
_INSTALL = 400.0         # fetching a release, verifying it, replacing the tree
# A publisher's signing key as hex (ML-DSA-65: 1952 bytes). Bounded well above
# that rather than exactly at it: a key size is the crypto's business, and this
# only has to refuse a payload. The id derived from it uses the shared bound.
_KEY_HEX = 8192


class ReleasesModule:
    """Mesh-native releases: publish, pin, install — and what GitHub offers."""

    NAME = "releases"

    OPERATIONS = (
        operation("overview", "What this node holds, pins and watches",
                  remote=True, timeout=_READ),
        operation("check", "Ask GitHub what the latest version is",
                  timeout=_CHECK),
        operation("apply", "Install a version from GitHub, then restart",
                  [param("version", "text"), param("confirm", "flag")],
                  changes=True, timeout=_INSTALL),
        operation("publish", "Sign the installed tree and announce it",
                  [param("notes", "text", required=False, default=""),
                   param("key_id", "text", required=False, default=""),
                   param("passphrase", "secret", required=False, default=None)],
                  changes=True, timeout=_PUBLISH),
        operation("install", "Fetch, verify and install one release",
                  [param("release", "text"), param("confirm", "flag")],
                  changes=True, timeout=_INSTALL),
        operation("trust", "Pin a signing key, and say what it is accepted for",
                  [param("key", "hex", limit=_KEY_HEX),
                   param("name", "text", required=False, default=""),
                   param("auto", "flag", required=False, default=False),
                   param("endorsed", "flag", required=False, default=False)],
                  changes=True, timeout=_READ),
        operation("untrust", "Take a pinned key back",
                  [param("publisher", "hex", limit=MAX_ID_HEX)],
                  changes=True, timeout=_READ),
        operation("auto", "Let one publisher's releases install themselves",
                  [param("publisher", "hex", limit=MAX_ID_HEX),
                   param("auto", "flag")],
                  changes=True, timeout=_READ),
        operation("endorse", "Let one publisher's signature count in a quorum",
                  [param("publisher", "hex", limit=MAX_ID_HEX),
                   param("endorsed", "flag")],
                  changes=True, timeout=_READ),
    )

    def __init__(self, context) -> None:
        self._context = context

    @property
    def _node(self):
        return self._context.node

    def _ask(self, coro, timeout: float):
        """Run it on the node's loop, and phrase what the release layer says.

        A `ReleaseError` is the caller's: a release that does not verify, a key
        that is not one, a version nobody offers. An `UpdateError` is the far
        side's — GitHub, or a tree that would not come down — which is
        `unavailable` rather than a mistake anybody here made."""
        try:
            return self._context.ask(coro, timeout)
        except ControlError:
            raise
        except ReleaseError as exc:
            raise ControlError("bad_request", str(exc)[:200]) from None
        except updater.UpdateError as exc:
            raise ControlError("unavailable", str(exc)[:200]) from None
        except (TypeError, ValueError) as exc:
            raise ControlError("bad_request", str(exc)[:200]) from None
        except Exception as exc:
            raise ControlError("failed", f"{type(exc).__name__}") from None

    def _on_loop(self, call, *args):
        """A plain node method, run where node state may be touched."""
        return self._ask(on_loop(call, *args), _READ)

    # -- reading -----------------------------------------------------------

    def op_overview(self) -> dict:
        return self._on_loop(self._node.release_overview)

    def op_check(self) -> dict:
        """What GitHub offers, and whether this install may take it.

        An `UpdateError` here is an answer rather than a failure: "GitHub could
        not be reached" is what the page has to show, next to the version that
        is running — so it comes back as a result, not as a refusal."""
        branch = updater.update_branch(self._context.config_path)
        try:
            result = self._context.ask(updater.check(branch=branch), _CHECK)
        except updater.UpdateError as exc:
            return {"error": str(exc)[:256], "current": updater.__version__}
        except ControlError:
            raise
        except Exception:
            raise ControlError("unavailable", "the update check failed") from None
        can, reason = updater.updatable()
        result["can_apply"] = can
        result["blocked"] = reason
        return result

    # -- acting ------------------------------------------------------------

    def op_apply(self, version: str, confirm: bool) -> dict:
        """Install **the version the operator confirmed**, and nothing else.

        If GitHub has moved on since the page was drawn, the mismatch is
        refused: a tab left open for an hour must not install something nobody
        looked at. That holds for a branch too — it is checked again here, and
        once more against the tree that comes down, because a branch moves
        under its own name."""
        if not version:
            raise ControlError("bad_request", "a version is required")
        if confirm is not True:
            raise ControlError("bad_request", "confirmation required")
        can, reason = updater.updatable()
        if not can:
            raise ControlError("conflict", reason)
        branch = updater.update_branch(self._context.config_path)
        latest = self._ask(updater.check(branch=branch), _CHECK)
        if latest.get("latest") != version:
            raise ControlError(
                "conflict",
                f"the latest version is now {latest.get('latest')}, not "
                f"{version} — check again and re-confirm")
        if not latest.get("available"):
            raise ControlError("conflict", "already up to date")
        result = self._ask(updater.apply(version, branch=branch), _INSTALL)
        # The files are in place; this process is still running the old ones.
        # Answer first, then leave, so the page's "restarting" is not a lie.
        return {"ok": True, **result, "restarting": self._context.restart()}

    def op_publish(self, notes: str, key_id: str, passphrase) -> dict:
        key_path = None
        if key_id:
            # A key this node was handed has no path its operator ever chose,
            # so it is named by id and the node resolves it.
            key_path = self._on_loop(self._node.publisher_key_path, key_id)
            if key_path is None:
                raise ControlError("not_found", "no such publisher key")
        return {"ok": True, **self._ask(
            self._node.publish_release(notes=notes, key_path=key_path,
                                       passphrase=passphrase), _PUBLISH)}

    def op_install(self, release: str, confirm: bool) -> dict:
        if not release:
            raise ControlError("bad_request", "a release is required")
        if confirm is not True:
            raise ControlError("bad_request", "confirmation required")
        result = self._ask(self._node.install_release(release), _INSTALL)
        # An operator pressed Install and is watching, so the restart is
        # immediate. The unattended path restarts too, but only after writing
        # the attempt down — a release that installs and never becomes the
        # running version is given up on rather than restarted into for ever.
        return {"ok": True, **result, "restarting": self._context.restart()}

    # -- what this node accepts -------------------------------------------

    def op_trust(self, key: str, name: str, auto: bool, endorsed: bool) -> dict:
        return {"ok": True, "publisher": self._on_loop(
            self._node.trust_publisher, key, name, auto, endorsed)}

    def op_untrust(self, publisher: str) -> dict:
        if not self._on_loop(self._node.untrust_publisher, publisher):
            raise ControlError("not_found", "this node has not pinned that key")
        return {"ok": True}

    def op_auto(self, publisher: str, auto: bool) -> dict:
        if not self._on_loop(self._node.set_publisher_auto, publisher, auto):
            # Not a key accepted for this node's *code*: there is no such
            # install to allow, which is a different answer from "refused".
            raise ControlError("not_found",
                               "no key pinned for this node's own program")
        return {"ok": True}

    def op_endorse(self, publisher: str, endorsed: bool) -> dict:
        if not self._on_loop(self._node.set_publisher_endorsed, publisher,
                             endorsed):
            raise ControlError("not_found", "this node has not pinned that key")
        return {"ok": True}
