"""
What an app may do on this node: asked for in a manifest, granted by a person.

The properties held here, each one a way the model could quietly stop being one:

* asking grants nothing above ``normal``, and a parent covers its children;
* a manifest is hostile input — bounded, typed, and refused by name when it asks
  for something that does not exist;
* nothing a broken or hostile state file says is ever a grant;
* a built-in's manifest is this build's, not whatever a client claims;
* every module of the control plane is mapped to a permission, and the ones that
  decide permissions are reachable by no app at all;
* the plane answers an app origin from its grants, and a mod is something the
  node survives: it falls back on failure, its arguments are checked again, and
  it never sees its own calls.
"""
import json
import time

import pytest

from src import app_perms, control
from src.app_perms import (ControlGate, ManifestError, PermissionBook,
                           parse_manifest)
from src.app_registry import BUILTIN_APPS, AppRegistry
from src.control import ControlError, Origin

APP = "a1b2c3d4e5f60718"
OTHER = "0011223344556677"


def _manifest(*perms, name="demo", **extra):
    document = {"name": name, "permissions": list(perms)}
    document.update(extra)
    return document


class TestTheTree:
    def test_every_name_is_unique_and_reachable_from_the_catalogue(self):
        seen = []

        def walk(rows):
            for row in rows:
                seen.append(row["name"])
                walk(row["children"])
        walk(app_perms.catalogue())
        assert len(seen) == len(set(seen)) == len(app_perms.NAMES)

    def test_a_child_is_named_under_its_parent(self):
        for name in app_perms.NAMES:
            parent = app_perms.parent(name)
            if parent:
                assert name.startswith(parent + ".")
                assert name in app_perms.children(parent)

    def test_what_every_app_always_had_is_normal_and_driving_is_dangerous(self):
        for name in ("network", "storage", "dht", "names", "identity", "log",
                     "notify", "report"):
            assert app_perms.level(name) == app_perms.NORMAL
        assert app_perms.level("readstate.logs") == app_perms.SENSITIVE
        assert app_perms.level("control") == app_perms.DANGEROUS
        assert app_perms.level("control.appweb") == app_perms.DANGEROUS
        assert app_perms.level("modding") == app_perms.DANGEROUS
        # Something that is not on the list is as dangerous as it gets.
        assert app_perms.level("root") == app_perms.DANGEROUS


class TestAManifestIsHostileInput:
    def test_a_well_formed_one(self):
        manifest = parse_manifest(json.dumps(_manifest(
            {"name": "readstate", "why": "to show the node"}, "network",
            title="Demo", version="1.2.0", description="A demo.")).encode())
        assert manifest["name"] == "demo" and manifest["version"] == "1.2.0"
        assert [row["name"] for row in manifest["permissions"]] == ["readstate", "network"]
        assert manifest["permissions"][0]["why"] == "to show the node"

    def test_an_unknown_permission_is_refused_by_name(self):
        """Dropping it silently would leave an app calling for something it
        was never going to get, with nothing saying which."""
        with pytest.raises(ManifestError, match="root"):
            parse_manifest(_manifest("network", "root"))

    @pytest.mark.parametrize("raw", [
        b"", b"not json", b"[]", b"3", b"null", b"\xff\xfe", "x" * 40000,
        b"{" * 5000, {"name": "Bad Name"}, {"name": 7}, {"name": "x" * 40},
        {"name": "demo", "permissions": "readstate"},
        {"name": "demo", "permissions": [7]},
        {"name": "demo", "permissions": [{"name": "../etc"}]},
        {"name": "demo", "permissions": ["network"] * 40},
        {"name": "demo", "api": "everything"},
        {"name": "demo", "api": [{}] * 40},
    ])
    def test_garbage_is_refused_never_a_crash(self, raw):
        with pytest.raises(ManifestError):
            parse_manifest(raw)

    def test_text_is_bounded_and_printable(self):
        manifest = parse_manifest(_manifest(
            {"name": "network", "why": "a\x00b‮" + "w" * 500},
            title="T\x07itle" * 30, description="d" * 2000))
        why = manifest["permissions"][0]["why"]
        assert "\x00" not in why and "‮" not in why
        assert len(why) <= app_perms.MAX_WHY
        assert len(manifest["title"]) <= app_perms.MAX_TITLE
        assert "\x07" not in manifest["title"]
        assert len(manifest["description"]) <= app_perms.MAX_DESCRIPTION

    def test_a_duplicate_request_is_kept_once(self):
        manifest = parse_manifest(_manifest("network", "network", "log"))
        assert [row["name"] for row in manifest["permissions"]] == ["network", "log"]


class TestTheBook:
    def test_asking_grants_nothing_above_normal(self):
        book = PermissionBook()
        book.declare(APP, _manifest("network", "readstate", "modding"))
        assert book.allows(APP, "network") is True
        assert book.allows(APP, "readstate") is False
        assert book.allows(APP, "readstate.logs") is False
        assert book.allows(APP, "modding") is False

    def test_a_normal_permission_not_asked_for_is_not_had(self):
        book = PermissionBook()
        book.declare(APP, _manifest("network"))
        assert book.allows(APP, "storage") is False

    def test_an_app_with_no_manifest_keeps_what_every_app_had(self):
        """Every app written before manifests existed: an upgrade must not take
        its section, its drawer or its names away."""
        book = PermissionBook()
        assert book.allows(APP, "network") is True
        assert book.allows(APP, "storage") is True
        assert book.allows(APP, "readstate") is False

    def test_a_parent_covers_its_children_and_taking_it_back_takes_them(self):
        book = PermissionBook()
        book.declare(APP, _manifest("readstate"))
        assert book.set_grant(APP, "readstate", True)
        assert book.allows(APP, "readstate.logs") is True
        assert book.set_grant(APP, "readstate.logs", True)
        assert book.set_grant(APP, "readstate", False)
        # The narrower answer is the one kept: no child survives its parent
        # being taken back.
        assert book.allows(APP, "readstate.logs") is False

    def test_only_what_was_asked_can_be_granted(self):
        book = PermissionBook()
        book.declare(APP, _manifest("readstate.links"))
        assert book.set_grant(APP, "readstate.logs", True) is False
        assert book.set_grant(APP, "control", True) is False
        assert book.set_grant(OTHER, "readstate.links", True) is False
        assert book.set_grant(APP, "readstate.links", True) is True

    def test_a_client_with_only_the_shared_token_gets_nothing_above_normal(self):
        book = PermissionBook()
        book.declare(APP, _manifest("network", "readstate"))
        book.set_grant(APP, "readstate", True)
        assert book.allows(APP, "readstate", identified=False) is False
        assert book.allows(APP, "network", identified=False) is True

    def test_a_new_manifest_drops_grants_it_no_longer_asks_for(self):
        book = PermissionBook()
        book.declare(APP, _manifest("readstate", "modding"))
        book.set_grant(APP, "modding", True)
        book.declare(APP, _manifest("readstate"))
        # Asking for it again does not bring the grant back with it.
        book.declare(APP, _manifest("readstate", "modding"))
        assert book.allows(APP, "modding") is False

    def test_an_operator_can_take_back_a_normal_permission(self):
        book = PermissionBook()
        book.declare(APP, _manifest("network"))
        book.set_grant(APP, "network", False)
        assert book.allows(APP, "network") is False

    def test_a_builtin_manifest_is_not_rewritten_by_a_client(self):
        book = PermissionBook()
        book.declare(APP, _manifest("network", name="chat"), source="builtin",
                     fixed=True)
        book.declare(APP, _manifest("network", "modding", name="chat"))
        assert "modding" not in book.requested(APP)
        assert book.forget(APP) is False

    def test_grants_survive_a_restart(self, tmp_path):
        book = PermissionBook(str(tmp_path))
        book.declare(APP, _manifest("readstate", title="Demo"))
        book.set_grant(APP, "readstate", True)
        again = PermissionBook(str(tmp_path))
        assert again.allows(APP, "readstate.node") is True
        assert again.view(APP)["title"] == "Demo"
        assert oct((tmp_path / "app_perms.json").stat().st_mode & 0o777) == "0o600"

    @pytest.mark.parametrize("content", [
        "not json", "[]", '{"apps": "all"}',
        '{"apps": {"a1b2c3d4e5f60718": {"grants": {"readstate": "yes"}}}}',
        '{"apps": {"a1b2c3d4e5f60718": {"grants": {"readstate": 1}}}}',
        '{"apps": {"A1B2C3D4E5F60718": {"grants": {"readstate": true}}}}',
        '{"apps": {"a1b2c3d4e5f60718": {"grants": {"root": true}}}}',
    ])
    def test_a_broken_file_can_never_grant(self, tmp_path, content):
        (tmp_path / "app_perms.json").write_text(content)
        book = PermissionBook(str(tmp_path))
        assert book.allows(APP, "readstate") is False
        assert book.allows(APP, "readstate.node") is False

    def test_the_book_is_bounded_and_keeps_what_matters(self):
        book = PermissionBook()
        book.declare(APP, _manifest("readstate", name="kept"))
        book.set_grant(APP, "readstate", True)
        book.declare(OTHER, _manifest("network", name="builtin"), source="builtin",
                     fixed=True)
        for index in range(app_perms.MAX_APPS + 10):
            book.declare(f"{index:016x}"[-16:].replace("0", "f", 1),
                         _manifest("network", name=f"app{index}"))
        assert len(book.known_apps()) <= app_perms.MAX_APPS
        assert APP in book.known_apps()      # holds a grant
        assert OTHER in book.known_apps()    # built in

    def test_a_view_lists_only_what_was_asked_with_the_reason(self):
        book = PermissionBook()
        book.declare(APP, _manifest({"name": "readstate.logs", "why": "to debug"}))
        rows = book.view(APP)["permissions"]
        assert [row["name"] for row in rows] == ["readstate.logs"]
        assert rows[0]["why"] == "to debug" and rows[0]["granted"] is False


class TestTheMap:
    def test_every_module_of_the_plane_is_mapped(self):
        """A module nobody mapped is reachable by no app — safe, and a hole in
        what the MCP app and the API page can offer. So it fails here."""
        plane = control.build(control.Context(node=None))
        for module in plane.catalogue(Origin.LOCAL):
            for entry in module["operations"]:
                op = module["module"] + "." + entry["name"]
                if op in app_perms.OPEN_TO_APPS or op in app_perms.OPERATOR_ONLY:
                    continue
                if op in ("jobs.start", "apps.call"):
                    continue
                assert module["module"] in app_perms.MODULE_SCOPE, op

    def test_reads_need_readstate_and_writes_need_control(self):
        assert app_perms.required("node.state", {"changes": False}) == "readstate.node"
        assert app_perms.required("node.restart", {"changes": True}) == "control.node"
        assert app_perms.required("logs.query", {"changes": False}) == "readstate.logs"
        assert app_perms.required("trace.set", {"changes": True}) == "control.diagnostics"
        assert app_perms.required("control.catalogue", {}) == ""
        assert app_perms.required("nonsense.op", {}) is None

    def test_what_decides_permissions_is_nobodys_but_a_person(self):
        for op in app_perms.OPERATOR_ONLY:
            assert app_perms.required(op, {"changes": True}) is None
            assert app_perms.moddable(op) is False

    def test_what_says_what_the_node_is_cannot_be_modded(self):
        assert app_perms.moddable("node.state") is True
        for op in ("apps.permissions", "control.catalogue", "jobs.poll",
                   "web.request", "apps.call", "nodot", "a.b.c"):
            assert app_perms.moddable(op) is False


def _plane_for(book, app_api=None):
    plane = control.build(control.Context(node=None))
    plane.set_app_gate(ControlGate(book, plane, app_api))
    return plane


class TestTheGate:
    def test_an_app_sees_only_what_it_may_call(self):
        book = PermissionBook()
        book.declare(APP, _manifest("readstate.node"))
        book.set_grant(APP, "readstate.node", True)
        plane = _plane_for(book)
        listed = {module["module"] + "." + entry["name"]
                  for module in plane.catalogue(Origin.app(APP))
                  for entry in module["operations"]}
        assert "node.state" in listed and "pseudo.get" in listed
        assert "node.restart" not in listed and "config.get" not in listed
        assert "apps.permit" not in listed and "apps.token" not in listed

    def test_a_refusal_names_the_permission_it_needs(self):
        book = PermissionBook()
        book.declare(APP, _manifest("readstate.node"))
        plane = _plane_for(book)
        with pytest.raises(ControlError) as raised:
            plane.check("node.restart", {}, origin=Origin.app(APP))
        assert raised.value.code == "refused"
        assert "control.node" in raised.value.message

    def test_an_app_holding_everything_still_cannot_grant(self):
        book = PermissionBook()
        book.declare(APP, _manifest("readstate", "control", "modding"))
        for name in ("readstate", "control", "modding"):
            book.set_grant(APP, name, True)
        plane = _plane_for(book)
        for op, params in (("apps.permit", {"app": APP, "permission": "modding",
                                            "granted": True}),
                           ("apps.token", {"app": APP}),
                           ("apps.forget", {"app": OTHER}),
                           ("apps.grant", {"app": "fleet", "capability": "logs",
                                           "granted": True})):
            with pytest.raises(ControlError) as raised:
                plane.check(op, params, origin=Origin.app(APP))
            assert raised.value.code == "refused"

    def test_a_job_is_answered_for_what_it_runs(self):
        book = PermissionBook()
        book.declare(APP, _manifest("readstate.node"))
        book.set_grant(APP, "readstate.node", True)
        plane = _plane_for(book)
        gate = ControlGate(book, plane)
        start = plane.find("jobs.start")[1]
        assert gate(APP, "jobs.start", start, {"op": "node.retry",
                                               "params": {}}) is not None
        assert gate(APP, "jobs.start", start, {"op": "pseudo.lookup",
                                               "params": {}}) is None
        # A job carrying a job, carrying anything, is not a way round.
        assert gate(APP, "jobs.start", start, {"op": "jobs.start",
                                               "params": {"op": "node.restart"}})

    def test_an_app_call_is_answered_for_the_operation_it_carries(self):
        book = PermissionBook()
        book.declare(APP, _manifest("readstate.apps"))
        book.set_grant(APP, "readstate.apps", True)
        declared = {("chat", "peer"): {"changes": False},
                    ("chat", "contact"): {"changes": True}}
        gate = ControlGate(book, None, lambda app, op: declared.get((app, op)))
        assert gate(APP, "apps.call", {}, {"app": "chat", "op": "peer"}) is None
        assert "control.apps" in gate(APP, "apps.call", {},
                                      {"app": "chat", "op": "contact"})

    def test_no_gate_means_no_app_reaches_anything(self):
        plane = control.build(control.Context(node=None))
        assert plane.catalogue(Origin.app(APP)) == []
        with pytest.raises(ControlError):
            plane.check("control.catalogue", {}, origin=Origin.app(APP))

    @pytest.mark.parametrize("origin", ["app:", "app:XYZ", "app:" + "0" * 15,
                                        "app:" + "0" * 17, "APP:" + APP, "apps"])
    def test_a_malformed_app_origin_is_not_one(self, origin):
        book = PermissionBook()
        plane = _plane_for(book)
        with pytest.raises(ControlError) as raised:
            plane.check("control.catalogue", {}, origin=origin)
        assert raised.value.code == "bad_request"


class TestAnAppMovesWhatItsPermissionsAllow:
    """The guide says `readstate.updates` and `control.updates` cover
    transfers, and every kind was closed to every app anyway: a kind's reach
    is a distance, and an app on this machine is at none. `transfer.kinds`
    over MCP was an empty list whatever the app had been granted."""

    @staticmethod
    def _kinds(*granted):
        book = PermissionBook()
        book.declare(APP, _manifest(*granted))
        for permission in granted:
            book.set_grant(APP, permission, True)
        plane = _plane_for(book)
        return plane, {entry["name"] for entry in plane.call(
            "transfer.kinds", origin=Origin.app(APP))["kinds"]}

    def test_reading_offers_what_comes_down(self):
        _plane, kinds = self._kinds("readstate.updates")
        assert kinds == {"package"}

    def test_control_offers_what_goes_up_as_well(self):
        _plane, kinds = self._kinds("readstate.updates", "control.updates")
        assert kinds == {"package", "app", "release"}

    def test_without_control_nothing_goes_up(self):
        plane, _kinds = self._kinds("readstate.updates")
        with pytest.raises(ControlError) as raised:
            plane.call("transfer.offer", {"kind": "app"}, origin=Origin.app(APP))
        assert raised.value.code == "refused"


class _Hook:
    def __init__(self, mode, answer=None, raises=None, app_hex=OTHER):
        self.mode, self._answer, self._raises = mode, answer, raises
        self.app_hex = app_hex
        self.asked = []

    def call(self, op, payload):
        self.asked.append((op, payload))
        if self._raises:
            raise self._raises
        return self._answer(payload) if callable(self._answer) else self._answer


class _Hooks:
    def __init__(self, table):
        self._table = table

    def lookup(self, op):
        return self._table.get(op)


class TestAModIsSurvived:
    def _plane(self, hook, op="control.catalogue"):
        plane = control.build(control.Context(node=None))
        plane.set_hooks(_Hooks({op: hook}))
        return plane

    def test_after_changes_the_answer(self):
        hook = _Hook("after", lambda payload: {"result": dict(payload["result"], tag="mod")})
        plane = self._plane(hook)
        assert plane.call("control.catalogue")["tag"] == "mod"

    def test_replace_answers_instead(self):
        plane = self._plane(_Hook("replace", {"result": {"modules": [], "by": "mod"}}))
        assert plane.call("control.catalogue") == {"modules": [], "by": "mod"}

    @pytest.mark.parametrize("hook", [
        _Hook("replace", raises=TimeoutError()),
        _Hook("replace", raises=RuntimeError("boom")),
        _Hook("replace", {"result": "not a mapping"}),
        _Hook("replace", None),
        _Hook("after", ["garbage"]),
        _Hook("before", {"params": {"undeclared": 1}}),
        _Hook("nonsense", {"result": {"x": 1}}),
    ])
    def test_a_mod_that_fails_is_the_native_answer(self, hook):
        plane = self._plane(hook)
        assert "modules" in plane.call("control.catalogue")

    def test_before_rewrites_arguments_that_are_checked_again(self):
        class Probe:
            NAME = "probe"
            OPERATIONS = (control.operation(
                "echo", "Say a number back",
                [control.param("value", "count", limit=100)], remote=True),)

            def op_echo(self, value):
                return {"value": value}

        def plane_with(answer):
            plane = control.ControlPlane()
            plane.register(Probe())
            plane.set_hooks(_Hooks({"probe.echo": _Hook("before", answer)}))
            return plane

        assert plane_with({"params": {"value": 7}}).call(
            "probe.echo", {"value": 3}) == {"value": 7}
        # Clamped to the declared limit like a caller's would be…
        assert plane_with({"params": {"value": 5000}}).call(
            "probe.echo", {"value": 3}) == {"value": 100}
        # …and refused like a caller's would be: the caller's own argument stands.
        assert plane_with({"params": {"value": "seven"}}).call(
            "probe.echo", {"value": 3}) == {"value": 3}
        assert plane_with({"params": {"value": 1, "extra": 2}}).call(
            "probe.echo", {"value": 3}) == {"value": 3}

    def test_a_mod_never_sees_its_own_calls(self):
        book = PermissionBook()
        book.declare(OTHER, _manifest("readstate"))
        book.set_grant(OTHER, "readstate", True)
        hook = _Hook("replace", {"result": {"modules": "replaced"}}, app_hex=OTHER)
        plane = self._plane(hook)
        plane.set_app_gate(ControlGate(book, plane))
        assert plane.call("control.catalogue", origin=Origin.app(OTHER))["modules"] != "replaced"
        assert plane.call("control.catalogue")["modules"] == "replaced"


class TestTheRegistryDeclaresItsOwn:
    def test_every_builtin_asks_for_what_it_says(self, tmp_path):
        registry = AppRegistry(str(tmp_path))
        for app in BUILTIN_APPS:
            asked = registry.perms.requested(app["app_id"].hex())
            for item in app.get("permissions", []):
                assert item["name"] in asked

    def test_an_old_grant_moves_over_once(self, tmp_path):
        (tmp_path / "apps.json").write_text(json.dumps(
            {"fleet": {"installed": True, "enabled": True,
                       "grants": {"logs": True, "links": False}}}))
        registry = AppRegistry(str(tmp_path))
        assert registry.granted("fleet", "logs") is True
        assert registry.granted("fleet", "links") is False
        # Taken back after the move, it stays taken back across a restart.
        registry.set_grant("fleet", "logs", False)
        assert AppRegistry(str(tmp_path)).granted("fleet", "logs") is False

    def test_uninstalling_takes_every_permission_above_normal(self, tmp_path):
        registry = AppRegistry(str(tmp_path))
        mcp = [app for app in BUILTIN_APPS if app["name"] == "mcp"][0]["app_id"].hex()
        registry.perms.set_grant(mcp, "control", True)
        registry.set_installed("mcp", False)
        assert registry.perms.allows(mcp, "control") is False
        assert registry.perms.allows(mcp, "log") is True

    def test_mcp_is_off_until_somebody_turns_it_on(self, tmp_path):
        registry = AppRegistry(str(tmp_path))
        assert registry.is_enabled("mcp") is False


class TestAnInstalledPackageSaysWhatItWillAsk:
    """A package's manifest is read off disk, so a person can grant before the
    app's first start rather than find it started and refused everything."""

    def test_its_manifest_appears_before_it_runs(self, tmp_path):
        from src.control.modules.apps import AppsModule

        app_dir = tmp_path / APP
        app_dir.mkdir()
        (app_dir / "nmesh.json").write_text(json.dumps(
            _manifest({"name": "readstate.node", "why": "a status widget"},
                      name="widget")))
        broken = tmp_path / OTHER
        broken.mkdir()
        (broken / "nmesh.json").write_text("{not json")

        class Node:
            def installed_list(self):
                return [{"app_id": APP}, {"app_id": OTHER}, {"app_id": "zz"}]

            def installed_app_dir(self, app_hex):
                return str(tmp_path / app_hex)

        book = PermissionBook()
        context = control.Context(node=Node())
        context.provide(perms=book)
        answer = AppsModule(context).op_permissions()
        widget = [app for app in answer["apps"] if app["app_id"] == APP][0]
        assert widget["source"] == "installed" and widget["name"] == "widget"
        assert widget["permissions"][0]["why"] == "a status widget"
        assert widget["permissions"][0]["granted"] is False
        assert OTHER not in book.known_apps()
