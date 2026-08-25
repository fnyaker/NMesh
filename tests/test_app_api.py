"""
The surface an app exposes to the rest of the product.

The whole point of this module is that it is *narrow*. A page in the browser can
ask chat what it knows about a node and ask fleet for rights on it, without the
console growing a route per action — and without any of that becoming a way to
reach something an app never offered. So the tests here are mostly about what is
refused: an undeclared operation, an undeclared argument, a value the wrong
shape, an app that is not running, a handler that throws.
"""
import pytest

from src import app_api
from src.app_api import AppAPI, AppAPIError, operation, param

NODE = "ab" * 20


class Bridge:
    """A bridge exactly as an app would write one."""

    API = (
        operation("look", "Read something", [param("node", "node")]),
        operation("touch", "Change something",
                  [param("node", "node"),
                   param("label", "text", required=False, default="none"),
                   param("caps", "tokens", required=False, default=None)],
                  changes=True),
        operation("boom", "Throw", []),
        operation("missing", "Declared but never written", []),
        operation("plain", "Return something that is not a mapping", []),
    )

    def __init__(self):
        self.seen = []

    def api_look(self, node):
        self.seen.append(("look", node))
        return {"node": node}

    def api_touch(self, node, label="none", caps=None):
        self.seen.append(("touch", node, label, caps))
        return {"label": label, "caps": caps}

    def api_boom(self):
        raise RuntimeError("a secret internal detail")

    def api_plain(self):
        return 42

    # Deliberately reachable as an attribute and *not* declared: the dispatcher
    # must not care that it exists.
    def api_secret(self):
        return {"leaked": True}

    def wipe_everything(self):
        raise AssertionError("never")


class Host:
    def __init__(self, bridges):
        self._bridges = bridges

    def running(self):
        return set(self._bridges)

    def bridge(self, name):
        return self._bridges.get(name)


@pytest.fixture
def api():
    return AppAPI(Host({"demo": Bridge()}))


# ── declaring ────────────────────────────────────────────────────────────────

class TestDeclaring:
    def test_a_bad_kind_is_refused_at_declaration(self):
        with pytest.raises(AppAPIError):
            param("node", "whatever")

    def test_a_name_that_is_not_a_name_is_refused(self):
        for bad in ("", "Node", "no-dash", "1st", "x" * 40, "../etc"):
            with pytest.raises(AppAPIError):
                operation(bad, "…")
            with pytest.raises(AppAPIError):
                param(bad, "text")

    def test_a_declaration_cannot_itself_be_a_payload(self):
        with pytest.raises(AppAPIError):
            operation("wide", "…", [param(f"p{i}", "text")
                                    for i in range(app_api.MAX_ARGS + 1)])

    def test_a_bridge_declaring_hundreds_is_truncated(self):
        class Greedy:
            API = tuple(operation(f"op{i}", "…") for i in range(200))
        assert len(app_api.declared(Greedy)) == app_api.MAX_OPERATIONS

    def test_rubbish_in_a_declaration_is_skipped_not_crashed(self):
        class Sloppy:
            API = (None, "nope", 7, operation("real", "…"),
                   operation("real", "duplicate"))
        assert [entry["name"] for entry in app_api.declared(Sloppy)] == ["real"]

    def test_a_bridge_with_no_api_declares_nothing(self):
        class Quiet:
            pass
        assert app_api.declared(Quiet) == []


# ── coercion ─────────────────────────────────────────────────────────────────

class TestValues:
    def test_a_node_must_be_a_node(self):
        field = param("node", "node")
        # Pasted identities arrive with the case and the whitespace of wherever
        # they were copied from; neither can hide anything, the pattern is
        # anchored.
        assert app_api.coerce(field, NODE.upper()) == NODE
        assert app_api.coerce(field, "  " + NODE + "\n") == NODE
        for bad in ("", None, "zz" * 20, "ab" * 19, "ab" * 21, "../" * 13,
                    NODE + " x", 12, [NODE]):
            with pytest.raises(AppAPIError):
                app_api.coerce(field, bad)

    def test_text_is_one_short_line(self):
        field = param("label", "text")
        assert app_api.coerce(field, "  hello  ") == "hello"
        for bad in ("x" * (app_api.MAX_TEXT + 1), "two\nlines", "a\rb"):
            with pytest.raises(AppAPIError):
                app_api.coerce(field, bad)

    def test_a_flag_takes_the_spellings_a_form_sends(self):
        field = param("on", "flag")
        for yes in (True, "true", "yes", "on", "1"):
            assert app_api.coerce(field, yes) is True
        for no in (False, "false", "no", "off", "0", ""):
            assert app_api.coerce(field, no) is False
        with pytest.raises(AppAPIError):
            app_api.coerce(field, "perhaps")

    def test_a_count_is_bounded_both_ways(self):
        field = param("n", "count")
        assert app_api.coerce(field, "12") == 12
        for bad in (-1, app_api.MAX_COUNT + 1, "lots", None):
            with pytest.raises(AppAPIError):
                app_api.coerce(field, bad)

    def test_tokens_are_bounded_deduplicated_and_shaped(self):
        field = param("caps", "tokens")
        assert app_api.coerce(field, "status, update ,status") == ["status", "update"]
        assert app_api.coerce(field, ["Shell", "shell"]) == ["shell"]
        for bad in (["x" * 40], ["with space"], ["semi;colon"], [""],
                    list(range(app_api.MAX_TOKENS + 1)), 7):
            with pytest.raises(AppAPIError):
                app_api.coerce(field, bad)


# ── dispatch ─────────────────────────────────────────────────────────────────

class TestDispatch:
    def test_a_declared_call_reaches_the_app(self, api):
        assert api.call("demo", "look", {"node": NODE}) == {"node": NODE}

    def test_an_undeclared_operation_does_not_exist(self, api):
        """`api_secret` is a real method on the bridge. It was never declared,
        so as far as anything outside the app is concerned it is not there."""
        with pytest.raises(AppAPIError):
            api.call("demo", "secret", {})

    def test_no_method_can_be_reached_by_guessing_its_name(self, api):
        for name in ("wipe_everything", "__init__", "api_look", "_bridges",
                     "../look", "look ", "LOOK"):
            with pytest.raises(AppAPIError):
                api.call("demo", name, {"node": NODE})

    def test_an_unknown_app_is_refused(self, api):
        for app in ("nope", "", "..", "demo/../demo", None, 7):
            with pytest.raises(AppAPIError):
                api.call(app, "look", {"node": NODE})

    def test_an_app_that_stopped_is_simply_not_there(self):
        host = Host({"demo": Bridge()})
        api = AppAPI(host)
        assert api.call("demo", "look", {"node": NODE})
        host._bridges.clear()
        with pytest.raises(AppAPIError):
            api.call("demo", "look", {"node": NODE})

    def test_an_undeclared_argument_is_refused_not_ignored(self, api):
        with pytest.raises(AppAPIError) as caught:
            api.call("demo", "look", {"node": NODE, "sudo": True})
        assert "sudo" in str(caught.value)

    def test_a_missing_required_argument_is_named(self, api):
        with pytest.raises(AppAPIError) as caught:
            api.call("demo", "look", {})
        assert "node" in str(caught.value)

    def test_an_optional_argument_falls_back_to_its_default(self, api):
        assert api.call("demo", "touch", {"node": NODE}) == {"label": "none",
                                                             "caps": None}

    def test_a_bad_value_says_which_argument(self, api):
        with pytest.raises(AppAPIError) as caught:
            api.call("demo", "touch", {"node": NODE, "label": "x" * 500})
        assert str(caught.value).startswith("label:")

    def test_too_many_arguments_is_refused_before_anything_is_read(self, api):
        args = {f"junk{i}": i for i in range(app_api.MAX_ARGS + 1)}
        with pytest.raises(AppAPIError):
            api.call("demo", "look", args)

    def test_args_that_are_not_a_mapping_are_treated_as_none(self, api):
        for rubbish in (None, [], "node=" + NODE, 7):
            with pytest.raises(AppAPIError):      # node is still required
                api.call("demo", "look", rubbish)

    def test_an_app_that_throws_does_not_hand_over_its_internals(self, api):
        with pytest.raises(AppAPIError) as caught:
            api.call("demo", "boom", {})
        message = str(caught.value)
        assert "secret internal detail" not in message
        assert "RuntimeError" in message

    def test_a_declared_operation_with_no_handler_says_so(self, api):
        with pytest.raises(AppAPIError):
            api.call("demo", "missing", {})

    def test_a_non_mapping_result_is_wrapped_rather_than_returned_raw(self, api):
        assert api.call("demo", "plain", {}) == {"result": 42}


# ── the catalogue ────────────────────────────────────────────────────────────

class TestCatalogue:
    def test_it_lists_what_is_running_and_only_that(self, api):
        entries = api.catalogue()
        assert [entry["app"] for entry in entries] == ["demo"]
        names = [op["name"] for op in entries[0]["operations"]]
        assert "look" in names and "secret" not in names

    def test_it_marks_what_changes_state(self, api):
        operations = {op["name"]: op for op in api.catalogue()[0]["operations"]}
        assert operations["look"]["changes"] is False
        assert operations["touch"]["changes"] is True

    def test_no_host_is_an_empty_catalogue_not_a_crash(self):
        assert AppAPI(None).catalogue() == []
        with pytest.raises(AppAPIError):
            AppAPI(None).call("demo", "look", {"node": NODE})

    def test_a_host_that_throws_is_an_empty_catalogue(self):
        class Broken:
            def running(self):
                raise RuntimeError("no")

            def bridge(self, name):
                raise RuntimeError("no")
        assert AppAPI(Broken()).catalogue() == []


# ── what the shipped apps declare ────────────────────────────────────────────

class TestTheShippedApps:
    """The declarations themselves are part of the product's surface: a rename
    here breaks a page, and a *widening* here is a security change."""

    def test_chat_offers_exactly_what_the_details_view_needs(self):
        from src.apps.chat_web import ChatBridge
        names = {op["name"] for op in app_api.declared(ChatBridge)}
        assert names == {"peer", "contact"}

    def test_fleet_offers_exactly_what_the_details_view_needs(self):
        from src.apps.fleet_web import FleetBridge
        operations = {op["name"]: op for op in app_api.declared(FleetBridge)}
        assert set(operations) == {"relation", "enrol", "request"}
        assert operations["relation"]["changes"] is False
        assert operations["enrol"]["changes"] is True
        assert operations["request"]["changes"] is True

    def test_no_shipped_operation_takes_a_free_form_blob(self):
        """Every argument that crosses this boundary has a shape. If one ever
        needs to carry arbitrary bytes, that is a decision to take on purpose."""
        from src.apps.chat_web import ChatBridge
        from src.apps.fleet_web import FleetBridge
        for bridge in (ChatBridge, FleetBridge):
            for op in app_api.declared(bridge):
                for field in op["params"]:
                    assert field["kind"] in app_api.KINDS

    def test_every_declared_operation_is_actually_implemented(self):
        from src.apps.chat_web import ChatBridge
        from src.apps.fleet_web import FleetBridge
        for bridge in (ChatBridge, FleetBridge):
            for op in app_api.declared(bridge):
                assert callable(getattr(bridge, "api_" + op["name"], None)), op
