"""
The control plane: what it refuses, and what it holds together.

The plane is the management surface of a node, reached from a page on this
machine *and* from a peer driving us through the fleet relay — which the threat
model says is an adversary. So these tests are mostly about refusals: an
operation nobody declared, an argument nobody declared, a frame that is not one,
a local-only operation asked for from a remote console, a ceiling that does not
fit the pipe it would have to cross.

The rest hold two files together — the frame's bounds against the relay's, every
remotely-reachable operation's ceiling against the budget — because a bound at
one layer is not a bound (`Docs/Architecture/gotchas.md`).
"""
import asyncio
import json
import os
import tempfile
from pathlib import Path

import pytest

from src import app_api
from src import control
from src.apps import fleet as fleet_app
from src.apps import fleet_console
from src.control import frame as frame_mod
from src.control import params as params_mod
from src.control.errors import ControlError
from src.control.plane import ControlPlane, Origin, REMOTE_BUDGET, operation
from src.node import MeshNode
from src.webconsole import CONTROL_PATH, WebConsole, _STATUS_BY_CODE
from tests.conftest import make_manager

PW = "correct-horse-battery-staple"


# --------------------------------------------------------------------------
# A module small enough to reason about, used by the dispatch tests.
# --------------------------------------------------------------------------

class _Sample:
    NAME = "sample"
    OPERATIONS = (
        operation("read", "Give something back", remote=True),
        operation("here", "Local only, deliberately"),
        operation("named", "Takes arguments",
                  [control.param("node", "node"),
                   control.param("label", "text", required=False, default="")],
                  remote=True),
        operation("boom", "Throws", remote=True),
        operation("plain", "Answers with something that is not a mapping",
                  remote=True),
        operation("mine", "Depends on who is asking", remote=True,
                  wants_origin=True),
    )

    def op_read(self):
        return {"value": 7}

    def op_here(self):
        return {"value": "local"}

    def op_named(self, node, label):
        return {"node": node, "label": label}

    def op_boom(self):
        raise RuntimeError("a secret about this machine")

    def op_plain(self):
        return 42

    def op_mine(self, origin):
        return {"origin": origin}


def _plane():
    plane = ControlPlane()
    plane.register(_Sample())
    return plane


class TestDeclaration:
    """A declaration that does not make sense fails at import, not on a press."""

    def test_a_bad_operation_name_is_refused(self):
        for name in ("", "Read", "read-it", "_read", "x" * 40):
            with pytest.raises(ControlError):
                operation(name, "no")

    def test_one_parameter_cannot_be_declared_twice(self):
        with pytest.raises(ControlError):
            operation("read", "no", [control.param("node", "node"),
                                     control.param("node", "text")])

    def test_a_remote_operation_must_fit_the_relay(self):
        # The whole point of the budget: an operator asking a distant machine
        # for something that takes longer than the pipe carries would wait for
        # the pipe to give up and be told nothing about why.
        with pytest.raises(ControlError):
            operation("slow", "no", remote=True, timeout=REMOTE_BUDGET + 1)
        # The same ceiling is fine when the operation stays local.
        assert operation("slow", "ok", timeout=REMOTE_BUDGET + 1)["timeout"]

    def test_the_injected_origin_cannot_also_be_declared(self):
        with pytest.raises(ControlError):
            operation("mine", "no", [control.param("origin", "text")],
                      wants_origin=True)

    def test_a_module_must_implement_what_it_declares(self):
        class Missing:
            NAME = "missing"
            OPERATIONS = (operation("gone", "declared and not written"),)

        with pytest.raises(ControlError):
            ControlPlane().register(Missing())

    def test_a_module_is_registered_once(self):
        plane = _plane()
        with pytest.raises(ControlError):
            plane.register(_Sample())

    def test_a_module_with_nothing_to_offer_is_not_a_module(self):
        class Empty:
            NAME = "empty"
            OPERATIONS = ()

        with pytest.raises(ControlError):
            ControlPlane().register(Empty())


class TestDispatch:
    def test_an_operation_nobody_declared_does_not_exist(self):
        plane = _plane()
        for op in ("sample.nope", "nope.read", "read", "sample.read.more",
                   "", None, 7, "op_read", "sample.op_read"):
            reply = plane.dispatch(control.Request(op))
            assert reply.ok is False
            assert reply.code == "not_found"

    def test_an_argument_nobody_declared_is_refused(self):
        reply = _plane().dispatch(control.Request("sample.read", {"extra": 1}))
        assert reply.ok is False and reply.code == "bad_request"

    def test_a_required_argument_missing_is_refused(self):
        reply = _plane().dispatch(control.Request("sample.named", {}))
        assert reply.ok is False and "node is required" in reply.error

    def test_arguments_are_coerced_before_the_module_sees_them(self):
        plane = _plane()
        good = plane.dispatch(control.Request(
            "sample.named", {"node": "AB" * 20, "label": " hi "}))
        assert good.result == {"node": "ab" * 20, "label": "hi"}
        bad = plane.dispatch(control.Request("sample.named", {"node": "nope"}))
        assert bad.ok is False and bad.code == "bad_request"

    def test_a_module_that_throws_says_nothing_about_this_machine(self):
        reply = _plane().dispatch(control.Request("sample.boom"))
        assert reply.ok is False and reply.code == "failed"
        assert "secret" not in reply.error
        assert "RuntimeError" in reply.error

    def test_an_answer_that_is_not_a_mapping_still_is_one(self):
        assert _plane().dispatch(control.Request("sample.plain")).result == {"result": 42}

    def test_the_request_id_comes_back_untouched(self):
        reply = _plane().dispatch(control.Request("sample.read", {}, "abc"))
        assert reply.document()["id"] == "abc"


class TestRemoteIsRefusedByDefault:
    def test_a_local_only_operation_is_refused_from_a_remote_console(self):
        plane = _plane()
        assert plane.dispatch(control.Request("sample.here"), Origin.LOCAL).ok
        refused = plane.dispatch(control.Request("sample.here"), Origin.REMOTE)
        assert refused.ok is False and refused.code == "refused"

    def test_an_unknown_origin_is_refused(self):
        assert _plane().dispatch(control.Request("sample.read"), "whoever").ok is False

    def test_the_catalogue_says_what_this_origin_can_reach(self):
        plane = _plane()
        local = plane.catalogue(Origin.LOCAL)[0]["operations"]
        remote = plane.catalogue(Origin.REMOTE)[0]["operations"]
        assert {entry["name"] for entry in local} > {entry["name"] for entry in remote}
        assert "here" not in {entry["name"] for entry in remote}
        # Machinery does not travel: a page reads this to draw buttons.
        assert all("wants_origin" not in entry for entry in local)

    def test_who_is_asking_is_injected_not_accepted(self):
        plane = _plane()
        assert plane.dispatch(control.Request("sample.mine"),
                              Origin.REMOTE).result == {"origin": "remote"}
        # A caller cannot claim to be somebody else: the name is not declared,
        # so supplying it is an unknown argument.
        assert plane.dispatch(control.Request("sample.mine", {"origin": "local"}),
                              Origin.REMOTE).ok is False


class TestFrames:
    def test_a_frame_is_answered_however_hostile_and_says_nothing_extra(self):
        """A sweep with the shapes an attacker actually sends.

        The generated half is the point: a frame this suite never thought of
        must still come back as a frame, with a code from the closed set and
        nothing of this machine in it."""
        import random
        import string

        chan = control.LocalChannel(_plane())
        random.seed(11)
        shapes = [
            json.dumps({"v": 1, "op": "sample.named",
                        "params": {"node": "../../etc/passwd"}}).encode(),
            json.dumps({"v": 1, "op": "sample.named",
                        "params": {"node": "ab" * 20, "label": "\x00"}}).encode(),
            json.dumps({"v": 1, "op": "sample.read", "id": "i" * 200}).encode(),
            json.dumps({"v": 1, "op": "sample.boom"}).encode(),
        ]
        for _ in range(60):
            shapes.append(json.dumps({
                "v": random.choice([1, 1, 1, 2, "1", None, []]),
                "op": random.choice([
                    "".join(random.choice(string.printable) for _ in range(10)),
                    "sample.read", "sample." * 3, None, 7, ["sample.read"]]),
                "params": random.choice([
                    {}, {"node": "z" * 60}, {"extra": 1}, [], "s", None,
                    {"node": {"deep": {"deeper": 1}}}]),
            }).encode())

        for raw in shapes:
            answer = json.loads(chan.send(raw))
            assert isinstance(answer, dict) and "ok" in answer, raw[:60]
            if not answer["ok"]:
                assert answer["code"] in control.CODES, raw[:60]
            text = json.dumps(answer)
            for internal in ("Traceback", "/home/", "site-packages",
                             "a secret about this machine"):
                assert internal not in text, (internal, raw[:60])

    def test_hostile_bytes_never_raise_and_never_pass(self):
        chan = control.LocalChannel(_plane())
        hostile = [
            b"", b" ", b"{", b"}", b"[]", b"null", b"3", b'"op"',
            b'{"op": null}', b'{"op": 3}', b'{"op": ["sample.read"]}',
            b'{"v": 2, "op": "sample.read"}', b'{"v": "1", "op": "sample.read"}',
            b'{"op": "sample.read", "params": []}',
            b'{"op": "sample.read", "params": "x"}',
            b'{"op": "sample.read", "id": 4}',
            b'{"op": "sample.read", "id": "' + b"i" * 200 + b'"}',
            b'{"op": "' + b"o" * 200 + b'"}',
            b"\x00\x01\x02", b"\xff\xfe", "é".encode("latin-1"),
            b'{"op": "sample.read", "params": {"' + b"k" * 200 + b'": 1}}',
            b'{"op": "sample.read", "params": {' + b",".join(
                b'"k%d": 1' % i for i in range(frame_mod.MAX_PARAMS + 5)) + b"}}",
            b"x" * (frame_mod.MAX_FRAME + 1),
            json.dumps({"op": "sample.read", "params": {"a": [[[[1]]]]}}).encode(),
        ]
        for raw in hostile:
            answer = json.loads(chan.send(raw))
            assert answer["ok"] is False, raw[:40]
            assert answer["code"] in control.CODES

    def test_a_frame_that_is_too_large_is_refused_on_its_bytes(self):
        # Refused before parsing: parsing a huge document to then decide it was
        # too big is the work an attacker was hoping for.
        with pytest.raises(control.FrameError):
            frame_mod.decode_request(b'{"op":"a.b","params":{"x":"' +
                                     b"y" * frame_mod.MAX_FRAME + b'"}}')

    def test_an_answer_that_cannot_be_encoded_is_still_an_answer(self):
        raw = frame_mod.encode({"v": 1, "result": {"socket": object()}})
        assert json.loads(raw)["ok"] is False

    def test_a_reply_from_somewhere_else_is_read_with_suspicion(self):
        for raw in [b"", b"{", b"[]", b'{"ok": "yes"}', b'{"ok": true, "result": 3}',
                    b'{"ok": false, "code": 7, "error": 9}']:
            try:
                reply = frame_mod.decode_reply(raw)
            except control.FrameError:
                continue
            assert isinstance(reply.result, dict)
            assert isinstance(reply.code, str) and isinstance(reply.error, str)

    def test_a_refusals_detail_is_bounded_on_the_way_in(self):
        crowded = {"code": "bad_request", "ok": False,
                   "detail": {str(i): i for i in range(50)}}
        assert frame_mod.decode_reply(json.dumps(crowded).encode()).detail == {}


class TestAValueCannotSmuggleASecondSetting:
    """The one finding from this feature's security review that mattered.

    A configuration file is one ``name = value`` per line, so a newline inside
    a value does not make a longer value — it makes a **second setting**, and
    the loader reads it. `spool` is editable from the console and `launch`
    deliberately is not ("turning an authenticated web form into a way to
    choose what the node executes is a bigger step than editing settings"), so
    a newline in the first wrote the second, and the launcher ran it on the
    next start. Reachable from `config.save`, which a peer holding the fleet's
    `manage` right may call.

    Both layers refuse it now, and both are tested: the field that declared the
    value, and the file format that owns the constraint.
    """

    SMUGGLED = '/tmp/spool\nlaunch = /bin/sh -c "id > /tmp/pwned"'

    def test_the_declared_field_refuses_a_value_that_spans_two_lines(self):
        field = control.param("settings", "document")
        with pytest.raises(ControlError):
            control.coerce(field, {"spool": self.SMUGGLED})
        # Including one level down, where a transport's fields live.
        with pytest.raises(ControlError):
            control.coerce(field, {"tcp": {"bind": self.SMUGGLED}})
        # And in a list, which is how a setting spelled as several values
        # arrives.
        with pytest.raises(ControlError):
            control.coerce(field, {"bootstrap": ["tcp://a:1", self.SMUGGLED]})

    def test_the_file_refuses_it_too(self):
        from src import config as node_config

        merged, rejected = node_config.apply_edits(node_config.defaults(),
                                                   {"spool": self.SMUGGLED})
        assert rejected and "two lines" in rejected[0]
        assert merged["spool"] is None

    async def test_nothing_reaches_the_file_through_the_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "nmesh.conf")
            context = control.Context(node=None, config_path=path)
            channel = control.LocalChannel(control.build(context))
            reply = channel.call("config.save",
                                 {"settings": {"spool": self.SMUGGLED}})
            assert reply.ok is False and reply.code == "bad_request"
            assert not os.path.exists(path) or "launch" not in open(path).read()

    async def test_a_setting_the_console_may_not_write_is_still_refused(self):
        """The direct attempt, which always was refused — here so the pair of
        them is visible: not by name, and not by smuggling either."""
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "nmesh.conf")
            channel = control.LocalChannel(control.build(
                control.Context(node=None, config_path=path)))
            reply = channel.call("config.save",
                                 {"settings": {"launch": "/bin/sh"}})
            assert reply.ok is False and reply.code == "bad_request"


class TestNothingEscapesTheChannel:
    """The other review finding: the parser recurses, and the frame's own
    docstring promised no recursion. Five thousand brackets fit inside a frame,
    so `json` reached the interpreter's limit before any check ran, and the
    `RecursionError` escaped a `send` that says it never raises."""

    def test_a_frame_of_brackets_is_refused_rather_than_raised(self):
        deep = (b'{"v":1,"op":"sample.read","params":{"x":'
                + b"[" * 5000 + b"]" * 5000 + b"}}")
        assert len(deep) < frame_mod.MAX_FRAME
        with pytest.raises(control.FrameError):
            frame_mod.decode_request(deep)
        answer = json.loads(control.LocalChannel(_plane()).send(deep))
        assert answer["ok"] is False and answer["code"] == "bad_request"
        # The reply side reads documents a machine we do not run composed.
        with pytest.raises(control.FrameError):
            frame_mod.decode_reply(deep)

    def test_a_channel_answers_even_when_the_target_is_wrong(self):
        """A node id that is not one is known to be wrong before the frame is
        read at all — and something still answers a frame."""
        channel = control.RefusedChannel("bad_request", "bad node id")
        reply = channel.call("node.state")
        assert reply.ok is False and reply.code == "bad_request"
        assert reply.error == "bad node id"
        assert channel.target == ""


class TestParams:
    def test_text_is_text_and_not_repaired(self):
        field = control.param("label", "text")
        assert control.coerce(field, " hi ") == "hi"
        for bad in (42, True, ["a"], {"a": 1}):
            with pytest.raises(ControlError):
                control.coerce(field, bad)

    def test_a_line_may_be_long_but_stays_one_line(self):
        field = control.param("uri", "line")
        assert control.coerce(field, "tcp://host:9000") == "tcp://host:9000"
        for bad in ("a\nb", "a\rb", "a\x00b", "x" * (params_mod.MAX_LINE + 1)):
            with pytest.raises(ControlError):
                control.coerce(field, bad)

    def test_a_document_is_two_levels_and_bounded(self):
        field = control.param("settings", "document")
        assert control.coerce(field, {"a": 1, "b": {"c": "d"}}) == {"a": 1, "b": {"c": "d"}}
        deep = {"a": {"b": {"c": 1}}}
        many = {f"k{i}": 1 for i in range(params_mod.MAX_KEYS + 1)}
        for bad in (deep, many, [1], "x", {"a": "x" * (params_mod.MAX_VALUE + 1)},
                    {"bad name": 1}, {"a": object()}, {"a": "x\x00y"}):
            with pytest.raises(ControlError):
                control.coerce(field, bad)

    def test_a_choice_is_one_of_the_names_the_operation_wrote_down(self):
        field = control.param("action", "choice", choices=("start", "stop"))
        assert control.coerce(field, "stop") == "stop"
        for bad in ("START", "clear", "", None):
            with pytest.raises(ControlError):
                control.coerce(field, bad)
        with pytest.raises(ControlError):
            control.param("action", "choice")

    def test_a_count_with_a_limit_is_clamped_because_something_owns_it(self):
        field = control.param("seconds", "count", limit=60)
        assert control.coerce(field, 10 ** 9) == 60
        assert control.coerce(field, -5) == 0
        with pytest.raises(ControlError):
            control.coerce(field, "soon")
        # Only a count has something downstream to defer to.
        with pytest.raises(ControlError):
            control.param("label", "text", limit=10)

    def test_a_count_with_no_limit_is_refused_rather_than_guessed_at(self):
        with pytest.raises(ControlError):
            control.coerce(control.param("n", "count"), 10 ** 9)


class TestBoundsFitTheRelay:
    """Two files that have to agree, and a test instead of a comment."""

    def test_a_frame_fits_what_the_relay_carries(self):
        assert frame_mod.MAX_FRAME <= fleet_app.CONSOLE_REQ_MAX
        assert frame_mod.MAX_REPLY <= fleet_app.CONSOLE_RESP_MAX
        assert frame_mod.MAX_REPLY <= fleet_console.READ_MAX

    def test_the_remote_budget_is_inside_the_relays_own_ceiling(self):
        assert REMOTE_BUDGET < fleet_console.CALL_TIMEOUT
        assert REMOTE_BUDGET < fleet_app.CONSOLE_TIMEOUT

    def test_every_remotely_reachable_operation_fits_the_budget(self):
        plane = control.build(control.Context(node=None))
        for module in plane.catalogue(Origin.REMOTE):
            for entry in module["operations"]:
                assert entry["timeout"] <= REMOTE_BUDGET, entry["name"]

    def test_every_code_a_refusal_can_carry_has_a_status(self):
        assert set(control.CODES) <= set(_STATUS_BY_CODE)


class TestTheLedgerIsTrue:
    """`Docs/Architecture/control-plane.md` carries a table of every module,
    every operation, and a star on the ones that stay local. The charter's
    rule is that documentation which lies is worse than none — so the table is
    read back and compared against the plane itself, rather than trusted to
    have been updated."""

    LEDGER = Path(__file__).resolve().parent.parent / "Docs" / "Architecture" \
        / "control-plane.md"

    def _table(self) -> dict:
        """``{module: {operation: travels}}`` as the document claims."""
        rows, inside = {}, False
        for line in self.LEDGER.read_text().splitlines():
            if line.startswith("| Module | Operations |"):
                inside = True
                continue
            if inside and not line.startswith("|"):
                break
            if not inside or line.startswith("|---"):
                continue
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if len(cells) < 2:
                continue
            module = cells[0].split("`")[1]
            operations = {}
            for word in cells[1].split():
                if not word.startswith("`"):
                    continue
                # The star marks local-only and sits *outside* the backticks,
                # escaped for markdown: `` `retry`\* ``.
                operations[word.replace("\\*", "").strip("`*")] = \
                    not word.endswith("*")
            rows.setdefault(module, {}).update(operations)
        return rows

    def test_every_operation_is_in_the_table_with_the_right_reach(self):
        plane = control.build(control.Context(node=None))
        claimed = self._table()
        assert claimed, "the ledger's table could not be read"
        real = {}
        for module in plane.catalogue():
            real.setdefault(module["module"], {}).update(
                {row["name"]: row["remote"] for row in module["operations"]})
        for name, operations in real.items():
            assert name in claimed, f"{name} is not in the ledger"
            for operation_name, travels in operations.items():
                assert operation_name in claimed[name], \
                    f"{name}.{operation_name} is not in the ledger"
                assert claimed[name][operation_name] is travels, (
                    f"{name}.{operation_name} travels={travels}, the ledger "
                    f"says {claimed[name][operation_name]}")
        for name in claimed:
            assert name in real, f"the ledger names {name}, which does not exist"

    def test_the_bounds_the_ledger_quotes_are_the_bounds(self):
        quoted = self.LEDGER.read_text()
        # The table quotes kilobytes, so the figures are read back in the same
        # units the reader sees. This caught the first drift the moment it was
        # written: the ledger still said 16 kB after a certificate made the
        # frame 24.
        assert f"| `frame.MAX_FRAME` | {frame_mod.MAX_FRAME // 1024} kB |" in quoted
        assert f"| `frame.MAX_REPLY` | {frame_mod.MAX_REPLY // 1024} kB |" in quoted
        assert f"| `plane.REMOTE_BUDGET` | {REMOTE_BUDGET:g} s |" in quoted
        assert (f"| `params.MAX_HEX` | {params_mod.MAX_HEX} |") in quoted
        assert (f"| `params.MAX_SECRET` | {params_mod.MAX_SECRET} |") in quoted


class TestChannels:
    def test_the_local_channel_goes_through_the_frame(self):
        chan = control.LocalChannel(_plane())
        assert json.loads(chan.send(control.encode(
            {"v": 1, "id": "z", "op": "sample.read"})))["result"] == {"value": 7}

    def test_a_relay_that_fails_is_unavailable_not_a_refusal(self):
        def broken(node_hex, raw):
            raise OSError("the mesh ate it")

        reply = control.RemoteChannel("ab" * 20, broken).call("sample.read")
        assert reply.ok is False and reply.code == "unavailable"

    def test_a_relay_that_answers_nonsense_never_crashes_the_caller(self):
        for answer in (None, "", b"not json", b'{"ok": true}', 7):
            chan = control.RemoteChannel("ab" * 20, lambda n, r, a=answer: a)
            reply = chan.call("sample.read")
            assert isinstance(reply.ok, bool)

    def test_the_relay_carries_the_frame_it_was_given(self):
        seen = {}

        def relay(node_hex, raw):
            seen["node"], seen["frame"] = node_hex, json.loads(raw)
            return control.encode({"v": 1, "id": seen["frame"]["id"], "ok": True,
                                   "result": {"from": "over there"}})

        reply = control.RemoteChannel("CD" * 20, relay).call(
            "sample.read", {"a": 1}, "7")
        assert seen["node"] == "cd" * 20
        assert seen["frame"]["op"] == "sample.read"
        assert reply.result == {"from": "over there"}


# --------------------------------------------------------------------------
# The built-in modules, over a node.
# --------------------------------------------------------------------------

class _FakeNode:
    """Enough of a node for the modules that only read it."""

    pseudo = ""

    class _Id:
        raw = bytes(range(20))

    id = _Id()

    def __init__(self) -> None:
        self.trace = _FakeTrace()

    def set_pseudo(self, wanted):
        from src.pseudo import canonical
        self.pseudo = canonical(wanted)
        return self.pseudo

    def find_pseudo(self, query, limit=20):
        return [{"pseudo": self.pseudo, "id": self.id.raw.hex()}] if self.pseudo else []


class _FakeTrace:
    def __init__(self) -> None:
        self.started = None

    def start(self, *, seconds, events, names=None):
        self.started = (seconds, events)
        return {"running": True, "seconds": seconds, "capacity": events}

    def stop(self):
        return {"running": False}

    def clear(self):
        self.started = None

    def status(self):
        return {"running": False}

    def summary(self):
        return {"rows": []}

    def events(self, limit=0):
        return []

    def export(self):
        return {"format": "nmesh-trace-1"}


def _built(node, config_path="", changes=None):
    context = control.Context(node=node, loop=asyncio.get_event_loop(),
                              config_path=config_path, changes=changes)
    return control.build(context)


class TestBuiltInModules:
    async def test_the_name_is_read_and_written_through_the_plane(self):
        node = _FakeNode()
        chan = control.LocalChannel(_built(node))
        assert chan.call("pseudo.get").result["max"]
        # From a thread, like the console's server: an operation that touches
        # the node marshals onto its loop and waits, so calling it *from* that
        # loop is refused outright rather than hanging (`Context.call`).
        saved = await asyncio.to_thread(chan.call, "pseudo.save",
                                        {"pseudo": "  Ada  "})
        assert saved.result["pseudo"] == "Ada"
        assert node.pseudo == "Ada"
        # A number is not a name: the plane does not repair a value into one.
        assert chan.call("pseudo.save", {"pseudo": 42}).ok is False
        on_the_loop = chan.call("pseudo.save", {"pseudo": "Grace"})
        assert on_the_loop.ok is False and node.pseudo == "Ada"

    async def test_a_name_the_mesh_refuses_is_refused_here(self):
        chan = control.LocalChannel(_built(_FakeNode()))
        for bad in ("x" * 60, "ali‮ce", "bo​b"):
            reply = await asyncio.to_thread(chan.call, "pseudo.save",
                                            {"pseudo": bad})
            assert reply.ok is False and reply.code == "bad_request"

    async def test_the_trace_clamps_what_it_owns(self):
        from src import trace as trace_mod
        node = _FakeNode()
        chan = control.LocalChannel(_built(node))
        chan.call("trace.set", {"action": "start", "seconds": 10 ** 9,
                                "events": 10 ** 9})   # the trace is in-process
        seconds, events = node.trace.started
        assert seconds <= trace_mod.MAX_SECONDS and events <= trace_mod.MAX_EVENTS
        assert chan.call("trace.set", {"action": "sideways"}).ok is False

    async def test_the_configuration_is_read_and_written_once(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "nmesh.conf")
            chan = control.LocalChannel(_built(_FakeNode(), config_path=path))
            assert chan.call("config.get").result["available"] is True
            assert chan.call("config.save", {"settings": {"fleet": True}}).result["saved"]
            refused = chan.call("config.save", {"settings": {"console_port": 99999}})
            assert refused.ok is False and refused.detail["rejected"]
            # A refused value writes nothing: the file still says what it said.
            assert "99999" not in open(path).read()

    async def test_a_node_with_no_configuration_file_says_so(self):
        chan = control.LocalChannel(_built(_FakeNode()))
        assert chan.call("config.get").result["available"] is False
        conflict = chan.call("config.save", {"settings": {"fleet": True}})
        assert conflict.ok is False and conflict.code == "conflict"

    async def test_what_has_moved_is_a_pull_as_well_as_a_stream(self):
        from src.webconsole import _Changes
        book = _Changes()
        chan = control.LocalChannel(_built(_FakeNode(), changes=book))
        first = chan.call("control.changes", {"since": 0}).result
        assert first["available"] is True and first["topics"] == []
        book.note("links")
        book.note("nodes")
        second = chan.call("control.changes", {"since": first["seq"]}).result
        assert sorted(second["topics"]) == ["links", "nodes"]
        # Asking again from the new sequence says nothing moved since.
        assert chan.call("control.changes",
                         {"since": second["seq"]}).result["topics"] == []

    async def test_a_node_that_is_not_running_is_unavailable_not_a_crash(self):
        # No loop bound: every operation that needs the node must answer, and
        # answer honestly. This is the shape a console gets during shutdown.
        plane = control.build(control.Context(node=_FakeNode()))
        reply = await asyncio.to_thread(
            control.LocalChannel(plane).call, "pseudo.search", {"query": "a"})
        assert reply.ok is False and reply.code == "unavailable"


class TestAppsOnTheChannel:
    """An app is reached through the plane, and its reach is its own to declare."""

    class _Bridge:
        API = (
            app_api.operation("look", "A read anybody may ask for",
                              [app_api.param("node", "node")], remote=True),
            app_api.operation("touch", "An action that stays at home",
                              [app_api.param("node", "node")], changes=True),
        )

        def api_look(self, node):
            return {"saw": node}

        def api_touch(self, node):
            return {"touched": node}

    class _Host:
        def __init__(self, bridges):
            self._bridges = bridges

        def running(self):
            return list(self._bridges)

        def bridge(self, name):
            return self._bridges.get(name)

    def _plane_over(self, bridges):
        host = self._Host(bridges)
        context = control.Context(node=_FakeNode(),
                                  api=lambda: app_api.AppAPI(host))
        return control.build(context)

    def test_an_app_operation_is_reached_through_the_plane(self):
        chan = control.LocalChannel(self._plane_over({"demo": self._Bridge()}))
        reply = chan.call("apps.call", {"app": "demo", "op": "look",
                                        "args": {"node": "ab" * 20}})
        assert reply.result["result"] == {"saw": "ab" * 20}

    def test_what_an_app_did_not_declare_remote_stays_at_home(self):
        plane = self._plane_over({"demo": self._Bridge()})
        here = control.LocalChannel(plane)
        there = control.LocalChannel(plane, Origin.REMOTE)
        assert here.call("apps.call", {"app": "demo", "op": "touch",
                                       "args": {"node": "ab" * 20}}).ok
        refused = there.call("apps.call", {"app": "demo", "op": "touch",
                                           "args": {"node": "ab" * 20}})
        assert refused.ok is False and refused.code == "refused"
        # And the one that says so travels.
        assert there.call("apps.call", {"app": "demo", "op": "look",
                                        "args": {"node": "ab" * 20}}).ok

    def test_the_catalogue_hides_what_that_console_cannot_call(self):
        plane = self._plane_over({"demo": self._Bridge()})
        here = control.LocalChannel(plane).call("apps.catalogue").result
        there = control.LocalChannel(plane, Origin.REMOTE).call(
            "apps.catalogue").result

        def names(answer):
            return {op["name"] for entry in answer["apps"]
                    for op in entry["operations"]}

        assert names(here) == {"look", "touch"}
        assert names(there) == {"look"}

    def test_an_app_that_is_not_running_does_not_exist(self):
        chan = control.LocalChannel(self._plane_over({}))
        gone = chan.call("apps.call", {"app": "demo", "op": "look",
                                       "args": {"node": "ab" * 20}})
        assert gone.ok is False and gone.code == "not_found"
        # Naming nothing is a malformed call, not a missing one.
        empty = chan.call("apps.call", {"app": "", "op": ""})
        assert empty.ok is False and empty.code == "bad_request"

    def test_an_undeclared_operation_is_not_reachable_by_its_method_name(self):
        chan = control.LocalChannel(self._plane_over({"demo": self._Bridge()}))
        for op in ("api_look", "__init__", "nope"):
            reply = chan.call("apps.call", {"app": "demo", "op": op,
                                            "args": {"node": "ab" * 20}})
            assert reply.ok is False, op

    def test_the_built_in_apps_declare_what_may_travel(self):
        # Pinned, because widening it is a security change: chat's operations
        # are somebody's conversations and fleet's actions would make a managed
        # node a way to reach the nodes it manages.
        from src.apps.chat_web import ChatBridge
        from src.apps.fleet_web import FleetBridge

        def remotes(bridge):
            return {entry["name"] for entry in bridge.API if entry.get("remote")}

        assert remotes(ChatBridge) == set()
        assert remotes(FleetBridge) == {"relation"}


class TestStoreAndJoining:
    """Apps somebody else wrote, and the ways into a network."""

    class _Node:
        pseudo = ""

        class _Id:
            raw = bytes(range(20))

        id = _Id()

        def __init__(self):
            self.did = []
            self.ttl = None

        def store_overview(self):
            return {"catalog": [{"app_id": "aa", "name": "one", "ts": 2},
                                {"app_id": "bb", "name": "two", "ts": 1}],
                    "installed": []}

        def installed_list(self):
            return [{"app_id": "aa", "name": "one"}]

        async def install_app(self, app_id):
            self.did.append(("install", app_id))
            return {"app_id": app_id} if app_id == "aa" else None

        async def update_app(self, app_id):
            return None

        def uninstall_app(self, app_id):
            return app_id == "aa"

        def generate_invite(self):
            return "a-code"

        def console_invite_block(self):
            return "a-block"

        def issue_join_ticket(self, ttl):
            self.ttl = ttl
            return {"ticket": "TICKET", "ttl": ttl, "code": "secret"}

        async def console_join(self, uri, code):
            self.did.append(("join", uri, code))
            return {"ok": False, "reason": "the invitation was refused",
                    "detail": "it had been used"}

    def _channel(self, node, origin=Origin.LOCAL):
        return control.LocalChannel(control.build(control.Context(
            node=node, loop=asyncio.get_event_loop())), origin)

    async def test_an_app_is_managed_from_the_console_that_manages_the_node(self):
        node = self._Node()
        there = self._channel(node, Origin.REMOTE)
        assert (await asyncio.to_thread(there.call, "store.install",
                                        {"app": "aa"})).ok
        assert node.did[-1] == ("install", "aa")
        # An app is not the node's own program: installing one writes a
        # directory beside it, and that is what managing a machine means.
        assert (await asyncio.to_thread(there.call, "store.overview")).ok

    async def test_an_app_nobody_offers_is_not_found_and_no_name_is_a_mistake(self):
        channel = self._channel(self._Node())
        missing = await asyncio.to_thread(channel.call, "store.install",
                                          {"app": "zz"})
        assert missing.ok is False and missing.code == "not_found"
        empty = await asyncio.to_thread(channel.call, "store.install",
                                        {"app": ""})
        assert empty.ok is False and empty.code == "bad_request"

    async def test_the_catalogue_is_paged_and_sorted_where_the_list_is(self):
        page = (await asyncio.to_thread(self._channel(self._Node()).call,
                                        "store.list",
                                        {"scope": "catalog", "limit": 1})).result
        assert page["total"] == 2 and len(page["items"]) == 1
        # Newest first, by the node's own timestamp.
        assert page["items"][0]["app_id"] == "aa"
        bad = await asyncio.to_thread(self._channel(self._Node()).call,
                                      "store.list", {"scope": "everything"})
        assert bad.ok is False and bad.code == "bad_request"

    async def test_minting_stays_here_and_joining_travels(self):
        node = self._Node()
        plane = control.build(control.Context(node=node,
                                              loop=asyncio.get_event_loop()))
        remote = {row["name"] for module in plane.catalogue(Origin.REMOTE)
                  for row in module["operations"] if module["module"] == "join"}
        # A code this node issues lets somebody into *its* network, and the
        # fleet has a capability for asking a node you manage to mint one.
        # Pointing a machine you manage at a network is provisioning it.
        assert remote == {"network", "use_block"}

    async def test_a_ticket_carries_both_or_you_send_both(self):
        channel = self._channel(self._Node())
        for params in ({}, {"uri": "tcp://host:9000"},
                       {"ticket": "T", "code": "c"}):
            reply = await asyncio.to_thread(channel.call, "join.network",
                                            params)
            assert reply.ok is False and reply.code == "bad_request", params

    async def test_a_join_that_fails_says_which_way(self):
        node = self._Node()
        reply = await asyncio.to_thread(
            self._channel(node).call, "join.network",
            {"uri": "tcp://127.0.0.1:1", "code": "no"})
        assert reply.ok is False and reply.code == "unavailable"
        # The node names which of the five ways, and the detail travels beside
        # it rather than being folded into the sentence.
        assert reply.error == "the invitation was refused"
        assert reply.detail["detail"] == "it had been used"

    async def test_a_silly_ticket_lifetime_is_clamped_by_the_ticket(self):
        from src import join_ticket
        node = self._Node()
        reply = await asyncio.to_thread(self._channel(node).call,
                                        "join.ticket", {"ttl": 10 ** 9})
        assert reply.ok is True and node.ttl == join_ticket.MAX_TTL
        # And the code inside it is not repeated beside it.
        assert "code" not in reply.result and reply.result["ticket"] == "TICKET"


class TestPackagesAndKeys:
    """The directory, and the keys this node can sign with."""

    class _Node:
        pseudo = ""

        class _Id:
            raw = bytes(range(20))

        id = _Id()

        def __init__(self):
            self.asked = []
            self.records = {"ab" * 20: {"id": "ab" * 20, "name": "thing"}}

        def find_packages(self, query, limit=20):
            self.asked.append(("local", query))
            return [{"name": "thing"}] if query in "thing" else []

        async def search_packages(self, query):
            self.asked.append(("wide", query))
            return [{"name": "thing", "from": "the network"}]

        async def packages_of(self, node, wide=False):
            self.asked.append(("of", node, wide))
            return []

        def package_entry(self, record):
            return self.records.get(record)

        def key_share_overview(self):
            return {"keys": [], "incoming": [], "outgoing": []}

        def create_publisher_key(self, passphrase, label=""):
            self.asked.append(("create", passphrase, label))
            return {"id": "cc" * 20, "label": label}

        def forget_publisher_key(self, key):
            return False

        def refuse_publisher_key(self, offer):
            return False

    def _channel(self, node, origin=Origin.LOCAL):
        return control.LocalChannel(control.build(control.Context(
            node=node, loop=asyncio.get_event_loop())), origin)

    async def test_asking_this_node_and_asking_the_network_are_two_operations(self):
        node = self._Node()
        channel = self._channel(node)
        assert (await asyncio.to_thread(channel.call, "packages.search",
                                        {"query": "thing"})).result["wide"] is False
        assert (await asyncio.to_thread(channel.call, "packages.lookup",
                                        {"query": "thing"})).result["wide"] is True
        assert node.asked == [("local", "thing"), ("wide", "thing")]
        # And a console managing this node gets the cheap one only: a Kademlia
        # round does not fit what the relay carries.
        there = self._channel(node, Origin.REMOTE)
        assert (await asyncio.to_thread(there.call, "packages.search",
                                        {"query": "thing"})).ok
        refused = await asyncio.to_thread(there.call, "packages.lookup",
                                          {"query": "thing"})
        assert refused.ok is False and refused.code == "refused"

    async def test_a_lookup_asks_one_question(self):
        channel = self._channel(self._Node())
        for params in ({}, {"query": "thing", "node": "ab" * 20}):
            reply = await asyncio.to_thread(channel.call, "packages.lookup",
                                            params)
            assert reply.ok is False and reply.code == "bad_request", params

    async def test_a_record_this_node_does_not_hold_is_not_found(self):
        channel = self._channel(self._Node())
        assert (await asyncio.to_thread(channel.call, "packages.entry",
                                        {"record": "ab" * 20})).ok
        missing = await asyncio.to_thread(channel.call, "packages.entry",
                                          {"record": "cd" * 20})
        assert missing.ok is False and missing.code == "not_found"

    async def test_installing_and_pinning_are_confirmed_and_local(self):
        node = self._Node()
        here, there = self._channel(node), self._channel(node, Origin.REMOTE)
        for op in ("install", "trust"):
            unconfirmed = await asyncio.to_thread(
                here.call, "packages." + op,
                {"record": "ab" * 20, "confirm": False})
            assert unconfirmed.ok is False and unconfirmed.code == "bad_request"
            refused = await asyncio.to_thread(
                there.call, "packages." + op,
                {"record": "ab" * 20, "confirm": True})
            assert refused.ok is False and refused.code == "refused", op

    async def test_only_the_key_overview_travels(self):
        node = self._Node()
        plane = control.build(control.Context(node=node,
                                              loop=asyncio.get_event_loop()))
        remote = {row["name"] for module in plane.catalogue(Origin.REMOTE)
                  for row in module["operations"] if module["module"] == "keys"}
        # A passphrase is typed at the machine that will hold the key.
        assert remote == {"overview"}
        there = control.LocalChannel(plane, Origin.REMOTE)
        for op, params in (("create", {"passphrase": "x"}),
                           ("adopt", {"path": "/tmp/k", "passphrase": "x"}),
                           ("forget", {"key": "ab" * 20, "confirm": True})):
            reply = await asyncio.to_thread(there.call, "keys." + op, params)
            assert reply.ok is False and reply.code == "refused", op

    async def test_a_key_passphrase_reaches_the_node_as_typed(self):
        node = self._Node()
        channel = self._channel(node)
        reply = await asyncio.to_thread(channel.call, "keys.create",
                                        {"passphrase": " kept as typed ",
                                         "label": "  a label  "})
        assert reply.ok is True
        assert node.asked[-1] == ("create", " kept as typed ", "a label")

    async def test_what_this_node_does_not_hold_cannot_be_forgotten(self):
        channel = self._channel(self._Node())
        for op, params in (("forget", {"key": "ab" * 20, "confirm": True}),
                           ("refuse", {"offer": "ab" * 20})):
            reply = await asyncio.to_thread(channel.call, "keys." + op, params)
            assert reply.ok is False and reply.code == "not_found", op


class TestReleases:
    """The node's own code: what travels, what does not, and what a refusal
    says. The most sensitive surface on the plane, and the one where almost
    nothing is reachable from another operator's console."""

    class _Node:
        pseudo = ""

        class _Id:
            raw = bytes(range(20))

        id = _Id()

        def __init__(self):
            self.pinned = {}
            self.published = None

        def release_overview(self):
            return {"releases": [], "publishers": list(self.pinned)}

        def trust_publisher(self, key_hex, name="", auto=False, endorsed=False):
            self.pinned[key_hex] = {"name": name, "auto": auto,
                                     "endorsed": endorsed}
            return {"id": key_hex[:40], "name": name}

        def untrust_publisher(self, publisher):
            return self.pinned.pop(publisher, None) is not None

        def set_publisher_auto(self, publisher, auto):
            return False

        def set_publisher_endorsed(self, publisher, endorsed):
            return False

        def publisher_key_path(self, key_id):
            return None

        async def publish_release(self, *, notes, key_path, passphrase):
            self.published = {"notes": notes, "passphrase": passphrase}
            return {"version": "9.9.9", "files": 3, "package_bytes": 10}

    def _plane(self, node):
        return control.build(control.Context(
            node=node, loop=asyncio.get_event_loop(), restart=lambda: False))

    async def test_only_the_read_travels(self):
        plane = self._plane(self._Node())
        remote = {row["name"] for module in plane.catalogue(Origin.REMOTE)
                  for row in module["operations"]
                  if module["module"] == "releases"}
        # What a node accepts for replacing its own program is pinned by a
        # human *at that node* (`MeshNode.trust_publisher`), and updating a
        # managed node has its own capability and its own path.
        assert remote == {"overview"}
        channel = control.LocalChannel(plane, Origin.REMOTE)
        for op in ("trust", "untrust", "auto", "endorse", "publish", "install",
                   "check", "apply"):
            reply = await asyncio.to_thread(channel.call, "releases." + op, {})
            assert reply.ok is False and reply.code == "refused", op
        assert (await asyncio.to_thread(channel.call, "releases.overview")).ok

    async def test_a_passphrase_is_not_trimmed(self):
        node = self._Node()
        channel = control.LocalChannel(self._plane(node))
        reply = await asyncio.to_thread(
            channel.call, "releases.publish",
            {"notes": "  a note  ", "passphrase": "  spaces matter  "})
        assert reply.ok is True
        # The note is a label and is trimmed; the passphrase is the passphrase.
        assert node.published == {"notes": "a note",
                                  "passphrase": "  spaces matter  "}

    async def test_a_key_is_hex_before_the_node_sees_it(self):
        node = self._Node()
        channel = control.LocalChannel(self._plane(node))
        for bad in ("zz", "abc", 7, None, ""):
            reply = await asyncio.to_thread(channel.call, "releases.trust",
                                            {"key": bad})
            assert reply.ok is False and reply.code == "bad_request", bad
        assert node.pinned == {}
        good = await asyncio.to_thread(channel.call, "releases.trust",
                                       {"key": "ab" * 32, "name": "me"})
        assert good.ok and node.pinned["ab" * 32]["name"] == "me"

    async def test_what_is_not_pinned_cannot_be_unpinned_or_armed(self):
        channel = control.LocalChannel(self._plane(self._Node()))
        for op, params in (("untrust", {"publisher": "ab" * 20}),
                           ("auto", {"publisher": "ab" * 20, "auto": True}),
                           ("endorse", {"publisher": "ab" * 20,
                                        "endorsed": True})):
            reply = await asyncio.to_thread(channel.call, "releases." + op,
                                            params)
            assert reply.ok is False and reply.code == "not_found", op

    async def test_installing_needs_the_confirmation_and_the_name(self):
        channel = control.LocalChannel(self._plane(self._Node()))
        for params in ({"release": "", "confirm": True},
                       {"release": "abc", "confirm": False}):
            reply = await asyncio.to_thread(channel.call, "releases.install",
                                            params)
            assert reply.ok is False and reply.code == "bad_request", params

    async def test_a_version_nobody_offers_any_more_is_refused(self, monkeypatch):
        from src import updater
        channel = control.LocalChannel(self._plane(self._Node()))
        monkeypatch.setattr(updater, "updatable", lambda: (True, ""))

        async def moved_on(branch=None):
            return {"latest": "2.0.0", "available": True}

        monkeypatch.setattr(updater, "check", moved_on)
        reply = await asyncio.to_thread(channel.call, "releases.apply",
                                        {"version": "1.0.0", "confirm": True})
        # A tab left open for an hour must not install something nobody looked
        # at, so the mismatch is a conflict rather than a silent upgrade.
        assert reply.ok is False and reply.code == "conflict"
        assert "2.0.0" in reply.error

    async def test_github_not_answering_is_an_answer(self, monkeypatch):
        from src import updater
        channel = control.LocalChannel(self._plane(self._Node()))

        async def unreachable(branch=None):
            raise updater.UpdateError("github is not answering")

        monkeypatch.setattr(updater, "check", unreachable)
        reply = await asyncio.to_thread(channel.call, "releases.check")
        # The page has to show it next to the version that is running, so it
        # comes back as a result rather than as a refusal.
        assert reply.ok is True
        assert "not answering" in reply.result["error"]
        assert reply.result["current"] == updater.__version__


class TestTheNodeTable:
    """The list every page reads, and the two things it has to get right."""

    class _Node:
        pseudo = ""

        class _Id:
            raw = bytes(range(20))

        id = _Id()

        def console_nodes(self, scope):
            if scope == "known":
                return [{"id": "cc" * 20, "seen_ago": 3, "pseudo": "far"},
                        {"id": "aa" * 20, "seen_ago": 1, "pseudo": "near"}]
            # One row per *link*: two nodes, and one of them holds two links.
            return [{"id": "aa" * 20, "transport": "tcp", "addresses": []},
                    {"id": "aa" * 20, "transport": "udp", "addresses": []},
                    {"id": "bb" * 20, "transport": "tcp", "addresses": []}]

    def _channel(self):
        return control.LocalChannel(control.build(control.Context(
            node=self._Node(), loop=asyncio.get_event_loop())))

    async def test_the_active_table_is_paged_by_node_not_by_link(self):
        chan = self._channel()
        page = (await asyncio.to_thread(chan.call, "node.list",
                                        {"scope": "active", "limit": 1})).result
        # One node, both of its links, and a total that counts *nodes* — the
        # number under a heading that says nodes.
        assert page["total"] == 2
        assert [row["id"] for row in page["items"]] == ["aa" * 20] * 2

    async def test_the_known_table_is_paged_by_row(self):
        page = (await asyncio.to_thread(self._channel().call, "node.list",
                                        {"scope": "known", "limit": 1})).result
        assert page["total"] == 2 and len(page["items"]) == 1
        # Sorted by how long ago each was seen, so the first is the freshest.
        assert page["items"][0]["seen_ago"] == 1

    async def test_a_query_matches_anything_a_row_carries(self):
        found = (await asyncio.to_thread(self._channel().call, "node.list",
                                         {"scope": "known", "query": "FAR"})).result
        assert [row["pseudo"] for row in found["items"]] == ["far"]

    async def test_a_scope_nobody_declared_does_not_exist(self):
        chan = self._channel()
        for scope in ("everything", "", "installed", None):
            reply = await asyncio.to_thread(chan.call, "node.list",
                                            {"scope": scope})
            assert reply.ok is False and reply.code == "bad_request", scope

    async def test_the_page_size_is_the_consoles_to_bound(self):
        from src.control import listing
        page = (await asyncio.to_thread(self._channel().call, "node.list",
                                        {"scope": "known", "limit": 10 ** 6})).result
        assert page["limit"] == listing.MAX_LIMIT
        long_one = await asyncio.to_thread(
            self._channel().call, "node.list",
            {"scope": "known", "query": "x" * (listing.MAX_QUERY + 1)})
        assert long_one.ok is False and long_one.code == "bad_request"


class TestTrustAndNetwork:
    """The two modules an operator uses on a machine that is not in front of
    them: what this node vouches for, and how it is reachable."""

    class _Node:
        pseudo = ""

        class _Id:
            raw = bytes(range(20))

        id = _Id()

        def __init__(self):
            self.trusted = []
            self.punch = True
            self.dynamic = None
            self.balance = None
            self.mlo = {}

        def console_add_root(self, cert_hex):
            # What the real one does with anything that is not a certificate.
            if len(cert_hex) < 100:
                return False
            self.trusted.append(cert_hex)
            return True

        def console_remove_root(self, node):
            return False

        def console_set_punch_enabled(self, enabled):
            self.punch = enabled
            return enabled

        def set_dynamic_address(self, enabled):
            self.dynamic = enabled

        def set_transport_balance(self, value):
            if not 0 <= int(value) <= 100:
                raise ValueError("balance must be between 0 and 100")
            self.balance = int(value)
            return self.balance

        def transport_preference(self):
            return [{"scheme": "tcp"}]

        def set_mlo_always(self, enabled):
            self.mlo["always"] = enabled
            return enabled

        def set_mlo_settings(self, **fields):
            self.mlo.update(fields)
            return dict(fields)

        def mlo_status(self):
            return dict(self.mlo)

        async def console_remove_listen(self, uri):
            return False

    def _channel(self, node, origin=Origin.LOCAL):
        context = control.Context(node=node, loop=asyncio.get_event_loop())
        return control.LocalChannel(control.build(context), origin)

    async def test_a_certificate_is_hex_before_the_node_is_asked(self):
        node = self._Node()
        chan = self._channel(node)
        for bad in ("deadbeefz", "abc", 42, None, "de ad be ef"):
            reply = await asyncio.to_thread(chan.call, "trust.add", {"cert": bad})
            assert reply.ok is False and reply.code == "bad_request", bad
        assert node.trusted == []
        # And one the node itself refuses is the caller's mistake, not ours.
        short = await asyncio.to_thread(chan.call, "trust.add", {"cert": "dead" * 4})
        assert short.ok is False and short.code == "bad_request"
        good = await asyncio.to_thread(chan.call, "trust.add", {"cert": "ab" * 200})
        assert good.ok is True and node.trusted

    async def test_an_anchor_this_node_does_not_hold_is_said_so(self):
        reply = await asyncio.to_thread(
            self._channel(self._Node()).call, "trust.untrust", {"node": "ab" * 20})
        assert reply.ok is False and reply.code == "bad_request"

    async def test_a_toggle_takes_a_boolean_and_nothing_else(self):
        node = self._Node()
        chan = self._channel(node)
        for bad in ("yes", 1, "true", None, ""):
            reply = await asyncio.to_thread(chan.call, "network.punch",
                                            {"enabled": bad})
            assert reply.ok is False and reply.code == "bad_request", bad
        assert node.punch is True
        assert (await asyncio.to_thread(chan.call, "network.punch",
                                        {"enabled": False})).ok
        assert node.punch is False

    async def test_the_node_decides_what_a_value_may_be(self):
        node = self._Node()
        chan = self._channel(node)
        refused = await asyncio.to_thread(chan.call, "network.balance",
                                          {"value": 500})
        assert refused.ok is False and "between 0 and 100" in refused.error
        assert node.balance is None
        ok = await asyncio.to_thread(chan.call, "network.balance", {"value": 40})
        assert ok.result["value"] == 40 and ok.result["preference"]

    async def test_a_partial_update_applies_what_it_was_given(self):
        node = self._Node()
        chan = self._channel(node)
        reply = await asyncio.to_thread(chan.call, "network.mlo",
                                        {"skew_ms": 250})
        assert reply.ok is True
        # One field typed must not rewrite the six that were not.
        assert node.mlo == {"skew_ms": 250}
        assert "always" not in node.mlo

    async def test_starting_a_listener_with_no_port_is_refused_not_guessed(self):
        chan = self._channel(self._Node())
        reply = await asyncio.to_thread(chan.call, "network.udp",
                                        {"action": "start"})
        assert reply.ok is False and reply.code == "bad_request"

    async def test_what_this_node_does_not_listen_on_is_not_found(self):
        reply = await asyncio.to_thread(
            self._channel(self._Node()).call, "network.unlisten",
            {"uri": "tcp://127.0.0.1:9"})
        assert reply.ok is False and reply.code == "not_found"

    async def test_managing_a_node_reaches_all_of_this(self):
        """The point of the two modules: an operator manages a machine they are
        not in front of. Everything here is reachable from there — what is not
        is named in the plane, and it is never one of these."""
        plane = control.build(control.Context(node=self._Node()))
        remote = {module["module"]: {row["name"] for row in module["operations"]}
                  for module in plane.catalogue(Origin.REMOTE)}
        assert remote["trust"] == {"add", "untrust", "revoke", "forgive",
                                   "accept_change", "witness"}
        assert "punch_open" in remote["network"] and "mlo" in remote["network"]
        assert "restart" in remote["node"]


# --------------------------------------------------------------------------
# The console's door onto it.
# --------------------------------------------------------------------------

async def _make_console(**kwargs):
    node = MeshNode(transport_manager=make_manager())
    console = WebConsole(node, host="127.0.0.1", port=0, use_tls=False,
                         password=PW, **kwargs)
    console.start(loop=asyncio.get_running_loop())
    return node, console


def _post(console, body, token=None, headers=None):
    """One POST to the control route, from a worker thread."""
    import http.client

    connection = http.client.HTTPConnection(console.host, console.port, timeout=8)
    sent = dict(headers or {})
    sent["Content-Type"] = "application/json"
    if token:
        sent["Authorization"] = "Bearer " + token
    connection.request("POST", CONTROL_PATH,
                       body=body if isinstance(body, bytes) else json.dumps(body).encode(),
                       headers=sent)
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    try:
        return response.status, json.loads(payload)
    except Exception:
        return response.status, None


def _with_fleet(monkeypatch, bridge):
    """Stand a fleet bridge in front of every console in this process.

    Through ``monkeypatch`` rather than by assignment: ``_fleet`` is a property
    on the class, so a test that replaced it by hand would have to put it back
    — and a test that gets that wrong takes every other console test in the
    worker down with it, which is exactly what happened once.
    """
    monkeypatch.setattr(WebConsole, "_fleet", property(lambda self: bridge))


async def _login(console):
    import http.client

    def call():
        connection = http.client.HTTPConnection(console.host, console.port, timeout=8)
        connection.request("POST", "/api/login",
                           body=json.dumps({"password": PW}).encode(),
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        token = json.loads(response.read())["token"]
        connection.close()
        return token

    return await asyncio.to_thread(call)


class TestConsoleControlRoute:
    async def test_a_stranger_gets_nothing(self):
        node, console = await _make_console()
        try:
            status, body = await asyncio.to_thread(
                _post, console, {"v": 1, "op": "node.state"})
            assert status == 401
        finally:
            console.stop()
            await node.stop()

    async def test_one_frame_in_one_frame_out(self):
        node, console = await _make_console()
        try:
            token = await _login(console)
            status, body = await asyncio.to_thread(
                _post, console, {"v": 1, "id": "9", "op": "pseudo.get"}, token)
            assert status == 200 and body["ok"] is True and body["id"] == "9"
            assert body["result"]["id"] == node.id.raw.hex()
        finally:
            console.stop()
            await node.stop()

    async def test_a_refusals_code_becomes_this_channels_status(self):
        node, console = await _make_console()
        try:
            token = await _login(console)
            for op, expected in (("nope.nope", 404),
                                 ("config.save", 400)):
                status, body = await asyncio.to_thread(
                    _post, console, {"v": 1, "op": op}, token)
                assert status == expected, op
                assert body["ok"] is False and body["code"] in control.CODES
        finally:
            console.stop()
            await node.stop()

    async def test_a_body_that_is_not_a_frame_is_answered_anyway(self):
        node, console = await _make_console()
        try:
            token = await _login(console)
            for raw in (b"", b"{", b"[]", b"\x00\x01", b'{"op": 3}'):
                status, body = await asyncio.to_thread(_post, console, raw, token)
                assert status == 400 and body["ok"] is False
        finally:
            console.stop()
            await node.stop()

    async def test_a_peers_replayed_frame_reaches_the_plane_as_remote(self):
        node, console = await _make_console()
        try:
            token = await _login(console)
            # The marker the fleet relay sets on a call it is replaying against
            # our own console: the same frame, and a local-only operation is
            # refused rather than answered.
            headers = {fleet_console.REPLAY_HEADER: "1"}
            status, body = await asyncio.to_thread(
                _post, console, {"v": 1, "op": "pseudo.lookup",
                                 "params": {"query": "ada"}}, token, headers)
            assert status == 403
            assert body["code"] == "refused"
            # And what it *may* ask for still works.
            status, body = await asyncio.to_thread(
                _post, console, {"v": 1, "op": "pseudo.get"}, token, headers)
            assert status == 200 and body["ok"] is True
        finally:
            console.stop()
            await node.stop()

    async def test_a_node_id_that_is_not_one_runs_nowhere(self):
        """The worst outcome this channel could have: a frame aimed at another
        machine, executed on **this** one because the address was malformed.

        The older routes answer `400 bad node id` for that; `/api/control` is
        routed before them, so it has to answer it itself."""
        node, console = await _make_console()
        try:
            token = await _login(console)
            before = node.pseudo
            # An *empty* header names nothing and means this node, which is
            # what a page that never heard of contexts sends; these are the
            # ones that name something and get it wrong.
            for bad in ("not-hex", "ab", "ab" * 21, "AB" * 20 + "zz",
                        "ab" * 19 + "zz"):
                status, body = await asyncio.to_thread(
                    _post, console,
                    {"v": 1, "op": "pseudo.save",
                     "params": {"pseudo": "ran on the wrong node"}},
                    token, {"X-NMesh-Node": bad})
                assert status == 400, bad
                assert body["ok"] is False and body["code"] == "bad_request"
                assert body["error"] == "bad node id"
            # Nothing happened here, which is the point.
            assert node.pseudo == before
        finally:
            console.stop()
            await node.stop()

    async def test_every_operation_answers_and_the_gate_holds_for_all_of_them(self):
        """One sweep over the whole plane, through the real door.

        Per-module tests check the operations somebody thought to write a test
        for. This asks the node what it exposes and then asks for **every one
        of them** with the marker a peer's relayed call carries: each must
        answer with a frame, and each one that is not declared remote must come
        back refused. A module added later is covered by construction, which is
        the only way a gate like this stays true."""
        node, console = await _make_console()
        try:
            token = await _login(console)
            replay = {fleet_console.REPLAY_HEADER: "1"}

            def names(answer):
                return {f"{module['module']}.{row['name']}"
                        for module in answer[1]["result"]["modules"]
                        for row in module["operations"]}

            offered = names(await asyncio.to_thread(
                _post, console, {"v": 1, "op": "control.catalogue"}, token))
            travels = names(await asyncio.to_thread(
                _post, console, {"v": 1, "op": "control.catalogue"}, token,
                replay))
            assert len(offered) > 60 and travels < offered

            for op in sorted(offered):
                status, body = await asyncio.to_thread(
                    _post, console, {"v": 1, "op": op, "params": {}}, token,
                    replay)
                # Every operation answers a frame — including the ones whose
                # arguments are missing, which is a refusal and not a silence.
                assert isinstance(body, dict) and "ok" in body, op
                if op not in travels:
                    assert body["code"] == "refused", (op, body)
                    assert status == 403, op
        finally:
            console.stop()
            await node.stop()

    async def test_the_catalogue_a_remote_console_reads_is_the_narrow_one(self):
        node, console = await _make_console()
        try:
            token = await _login(console)
            here = await asyncio.to_thread(
                _post, console, {"v": 1, "op": "control.catalogue"}, token)
            there = await asyncio.to_thread(
                _post, console, {"v": 1, "op": "control.catalogue"}, token,
                {fleet_console.REPLAY_HEADER: "1"})

            def names(answer):
                return {module["module"] + "." + entry["name"]
                        for module in answer[1]["result"]["modules"]
                        for entry in module["operations"]}

            assert "node.retry" in names(here)
            assert "node.retry" not in names(there)
            assert names(there) < names(here)
        finally:
            console.stop()
            await node.stop()

    async def test_driving_a_node_with_no_fleet_app_says_which_it_is(self):
        node, console = await _make_console()
        try:
            token = await _login(console)
            status, body = await asyncio.to_thread(
                _post, console, {"v": 1, "op": "node.state"}, token,
                {"X-NMesh-Node": "ab" * 20})
            # The status describes the console we asked — it answered — and the
            # frame describes the node we asked about, which we could not reach.
            assert status == 200
            assert body["ok"] is False and body["code"] == "conflict"
        finally:
            console.stop()
            await node.stop()

    async def test_a_frame_travels_to_the_node_it_names(self, monkeypatch):
        node, console = await _make_console()
        seen = {}

        class _FakeFleetBridge:
            def remote_call(self, session, node_hex, method, path, body):
                seen.update(session=session, node=node_hex, method=method,
                            path=path, frame=json.loads(body))
                return 200, "application/json", control.encode(
                    {"v": 1, "id": seen["frame"]["id"], "ok": True,
                     "result": {"pseudo": "over there"}})

        try:
            token = await _login(console)
            _with_fleet(monkeypatch, _FakeFleetBridge())
            # The console's own channel, pointed elsewhere: what the page's
            # `X-NMesh-Node` header does, without a mesh to stand up.
            channel = control.RemoteChannel(
                "ab" * 20, console._control_relay(token))
            reply = await asyncio.to_thread(channel.call, "pseudo.get")
            assert reply.result == {"pseudo": "over there"}
            assert seen["path"] == CONTROL_PATH and seen["method"] == "POST"
            assert seen["node"] == "ab" * 20 and seen["frame"]["op"] == "pseudo.get"
            assert seen["session"] == token
        finally:
            console.stop()
            await node.stop()

    async def test_a_node_that_never_answered_is_unavailable(self, monkeypatch):
        """The status the relay gives up with, read back as a code.

        It comes back as a 502, and calling that `failed` told the page
        "something went wrong over there" — when what happened is that there is
        no over there. The console driving a machine that had gone stayed
        pointed at it, looking alive and showing nothing."""
        node, console = await _make_console()

        class _Silent:
            def remote_call(self, session, node_hex, method, path, body):
                return 502, "application/json", json.dumps(
                    {"error": "could not reach that node (TimeoutError)"}).encode()

        try:
            token = await _login(console)
            _with_fleet(monkeypatch, _Silent())
            channel = control.RemoteChannel(
                "ab" * 20, console._control_relay(token))
            reply = await asyncio.to_thread(channel.call, "node.state")
            assert reply.ok is False and reply.code == "unavailable"
        finally:
            console.stop()
            await node.stop()

    async def test_the_far_nodes_session_expiring_is_not_ours(self, monkeypatch):
        node, console = await _make_console()

        class _NoSession:
            def remote_call(self, session, node_hex, method, path, body):
                return 401, "application/json", json.dumps(
                    {"error": "no session on that node"}).encode()

        try:
            token = await _login(console)
            _with_fleet(monkeypatch, _NoSession())
            channel = control.RemoteChannel(
                "ab" * 20, console._control_relay(token))
            reply = await asyncio.to_thread(channel.call, "pseudo.get")
            # Phrased as a refusal *of that node*, so nothing here reads it as
            # this console signing the operator out.
            assert reply.ok is False and reply.code == "unauthorized"
            assert "that node" in reply.error
        finally:
            console.stop()
            await node.stop()
