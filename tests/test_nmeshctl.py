"""
nmeshctl: the console from a terminal.

Against a real console where the property is about the wire — the pinned
certificate, the lasting session, the operations read from the catalogue — and
against a stand-in where it is about what the tool decides on its own: an
approval that may only narrow, a job waited out, a node named by its label.
"""
import asyncio
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from src.node import MeshNode
from src.webconsole import WebConsole
from tests.conftest import make_manager
from tests.test_webconsole import PW

_SPEC = importlib.util.spec_from_file_location(
    "nmeshctl", Path(__file__).resolve().parent.parent / "scripts" / "nmeshctl.py")
ctl = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ctl)


def run(*argv):
    """``(exit code, stdout, stderr)`` of one invocation."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = ctl.main(list(argv))
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("NMESH_CTL_CONFIG", str(tmp_path / "ctl" / "ctl.json"))
    monkeypatch.setenv("NMESH_PASSWORD", PW)
    monkeypatch.delenv("NMESH_CONSOLE_URL", raising=False)
    return tmp_path


async def _console(state):
    node = MeshNode(transport_manager=make_manager())
    console = WebConsole(node, host="127.0.0.1", port=0, use_tls=True,
                         password=PW, state_dir=state)
    console.start(loop=asyncio.get_running_loop())
    return node, console


class TestAgainstARealConsole:
    async def test_sign_in_drive_and_sign_out(self, home, monkeypatch):
        with tempfile.TemporaryDirectory() as state:
            monkeypatch.setenv("NMESH_DATA", state)    # the cert is readable here
            node, console = await _console(state)
            url = f"https://127.0.0.1:{console.port}"
            try:
                code, out, err = await asyncio.to_thread(
                    run, "login", "--url", url, "--for", "1h")
                assert code == 0, err
                config = json.loads(Path(ctl.config_path()).read_text())
                assert config["fingerprint"] == console.cert_fingerprint
                assert stat.S_IMODE(os.stat(ctl.config_path()).st_mode) == 0o600

                code, out, err = await asyncio.to_thread(run, "node", "state",
                                                         "--json")
                assert code == 0, err
                assert json.loads(out)["id"] == node.id.raw.hex()

                code, out, _ = await asyncio.to_thread(run, "ops", "node")
                assert code == 0 and "node state" in out

                code, out, _ = await asyncio.to_thread(run, "status")
                assert code == 0 and "until" in out

                token = config["token"]
                code, _, _ = await asyncio.to_thread(run, "logout")
                assert code == 0
                assert not console._valid_token(token)
                code, _, err = await asyncio.to_thread(run, "node", "state")
                assert code == ctl.EXIT_SIGNED_OUT
            finally:
                console.stop()
                await node.stop()

    async def test_a_certificate_that_changed_is_never_spoken_to(self, home,
                                                                 monkeypatch):
        with tempfile.TemporaryDirectory() as state:
            monkeypatch.setenv("NMESH_DATA", state)
            node, console = await _console(state)
            url = f"https://127.0.0.1:{console.port}"
            try:
                assert (await asyncio.to_thread(run, "login", "--url", url))[0] == 0
                config = json.loads(Path(ctl.config_path()).read_text())
                config["fingerprint"] = "00" * 32
                ctl.save_config(config)
                code, _, err = await asyncio.to_thread(run, "node", "state")
                assert code == ctl.EXIT_FAILED
                assert "not the one pinned" in err
            finally:
                console.stop()
                await node.stop()

    async def test_an_unverifiable_certificate_is_asked_about(self, home,
                                                              monkeypatch):
        with tempfile.TemporaryDirectory() as state:
            monkeypatch.delenv("NMESH_DATA", raising=False)
            monkeypatch.setattr(ctl, "STATE_DIRS", ())
            monkeypatch.setattr("builtins.input", lambda _prompt: "n")
            node, console = await _console(state)
            try:
                code, _, err = await asyncio.to_thread(
                    run, "login", "--url", f"https://127.0.0.1:{console.port}")
                assert code == ctl.EXIT_FAILED and "not signed in" in err
                assert not Path(ctl.config_path()).exists()
                code, _, _ = await asyncio.to_thread(
                    run, "login", "--url", f"https://127.0.0.1:{console.port}",
                    "--fingerprint", console.cert_fingerprint)
                assert code == 0
            finally:
                console.stop()
                await node.stop()

    async def test_the_wrong_password_signs_nobody_in(self, home, monkeypatch):
        with tempfile.TemporaryDirectory() as state:
            monkeypatch.setenv("NMESH_DATA", state)
            monkeypatch.setenv("NMESH_PASSWORD", "not-the-password")
            node, console = await _console(state)
            try:
                code, _, err = await asyncio.to_thread(
                    run, "login", "--url", f"https://127.0.0.1:{console.port}")
                assert code == ctl.EXIT_FAILED and "invalid password" in err
            finally:
                console.stop()
                await node.stop()


class TestArguments:
    ROW = {"name": "save", "params": [
        {"name": "settings", "kind": "document"},
        {"name": "seconds", "kind": "count"},
        {"name": "events", "kind": "flag"},
        {"name": "node", "kind": "node"}]}

    def test_every_spelling_lands_on_the_declared_name(self):
        params = ctl.bind_arguments(self.ROW, [
            "--settings", '{"pseudo": "box"}', "--seconds=30", "--events",
            "node=" + "ab" * 20])
        assert params == {"settings": {"pseudo": "box"}, "seconds": 30,
                          "events": True, "node": "ab" * 20}

    def test_a_name_the_operation_does_not_take_is_refused_here(self):
        with pytest.raises(ctl.CtlError) as refused:
            ctl.bind_arguments(self.ROW, ["--setings", "{}"])
        assert refused.value.code == ctl.EXIT_USAGE

    def test_a_value_of_the_wrong_kind_is_refused_here(self):
        for words in (["--seconds", "ten"], ["--settings", "{nope"],
                      ["--events=maybe"]):
            with pytest.raises(ctl.CtlError):
                ctl.bind_arguments(self.ROW, words)

    def test_durations(self):
        assert ctl.parse_duration("8h") == 8 * 3600
        assert ctl.parse_duration("30m") == 1800
        assert ctl.parse_duration("1d") == 86400
        assert ctl.parse_duration("90") == 90
        with pytest.raises(ctl.CtlError):
            ctl.parse_duration("forever")

    def test_plain_http_only_on_this_machine(self):
        ctl.Console("http://127.0.0.1:8787")
        with pytest.raises(ctl.CtlError):
            ctl.Console("http://192.168.1.5:8787")

    def test_json_anywhere_and_node_only_before_the_command(self, monkeypatch):
        seen = {}

        def operation(args, console):
            seen.update(words=args.words, json=args.json, node=args.node)
            return 0

        monkeypatch.setattr(ctl, "cmd_operation", operation)
        monkeypatch.setattr(ctl, "signed_in", lambda: object())
        assert run("node", "ping", "--node", "ab" * 20, "--json")[0] == 0
        # After the command, --node is the operation's own argument.
        assert seen == {"words": ["node", "ping", "--node", "ab" * 20],
                        "json": True, "node": None}


class _Fake:
    """A console that answers from a dict and remembers what it was sent."""

    def __init__(self, state=None, frames=None):
        self.state = state or {}
        self.frames = list(frames or [])
        self.posts = []
        self.node = None
        self.then = None

    def request(self, method, path, body=None, **_kw):
        if path == "/api/fleet/state":
            return 200, self.state
        if path == "/api/remote/targets":
            return 200, {"available": True, "targets": self.state.get("targets", [])}
        self.posts.append((path, body))
        return 200, {"ok": True}

    def frame(self, op, params=None, **_kw):
        self.posts.append((op, params))
        return self.frames.pop(0)


CAPS = [{"name": n, "description": n} for n in
        ("status", "manage", "apps", "full", "shell")]


def _fleet(console, *words):
    args = ctl.build_parser().parse_args(["fleet", *words])
    args.caps = list(args.caps or []) + ctl._caps([args.caps_opt])
    return ctl.cmd_fleet(args, console)


class TestFleetRights:
    def _asking(self):
        return {"capabilities": CAPS, "operators": [], "managed": [],
                "pending_in": [{"id": "ab" * 20, "label": "laptop",
                                "caps": ["status", "manage"], "have": []}]}

    def test_an_approval_can_only_narrow(self, capsys):
        console = _Fake(self._asking())
        with pytest.raises(ctl.CtlError) as refused:
            _fleet(console, "approve", "laptop", "--caps", "status,shell")
        assert "only narrow" in str(refused.value)
        assert console.posts == []
        assert _fleet(console, "approve", "laptop", "status") == 0
        assert console.posts == [("/api/fleet/approve",
                                  {"node": "ab" * 20, "caps": ["status"]})]

    def test_approving_with_no_list_grants_what_was_asked(self):
        console = _Fake(self._asking())
        _fleet(console, "approve", "abab")
        assert console.posts[0][1]["caps"] == ["status", "manage"]

    def test_an_unknown_capability_is_refused_not_dropped(self):
        console = _Fake(self._asking())
        with pytest.raises(ctl.CtlError) as refused:
            _fleet(console, "approve", "laptop", "statsu")
        assert "unknown capability" in str(refused.value)

    def test_grant_sets_adds_and_removes(self):
        state = {"capabilities": CAPS, "pending_in": [], "managed": [],
                 "operators": [{"id": "cd" * 20, "label": "ops",
                                "caps": ["status", "manage"]}]}
        console = _Fake(state)
        _fleet(console, "grant", "ops", "full")
        _fleet(console, "grant", "ops", "apps", "--add")
        _fleet(console, "grant", "ops", "manage", "--remove")
        assert [body["caps"] for _, body in console.posts] == [
            ["full"], ["status", "manage", "apps"], ["status"]]

    def test_grant_never_creates_an_operator_nobody_asked_for(self):
        console = _Fake({"capabilities": CAPS, "pending_in": [], "managed": [],
                         "operators": []})
        with pytest.raises(ctl.CtlError):
            _fleet(console, "grant", "ef" * 20, "full")
        assert console.posts == []


class TestJobsAreWaitedOut:
    def test_a_long_operation_becomes_a_job_and_its_answer_comes_back(
            self, monkeypatch):
        monkeypatch.setattr(ctl, "JOB_POLL", 0)
        console = _Fake(frames=[
            {"ok": False, "code": "refused", "error": "start it as a job",
             "detail": {"background": True, "job": "releases.install"}},
            {"ok": True, "result": {"job": "j1"}},
            {"ok": True, "result": {"state": "running"}},
            {"ok": True, "result": {"state": "done", "result": {"installed": 1}}},
        ])
        out = ctl.run_operation(console, "releases.install", {"x": 1}, None,
                                quiet=True)
        assert out == {"installed": 1}
        assert console.posts[1] == ("jobs.start", {"op": "releases.install",
                                                   "params": {"x": 1}})

    def test_a_job_that_failed_reads_like_a_refusal(self, monkeypatch):
        monkeypatch.setattr(ctl, "JOB_POLL", 0)
        console = _Fake(frames=[
            {"ok": False, "detail": {"background": True}},
            {"ok": True, "result": {"job": "j1"}},
            {"ok": True, "result": {"state": "failed", "code": "conflict",
                                    "error": "nothing to install"}},
        ])
        with pytest.raises(ctl.CtlError) as failed:
            ctl.run_operation(console, "releases.install", {}, None, quiet=True)
        assert "conflict: nothing to install" in str(failed.value)


class TestNamingANode:
    TARGETS = [{"id": "ab" * 20, "label": "web", "pseudo": "WebBox"},
               {"id": "abcd" + "00" * 18, "label": "", "pseudo": "Db"}]

    def test_by_label_name_or_prefix(self):
        console = _Fake({"targets": self.TARGETS})
        assert ctl.resolve_node(console, "web")["id"] == "ab" * 20
        assert ctl.resolve_node(console, "db")["id"] == "abcd" + "00" * 18
        assert ctl.resolve_node(console, "abcd00")["id"] == "abcd" + "00" * 18

    def test_a_name_for_two_nodes_is_not_a_guess(self):
        twins = [{"id": "ab" * 20, "label": "web"}, {"id": "cd" * 20, "label": "web"}]
        with pytest.raises(ctl.CtlError) as ambiguous:
            ctl.resolve_node(_Fake({"targets": twins}), "web")
        assert ambiguous.value.code == ctl.EXIT_USAGE
        console = _Fake({"targets": self.TARGETS})
        with pytest.raises(ctl.CtlError) as unknown:
            ctl.resolve_node(console, "nobody")
        assert "no node" in str(unknown.value)


class TestDrivingAnotherNode:
    def _main(self, monkeypatch, targets, *argv):
        console = _Fake({"targets": targets})
        seen = {}

        def operation(args, given):
            seen.update(node=given.node, then=given.then)
            return 0

        monkeypatch.setattr(ctl, "signed_in", lambda: console)
        monkeypatch.setattr(ctl, "cmd_operation", operation)
        return run(*argv), seen, console

    def test_the_node_is_named_and_its_session_opened_without_a_password(
            self, monkeypatch):
        targets = [{"id": "ab" * 20, "label": "web", "passwordless": True,
                    "connected": False, "caps": ["manage", "passwordless"]}]
        (code, _, err), seen, console = self._main(
            monkeypatch, targets, "--node", "web", "node", "state")
        assert code == 0, err
        assert seen == {"node": "ab" * 20, "then": None}
        assert ("/api/remote/connect", {"node": "ab" * 20, "password": None}) \
            in console.posts

    def test_reaching_on_needs_that_nodes_full_grant(self, monkeypatch):
        targets = [{"id": "ab" * 20, "label": "web", "connected": True,
                    "caps": ["manage"]}]
        (code, _, err), seen, _ = self._main(
            monkeypatch, targets, "--node", "web", "--then", "cd" * 20,
            "node", "state")
        assert code == ctl.EXIT_FAILED and "full" in err
        targets[0]["caps"] = ["manage", "full"]
        (code, _, err), seen, _ = self._main(
            monkeypatch, targets, "--node", "web", "--then", "cd" * 20,
            "node", "state")
        assert code == 0, err
        assert seen == {"node": "ab" * 20, "then": "cd" * 20}
