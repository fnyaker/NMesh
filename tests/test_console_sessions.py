"""
Sessions a command line keeps across the node's restarts (`nmeshctl login`).

The property that matters: a session asked for "eight hours" survives the
restart every update ends in, ends on the date it was given, and is gone the
moment its holder signs out or the password changes. And the file it lives in
says nothing a reader could sign in with.
"""
import asyncio
import json
import os
import stat
import tempfile
import time

from src import console_sessions as cs
from src.node import MeshNode
from src.webconsole import WebConsole
from tests.conftest import make_manager
from tests.test_webconsole import PW, _request


class TestLastingSessions:
    def test_a_session_outlives_the_object_that_issued_it(self, tmp_path):
        path = str(tmp_path / cs.FILENAME)
        token, until = cs.LastingSessions(path).issue(3600, "laptop")
        again = cs.LastingSessions(path)
        assert again.valid(token)
        assert abs(again.deadline(token) - until) < 1

    def test_the_file_holds_no_token_and_nobody_else_reads_it(self, tmp_path):
        path = str(tmp_path / cs.FILENAME)
        token, _ = cs.LastingSessions(path).issue(3600)
        raw = open(path).read()
        assert token not in raw
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_it_ends_on_its_date_and_does_not_slide(self, tmp_path, monkeypatch):
        sessions = cs.LastingSessions(str(tmp_path / cs.FILENAME))
        token, until = sessions.issue(cs.MIN_SECONDS)
        for _ in range(3):
            assert sessions.valid(token)
        assert sessions.deadline(token) == until       # using it moved nothing
        monkeypatch.setattr(cs.time, "time", lambda: until + 1)
        assert not sessions.valid(token)

    def test_a_lifetime_is_held_inside_its_bounds(self):
        assert cs.clamp_seconds(1) == cs.MIN_SECONDS
        assert cs.clamp_seconds(10 ** 9) == cs.MAX_SECONDS
        assert cs.clamp_seconds("eight hours") == cs.DEFAULT_SECONDS
        assert cs.clamp_seconds(None) == cs.DEFAULT_SECONDS

    def test_revoking_one_leaves_the_others(self, tmp_path):
        sessions = cs.LastingSessions(str(tmp_path / cs.FILENAME))
        kept, _ = sessions.issue(3600)
        gone, _ = sessions.issue(3600)
        assert sessions.revoke(gone)
        assert not sessions.valid(gone) and sessions.valid(kept)
        assert not cs.LastingSessions(str(tmp_path / cs.FILENAME)).valid(gone)

    def test_all_but_one(self, tmp_path):
        sessions = cs.LastingSessions(str(tmp_path / cs.FILENAME))
        tokens = [sessions.issue(3600)[0] for _ in range(4)]
        assert sessions.revoke_all_except(tokens[1]) == 3
        assert [sessions.valid(t) for t in tokens] == [False, True, False, False]

    def test_bounded_oldest_first(self, tmp_path):
        sessions = cs.LastingSessions(str(tmp_path / cs.FILENAME))
        tokens = [sessions.issue(3600)[0] for _ in range(cs.MAX_SESSIONS + 3)]
        assert not any(sessions.valid(t) for t in tokens[:3])
        assert all(sessions.valid(t) for t in tokens[3:])
        assert len(sessions.overview()) == cs.MAX_SESSIONS

    def test_a_hostile_file_is_read_as_nothing(self, tmp_path):
        path = str(tmp_path / cs.FILENAME)
        for content in (b"{not json", b"[" + b"1," * 50000 + b"1]", b'{"h": 1}',
                        json.dumps([{"h": "zz" * 32, "until": time.time() + 60}]
                                   ).encode()):
            with open(path, "wb") as handle:
                handle.write(content)
            assert cs.LastingSessions(path).overview() == []

    def test_a_deadline_no_login_could_have_asked_for_is_not_believed(self, tmp_path):
        """A file edited to keep somebody signed in for a year: the bound is
        checked on the way in, not only when the session was issued."""
        path = str(tmp_path / cs.FILENAME)
        token, _ = cs.LastingSessions(path).issue(3600)
        rows = json.load(open(path))
        rows[0]["until"] = time.time() + 365 * 86400
        json.dump(rows, open(path, "w"))
        assert not cs.LastingSessions(path).valid(token)

    def test_without_a_state_directory_it_still_honours_what_it_issued(self):
        sessions = cs.LastingSessions(None)
        token, _ = sessions.issue(3600)
        assert sessions.valid(token)

    def test_the_overview_shows_no_secret(self, tmp_path):
        sessions = cs.LastingSessions(str(tmp_path / cs.FILENAME))
        token, _ = sessions.issue(3600, "ops\x00box")
        row = sessions.overview()[0]
        assert set(row) == {"label", "made", "expires_at"}
        assert row["label"] == "opsbox"
        assert token not in json.dumps(row)


async def _console(state_dir):
    node = MeshNode(transport_manager=make_manager())
    console = WebConsole(node, host="127.0.0.1", port=0, use_tls=False,
                         password=PW, state_dir=state_dir)
    console.start(loop=asyncio.get_running_loop())
    return node, console


async def _lasting_login(console, seconds=3600):
    status, headers, _, body = await asyncio.to_thread(
        _request, console, "POST", "/api/login", None,
        {"password": PW, "for": seconds, "label": "test"})
    return status, headers, body


class TestTheConsoleKeepsThem:
    async def test_a_lasting_session_survives_a_restart(self):
        with tempfile.TemporaryDirectory() as state:
            node, console = await _console(state)
            try:
                status, headers, body = await _lasting_login(console)
                assert status == 200 and body["expires_at"] > time.time()
                # No cookie: a tab never asks for this, and must not be handed it.
                assert "set-cookie" not in headers
                token = body["token"]
            finally:
                console.stop()
            node2 = MeshNode(transport_manager=make_manager())
            again = WebConsole(node2, host="127.0.0.1", port=0, use_tls=False,
                               password=PW, state_dir=state)
            again.start(loop=asyncio.get_running_loop())
            try:
                status, _, _, answer = await asyncio.to_thread(
                    _request, again, "GET", "/api/session", token)
                assert status == 200 and answer["lasting"] is True
                status, _, _, _ = await asyncio.to_thread(
                    _request, again, "GET", "/api/state", token)
                assert status == 200
            finally:
                again.stop()
                await node.stop()
                await node2.stop()

    async def test_signing_out_ends_it_for_good(self):
        with tempfile.TemporaryDirectory() as state:
            node, console = await _console(state)
            try:
                _, _, body = await _lasting_login(console)
                token = body["token"]
                await asyncio.to_thread(_request, console, "POST", "/api/logout",
                                        token, {})
                status, _, _, _ = await asyncio.to_thread(
                    _request, console, "GET", "/api/state", token)
                assert status == 401
                assert not cs.LastingSessions(cs.path_for(state)).valid(token)
            finally:
                console.stop()
                await node.stop()

    async def test_a_password_change_ends_every_other_one(self):
        with tempfile.TemporaryDirectory() as state:
            node, console = await _console(state)
            try:
                _, _, mine = await _lasting_login(console)
                _, _, theirs = await _lasting_login(console)
                status, _, _, _ = await asyncio.to_thread(
                    _request, console, "POST", "/api/password", mine["token"],
                    {"current": PW, "new": "another-long-password"})
                assert status == 200
                ok = await asyncio.to_thread(_request, console, "GET",
                                             "/api/state", mine["token"])
                gone = await asyncio.to_thread(_request, console, "GET",
                                               "/api/state", theirs["token"])
                assert ok[0] == 200 and gone[0] == 401
            finally:
                console.stop()
                await node.stop()

    async def test_a_browser_session_is_not_a_lasting_one(self):
        with tempfile.TemporaryDirectory() as state:
            node, console = await _console(state)
            try:
                status, _, _, body = await asyncio.to_thread(
                    _request, console, "POST", "/api/login", None, {"password": PW})
                assert status == 200
                _, _, _, answer = await asyncio.to_thread(
                    _request, console, "GET", "/api/session", body["token"])
                assert answer["lasting"] is False and answer["expires_at"] is None
                assert not os.path.exists(cs.path_for(state))
            finally:
                console.stop()
                await node.stop()

    async def test_the_wrong_password_buys_no_lasting_session(self):
        with tempfile.TemporaryDirectory() as state:
            node, console = await _console(state)
            try:
                status, _, _, _ = await asyncio.to_thread(
                    _request, console, "POST", "/api/login", None,
                    {"password": "nope", "for": 3600})
                assert status == 401
                assert cs.LastingSessions(cs.path_for(state)).overview() == []
            finally:
                console.stop()
                await node.stop()
