"""
A setting saved from the console is in force when the console says it is.

The configuration page used to say "nothing here changes a running node", and
that was true of every field — including the ones the node had been able to
change live all along through other pages. Now each setting says which it is
(`config.LIVE`), the live ones are applied to the running node before the file
is written, and the answer names the ones that still wait for a restart. These
tests hold the three claims that makes:

* every setting marked live has something that applies it, and nothing applies
  a setting that is not marked — a console promising what the node never does
  is the bug this exists to remove;
* a live setting saved is a live setting changed, on a real node;
* the restart list is exactly what changed and is not live.

And the consumption/performance bar (`src/power.py`), which is only a set of
live settings chosen together — so it is held to the same rules.
"""
import asyncio
import os
import tempfile

import pytest

from src import config as node_config
from src import control, mlo, power
from src.control.modules import settings as settings_module
from src.node import MeshNode
from tests.conftest import make_manager


def _channel(node, path):
    context = control.Context(node=node, loop=asyncio.get_running_loop(),
                              config_path=path)
    return control.LocalChannel(control.build(context))


async def _call(channel, op, params):
    # From a thread, like the console's server: an operation that touches the
    # node marshals onto its loop and waits for it.
    return await asyncio.to_thread(channel.call, op, params)


class TestTheListsAgree:
    def test_every_live_setting_is_applied_and_nothing_else_is(self):
        applied = set()
        for group in settings_module.LIVE_GROUPS:
            applied.update(group)
        assert applied == set(node_config.LIVE)

    def test_every_live_setting_is_a_setting_the_console_may_write(self):
        for name in node_config.LIVE:
            assert name in node_config.SETTINGS, name
            assert node_config.SETTINGS[name][2] is True, name

    def test_the_console_is_told_which_is_which(self):
        shown = {row["name"]: row["live"]
                 for row in node_config.public(node_config.defaults())}
        assert shown["mlo_always"] is True
        assert shown["console_port"] is False
        assert shown["listen"] is False


class TestSavingAppliesWhatItCan:
    async def test_a_live_setting_is_in_force_once_saved(self):
        node = MeshNode(transport_manager=make_manager())
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = os.path.join(directory, "nmesh.conf")
                channel = _channel(node, path)
                reply = await _call(channel, "config.save", {"settings": {
                    "mlo_always": True, "dynamic_address": True,
                    "transport_balance": 70, "update_check_minutes": 60,
                    "update_when_active": True, "no_abuse_gossip": True,
                    "route_hold_minutes": 3}})
                assert reply.ok, reply.error
                assert reply.result["restart_required"] is False
                assert reply.result["pending"] == []
                assert node._mlo_always is True
                assert node.dynamic_address is True
                assert node.transport_balance == 70
                assert node._update_check_seconds == 3600
                assert node._update_when_active is True
                assert node._gossip_abuse is False
                assert node._route_hold == 180
                stored, problems = node_config.load(path)
                assert problems == []
                assert stored["mlo_always"] is True
        finally:
            await node.stop()

    async def test_only_what_changed_and_is_not_live_waits(self):
        node = MeshNode(transport_manager=make_manager())
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = os.path.join(directory, "nmesh.conf")
                channel = _channel(node, path)
                reply = await _call(channel, "config.save", {"settings": {
                    "console_port": 9443, "mlo_always": True,
                    # Unchanged from the default: not a reason to restart.
                    "listen": "0.0.0.0:9000"}})
                assert reply.ok, reply.error
                assert reply.result["pending"] == ["console_port"]
                assert reply.result["applied"] == ["mlo_always"]
                assert reply.result["restart_required"] is True
        finally:
            await node.stop()

    async def test_the_keepalive_bounds_move_together(self):
        """Applied one at a time, each bound is clamped against its old
        neighbours and the four land somewhere neither set describes."""
        node = MeshNode(transport_manager=make_manager())
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = os.path.join(directory, "nmesh.conf")
                channel = _channel(node, path)
                wanted = (2000, 5000, 60000, 120000)
                reply = await _call(channel, "config.save", {"settings": dict(zip(
                    ("keepalive_fast_min_ms", "keepalive_fast_max_ms",
                     "keepalive_slow_min_ms", "keepalive_slow_max_ms"), wanted))})
                assert reply.ok, reply.error
                assert node.keepalive_bounds().as_tuple() == wanted
        finally:
            await node.stop()

    async def test_bounds_typed_out_of_order_are_stored_as_they_run(self):
        """The node sorts them into shape; the file records what is running,
        not what was typed, or the next start would disagree with this one."""
        node = MeshNode(transport_manager=make_manager())
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = os.path.join(directory, "nmesh.conf")
                channel = _channel(node, path)
                reply = await _call(channel, "config.save", {"settings": {
                    "keepalive_fast_min_ms": 30000}})
                assert reply.ok, reply.error
                running = node.keepalive_bounds().as_tuple()
                assert list(running) == sorted(running)
                stored, _ = node_config.load(path)
                assert (stored["keepalive_fast_min_ms"], stored["keepalive_fast_max_ms"],
                        stored["keepalive_slow_min_ms"],
                        stored["keepalive_slow_max_ms"]) == running
        finally:
            await node.stop()

    async def test_a_refused_value_applies_nothing_either(self):
        node = MeshNode(transport_manager=make_manager())
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = os.path.join(directory, "nmesh.conf")
                channel = _channel(node, path)
                reply = await _call(channel, "config.save", {"settings": {
                    "mlo_always": True, "console_port": 99999}})
                assert reply.ok is False and reply.code == "bad_request"
                assert node._mlo_always is False
                assert not os.path.exists(path)
        finally:
            await node.stop()


class TestTheProfiles:
    def test_the_default_is_a_step(self):
        """A node nobody touched reads as a step, not as "custom"."""
        assert power.match(node_config.defaults()) == 6

    def test_there_are_ten_and_each_is_distinct(self):
        assert sorted(power.PROFILES) == list(range(1, 11))
        rows = [power.PROFILES[step][2] for step in power.PROFILES]
        assert len(set(rows)) == len(rows)
        for step in power.PROFILES:
            assert power.match(power.values_for(step)) == step

    def test_a_profile_only_moves_live_settings(self):
        """A bar that moved and changed nothing until a restart would be lying
        to whoever moved it."""
        assert set(power.FIELDS) <= set(node_config.LIVE)

    def test_every_profile_is_a_declaration_a_correct_node_could_mean(self):
        for step, (_name, text, row) in power.PROFILES.items():
            assert mlo.well_formed(*row[:4]), step
            assert text and len(text) < 260, step
            values = power.values_for(step)
            for name, value in values.items():
                assert node_config.validate(name, value) == value, (step, name)

    def test_the_bar_runs_from_spending_least_to_spending_most(self):
        """Read as the operator reads it: each step to the right probes at
        least as often at rest, and never looks for updates less often."""
        previous = None
        for step in range(power.LOWEST, power.HIGHEST + 1):
            values = power.values_for(step)
            if previous is not None:
                assert values["keepalive_slow_min_ms"] <= previous["keepalive_slow_min_ms"]
                assert values["keepalive_fast_min_ms"] <= previous["keepalive_fast_min_ms"]
                assert values["update_check_minutes"] <= previous["update_check_minutes"]
                # A relay is kept no longer as the bar goes right; zero (spread
                # over every relay) is the far end of it.
                assert (values["route_hold_minutes"] == 0 or previous["route_hold_minutes"] == 0
                        or values["route_hold_minutes"] <= previous["route_hold_minutes"])
            previous = values

    def test_a_hand_tuned_node_is_custom(self):
        values = power.values_for(6)
        values["keepalive_slow_min_ms"] += 1
        assert power.match(values) is None
        assert power.match(None) is None
        assert power.match({"mlo_always": 1}) is None

    @pytest.mark.parametrize("bad", [0, 11, -1, "6.5", None, "", "x", 10 ** 9])
    def test_anything_but_a_step_is_refused(self, bad):
        with pytest.raises(ValueError):
            power.values_for(bad)

    async def test_choosing_a_step_applies_and_remembers_it(self):
        node = MeshNode(transport_manager=make_manager())
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = os.path.join(directory, "nmesh.conf")
                channel = _channel(node, path)
                reply = await _call(channel, "config.profile", {"step": 1})
                assert reply.ok, reply.error
                assert reply.result["profile"] == 1
                assert reply.result["restart_required"] is False
                assert node.keepalive_bounds().as_tuple() == (2000, 5000, 60000, 120000)
                assert node._update_check_seconds == 1440 * 60
                assert node._route_hold == 3600
                got = await _call(channel, "config.get", {})
                assert got.result["profile"] == 1

                reply = await _call(channel, "config.profile", {"step": 10})
                assert reply.ok and node._mlo_always is True
                assert node.dynamic_address is True
                # And moving a value by hand makes it custom, read off the file.
                await _call(channel, "config.save",
                            {"settings": {"keepalive_slow_min_ms": 3001}})
                got = await _call(channel, "config.get", {})
                assert got.result["profile"] is None
        finally:
            await node.stop()

    async def test_a_step_out_of_range_is_refused_before_anything_moves(self):
        node = MeshNode(transport_manager=make_manager())
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = os.path.join(directory, "nmesh.conf")
                channel = _channel(node, path)
                before = node.keepalive_bounds()
                reply = await _call(channel, "config.profile", {"step": 42})
                assert reply.ok is False and reply.code == "bad_request"
                assert node.keepalive_bounds() == before
                assert not os.path.exists(path)
        finally:
            await node.stop()

    async def test_a_node_with_no_file_still_takes_the_step(self):
        node = MeshNode(transport_manager=make_manager())
        try:
            channel = _channel(node, "")
            reply = await _call(channel, "config.profile", {"step": 9})
            assert reply.ok, reply.error
            assert reply.result["saved"] is False
            assert node._mlo_always is True
        finally:
            await node.stop()


class TestBoundsOutOfOrderFromAConsole:
    """`network.mlo` answered a fast floor above the fast ceiling by swapping
    the two and saying nothing; the operator found out by reading the bounds
    back. Refused now, with the order named. `config.save` keeps its own
    answer — it sorts and reports what it stored (above)."""

    async def test_network_mlo_refuses_them(self):
        node = MeshNode(transport_manager=make_manager())
        try:
            before = node.keepalive_bounds()
            channel = _channel(node, None)
            reply = await _call(channel, "network.mlo", {
                "keepalive_fast_min": 5000, "keepalive_fast_max": 1000})
            assert reply.ok is False and reply.code == "bad_request"
            assert "fast_min < fast_max" in reply.error
            assert node.keepalive_bounds() == before
        finally:
            await node.stop()

    async def test_in_order_they_are_applied(self):
        node = MeshNode(transport_manager=make_manager())
        try:
            channel = _channel(node, None)
            reply = await _call(channel, "network.mlo", {
                "keepalive_fast_min": 200, "keepalive_fast_max": 1500})
            assert reply.ok, reply.error
            bounds = node.keepalive_bounds()
            assert (bounds.fast_min, bounds.fast_max) == (200, 1500)
        finally:
            await node.stop()

    async def test_at_start_up_they_are_sorted_and_the_log_says_so(self):
        """A node that will not start over a hand-edited file is worse than
        one that runs the sorted values and says it did."""
        node = MeshNode(transport_manager=make_manager())
        try:
            node.logs.hold()
            node.set_keepalive_bounds(fast_min_ms=5000, fast_max_ms=1000)
            running = node.keepalive_bounds().as_tuple()
            assert list(running) == sorted(running)
            lines = [line for line in node.logs.query()["lines"]
                     if line["message"] == "keepalive bounds out of order: read as sorted"]
            assert len(lines) == 1
        finally:
            await node.stop()
