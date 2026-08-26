"""
Configuring a transport without the console knowing what a transport is.

A medium **declares** what it takes (`OPTIONS`); the coercion, the bounds, the
refusal messages and the rendering are written **once**. Adding a setting to a
transport is one line; adding a transport costs the console nothing.

This file checks both halves of the contract: what we accept, and above all what
we refuse — a setting is an external input like any other.
"""
import pytest

from src import config
from src.spool_transport import SpoolTransport
from src.tcp_transport import TCPTransport, TCPServer
from src.transport import BaseTransport, OptionError, coerce, option
from src.transport_manager import TransportManager, TransportError
from src.udp_transport import UDPTransport


@pytest.fixture(autouse=True)
def restore_settings():
    """Settings live on the class: one test must not leave them changed for the
    next."""
    saved = {cls: dict(cls.SETTINGS)
             for cls in (TCPTransport, UDPTransport, SpoolTransport)}
    yield
    for cls, values in saved.items():
        cls.SETTINGS = values


class TestCoercion:
    def test_a_boolean_takes_the_spellings_people_use(self):
        field = option("x", "bool", False, "")
        for raw in (True, "true", "yes", "on", "1"):
            assert coerce(field, raw) is True
        for raw in (False, "false", "no", "off", "0", ""):
            assert coerce(field, raw) is False
        with pytest.raises(OptionError):
            coerce(field, "maybe")

    def test_numbers_are_bounded_by_the_declaration(self):
        field = option("x", "float", 4.0, "", minimum=0.5, maximum=60.0)
        assert coerce(field, "2.5") == 2.5
        for bad, expected in (("nope", "number"), (999, "at most"), (0.1, "at least")):
            with pytest.raises(OptionError) as failure:
                coerce(field, bad)
            assert expected in str(failure.value)

    def test_a_number_that_is_not_one_is_refused(self):
        """`float("nan")` passes `float()` without being a usable number."""
        field = option("x", "float", 1.0, "")
        for bad in ("nan", "inf", "-inf"):
            with pytest.raises(OptionError):
                coerce(field, bad)

    def test_text_is_one_bounded_line(self):
        field = option("x", "text", "", "")
        assert coerce(field, "  192.168.1.2  ") == "192.168.1.2"
        with pytest.raises(OptionError):
            coerce(field, "a" * 300)
        # A value carrying a newline would split into two keys when the
        # configuration file is read back.
        with pytest.raises(OptionError):
            coerce(field, "one\ntwo")

    def test_a_choice_is_one_of_the_offered_values(self):
        field = option("x", "choice", "a", "",
                       choices=[{"value": "a"}, {"value": "b"}])
        assert coerce(field, "b") == "b"
        with pytest.raises(OptionError):
            coerce(field, "c")

    def test_a_multi_choice_accepts_a_list_or_a_line(self):
        field = option("x", "multi", [], "",
                       choices=[{"value": "ipv4"}, {"value": "ipv6"}])
        assert coerce(field, ["ipv4"]) == ["ipv4"]
        assert coerce(field, "ipv4, ipv6") == ["ipv4", "ipv6"]
        assert coerce(field, ["ipv4", "ipv4"]) == ["ipv4"]     # deduplicated
        with pytest.raises(OptionError):
            coerce(field, ["ipv4", "carrier-pigeon"])
        with pytest.raises(OptionError):
            coerce(field, ["ipv4"] * 100)


class Declaring(BaseTransport):
    OPTIONS = (
        option("timeout", "float", 4.0, "", minimum=1.0, maximum=10.0),
        option("loud", "bool", False, ""),
    )
    SETTINGS: dict = {}

    async def connect(self, address): ...
    async def listen(self, address): ...
    async def send(self, packet): ...
    async def receive(self): ...
    async def close(self): ...


class TestConfigure:
    def setup_method(self):
        Declaring.SETTINGS = {}

    def test_one_bad_field_does_not_throw_away_the_good_ones(self):
        result = Declaring.configure({"timeout": 5, "loud": "yes", "timeout2": 1})
        assert result["applied"] == {"timeout": 5.0, "loud": True}
        assert "unknown setting" in result["rejected"]["timeout2"]
        assert Declaring.setting("timeout") == 5.0

    def test_a_refused_value_leaves_the_old_one_in_place(self):
        Declaring.configure({"timeout": 5})
        result = Declaring.configure({"timeout": 99})
        assert result["applied"] == {}
        assert "at most" in result["rejected"]["timeout"]
        assert Declaring.setting("timeout") == 5.0

    def test_the_declaration_reports_what_is_in_force(self):
        Declaring.configure({"loud": True})
        fields = {field["name"]: field for field in Declaring.options()}
        assert fields["loud"]["value"] is True
        assert fields["loud"]["default"] is False
        assert fields["timeout"]["value"] == 4.0        # never touched → the default

    def test_settings_are_replaced_not_mutated(self):
        """A shared class dictionary is not a place to edit under a live
        link."""
        Declaring.configure({"loud": True})
        before = Declaring.SETTINGS
        Declaring.configure({"timeout": 2})
        assert Declaring.SETTINGS is not before
        assert before == {"loud": True}

    def test_a_transport_that_declares_nothing_is_not_a_problem(self):
        class Silent(Declaring):
            OPTIONS = ()
            SETTINGS: dict = {}
        assert Silent.options() == []
        assert Silent.configure({"anything": 1})["rejected"]


class TestThroughTheManager:
    def manager(self):
        manager = TransportManager()
        manager.register("tcp", TCPTransport, TCPServer)
        return manager

    def test_the_manager_only_passes_things_through(self):
        manager = self.manager()
        assert "tcp" in manager.options()
        result = manager.configure("tcp", {"connect_timeout": 9})
        assert result["applied"] == {"connect_timeout": 9.0}
        assert manager.settings() == {"tcp": {"connect_timeout": 9.0}}

    def test_only_what_differs_from_the_default_is_stored(self):
        manager = self.manager()
        manager.configure("tcp", {"nodelay": True})       # already the default
        assert manager.settings() == {}

    def test_an_unregistered_scheme_is_refused(self):
        with pytest.raises(TransportError):
            self.manager().configure("carrier-pigeon", {"x": 1})


class TestTheFileCarriesThemWithoutUnderstandingThem:
    def test_a_namespaced_key_is_parsed_and_kept_as_text(self):
        values, problems = config.parse(
            "listen = 0.0.0.0:9000\ntcp.connect_timeout = 9\nudp.max_reorder = 64\n")
        assert problems == []
        assert values["transports"] == {"tcp": {"connect_timeout": "9"},
                                        "udp": {"max_reorder": "64"}}

    def test_the_file_never_validates_a_transport_setting(self):
        """C'est le medium qui sait ; le fichier ne fait que transporter."""
        values, problems = config.parse("tcp.connect_timeout = banana\n")
        assert problems == []
        assert values["transports"]["tcp"]["connect_timeout"] == "banana"

    def test_a_malformed_key_is_reported_and_dropped(self):
        values, problems = config.parse("bad key.with space = 1\ntcp. = 2\n")
        assert len(problems) == 2
        assert "transports" not in values

    def test_the_section_is_bounded(self):
        text = "".join(f"t{i}.x = 1\n" for i in range(config.MAX_LIST * 2))
        values, problems = config.parse(text)
        assert len(values["transports"]) <= config.MAX_LIST
        assert problems
        text = "".join(f"tcp.x{i} = 1\n" for i in range(config.MAX_LIST * 2))
        values, problems = config.parse(text)
        assert len(values["transports"]["tcp"]) <= config.MAX_LIST

    def test_it_survives_a_round_trip(self):
        rendered = config.render({"transports": {"tcp": {"families": "ipv4",
                                                         "connect_timeout": "9"}}})
        assert config.parse(rendered)[0]["transports"] == {
            "tcp": {"families": "ipv4", "connect_timeout": "9"}}


class TestAtStartup:
    def loader(self):
        import importlib.util
        import os
        spec = importlib.util.spec_from_file_location(
            "nmesh_node_for_test",
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "scripts", "nmesh_node.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_a_mistyped_setting_is_reported_not_fatal(self):
        """A node that refuses to start because a timeout is mistyped is a worse
        outcome than a node running on its default."""
        module = self.loader()
        manager = TransportManager()
        manager.register("tcp", TCPTransport, TCPServer)
        problems = module._apply_transport_settings(manager, {
            "tcp": {"connect_timeout": "9", "nope": "1"},
            "carrier-pigeon": {"speed": "fast"},
        })
        assert TCPTransport.setting("connect_timeout") == 9.0
        assert any("nope" in line for line in problems)
        assert any("carrier-pigeon" in line for line in problems)


class TestTheTransportsActuallyUseThem:
    def test_tcp_reads_its_timeouts_where_they_are_used(self):
        TCPTransport.configure({"connect_timeout": 1.5, "read_timeout": 12.0})
        assert TCPTransport().setting("connect_timeout") == 1.5
        assert TCPTransport().setting("read_timeout") == 12.0

    def test_the_address_family_follows_the_multi_choice(self):
        import socket
        TCPTransport.configure({"families": ["ipv4"]})
        assert TCPTransport._family() == socket.AF_INET
        TCPTransport.configure({"families": ["ipv6"]})
        assert TCPTransport._family() == socket.AF_INET6
        TCPTransport.configure({"families": ["ipv4", "ipv6"]})
        assert TCPTransport._family() == socket.AF_UNSPEC

    def test_udp_liveness_follows_its_setting(self):
        import time

        from src.udp_transport import _ReliableLink
        link = _ReliableLink()
        link._last_recv_time = time.monotonic() - 30.0
        assert UDPTransport.configure({"keepalive_timeout": 20.0})["applied"]
        assert link.is_alive() is False          # silencieux depuis 30 s > 20 s
        UDPTransport.configure({"keepalive_timeout": 600.0})
        assert link.is_alive() is True
