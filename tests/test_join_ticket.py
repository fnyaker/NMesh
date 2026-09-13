"""Le ticket de join compact.

It travels on a screen, a scrap of paper, a photo. Everything that comes back
must therefore be treated as hostile, and nothing may raise anything other than a
`TicketError`.
"""
import time

import pytest

from src import join_ticket as jt

SEED = bytes(range(8))


def a_ticket(host="203.0.113.7", port=9000, seed=SEED, ttl=600):
    return jt.encode(host, port, seed, time.time() + ttl)


class TestRoundTrip:
    def test_an_ipv4_ticket_stays_short(self):
        """34 characters: dictable, typable on a phone, and a QR of
        version 2."""
        assert len(a_ticket()) == 34

    def test_it_carries_the_address_and_the_code(self):
        parsed = jt.decode(a_ticket())
        assert parsed["uri"] == "tcp://203.0.113.7:9000"
        assert parsed["code"] == jt.code_from_seed(SEED)

    def test_ipv6_works_too(self):
        parsed = jt.decode(a_ticket(host="2001:db8::1"))
        assert parsed["uri"] == "tcp://[2001:db8::1]:9000"

    def test_case_and_spacing_do_not_matter(self):
        """Base32 is case-insensitive so the ticket can be dictated and
        retyped."""
        text = a_ticket()
        spaced = text.lower()[:8] + " " + text.lower()[8:20] + "-" + text.lower()[20:]
        assert jt.decode(spaced)["uri"] == jt.decode(text)["uri"]

    def test_the_expiry_travels_with_it(self):
        parsed = jt.decode(a_ticket(ttl=600))
        assert parsed["expired"] is False
        assert abs(parsed["expires_at"] - (time.time() + 600)) < 120

    def test_an_expired_ticket_says_so(self):
        parsed = jt.decode(jt.encode("203.0.113.7", 9000, SEED, time.time() - 600))
        assert parsed["expired"] is True

    def test_the_code_is_derived_the_same_way_on_both_sides(self):
        assert jt.code_from_seed(SEED) == jt.code_from_seed(bytes(range(8)))
        assert jt.code_from_seed(SEED) != jt.code_from_seed(b"\xff" * 8)


class TestHostileInput:
    """Nothing may raise anything other than a TicketError."""

    @pytest.mark.parametrize("text", [
        "", "   ", "nonsense", "!!!!!!!!", "A", "=" * 40,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "0" * 34, "é" * 34,
    ])
    def test_junk_is_refused_cleanly(self, text):
        with pytest.raises(jt.TicketError):
            jt.decode(text)

    def test_a_non_string_is_refused(self):
        for value in (None, 42, b"bytes", [], {}):
            with pytest.raises(jt.TicketError):
                jt.decode(value)

    def test_an_over_long_string_is_refused_before_decoding(self):
        with pytest.raises(jt.TicketError):
            jt.decode("A" * (jt.MAX_TEXT + 1))

    def test_a_single_flipped_character_is_caught(self):
        """The checksum is no protection against an attacker — they would
        recompute it — but it catches a typo before we dial anything."""
        text = a_ticket()
        caught = 0
        for index in range(len(text)):
            other = "B" if text[index] != "B" else "C"
            broken = text[:index] + other + text[index + 1:]
            try:
                jt.decode(broken)
            except jt.TicketError:
                caught += 1
        assert caught >= len(text) - 2      # nearly all of them, at the margin of chance

    def test_a_truncated_ticket_is_refused(self):
        text = a_ticket()
        for cut in range(1, 20):
            with pytest.raises(jt.TicketError):
                jt.decode(text[:-cut])

    def test_random_bytes_never_raise_anything_else(self):
        import base64
        import random
        random.seed(99)
        for _ in range(500):
            blob = bytes(random.randrange(256) for _ in range(random.randrange(1, 40)))
            text = base64.b32encode(blob).decode().rstrip("=")
            try:
                jt.decode(text)
            except jt.TicketError:
                pass

    def test_an_unknown_version_is_refused(self):
        import base64
        text = a_ticket()
        raw = bytearray(base64.b32decode(text + "=" * (-len(text) % 8)))
        raw[0] = (9 << 4) | jt.FAMILY_V4         # version 9
        body = bytes(raw[:-jt.CHECK_BYTES])
        forged = base64.b32encode(body + jt._checksum(body)).decode().rstrip("=")
        with pytest.raises(jt.TicketError) as exc:
            jt.decode(forged)
        assert "version" in str(exc.value)


class TestEncodeRefusals:
    def test_a_hostname_is_refused(self):
        """A ticket carries an address, never a name: a name would need a
        resolver on the scanner's side and could point elsewhere later."""
        with pytest.raises(jt.TicketError):
            jt.encode("example.com", 9000, SEED, time.time() + 600)

    def test_a_bad_port_is_refused(self):
        for port in (0, -1, 65536, 999999):
            with pytest.raises(jt.TicketError):
                jt.encode("203.0.113.7", port, SEED, time.time() + 600)

    def test_a_wrong_seed_length_is_refused(self):
        with pytest.raises(jt.TicketError):
            jt.encode("203.0.113.7", 9000, b"\x00" * 4, time.time() + 600)


class TestTtlBounds:
    def test_a_silly_lifetime_is_brought_back_in_range(self):
        assert jt.clamp_ttl(10 ** 9) == jt.MAX_TTL
        assert jt.clamp_ttl(0) == jt.MIN_TTL
        assert jt.clamp_ttl(-5) == jt.MIN_TTL

    def test_nonsense_falls_back_to_the_default(self):
        assert jt.clamp_ttl("banana") == jt.DEFAULT_TTL
        assert jt.clamp_ttl(None) == jt.DEFAULT_TTL

    def test_a_sensible_lifetime_is_kept(self):
        assert jt.clamp_ttl(600) == 600.0


# ---------------------------------------------------------------------------
# Both routes in one string
# ---------------------------------------------------------------------------
#
# An invitation used to be either a ticket (direct only, useless if the inviter
# had no public address) or a block of base64 pasted between two consoles — and
# an operator had to know which situation they were in before they could invite
# anybody. One string carrying both removes that question, and the second
# exchange with it.

NODE = bytes(range(20))


class TestBothRoutes:
    def test_it_carries_a_direct_endpoint_and_a_relay(self):
        text = jt.encode("203.0.113.7", 9000, SEED, time.time() + 600,
                         relay=("198.51.100.4", 9100), node_id=NODE)
        parsed = jt.decode(text)
        assert parsed["uri"] == "tcp://203.0.113.7:9000"
        assert parsed["relay_uri"] == "tcp://198.51.100.4:9100"
        assert parsed["node"] == NODE.hex()
        assert parsed["code"] == jt.code_from_seed(SEED)

    def test_and_still_fits_somewhere_scannable(self):
        text = jt.encode("203.0.113.7", 9000, SEED, time.time() + 600,
                         relay=("198.51.100.4", 9100), node_id=NODE)
        assert len(text) <= 80, text

    def test_a_relay_only_ticket_has_no_direct_endpoint(self):
        """The case the whole thing exists for: an inviter with no address of
        its own."""
        text = jt.encode("", 0, SEED, time.time() + 600,
                         relay=("198.51.100.4", 9100), node_id=NODE)
        parsed = jt.decode(text)
        assert parsed["uri"] == "" and parsed["host"] == ""
        assert parsed["relay_uri"] == "tcp://198.51.100.4:9100"
        assert parsed["node"] == NODE.hex()

    def test_a_direct_only_ticket_names_no_relay(self):
        parsed = jt.decode(jt.encode("203.0.113.7", 9000, SEED,
                                     time.time() + 600))
        assert parsed["relay_uri"] == "" and parsed["node"] == ""

    def test_ipv6_on_either_side(self):
        text = jt.encode("2001:db8::1", 9000, SEED, time.time() + 600,
                         relay=("2001:db8::2", 9100), node_id=NODE)
        parsed = jt.decode(text)
        assert parsed["uri"] == "tcp://[2001:db8::1]:9000"
        assert parsed["relay_uri"] == "tcp://[2001:db8::2]:9100"
        mixed = jt.decode(jt.encode("203.0.113.7", 9000, SEED,
                                    time.time() + 600,
                                    relay=("2001:db8::2", 9100), node_id=NODE))
        assert mixed["host"] == "203.0.113.7"
        assert mixed["relay_host"] == "2001:db8::2"

    def test_a_relay_needs_the_inviters_identity(self):
        """A relayed invitation is routed to an identity, so the identity has to
        be in the string — there is nothing else to address it to."""
        for bad in (b"", b"\x00" * 19, b"\x00" * 21):
            with pytest.raises(jt.TicketError):
                jt.encode("203.0.113.7", 9000, SEED, time.time() + 600,
                          relay=("198.51.100.4", 9100), node_id=bad)

    def test_a_ticket_that_points_nowhere_is_refused(self):
        with pytest.raises(jt.TicketError):
            jt.encode("", 0, SEED, time.time() + 600)

    def test_a_flipped_character_is_still_caught(self):
        text = jt.encode("203.0.113.7", 9000, SEED, time.time() + 600,
                         relay=("198.51.100.4", 9100), node_id=NODE)
        for index in (1, len(text) // 2, len(text) - 3):
            broken = list(text)
            broken[index] = "A" if broken[index] != "A" else "B"
            with pytest.raises(jt.TicketError):
                jt.decode("".join(broken))

    def test_a_truncated_one_is_refused(self):
        text = jt.encode("203.0.113.7", 9000, SEED, time.time() + 600,
                         relay=("198.51.100.4", 9100), node_id=NODE)
        for cut in range(1, 12):
            with pytest.raises(jt.TicketError):
                jt.decode(text[:-cut])

    def test_random_bytes_never_raise_anything_else(self):
        import base64
        import random
        rng = random.Random(7)
        for _ in range(400):
            size = rng.randrange(14, 60)
            blob = bytes(rng.randrange(256) for _ in range(size))
            # Give it a valid checksum, so the parsing past it is what is tested
            # rather than the checksum catching everything first.
            blob = blob[:-2] + jt._checksum(blob[:-2])
            text = base64.b32encode(blob).decode().rstrip("=")
            try:
                jt.decode(text)
            except jt.TicketError:
                pass


class TestTheOldTicketStillReads:
    """Refusing to read a version 1 ticket would strand invitations already in
    somebody's hands."""

    def _v1(self, host="203.0.113.7", port=9000):
        import base64
        import ipaddress
        import struct
        address = ipaddress.ip_address(host)
        family = 4 if address.version == 4 else 6
        body = (bytes([(1 << 4) | family]) + address.packed
                + struct.pack("!H", port) + SEED
                + struct.pack("!I", int((time.time() + 600) // 60)))
        return base64.b32encode(body + jt._checksum(body)).decode().rstrip("=")

    def test_it_decodes_as_the_direct_only_case(self):
        parsed = jt.decode(self._v1())
        assert parsed["uri"] == "tcp://203.0.113.7:9000"
        assert parsed["relay_uri"] == "" and parsed["node"] == ""
        assert parsed["code"] == jt.code_from_seed(SEED)

    def test_ipv6_too(self):
        assert jt.decode(self._v1("2001:db8::1"))["uri"] == "tcp://[2001:db8::1]:9000"
