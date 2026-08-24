"""Le ticket de join compact.

Il voyage sur un écran, un bout de papier, une photo. Tout ce qui revient doit
donc être traité comme hostile, et rien ne doit pouvoir lever autre chose qu'une
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
        """34 caractères : dictable, tapable sur un téléphone, et un QR de
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
        """Base32 est insensible à la casse pour que le ticket puisse être
        dicté et retapé."""
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
    """Rien ne doit lever autre chose qu'une TicketError."""

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
        """Le checksum n'est pas une protection contre un attaquant — il
        recalculerait — mais il attrape une faute de frappe avant qu'on
        compose quoi que ce soit."""
        text = a_ticket()
        caught = 0
        for index in range(len(text)):
            other = "B" if text[index] != "B" else "C"
            broken = text[:index] + other + text[index + 1:]
            try:
                jt.decode(broken)
            except jt.TicketError:
                caught += 1
        assert caught >= len(text) - 2      # quasi toutes, à la marge du hasard

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
        """Un ticket porte une adresse, jamais un nom : un nom demanderait un
        résolveur côté scanner et pourrait pointer ailleurs plus tard."""
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
