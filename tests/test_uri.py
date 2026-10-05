import pytest
import src.uri as uri_module
from src.uri import _validate_uri, uri_scheme


class TestValidUri:
    def test_valid_tcp(self):
        assert _validate_uri("tcp://192.168.1.5:9000") == ("tcp", "192.168.1.5:9000")

    def test_valid_ble(self):
        assert _validate_uri("ble://AA:BB:CC:DD:EE:FF") == ("ble", "AA:BB:CC:DD:EE:FF")

    def test_valid_ws(self):
        assert _validate_uri("ws://example.com/mesh") == ("ws", "example.com/mesh")

    def test_valid_lora(self):
        assert _validate_uri("lora://node42") == ("lora", "node42")

    def test_empty_opaque_accepted(self):
        assert _validate_uri("tcp://") == ("tcp", "")

    def test_scheme_16_chars_valid(self):
        assert _validate_uri("abcdefghijklmnop://host") is not None  # 16 chars

    def test_uppercase_scheme_rejected(self):
        assert _validate_uri("TCP://192.168.1.5:9000") is None

    def test_mixed_case_scheme_rejected(self):
        assert _validate_uri("Tcp://host") is None

    def test_no_scheme_rejected(self):
        assert _validate_uri("192.168.1.5:9000") is None

    def test_control_chars_rejected(self):
        assert _validate_uri("tcp://host\x00evil") is None
        assert _validate_uri("tcp://host\x1fevilhost") is None
        assert _validate_uri("tcp://host\x7fevil") is None

    def test_too_long_uri_rejected(self):
        long_uri = "tcp://" + "a" * 251  # total 257 bytes
        assert _validate_uri(long_uri) is None

    def test_exactly_256_bytes_accepted(self):
        uri = "tcp://" + "a" * 250  # 256 bytes exactly
        assert _validate_uri(uri) is not None

    def test_scheme_with_digit_first_rejected(self):
        assert _validate_uri("1tcp://host") is None

    def test_scheme_too_long_rejected(self):
        assert _validate_uri("abcdefghijklmnopq://host") is None  # 17 chars

    def test_no_separator_rejected(self):
        assert _validate_uri("tcp:host") is None
        assert _validate_uri("tcphost") is None


class TestTheSchemeMemo:
    """`uri_scheme` is asked per link per packet sent, and remembers. What it
    remembers comes from the network, so the memory has to be bounded and the
    answer has to be exactly what `_validate_uri` would have said."""

    @pytest.mark.parametrize("uri", [
        "tcp://192.168.1.5:9000", "lora://node42", "tcp:host", "1tcp://host",
        "tcp://host\x1fevil", "tcp://" + "a" * 251, "",
    ])
    def test_it_answers_what_the_validator_answers(self, uri):
        result = _validate_uri(uri)
        expected = None if result is None else result[0]
        assert uri_scheme(uri) == expected
        assert uri_scheme(uri) == expected          # …and again, from memory

    def test_a_string_too_long_to_be_valid_is_never_kept(self):
        for uri in ("tcp://" + "a" * 5000, "tcp://" + "\u00e9" * 251):
            assert uri_scheme(uri) is None
            assert len(uri) > uri_module._MAX_URI_LEN
            assert uri not in uri_module._scheme_memo

    def test_the_memory_is_bounded(self):
        for index in range(uri_module._SCHEME_MEMO_MAX * 3):
            uri_scheme(f"tcp://10.0.{index // 256}.{index % 256}:1")
        assert len(uri_module._scheme_memo) <= uri_module._SCHEME_MEMO_MAX
