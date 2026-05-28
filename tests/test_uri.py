import pytest
from src.uri import _validate_uri


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
