import time
import hmac
import hashlib
from unittest.mock import patch
import pytest
from src.invite import InviteManager, compute_response


class TestGenerateCode:
    def test_code_is_10_chars(self):
        im = InviteManager()
        assert len(im.generate_code()) == 10

    def test_code_is_alphanumeric(self):
        im = InviteManager()
        assert im.generate_code().isalnum()

    def test_codes_are_unique(self):
        im = InviteManager()
        codes = {im.generate_code() for _ in range(20)}
        assert len(codes) == 20

    def test_has_code_after_generate(self):
        im = InviteManager()
        im.generate_code()
        assert im.has_code()

    def test_no_code_initially(self):
        assert not InviteManager().has_code()


class TestChallenge:
    def test_challenge_is_32_bytes(self):
        im = InviteManager()
        assert len(im.generate_challenge()) == 32

    def test_challenges_are_unique(self):
        im = InviteManager()
        assert im.generate_challenge() != im.generate_challenge()


class TestVerifyResponse:
    def test_correct_response_accepted(self):
        im = InviteManager()
        code = im.generate_code()
        challenge = im.generate_challenge()
        response = compute_response(code, challenge)
        assert im.verify_response(challenge, response)

    def test_wrong_response_rejected(self):
        im = InviteManager()
        im.generate_code()
        challenge = im.generate_challenge()
        assert not im.verify_response(challenge, b"wrong")

    def test_no_code_rejects_all(self):
        im = InviteManager()
        challenge = im.generate_challenge()
        response = compute_response("anycode", challenge)
        assert not im.verify_response(challenge, response)

    def test_single_use(self):
        im = InviteManager()
        code = im.generate_code()
        challenge = im.generate_challenge()
        response = compute_response(code, challenge)
        assert im.verify_response(challenge, response)
        im.consume(challenge, response)
        assert not im.verify_response(challenge, response)

    def test_multiple_codes_each_single_use(self):
        im = InviteManager()
        code1 = im.generate_code()
        code2 = im.generate_code()
        challenge = im.generate_challenge()
        r1 = compute_response(code1, challenge)
        r2 = compute_response(code2, challenge)
        assert im.verify_response(challenge, r1)
        assert im.verify_response(challenge, r2)
        im.consume(challenge, r1)
        assert not im.verify_response(challenge, r1)
        assert im.verify_response(challenge, r2)


class TestExpiry:
    def test_code_valid_within_5_minutes(self):
        im = InviteManager()
        code = im.generate_code()
        challenge = im.generate_challenge()
        response = compute_response(code, challenge)
        assert im.verify_response(challenge, response)

    def test_code_expired_after_5_minutes(self):
        im = InviteManager()
        code = im.generate_code()
        challenge = im.generate_challenge()
        response = compute_response(code, challenge)
        with patch('src.invite.time') as mock_time:
            mock_time.return_value = time.time() + 301
            assert not im.verify_response(challenge, response)


class TestRateLimit:
    def test_not_locked_initially(self):
        assert not InviteManager().is_locked_out()

    def test_not_locked_after_2_failures(self):
        im = InviteManager()
        im.record_failure()
        im.record_failure()
        assert not im.is_locked_out()

    def test_locked_after_3_failures(self):
        im = InviteManager()
        for _ in range(3):
            im.record_failure()
        assert im.is_locked_out()

    def test_lockout_expires_after_60s(self):
        im = InviteManager()
        for _ in range(3):
            im.record_failure()
        with patch('src.invite.time') as mock_time:
            mock_time.return_value = time.time() + 61
            assert not im.is_locked_out()

    def test_verify_rejects_when_locked(self):
        im = InviteManager()
        code = im.generate_code()
        for _ in range(3):
            im.record_failure()
        challenge = im.generate_challenge()
        response = compute_response(code, challenge)
        assert not im.verify_response(challenge, response)
