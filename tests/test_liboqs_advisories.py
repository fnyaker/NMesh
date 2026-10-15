"""
The weekly check of liboqs's own advisories (`tests/tools/liboqs_advisories.py`)
reads ranges, exceptions and verdicts correctly — offline, on advisories shaped
like the ones GitHub's API returns.
"""
import pytest

from tests.tools import liboqs_advisories as check


def _advisory(ghsa, *ranges, withdrawn=None):
    return {"ghsa_id": ghsa, "severity": "moderate", "summary": "s",
            "withdrawn_at": withdrawn,
            "vulnerabilities": [{"package": {"ecosystem": "other", "name": "liboqs"},
                                 "vulnerable_version_range": r} for r in ranges]}


class TestRanges:
    @pytest.mark.parametrize("spec, hit", [
        (">= 0.11.0, <= 0.16.0", True),
        ("<= 0.15.0", False),
        ("< 0.16.0", False),
        ("< 0.16.1", True),
        ("0.15.0", False),
        ("0.16.0", True),
        ("= 0.16", True),
        ("> 0.16.0", False),
        (">= 0.17.0", False),
    ])
    def test_the_bounds_are_read(self, spec, hit):
        assert check.in_range("0.16.0", spec) is hit

    @pytest.mark.parametrize("spec", [None, "", "all versions", "<= 0.16.x", 7])
    def test_a_range_nobody_can_read_is_affected(self, spec):
        assert check.in_range("0.16.0", spec) is True


class TestAdvisories:
    def test_one_affected_entry_is_enough(self):
        assert check.affects(_advisory("GHSA-a", "<= 0.10.0", ">= 0.16.0"), "0.16.0")

    def test_a_withdrawn_advisory_affects_nothing(self):
        assert not check.affects(_advisory("GHSA-a", "<= 0.16.0", withdrawn="2026-01-01"), "0.16.0")

    @pytest.mark.parametrize("vulnerabilities", [None, [], "x", [None]])
    def test_an_advisory_that_names_no_range_is_affected(self, vulnerabilities):
        advisory = _advisory("GHSA-a")
        advisory["vulnerabilities"] = vulnerabilities
        assert check.affects(advisory, "0.16.0")


class TestVerdict:
    def test_open_excused_and_stale(self):
        advisories = [_advisory("GHSA-open", "<= 0.16.0"),
                      _advisory("GHSA-ok", "<= 0.16.0"),
                      _advisory("GHSA-old", "<= 0.15.0"),
                      "not an advisory"]
        still_open, excused, stale = check.verdict(
            advisories, "0.16.0", {"GHSA-ok": "why", "GHSA-gone": "why"})
        assert [a["ghsa_id"] for a in still_open] == ["GHSA-open"]
        assert [a["ghsa_id"] for a in excused] == ["GHSA-ok"]
        assert stale == ["GHSA-gone"]


class TestFiles:
    def test_the_locked_version_is_read(self):
        assert check.version(check.locked_version())

    def test_every_accepted_entry_says_why(self):
        assert all(reason for reason in check.accepted().values())

    @pytest.mark.parametrize("line", ["GHSA-xv6c-h66p-6mfq", "GHSA-nope reason",
                                      "CVE-2026-1 reason"])
    def test_an_entry_without_an_id_and_a_reason_is_refused(self, tmp_path, line):
        path = tmp_path / "accepted"
        path.write_text(f"# header\n{line}\n")
        with pytest.raises(ValueError):
            check.accepted(path)

    def test_a_lock_without_a_version_is_refused(self, tmp_path):
        path = tmp_path / "lock"
        path.write_text("LIBOQS_COMMIT=abc\n")
        with pytest.raises(ValueError):
            check.locked_version(path)
