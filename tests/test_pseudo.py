"""
The canonical pseudo form.

This is the whole reason a receiver can call a mismatch a lie, so the rules are
pinned here one by one — especially the hostile ones: the characters that render
as nothing, or that reorder what follows them, are exactly how you make one name
look like another.
"""
import pytest

from src.pseudo import (MAX_PSEUDO, PseudoError, canonical, is_canonical, fold,
                        rank, EXACT, PREFIX, WORD, CONTAINS)


class TestCanonical:
    def test_plain_names_pass_through(self):
        for name in ("bob", "Alice Ada", "Zoé", "田中", "x", "a-b_c.d", "🙂"):
            assert canonical(name) == name
            assert is_canonical(name)

    def test_edges_and_runs_of_spaces_are_tidied(self):
        assert canonical("  Alice   Ada  ") == "Alice Ada"
        # …which means the tidied-up form is not itself what may travel.
        assert not is_canonical("  Alice   Ada  ")

    def test_nfc_is_the_stored_form(self):
        composed, decomposed = "é", "é"
        assert canonical(decomposed) == composed
        assert not is_canonical(decomposed)

    def test_fifty_characters_is_the_ceiling(self):
        assert canonical("x" * MAX_PSEUDO) == "x" * MAX_PSEUDO
        with pytest.raises(PseudoError):
            canonical("x" * (MAX_PSEUDO + 1))

    def test_counted_in_characters_not_bytes(self):
        # 50 characters that weigh far more than 50 bytes in UTF-8.
        wide = "é" * MAX_PSEUDO
        assert canonical(wide) == wide
        assert len(wide.encode("utf-8")) > MAX_PSEUDO

    def test_empty_is_refused(self):
        for text in ("", "   ", " "):
            with pytest.raises(PseudoError):
                canonical(text)

    @pytest.mark.parametrize("text", [
        "bo​b",      # zero width space — a word split into two invisibly
        "ali‮ce",    # right-to-left override — renders reversed
        "bob‎",      # left-to-right mark
        "a‍b",       # zero width joiner
        "a\tb", "a\nb", "a\rb",
        "bob\x00",
        "a b",       # no-break space: looks like a space, is not one
        "a　b",       # ideographic space
        "a b",       # line separator
        "﻿bob",      # byte order mark
    ])
    def test_invisible_and_directional_are_refused(self, text):
        with pytest.raises(PseudoError):
            canonical(text)
        assert not is_canonical(text)

    def test_non_text_is_refused(self):
        for value in (None, 123, b"bob", ["bob"]):
            with pytest.raises(PseudoError):
                canonical(value)
            assert not is_canonical(value)

    def test_canonical_is_idempotent(self):
        for text in ("  Bob  Ada ", "élise", "x"):
            once = canonical(text)
            assert canonical(once) == once
            assert is_canonical(once)


class TestFold:
    def test_case_and_accent_insensitive(self):
        assert fold("José") == fold("jose") == fold("JOSE")

    def test_folds_a_query_that_is_not_yet_a_pseudo(self):
        # What a human types mid-word still has to be searchable.
        assert fold("  ALI  ") == "ali"

    def test_unusable_input_folds_to_nothing(self):
        assert fold("") == "" and fold(None) == "" and fold(123) == ""


class TestRank:
    def test_order_runs_exact_prefix_word_contains(self):
        assert rank("alice ada", "Alice Ada") == EXACT
        assert rank("ali", "Alice Ada") == PREFIX
        assert rank("ada", "Alice Ada") == WORD
        assert rank("lic", "Alice Ada") == CONTAINS
        assert rank("zz", "Alice Ada") is None
        assert EXACT < PREFIX < WORD < CONTAINS

    def test_accent_and_case_do_not_change_the_rank(self):
        assert rank("jose", "José") == EXACT

    def test_empty_matches_nothing(self):
        assert rank("", "alice") is None and rank("ali", "") is None
