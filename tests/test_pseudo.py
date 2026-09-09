"""
The canonical pseudo form.

This is the whole reason a receiver can call a mismatch a lie, so the rules are
pinned here one by one — especially the hostile ones: the characters that render
as nothing, or that reorder what follows them, are exactly how you make one name
look like another.
"""
import pytest

from src.pseudo import (MAX_INDEX_TERMS, MAX_PSEUDO, MAX_TERM, PseudoError,
                        canonical, is_canonical, fold, key_terms,
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


class TestKeyTerms:
    """The terms a name is filed under, so a *partial* query finds it on a node
    that has never met the claimant. Half a name does not hash to the same key
    as the whole one, which is why this exists at all."""

    def test_the_whole_name_and_every_word_prefix(self):
        terms = key_terms("Alice Ada")
        assert terms[0] == "alice ada"
        for term in ("al", "ali", "alic", "alice", "ad", "ada"):
            assert term in terms, term

    def test_the_terms_are_the_ranks_that_can_be_hashed(self):
        """EXACT, PREFIX and WORD each have a term; CONTAINS cannot have one —
        you cannot hash the middle of a word."""
        terms = key_terms("Alice Ada")
        assert fold("alice ada") in terms          # EXACT
        assert fold("ali") in terms                # PREFIX
        assert fold("ada") in terms                # WORD
        assert fold("lic") not in terms            # CONTAINS

    def test_folding_applies_so_accents_and_case_land_together(self):
        assert key_terms("José") == key_terms("jose")

    def test_a_single_letter_is_not_a_term(self):
        """Every name in the mesh would land on one key, and a directory bucket
        holds a handful — so it would answer with a handful of arbitrary names."""
        assert "a" not in key_terms("Alice Ada")

    def test_a_one_letter_word_is_indexed_as_itself(self):
        assert "a" in key_terms("a team")

    def test_the_list_is_deduplicated_and_bounded(self):
        terms = key_terms(" ".join(f"word{index}" for index in range(20)))
        assert len(terms) == len(set(terms)) <= MAX_INDEX_TERMS

    def test_a_long_word_stops_at_the_ceiling(self):
        terms = key_terms("a" * 40)
        assert max(len(term) for term in terms if term != fold("a" * 40)) <= MAX_TERM

    def test_nothing_usable_yields_nothing(self):
        assert key_terms("") == [] and key_terms(None) == []


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
