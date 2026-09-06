"""
The set that answers "have I handled this packet already?".

Asked once per routable packet, so its cost is on the hot path and its size
decides how far back the anti-replay window reaches. It was an
``OrderedDict[int, None]``: exact and correct, and about a hundred bytes an
entry to hold eight bytes of information — which is why the window was capped at
ten thousand ids.

What is proved here is that the flat table is **exactly** as truthful as the
dictionary it replaces. Nothing else would be worth the change: a false positive
here is a dropped packet, which the protocol tolerates, but this is the shape
anything else bounded by identity will be modelled on, and a false positive on
something punitive is an innocent node cut off with no way to find out.
"""
import random

import pytest

from src.seen import SeenSet


class TestItIsExact:
    def test_a_new_id_is_new_and_the_same_id_is_not(self):
        seen = SeenSet(1000)
        assert seen.add(12345) is False
        assert seen.add(12345) is True

    def test_no_id_it_holds_is_ever_missed(self):
        """No false negatives, inside the window."""
        seen = SeenSet(10_000)
        ids = [random.getrandbits(64) for _ in range(4000)]
        for value in ids:
            seen.add(value)
        assert all(value in seen for value in ids)

    def test_no_id_it_does_not_hold_is_ever_claimed(self):
        """No false positives — the property a filter would trade away."""
        seen = SeenSet(10_000)
        held = {random.getrandbits(64) for _ in range(4000)}
        for value in held:
            seen.add(value)
        strangers = [random.getrandbits(64) for _ in range(100_000)]
        assert not [s for s in strangers if s in seen and s not in held]

    def test_zero_is_an_id_like_any_other(self):
        """It is also the empty-slot sentinel, so it is held apart. A digest
        can be zero — rarely, and rare is not never."""
        seen = SeenSet(64)
        assert seen.add(0) is False
        assert seen.add(0) is True
        assert 0 in seen

    def test_an_id_that_does_not_fit_is_refused(self):
        seen = SeenSet(64)
        with pytest.raises(ValueError):
            seen.add(-1)
        with pytest.raises(ValueError):
            seen.add(1 << 64)


class TestItForgetsInOrderOfAge:
    def test_the_most_recent_capacity_ids_are_all_still_there(self):
        """The guarantee the FIFO gave, without paying to order anything."""
        seen = SeenSet(1000)
        for value in range(1, 4001):
            seen.add(value)
        recent = range(4000 - seen.capacity + 1, 4001)
        assert all(value in seen for value in recent)

    def test_it_never_grows(self):
        seen = SeenSet(1000)
        size = seen.nbytes()
        for value in range(200_000):
            seen.add(value)
        assert seen.nbytes() == size
        assert len(seen) <= 2 * seen.capacity

    def test_clearing_forgets_everything(self):
        seen = SeenSet(64)
        seen.add(7)
        seen.clear()
        assert 7 not in seen
        assert len(seen) == 0


class TestTheBucketCannotBeGround:
    def test_two_sets_place_the_same_id_differently(self):
        """The index is seeded per process.

        The obvious index is the id's own low bits, and they are uniform — it is
        a SHA-256 truncation. But the attacker picks the payload the digest is
        taken over, so they can grind ids into one bucket for a few thousand
        hashes each and turn every lookup into a walk. They cannot grind what
        they cannot predict."""
        a, b = SeenSet(4096), SeenSet(4096)
        # pylint: disable=protected-access
        placements = [(a._index(v), b._index(v)) for v in range(2000)]
        assert any(x != y for x, y in placements), \
            "both sets place every id identically: the seed is not being used"

    def test_the_seed_does_not_change_the_answers(self):
        """Where an id lands is unpredictable; whether it is there is not."""
        for _ in range(5):
            seen = SeenSet(256)
            values = [random.getrandbits(64) for _ in range(100)]
            for value in values:
                seen.add(value)
            assert all(value in seen for value in values)


class TestWhatItCosts:
    def test_it_is_far_smaller_than_the_dictionary_it_replaced(self):
        """An `OrderedDict` of 10k boxed ints is ~1 MB. The reason the window
        was capped where it was."""
        seen = SeenSet(10_000)
        assert seen.nbytes() / seen.capacity < 40   # bytes per id guaranteed
        assert seen.capacity >= 10_000
