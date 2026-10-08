"""
The book a root keeps of who vouched for whom before it shortened a chain.

What is proved: it is bounded and refuses rather than evicts (evicting would make
a member unrevocable by its inviter), it answers "who is below this issuer", it
takes nothing malformed — from the network or from its own file — and it
survives the certificate store being written and read back.
"""
import os
import tempfile

from src.cert_store import CertStore
from src.lineage import MAX_ANCESTORS, Lineage
from src.node_id import NodeID


def _id(n: int) -> bytes:
    return n.to_bytes(20, "big")


class TestTheBook:

    def test_it_answers_who_is_below_an_issuer(self):
        book = Lineage()
        assert book.record(_id(3), [_id(2), _id(1)])
        assert book.record(_id(4), [_id(1)])
        assert book.record(_id(5), [_id(9)])
        assert sorted(book.descendants(_id(1))) == [_id(3), _id(4)]
        assert book.descendants(_id(2)) == [_id(3)]
        assert book.ancestors(_id(5)) == (_id(9),)

    def test_full_refuses_and_keeps_what_it_has(self):
        book = Lineage(max_entries=2)
        assert book.record(_id(1), [_id(9)]) and book.record(_id(2), [_id(9)])
        assert not book.record(_id(3), [_id(9)])
        assert len(book) == 2 and book.ancestors(_id(1)) == (_id(9),)
        assert book.record(_id(1), [_id(8)])          # an update is not growth

    def test_what_is_not_a_lineage_is_refused(self):
        book = Lineage()
        assert not book.record(b"short", [_id(1)])
        assert not book.record(_id(1), [])
        assert not book.record(_id(1), [b"short"])
        assert not book.record(_id(1), [_id(1)])           # its own ancestor
        assert not book.record(_id(1), [_id(n) for n in range(2, MAX_ANCESTORS + 3)])
        assert len(book) == 0

    def test_a_file_read_back_is_hostile_input(self):
        good = {_id(3).hex(): [_id(2).hex()]}
        junk = {"zz": ["00"], _id(4).hex(): "not a list", _id(5).hex(): [7],
                _id(6).hex(): ["nothex"]}
        book = Lineage.from_json({**good, **junk})
        assert len(book) == 1 and book.ancestors(_id(3)) == (_id(2),)
        assert len(Lineage.from_json(["not", "a", "dict"])) == 0

    def test_forgetting(self):
        book = Lineage()
        book.record(_id(3), [_id(2)])
        book.forget(_id(3))
        book.forget(_id(99))
        assert len(book) == 0


class TestItIsKeptWithTheCertificates:

    def test_it_survives_a_save_and_a_load(self):
        own = NodeID(_id(1))
        store = CertStore(own)
        store.lineage.record(_id(3), [_id(2)])
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "certs.json")
            store.save(path)
            back = CertStore.load(path, own)
        assert back.lineage.ancestors(_id(3)) == (_id(2),)
