"""
The package directory: signed records, the keys they are filed under, and the
bounded book that holds them.

Everything here is about one question — can a record say something its signer
did not sign? — asked from every side a hostile peer could ask it from.
"""
import struct

import pytest

from src import pkg_dir
from src.crypto import CryptoIdentity


@pytest.fixture(scope="module")
def signer():
    return CryptoIdentity()


@pytest.fixture(scope="module")
def other():
    return CryptoIdentity()


def _record(identity, name="Chat Deluxe", version="1.2.3", ref=b"\x11" * 20,
            src=b"\x22" * 32, kind=pkg_dir.KIND_APP, notes="", ts=None,
            recommend=False):
    return pkg_dir.build_record(kind, name, version, ref, src,
                                identity.dsa_public_key, identity.sign,
                                notes=notes, ts=ts, recommend=recommend)


class TestTheRecordSaysOnlyWhatWasSigned:
    def test_a_record_round_trips(self, signer):
        raw = _record(signer, notes="a chat client\nwith two lines")
        doc = pkg_dir.parse_record(raw, signer.verify)
        assert doc is not None
        assert doc["name"] == "Chat Deluxe"
        assert doc["version"] == "1.2.3"
        assert doc["notes"] == "a chat client\nwith two lines"
        assert doc["ref"] == b"\x11" * 20
        assert doc["src"] == b"\x22" * 32
        assert doc["kind"] == pkg_dir.KIND_APP
        assert doc["recommend"] is False

    def test_the_publisher_id_follows_from_the_key(self, signer):
        doc = pkg_dir.parse_record(_record(signer), signer.verify)
        assert doc["publisher_id"] == pkg_dir.publisher_id(signer.dsa_public_key)

    def test_a_flipped_byte_is_refused(self, signer):
        raw = bytearray(_record(signer))
        raw[-1] ^= 0xFF
        assert pkg_dir.parse_record(bytes(raw), signer.verify) is None

    def test_another_key_cannot_claim_this_record(self, signer, other):
        """The signature is checked under the key *inside* the record, so
        substituting the key substitutes what the signature has to match."""
        raw = _record(signer)
        doc = pkg_dir.parse_record(raw, signer.verify)
        forged = (raw[:pkg_dir._HDR.size] + other.dsa_public_key
                  + raw[pkg_dir._HDR.size + len(doc["publisher"]):])
        assert pkg_dir.parse_record(forged, signer.verify) is None

    def test_a_name_that_is_not_canonical_is_refused(self, signer):
        with pytest.raises(pkg_dir.PackageDirError):
            _record(signer, name="chat​deluxe")

    def test_an_unknown_flag_is_refused(self, signer):
        raw = bytearray(_record(signer))
        raw[2] = 0x80
        assert pkg_dir.parse_record(bytes(raw), signer.verify) is None

    def test_an_unknown_kind_is_refused(self, signer):
        raw = bytearray(_record(signer))
        raw[1] = 9
        assert pkg_dir.parse_record(bytes(raw), signer.verify) is None

    def test_trailing_bytes_are_refused(self, signer):
        assert pkg_dir.parse_record(_record(signer) + b"x", signer.verify) is None

    @pytest.mark.parametrize("blob", [b"", b"\x00", b"\x01" * 40, None, 7,
                                      struct.pack("!BBBQHHHHH", 1, 1, 0, 0,
                                                  0xFFFF, 0, 0, 0, 0)])
    def test_hostile_input_never_raises(self, signer, blob):
        assert pkg_dir.parse_record(blob, signer.verify) is None

    def test_a_recommendation_says_so(self, signer):
        doc = pkg_dir.parse_record(_record(signer, recommend=True), signer.verify)
        assert doc["recommend"] is True
        assert doc["flags"] == pkg_dir.FLAG_RECOMMEND


class TestKeysAreDerivedNeverDeclared:
    def test_a_record_is_filed_under_its_name_and_prefixes(self, signer):
        doc = pkg_dir.parse_record(_record(signer, name="Chat Deluxe"),
                                   signer.verify)
        for query in ("chat deluxe", "cha", "del", "chat"):
            assert pkg_dir.name_key(query) in doc["keys"], query

    def test_it_is_filed_under_its_publisher(self, signer):
        doc = pkg_dir.parse_record(_record(signer), signer.verify)
        assert pkg_dir.publisher_key(doc["publisher_id"]) in doc["keys"]

    def test_a_name_key_folds_case_and_accents(self):
        assert pkg_dir.name_key("JOSÉ") == pkg_dir.name_key("jose")

    def test_a_single_letter_is_not_a_key(self, signer):
        """Every package in the mesh would land on one key, and a bucket holds
        eight — so it would answer with eight arbitrary packages."""
        doc = pkg_dir.parse_record(_record(signer, name="Chat"), signer.verify)
        assert pkg_dir.name_key("c") not in doc["keys"]


class TestTheSourceDigest:
    def test_documentation_does_not_change_it(self):
        one = pkg_dir.source_digest({"src/a.py": b"code", "README.md": b"hello"})
        two = pkg_dir.source_digest({"src/a.py": b"code", "README.md": b"other"})
        assert one == two

    def test_docs_directories_do_not_change_it(self):
        one = pkg_dir.source_digest({"src/a.py": b"code", "Docs/guide": b"x"})
        two = pkg_dir.source_digest({"src/a.py": b"code", "Docs/guide": b"y"})
        assert one == two

    def test_code_does_change_it(self):
        one = pkg_dir.source_digest({"src/a.py": b"code"})
        two = pkg_dir.source_digest({"src/a.py": b"other"})
        assert one != two

    def test_a_removed_file_changes_it(self):
        one = pkg_dir.source_digest({"src/a.py": b"code", "src/b.py": b"more"})
        two = pkg_dir.source_digest({"src/a.py": b"code"})
        assert one != two

    def test_a_file_that_runs_is_never_documentation(self):
        assert pkg_dir.is_documentation("README.md") is True
        assert pkg_dir.is_documentation("Docs/Updates/guide") is True
        assert pkg_dir.is_documentation("src/node.py") is False
        assert pkg_dir.is_documentation("start.sh") is False
        assert pkg_dir.is_documentation("scripts/readme_builder.py") is False


class TestTheBook:
    def test_a_record_is_found_by_name_and_by_publisher(self, signer):
        book = pkg_dir.PackageBook()
        raw = _record(signer, name="Chat Deluxe")
        doc = pkg_dir.parse_record(raw, signer.verify)
        assert book.offer(doc, raw) is True
        assert book.get(pkg_dir.name_key("cha")) == [raw]
        assert book.get(pkg_dir.publisher_key(doc["publisher_id"])) == [raw]

    def test_a_newer_record_replaces_an_older_one(self, signer):
        book = pkg_dir.PackageBook()
        old = _record(signer, version="1.0.0", ts=100)
        new = _record(signer, version="2.0.0", ts=200)
        book.offer(pkg_dir.parse_record(old, signer.verify), old)
        assert book.offer(pkg_dir.parse_record(new, signer.verify), new) is True
        assert book.get(pkg_dir.name_key("chat deluxe")) == [new]

    def test_an_older_record_changes_nothing(self, signer):
        book = pkg_dir.PackageBook()
        new = _record(signer, version="2.0.0", ts=200)
        old = _record(signer, version="1.0.0", ts=100)
        book.offer(pkg_dir.parse_record(new, signer.verify), new)
        assert book.offer(pkg_dir.parse_record(old, signer.verify), old) is False

    def test_two_publishers_of_one_name_are_two_entries(self, signer, other):
        book = pkg_dir.PackageBook()
        mine = _record(signer, name="NMesh", kind=pkg_dir.KIND_CORE)
        theirs = _record(other, name="NMesh", kind=pkg_dir.KIND_CORE)
        book.offer(pkg_dir.parse_record(mine, signer.verify), mine)
        book.offer(pkg_dir.parse_record(theirs, signer.verify), theirs)
        assert len(book) == 2

    def test_one_publisher_may_offer_a_core_release_and_an_app(self, signer):
        book = pkg_dir.PackageBook()
        core = _record(signer, name="NMesh", kind=pkg_dir.KIND_CORE)
        app = _record(signer, name="NMesh", kind=pkg_dir.KIND_APP)
        book.offer(pkg_dir.parse_record(core, signer.verify), core)
        book.offer(pkg_dir.parse_record(app, signer.verify), app)
        assert len(book) == 2

    def test_agreement_is_counted_over_the_source(self, signer, other):
        book = pkg_dir.PackageBook()
        for identity in (signer, other):
            raw = _record(identity, name="NMesh", kind=pkg_dir.KIND_CORE,
                          src=b"\x33" * 32, ref=b"\x44" * 20)
            book.offer(pkg_dir.parse_record(raw, identity.verify), raw)
        assert len(book.by_source(b"\x33" * 32)) == 2

    def test_an_empty_source_digest_agrees_with_nobody(self, signer):
        """"I did not read the package" must not read as "I vouch for it"."""
        book = pkg_dir.PackageBook()
        raw = _record(signer, src=b"\x00" * 32)
        book.offer(pkg_dir.parse_record(raw, signer.verify), raw)
        assert book.by_source(b"\x00" * 32) == []

    def test_the_book_is_bounded(self, signer):
        book = pkg_dir.PackageBook(max_entries=3)
        for index in range(6):
            raw = _record(signer, name=f"App {index}")
            book.offer(pkg_dir.parse_record(raw, signer.verify), raw)
        assert len(book) == 3

    def test_a_hot_prefix_bucket_never_evicts_a_package(self, signer):
        """A short prefix is shared by every second name. Dropping the record
        would let a busy bucket evict a package that is still the only answer
        to its own exact name."""
        book = pkg_dir.PackageBook(max_per_key=2)
        names = [f"Chatter {index}" for index in range(5)]
        for name in names:
            raw = _record(signer, name=name)
            book.offer(pkg_dir.parse_record(raw, signer.verify), raw)
        assert len(book) == len(names)
        for name in names:
            assert book.get(pkg_dir.name_key(name)), name

    def test_a_search_ranks_exact_before_prefix(self, signer):
        book = pkg_dir.PackageBook()
        for name in ("Chatter", "Chat"):
            raw = _record(signer, name=name)
            book.offer(pkg_dir.parse_record(raw, signer.verify), raw)
        assert [hit["name"] for hit in book.search("chat")] == ["Chat", "Chatter"]

    def test_two_versions_at_one_instant_are_kept_as_a_proof(self, signer):
        book = pkg_dir.PackageBook()
        one = _record(signer, version="1.0.0", ref=b"\x11" * 20, ts=500)
        two = _record(signer, version="1.0.0", ref=b"\x99" * 20, ts=500)
        doc = pkg_dir.parse_record(one, signer.verify)
        book.offer(doc, one)
        book.offer(pkg_dir.parse_record(two, signer.verify), two)
        assert book.equivocated(doc["publisher_id"]) is not None

    def test_forgetting_leaves_no_pointer_behind(self, signer):
        book = pkg_dir.PackageBook()
        raw = _record(signer, name="Chat Deluxe")
        doc = pkg_dir.parse_record(raw, signer.verify)
        book.offer(doc, raw)
        book.forget(pkg_dir.entry_key(doc))
        assert book.get(pkg_dir.name_key("cha")) == []
        assert len(book) == 0 and book.nbytes == 0


class TestPairingTakesTwo:
    """A detached publisher key and the node that uses it are tied together by
    two halves, each signed by one party. One half is one party's word about
    another — the thing this design exists so nobody has to believe."""

    def _pair(self, node, publisher):
        node_id = pkg_dir.publisher_id(node.dsa_public_key)
        pub_id = pkg_dir.publisher_id(publisher.dsa_public_key)
        return (pkg_dir.build_pairing(pub_id, node.dsa_public_key, node.sign),
                pkg_dir.build_pairing(node_id, publisher.dsa_public_key,
                                      publisher.sign),
                node_id, pub_id)

    def test_both_halves_confirm_each_other(self, signer, other):
        half_a, half_b, node_id, pub_id = self._pair(signer, other)
        book = pkg_dir.PairingBook()
        for raw in (half_a, half_b):
            book.offer(pkg_dir.parse_pairing(raw, signer.verify), raw)
        assert book.confirmed(node_id, pub_id) is True
        assert book.confirmed(pub_id, node_id) is True

    def test_one_half_confirms_nothing(self, signer, other):
        """The attack this closes: a node naming a stranger's publisher key
        would otherwise put that stranger's packages on its own page."""
        half_a, _half_b, node_id, pub_id = self._pair(signer, other)
        book = pkg_dir.PairingBook()
        book.offer(pkg_dir.parse_pairing(half_a, signer.verify), half_a)
        assert book.confirmed(node_id, pub_id) is False
        assert book.named_by(node_id) == [pub_id]   # …said, not believed

    def test_a_half_is_filed_under_its_own_signer(self, signer, other):
        half_a, half_b, node_id, pub_id = self._pair(signer, other)
        assert pkg_dir.parse_pairing(half_a, signer.verify)["key"] == \
            pkg_dir.publisher_key(node_id)
        assert pkg_dir.parse_pairing(half_b, signer.verify)["key"] == \
            pkg_dir.publisher_key(pub_id)

    def test_the_signer_is_derived_from_the_key_inside(self, signer, other):
        parsed = pkg_dir.parse_pairing(
            self._pair(signer, other)[0], signer.verify)
        assert parsed["signer_id"] == pkg_dir.publisher_id(signer.dsa_public_key)

    def test_a_flipped_byte_is_refused(self, signer, other):
        raw = bytearray(self._pair(signer, other)[0])
        raw[-1] ^= 0xFF
        assert pkg_dir.parse_pairing(bytes(raw), signer.verify) is None

    def test_a_key_cannot_pair_with_itself(self, signer):
        own = pkg_dir.publisher_id(signer.dsa_public_key)
        raw = pkg_dir.build_pairing(own, signer.dsa_public_key, signer.sign)
        assert pkg_dir.parse_pairing(raw, signer.verify) is None

    def test_an_older_half_cannot_undo_a_newer_one(self, signer, other):
        node_id = pkg_dir.publisher_id(signer.dsa_public_key)
        book = pkg_dir.PairingBook()
        new = pkg_dir.build_pairing(b"\x22" * 20, signer.dsa_public_key,
                                    signer.sign, ts=200)
        old = pkg_dir.build_pairing(b"\x22" * 20, signer.dsa_public_key,
                                    signer.sign, ts=100)
        assert book.offer(pkg_dir.parse_pairing(new, signer.verify), new) is True
        assert book.offer(pkg_dir.parse_pairing(old, signer.verify), old) is False

    def test_one_key_may_name_several_but_not_without_end(self, signer):
        book = pkg_dir.PairingBook(max_per_key=2)
        for index in range(5):
            raw = pkg_dir.build_pairing(bytes([index]) + b"\x00" * 19,
                                        signer.dsa_public_key, signer.sign)
            book.offer(pkg_dir.parse_pairing(raw, signer.verify), raw)
        assert len(book.named_by(
            pkg_dir.publisher_id(signer.dsa_public_key))) == 2

    def test_the_book_is_bounded(self, signer):
        book = pkg_dir.PairingBook(max_entries=3, max_per_key=99)
        for index in range(9):
            raw = pkg_dir.build_pairing(bytes([index]) + b"\x00" * 19,
                                        signer.dsa_public_key, signer.sign)
            book.offer(pkg_dir.parse_pairing(raw, signer.verify), raw)
        assert len(book) == 3

    @pytest.mark.parametrize("blob", [b"", b"\x01" * 9, None, 7,
                                      b"\x02" + b"\x00" * 40])
    def test_hostile_input_never_raises(self, signer, blob):
        assert pkg_dir.parse_pairing(blob, signer.verify) is None

    def test_a_package_record_does_not_parse_as_a_pairing(self, signer):
        """One plane carries both, so each gate has to refuse the other's."""
        record = _record(signer)
        assert pkg_dir.parse_pairing(record, signer.verify) is None
        half = pkg_dir.build_pairing(b"\x33" * 20, signer.dsa_public_key,
                                     signer.sign)
        assert pkg_dir.parse_record(half, signer.verify) is None


class TestEncoding:
    def test_records_round_trip_through_a_reply(self, signer):
        records = [_record(signer, name=f"App {i}") for i in range(3)]
        assert pkg_dir.decode_records(pkg_dir.encode_records(records)) == records

    @pytest.mark.parametrize("blob", [b"", b"\x00\x05", b"\xff\xff" + b"x" * 4])
    def test_a_malformed_reply_yields_nothing(self, blob):
        assert pkg_dir.decode_records(blob) == []

    def test_a_reply_is_capped(self, signer):
        records = [_record(signer, name=f"App {i}") for i in range(64)]
        blob = pkg_dir.encode_records(records)
        assert len(blob) <= 60_000
