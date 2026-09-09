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


def _record(identity, name="Chat Deluxe", version="1.2.3",
            release=b"\x11" * 20, src=b"\x22" * 32, kind=pkg_dir.KIND_APP,
            notes="", ts=None, signer=None):
    """A node saying it holds a release. ``signer`` adds the proof that it also
    holds the key which signed that release."""
    return pkg_dir.build_record(kind, name, version, release, src,
                                identity.dsa_public_key, identity.sign,
                                notes=notes, ts=ts,
                                signer_pub=signer.dsa_public_key if signer else None,
                                signer_sign=signer.sign if signer else None)


class TestTheRecordSaysOnlyWhatWasSigned:
    def test_a_record_round_trips(self, signer):
        raw = _record(signer, notes="a chat client\nwith two lines")
        doc = pkg_dir.parse_record(raw, signer.verify)
        assert doc is not None
        assert doc["name"] == "Chat Deluxe"
        assert doc["version"] == "1.2.3"
        assert doc["notes"] == "a chat client\nwith two lines"
        assert doc["release"] == b"\x11" * 20
        assert doc["src"] == b"\x22" * 32
        assert doc["kind"] == pkg_dir.KIND_APP
        assert doc["published"] is False

    def test_the_node_id_follows_from_the_key(self, signer):
        doc = pkg_dir.parse_record(_record(signer), signer.verify)
        assert doc["node_id"] == pkg_dir.identity_id(signer.dsa_public_key)

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
                  + raw[pkg_dir._HDR.size + len(doc["node"]):])
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
                                      struct.pack("!BBBQHHHHHHH", 2, 1, 0, 0,
                                                  0xFFFF, 0, 0, 0, 0, 0, 0)])
    def test_hostile_input_never_raises(self, signer, blob):
        assert pkg_dir.parse_record(blob, signer.verify) is None

    def test_a_publication_says_so_and_names_the_key(self, signer, other):
        doc = pkg_dir.parse_record(_record(signer, signer=other), signer.verify)
        assert doc["published"] is True
        assert doc["flags"] == pkg_dir.FLAG_PUBLISHED
        assert doc["signer"] == other.dsa_public_key
        assert doc["signer_id"] == pkg_dir.identity_id(other.dsa_public_key)

    def test_a_record_that_only_holds_names_no_key(self, signer):
        doc = pkg_dir.parse_record(_record(signer), signer.verify)
        assert doc["signer"] is None and doc["signer_id"] is None


class TestKeysAreDerivedNeverDeclared:
    def test_a_record_is_filed_under_its_name_and_prefixes(self, signer):
        doc = pkg_dir.parse_record(_record(signer, name="Chat Deluxe"),
                                   signer.verify)
        for query in ("chat deluxe", "cha", "del", "chat"):
            assert pkg_dir.name_key(query) in doc["keys"], query

    def test_it_is_filed_under_its_node(self, signer):
        doc = pkg_dir.parse_record(_record(signer), signer.verify)
        assert pkg_dir.node_key(doc["node_id"]) in doc["keys"]

    def test_it_is_filed_under_the_release_it_holds(self, signer):
        """This is what makes a fetch work through routing: the key everybody
        derives from the release itself lists who can serve it."""
        doc = pkg_dir.parse_record(_record(signer, release=b"\x33" * 20),
                                   signer.verify)
        assert pkg_dir.release_key(b"\x33" * 20) in doc["keys"]

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
    def test_a_record_is_found_by_name_by_node_and_by_release(self, signer):
        book = pkg_dir.PackageBook()
        raw = _record(signer, name="Chat Deluxe", release=b"\x55" * 20)
        doc = pkg_dir.parse_record(raw, signer.verify)
        assert book.offer(doc, raw) is True
        assert book.get(pkg_dir.name_key("cha")) == [raw]
        assert book.get(pkg_dir.node_key(doc["node_id"])) == [raw]
        assert book.get(pkg_dir.release_key(b"\x55" * 20)) == [raw]

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

    def test_two_nodes_holding_one_name_are_two_entries(self, signer, other):
        book = pkg_dir.PackageBook()
        mine = _record(signer, name="NMesh", kind=pkg_dir.KIND_CORE)
        theirs = _record(other, name="NMesh", kind=pkg_dir.KIND_CORE)
        book.offer(pkg_dir.parse_record(mine, signer.verify), mine)
        book.offer(pkg_dir.parse_record(theirs, signer.verify), theirs)
        assert len(book) == 2

    def test_one_node_may_offer_a_core_release_and_an_app(self, signer):
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
                          src=b"\x33" * 32, release=b"\x44" * 20)
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
        one = _record(signer, version="1.0.0", release=b"\x11" * 20, ts=500)
        two = _record(signer, version="1.0.0", release=b"\x99" * 20, ts=500)
        doc = pkg_dir.parse_record(one, signer.verify)
        book.offer(doc, one)
        book.offer(pkg_dir.parse_record(two, signer.verify), two)
        assert book.equivocated(doc["node_id"]) is not None

    def test_forgetting_leaves_no_pointer_behind(self, signer):
        book = pkg_dir.PackageBook()
        raw = _record(signer, name="Chat Deluxe")
        doc = pkg_dir.parse_record(raw, signer.verify)
        book.offer(doc, raw)
        book.forget(pkg_dir.entry_key(doc))
        assert book.get(pkg_dir.name_key("cha")) == []
        assert len(book) == 0 and book.nbytes == 0


class TestThePublicationProof:
    """"I hold this" is one sentence; "and I signed it" is a second, and it has
    to be proved. The proof names the node, which is what stops it being lifted
    onto somebody else's record."""

    def test_a_proof_made_for_another_node_is_refused(self, signer, other):
        """The attack: take a real publisher's proof and put it on your own
        record, so your machine claims to have published their release."""
        victim = pkg_dir.identity_id(signer.dsa_public_key)
        release = b"\x77" * 20
        genuine = other.sign(pkg_dir._publisher_input(
            victim, pkg_dir.identity_id(other.dsa_public_key), release))

        thief = CryptoIdentity()
        forged = pkg_dir.build_record(
            pkg_dir.KIND_APP, "Chat Deluxe", "1.2.3", release, b"\x22" * 32,
            thief.dsa_public_key, thief.sign,
            signer_pub=other.dsa_public_key,
            signer_sign=lambda _message: genuine)
        assert pkg_dir.parse_record(forged, signer.verify) is None

    def test_a_proof_made_for_another_release_is_refused(self, signer, other):
        """The proof names the release too, so holding a real one for version A
        does not authorise a claim about version B."""
        node = pkg_dir.identity_id(signer.dsa_public_key)
        elsewhere = other.sign(pkg_dir._publisher_input(
            node, pkg_dir.identity_id(other.dsa_public_key), b"\x11" * 20))
        forged = pkg_dir.build_record(
            pkg_dir.KIND_APP, "Chat Deluxe", "1.2.3", b"\x99" * 20,
            b"\x22" * 32, signer.dsa_public_key, signer.sign,
            signer_pub=other.dsa_public_key,
            signer_sign=lambda _message: elsewhere)
        assert pkg_dir.parse_record(forged, signer.verify) is None

    def test_a_flag_with_no_proof_is_refused(self, signer):
        raw = bytearray(_record(signer))
        raw[2] = pkg_dir.FLAG_PUBLISHED
        assert pkg_dir.parse_record(bytes(raw), signer.verify) is None

    def test_a_proof_with_no_flag_is_refused(self, signer, other):
        """Two spellings of "published" is one for a reader to disagree
        about."""
        raw = bytearray(_record(signer, signer=other))
        raw[2] = 0
        assert pkg_dir.parse_record(bytes(raw), signer.verify) is None

    def test_half_a_proof_is_a_mistake_not_a_downgrade(self, signer, other):
        with pytest.raises(pkg_dir.PackageDirError):
            pkg_dir.build_record(pkg_dir.KIND_APP, "Chat", "1.0.0",
                                 b"\x11" * 20, b"\x22" * 32,
                                 signer.dsa_public_key, signer.sign,
                                 signer_pub=other.dsa_public_key)

    def test_a_node_may_prove_it_signed_with_its_own_identity(self, signer):
        """The ordinary case: one key, doing both jobs."""
        doc = pkg_dir.parse_record(_record(signer, signer=signer),
                                   signer.verify)
        assert doc["published"] is True
        assert doc["signer_id"] == doc["node_id"]

    def test_a_holder_and_a_publisher_of_one_release_are_both_kept(
            self, signer, other):
        """Both are sources for the same bytes, which is the point: the
        directory key derived from a release lists everyone who can serve it."""
        book = pkg_dir.PackageBook()
        published = _record(signer, signer=signer, release=b"\x66" * 20)
        held = _record(other, release=b"\x66" * 20)
        for raw in (published, held):
            book.offer(pkg_dir.parse_record(raw, signer.verify), raw)
        assert len(book.holders(b"\x66" * 20)) == 2
        assert len(book.get(pkg_dir.release_key(b"\x66" * 20))) == 2

    def test_only_a_published_record_carries_a_key_to_pin(self, signer):
        held = pkg_dir.parse_record(_record(signer), signer.verify)
        assert held["signer"] is None


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
