"""
The file surface behind the `shell` right.

It grants nothing a shell does not already grant, so what these tests are about
is the other half: every call arrives as a string somebody else chose, and this
module is where the bounds on those strings live. A path that is not a path, a
name carrying a separator, a device pretending to be a file, an upload that
never finishes — each one is refused rather than tidied up, and none of them
leaves anything behind.
"""
import os
import stat

import pytest

from src.apps import fleet_files as ff


class TestPaths:
    def test_nothing_means_home(self):
        assert ff.clean_path("") == ff.home()
        assert ff.clean_path(None) == ff.home()

    def test_a_relative_path_is_refused(self):
        """It would resolve against a working directory the operator cannot
        see, which is a different file on every node."""
        for bad in ("etc/passwd", "./x", "../x"):
            with pytest.raises(ff.FileError, match="absolute"):
                ff.clean_path(bad)

    def test_junk_is_refused(self):
        for bad in (42, b"/tmp", "/tmp/\x00etc", "/" + "x" * (ff.MAX_PATH + 1)):
            with pytest.raises(ff.FileError):
                ff.clean_path(bad)

    def test_a_path_is_resolved_before_it_is_used(self, tmp_path):
        (tmp_path / "real").mkdir()
        link = tmp_path / "link"
        link.symlink_to(tmp_path / "real")
        assert ff.clean_path(str(link)) == str((tmp_path / "real").resolve())

    @pytest.mark.parametrize("bad", ["", ".", "..", "a/b", "a\\b", "x" * 300,
                                     "nul\x00", 42, None])
    def test_a_name_is_one_component_or_nothing(self, bad):
        with pytest.raises(ff.FileError):
            ff.clean_name(bad)

    def test_an_ordinary_name_passes(self):
        assert ff.clean_name("notes 2026.txt") == "notes 2026.txt"


class TestListing:
    def test_directories_come_first_then_names(self, tmp_path):
        (tmp_path / "b.txt").write_text("x")
        (tmp_path / "A.txt").write_text("xx")
        (tmp_path / "zdir").mkdir()
        listed = ff.listing(str(tmp_path))
        assert [row["name"] for row in listed["entries"]] == ["zdir", "A.txt", "b.txt"]
        assert listed["entries"][1]["size"] == 2
        assert listed["entries"][0]["kind"] == "dir"

    def test_the_parent_is_named_so_navigation_needs_no_string_maths(self, tmp_path):
        child = tmp_path / "sub"
        child.mkdir()
        assert ff.listing(str(child))["parent"] == str(tmp_path)
        # The root has none, and saying so is what stops a page offering "up"
        # from the top of the filesystem.
        assert ff.listing("/")["parent"] == ""

    def test_a_directory_too_big_to_sort_is_counted_not_read(self, tmp_path,
                                                             monkeypatch):
        """Sorting cannot start until every name is in memory, so a directory
        with a million files has to stop being read at some point."""
        monkeypatch.setattr(ff, "MAX_SCAN", 4)
        monkeypatch.setattr(ff, "MAX_ENTRIES", 4)
        for index in range(10):
            (tmp_path / f"f{index}").write_text("")
        listed = ff.listing(str(tmp_path))
        assert len(listed["entries"]) == 4
        assert listed["truncated"] == 6

    def test_it_is_bounded_and_says_what_it_left_out(self, tmp_path):
        for index in range(ff.MAX_ENTRIES + 5):
            (tmp_path / f"f{index:04d}").write_text("")
        listed = ff.listing(str(tmp_path))
        assert len(listed["entries"]) == ff.MAX_ENTRIES
        assert listed["truncated"] == 5

    def test_a_broken_link_is_a_row_not_a_failure(self, tmp_path):
        (tmp_path / "dangling").symlink_to(tmp_path / "gone")
        listed = ff.listing(str(tmp_path))
        assert len(listed["entries"]) == 1
        row = listed["entries"][0]
        assert row["name"] == "dangling" and row["link"] is True
        assert row["kind"] == "other"

    def test_a_file_is_not_a_directory(self, tmp_path):
        (tmp_path / "f").write_text("x")
        with pytest.raises(ff.FileError, match="not a directory"):
            ff.listing(str(tmp_path / "f"))

    def test_a_directory_nobody_may_read_says_so(self, tmp_path):
        if os.geteuid() == 0:
            pytest.skip("root reads anything, so nothing is unreadable")
        locked = tmp_path / "locked"
        locked.mkdir()
        os.chmod(locked, 0o000)
        try:
            with pytest.raises(ff.FileError, match="permission"):
                ff.listing(str(locked))
        finally:
            os.chmod(locked, 0o700)


class TestReading:
    def test_a_file_is_read_in_slices(self, tmp_path):
        body = os.urandom(ff.READ_SLICE + 100)
        target = tmp_path / "blob"
        target.write_bytes(body)
        first, eof, info = ff.read_slice(str(target), 0, ff.READ_SLICE)
        assert first == body[:ff.READ_SLICE] and eof is False
        assert info["size"] == len(body) and info["name"] == "blob"
        rest, eof, _info = ff.read_slice(str(target), ff.READ_SLICE, ff.READ_SLICE)
        assert rest == body[ff.READ_SLICE:] and eof is True

    def test_an_empty_file_is_one_empty_slice(self, tmp_path):
        (tmp_path / "empty").write_bytes(b"")
        data, eof, _info = ff.read_slice(str(tmp_path / "empty"), 0, ff.READ_SLICE)
        assert data == b"" and eof is True

    def test_only_a_regular_file_is_transferable(self, tmp_path):
        """A fifo blocks whoever opens it and a device never ends. Neither is a
        file transfer, so neither is offered."""
        os.mkfifo(str(tmp_path / "pipe"))
        (tmp_path / "dir").mkdir()
        for bad in ("pipe", "dir"):
            with pytest.raises(ff.FileError, match="regular file"):
                ff.stat_file(str(tmp_path / bad))

    def test_a_slice_beyond_the_end_is_refused(self, tmp_path):
        (tmp_path / "f").write_text("hello")
        with pytest.raises(ff.FileError, match="past the end"):
            ff.read_slice(str(tmp_path / "f"), 99, ff.READ_SLICE)
        for bad in (-1, "0", True):
            with pytest.raises(ff.FileError, match="offset"):
                ff.read_slice(str(tmp_path / "f"), bad, ff.READ_SLICE)

    def test_a_slice_is_capped_whatever_was_asked_for(self, tmp_path):
        (tmp_path / "f").write_bytes(b"x" * (ff.READ_SLICE * 2))
        data, _eof, _info = ff.read_slice(str(tmp_path / "f"), 0, ff.READ_SLICE * 10)
        assert len(data) == ff.READ_SLICE

    def test_a_missing_file_says_so(self, tmp_path):
        with pytest.raises(ff.FileError, match="no such file"):
            ff.stat_file(str(tmp_path / "nope"))


class TestMakingADirectory:
    def test_it_is_created_inside_its_parent(self, tmp_path):
        path = ff.make_dir(str(tmp_path), "logs")
        assert path == str(tmp_path / "logs") and os.path.isdir(path)

    def test_an_existing_name_is_refused(self, tmp_path):
        (tmp_path / "logs").mkdir()
        with pytest.raises(ff.FileError, match="already there"):
            ff.make_dir(str(tmp_path), "logs")

    def test_a_name_that_reaches_out_is_refused(self, tmp_path):
        (tmp_path / "inside").mkdir()
        for bad in ("../outside", "a/b", ".."):
            with pytest.raises(ff.FileError):
                ff.make_dir(str(tmp_path / "inside"), bad)
        assert [p.name for p in tmp_path.iterdir()] == ["inside"]


class TestUploads:
    def test_a_file_appears_only_when_it_is_whole(self, tmp_path):
        upload = ff.Upload(str(tmp_path), "report.bin")
        upload.write(0, b"head")
        # Present as a temporary, absent under its own name: a half-arrived
        # file must never look like a complete one.
        assert not (tmp_path / "report.bin").exists()
        assert len(list(tmp_path.iterdir())) == 1
        upload.write(4, b"tail")
        result = upload.finish()
        assert result == {"path": str(tmp_path / "report.bin"),
                          "name": "report.bin", "size": 8}
        assert (tmp_path / "report.bin").read_bytes() == b"headtail"
        assert [p.name for p in tmp_path.iterdir()] == ["report.bin"]

    def test_a_slice_out_of_order_ends_it_and_leaves_nothing(self, tmp_path):
        upload = ff.Upload(str(tmp_path), "report.bin")
        upload.write(0, b"head")
        with pytest.raises(ff.FileError, match="does not follow"):
            upload.write(99, b"tail")
        assert list(tmp_path.iterdir()) == []

    def test_it_cannot_grow_past_the_transfer_ceiling(self, tmp_path,
                                                      monkeypatch):
        monkeypatch.setattr(ff, "MAX_TRANSFER", 8)
        upload = ff.Upload(str(tmp_path), "big.bin")
        with pytest.raises(ff.FileError, match="too large"):
            upload.write(0, b"x" * 9)
        assert list(tmp_path.iterdir()) == []

    def test_the_temporary_sits_beside_its_target(self, tmp_path):
        """The rename that puts the file in place has to stay on one
        filesystem, or the last step of every upload becomes a copy."""
        upload = ff.Upload(str(tmp_path), "report.bin")
        try:
            assert os.path.dirname(upload.temp) == str(tmp_path)
            assert os.path.basename(upload.temp).startswith(".report.bin.nmesh-part-")
            assert stat.S_IMODE(os.stat(upload.temp).st_mode) == 0o600
        finally:
            upload.abort()

    def test_aborting_twice_is_harmless(self, tmp_path):
        upload = ff.Upload(str(tmp_path), "report.bin")
        upload.abort()
        upload.abort()
        assert list(tmp_path.iterdir()) == []

    def test_an_upload_into_something_that_is_not_a_directory(self, tmp_path):
        (tmp_path / "f").write_text("x")
        with pytest.raises(ff.FileError, match="not a directory"):
            ff.Upload(str(tmp_path / "f"), "report.bin")

    def test_it_replaces_what_was_there(self, tmp_path):
        (tmp_path / "report.bin").write_bytes(b"old")
        upload = ff.Upload(str(tmp_path), "report.bin")
        upload.write(0, b"new")
        upload.finish()
        assert (tmp_path / "report.bin").read_bytes() == b"new"
