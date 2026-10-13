"""
`src/liboqs_guard.py`: no liboqs on disk means the node does not start, rather
than liboqs-python fetching one and compiling it unchecked.
"""
import pathlib
import sys

import pytest

from src import liboqs_guard

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture
def bare(monkeypatch, tmp_path):
    """A machine with no liboqs anywhere the wrapper would look."""
    monkeypatch.setenv("OQS_INSTALL_PATH", str(tmp_path / "prefix"))
    monkeypatch.delenv("LD_LIBRARY_PATH", raising=False)
    monkeypatch.delenv("DYLD_LIBRARY_PATH", raising=False)
    monkeypatch.setattr(liboqs_guard.ctypes.util, "find_library", lambda name: None)
    return tmp_path / "prefix"


class TestFindingTheLibrary:
    def test_nothing_anywhere_is_nothing(self, bare):
        assert liboqs_guard.library_on_disk() is False

    @pytest.mark.parametrize("part", ["lib", "lib64"])
    def test_the_install_prefix(self, bare, part):
        (bare / part).mkdir(parents=True)
        (bare / part / "liboqs.so.9").write_bytes(b"")
        assert liboqs_guard.library_on_disk() is True

    def test_the_loader_path(self, bare, monkeypatch, tmp_path):
        (tmp_path / "elsewhere").mkdir()
        (tmp_path / "elsewhere" / "liboqs.so").write_bytes(b"")
        monkeypatch.setenv("LD_LIBRARY_PATH", str(tmp_path / "elsewhere"))
        assert liboqs_guard.library_on_disk() is True

    def test_the_system_linker(self, bare, monkeypatch):
        monkeypatch.setattr(liboqs_guard.ctypes.util, "find_library",
                            lambda name: "liboqs.so.9" if name == "oqs" else None)
        assert liboqs_guard.library_on_disk() is True


class TestTheGuard:
    def test_with_no_library_the_wrapper_is_never_imported(self, bare, monkeypatch):
        monkeypatch.delitem(sys.modules, "oqs", raising=False)
        with pytest.raises(ImportError, match="unchecked"):
            liboqs_guard.ensure()

    def test_a_wrapper_already_loaded_is_left_alone(self, bare, monkeypatch):
        monkeypatch.setitem(sys.modules, "oqs", object())
        liboqs_guard.ensure()

    def test_crypto_asks_before_it_imports(self):
        text = (ROOT / "src" / "crypto.py").read_text()
        assert text.index("liboqs_guard.ensure()") < text.index("import oqs")

    def test_start_sh_asks_the_same_question(self):
        assert "src/liboqs_guard.py" in (ROOT / "start.sh").read_text()
