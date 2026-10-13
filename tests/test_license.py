"""The GPL is in the tree, says so in the metadata, and travels with the
program in every form a node hands it over."""
import pathlib
import zipfile

from src import boot_guard
from src.apps import fleet_provision

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_the_license_is_the_gpl_version_3():
    text = (ROOT / "LICENSE").read_text()
    assert text.lstrip().startswith("GNU GENERAL PUBLIC LICENSE")
    assert "Version 3, 29 June 2007" in text
    assert 'license = "GPL-3.0-only"' in (ROOT / "pyproject.toml").read_text()


def test_it_travels_with_every_copy():
    assert "LICENSE" in boot_guard.REPLACE_ENTRIES
    assert "LICENSE" in fleet_provision.PAYLOAD_INCLUDE
    assert "LICENSE" in (ROOT / "docker" / "Dockerfile").read_text()


def test_the_zipapp_carries_it(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("build_pyz", ROOT / "scripts" / "build_pyz.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    out = tmp_path / "nmesh.pyz"
    module.build(str(out))
    with zipfile.ZipFile(out) as archive:
        assert "LICENSE" in archive.namelist()
