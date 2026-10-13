"""The Docker image has to carry what it takes to provision other machines.

The fleet app pushes the node's NMesh tree to the machines it installs. If the
image does not contain the entries `build_payload` requires, a containerised node
fails at runtime with "no NMesh tree at /app" — a bug invisible at build time,
hence this test.
"""
import re
from pathlib import Path

from src.apps import fleet_provision

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "docker" / "Dockerfile"


def copied_entries() -> set:
    """What the Dockerfile puts in /app, according to its COPY instructions."""
    copied = set()
    for line in DOCKERFILE.read_text().splitlines():
        match = re.match(r"\s*COPY\s+(.*)$", line)
        if match is None:
            continue
        parts = [p for p in match.group(1).split() if not p.startswith("--")]
        if len(parts) < 2:
            continue
        sources, destination = parts[:-1], parts[-1]
        # Seules les copies vers le WORKDIR comptent ; /entrypoint.sh n'est pas
        # in the pushed tree.
        if not destination.startswith(("./", "/app")):
            continue
        for source in sources:
            copied.add(source.rstrip("/").lstrip("./") or source)
    return copied


def test_image_ships_everything_build_payload_requires():
    copied = copied_entries()
    missing = [entry for entry in fleet_provision.PAYLOAD_INCLUDE
               if entry not in copied]
    assert not missing, (
        f"the Dockerfile does not copy {missing}: a containerised node "
        'would fail with "no NMesh tree at /app"')


def test_the_mandatory_pair_is_present():
    """`build_payload` refuses any tree without both `src` and `start.sh`."""
    copied = copied_entries()
    assert {"src", "start.sh"} <= copied


def _python_images(path: Path) -> list:
    return re.findall(r"^FROM\s+(python:\S+)", path.read_text(), re.M)


def test_both_images_run_the_same_python():
    """The application image is a fresh stage that copies the base's
    ``site-packages`` by path. A base on another Python puts them where this
    interpreter never looks, and the build still succeeds until the import."""
    base = _python_images(ROOT / "docker" / "Dockerfile.base")
    app = _python_images(DOCKERFILE)
    assert base and app and set(base) == set(app)
    version = re.match(r"python:(\d+\.\d+)", app[0]).group(1)
    assert f"/usr/local/lib/python{version}/site-packages" in DOCKERFILE.read_text()
