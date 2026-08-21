"""L'image Docker doit embarquer de quoi provisionner d'autres machines.

L'app fleet pousse l'arbre NMesh du nœud vers les machines qu'elle installe. Si
l'image ne contient pas les entrées que `build_payload` exige, un nœud
conteneurisé échoue à l'exécution avec « no NMesh tree at /app » — un bug
invisible à la construction, d'où ce test.
"""
import re
from pathlib import Path

from src.apps import fleet_provision

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "docker" / "Dockerfile"


def copied_entries() -> set:
    """Ce que le Dockerfile dépose dans /app, d'après ses instructions COPY."""
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
        # dans l'arbre poussé.
        if not destination.startswith(("./", "/app")):
            continue
        for source in sources:
            copied.add(source.rstrip("/").lstrip("./") or source)
    return copied


def test_image_ships_everything_build_payload_requires():
    copied = copied_entries()
    missing = [entry for entry in fleet_provision.PAYLOAD_INCLUDE
               if entry not in copied and entry != "requirements.txt"]
    assert not missing, (
        f"le Dockerfile ne copie pas {missing} : un nœud conteneurisé "
        "échouerait avec « no NMesh tree at /app »")


def test_the_mandatory_pair_is_present():
    """`build_payload` refuse tout arbre sans `src` ET `start.sh`."""
    copied = copied_entries()
    assert {"src", "start.sh"} <= copied


def test_requirements_come_from_the_base_image():
    """requirements.txt n'est pas recopié ici : l'image de base l'a déjà posé
    dans /app. Si cette ligne disparaît de la base, le payload perdra le
    fichier sans que rien ne casse à la construction."""
    base = (ROOT / "docker" / "Dockerfile.base").read_text()
    assert re.search(r"COPY\s+requirements\.txt", base)
