"""
The CodeQL queries that take mesh input as their source stay wired up.

They are compiled and run by `.github/workflows/codeql.yml`, which is where a
broken query fails; this holds the shape that makes them mean anything: each
one asks for `MeshInput`, and the workflow loads them.
"""
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PACK = ROOT / ".github" / "codeql" / "nmesh"
QUERIES = sorted((PACK / "queries").glob("*.ql"))


def test_there_are_queries():
    assert len(QUERIES) >= 10


@pytest.mark.parametrize("query", QUERIES, ids=lambda p: p.stem)
def test_each_query_takes_mesh_input_as_its_source(query):
    text = query.read_text()
    assert "import NMeshSources" in text
    assert "source.getNode() instanceof MeshInput" in text
    assert re.search(r"@id nmesh/[a-z-]+", text)


def test_ids_are_unique():
    ids = [re.search(r"@id (\S+)", q.read_text()).group(1) for q in QUERIES]
    assert len(ids) == len(set(ids))


def test_every_source_kind_is_part_of_mesh_input():
    text = (PACK / "NMeshSources.qll").read_text()
    kinds = re.findall(r"^class (\w+) extends RemoteFlowSource::Range", text, re.M)
    assert kinds
    union = text[text.index("class MeshInput"):]
    for kind in kinds:
        assert f"instanceof {kind}" in union, kind


def test_the_workflow_loads_them():
    config = (ROOT / ".github" / "codeql" / "codeql-config.yml").read_text()
    assert "./.github/codeql/nmesh/queries" in config
    assert "security-extended" in config
    workflow = (ROOT / ".github" / "workflows" / "codeql.yml").read_text()
    assert "./.github/codeql/codeql-config.yml" in workflow
