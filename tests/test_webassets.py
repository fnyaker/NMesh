"""Les assets de la console sont des chaînes Python : rien ne les compile.

Une erreur de syntaxe dans le JS ne casse pas un test, elle casse *toute* la
console à l'exécution — page blanche, sans message. Ces vérifications-là sont
donc faites ici, à la construction.
"""
import shutil
import subprocess
import tempfile

import pytest

from src import webassets

NODE = shutil.which("node")

SCRIPTS = ("APP_JS", "CHAT_JS", "FLEET_JS")


@pytest.mark.skipif(NODE is None, reason="node requis pour analyser le JS")
@pytest.mark.parametrize("name", SCRIPTS)
def test_the_script_parses(name):
    source = getattr(webassets, name)
    with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as handle:
        handle.write(source)
        handle.flush()
        result = subprocess.run([NODE, "--check", handle.name],
                                capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr


# Les URI de namespace XML (`http://www.w3.org/...`) sont des identifiants, pas
# des adresses à charger : `createElementNS` ne va sur le réseau pour rien.
_NAMESPACE_URIS = ("http://www.w3.org/", "http://www.w3.org/1999/xhtml")


@pytest.mark.parametrize("name", SCRIPTS)
def test_no_external_resource_is_pulled_in(name):
    """La console est hors ligne par construction : rien ne doit être chargé
    depuis un tiers, ni script, ni police, ni image."""
    import re
    source = getattr(webassets, name)
    for match in re.finditer(r'https?://[^\s"\'`)]*', source):
        url = match.group(0)
        assert url.startswith(_NAMESPACE_URIS), url


def test_every_element_the_scripts_reach_for_exists():
    """Un `$("id")` qui ne correspond à rien lève au chargement et emporte le
    reste du script avec lui."""
    import re
    pages = {"APP_JS": "INDEX_HTML", "CHAT_JS": "CHAT_HTML", "FLEET_JS": "FLEET_HTML"}
    for script_name, html_name in pages.items():
        html = getattr(webassets, html_name)
        source = getattr(webassets, script_name)
        # Seulement les accès littéraux au chargement : ceux construits
        # dynamiquement visent des éléments créés par le script lui-même.
        for match in re.finditer(r'\$\("([a-z0-9-]+)"\)\.addEventListener', source):
            element = match.group(1)
            # Un id que le script fabrique lui-même (markup injecté) n'a rien à
            # faire dans la page statique.
            if f'id="{element}"' in source:
                continue
            assert f'id="{element}"' in html, f"{script_name}: {element}"
