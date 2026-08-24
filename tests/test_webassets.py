"""Les assets de la console sont des chaînes Python : rien ne les compile.

Une erreur de syntaxe dans le JS ne casse pas un test, elle casse *toute* la
console à l'exécution — page blanche, sans message. Ces vérifications-là sont
donc faites ici, à la construction.
"""
import pathlib
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


# ── l'émulateur de terminal ─────────────────────────────────────────────────
# Écrit plutôt que pris en dépendance (un shell où l'on tape `sudo` a besoin
# d'un terminal, pas d'un panneau de log). Il est donc à nous de prouver qu'il
# lit correctement ce qu'un vrai shell écrit.

TERM_SUITE = pathlib.Path(__file__).with_name("term_emulator_test.js")


def _terminal_source() -> str:
    body = webassets.FLEET_JS.split("// ---- a small terminal")[1]
    return "// ---- a small terminal" + body.split("// ---- shell ----")[0]


@pytest.mark.skipif(NODE is None, reason="node requis pour exécuter le JS")
def test_the_terminal_reads_back_what_a_shell_writes(tmp_path):
    source = tmp_path / "term.js"
    source.write_text(_terminal_source(), encoding="utf-8")
    result = subprocess.run([NODE, str(TERM_SUITE), str(source)],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_terminal_never_renders_unescaped_markup():
    """La sortie vient d'une machine distante : elle est écrite dans le DOM en
    innerHTML, donc l'échappement n'est pas cosmétique."""
    source = _terminal_source()
    assert "escHtml" in source
    assert 'replace(/&/g,"&amp;")' in source


def test_the_terminal_pane_takes_real_keystrokes():
    """Un champ texte ligne par ligne afficherait un mot de passe en clair ; des
    frappes brutes laissent le pty distant décider de ce qui revient."""
    assert 'addEventListener("keydown"' in webassets.FLEET_JS
    assert "function keyBytes" in webassets.FLEET_JS
    assert 'tabindex="0"' in webassets.FLEET_HTML
