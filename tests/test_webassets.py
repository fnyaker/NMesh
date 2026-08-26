"""Les assets de la console sont des chaînes Python : rien ne les compile.

Une erreur de syntaxe dans le JS ne casse pas un test, elle casse *toute* la
console à l'exécution — page blanche, sans message. Ces vérifications-là sont
donc faites ici, à la construction.
"""
import pathlib
import re
import shutil
import subprocess
import tempfile

import pytest

from src import webassets
from src.webassets import ui

NODE = shutil.which("node")

SCRIPTS = ("APP_JS", "CHAT_JS", "FLEET_JS", "NODE_JS")


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
    pages = {"APP_JS": "INDEX_HTML", "CHAT_JS": "CHAT_HTML",
             "FLEET_JS": "FLEET_HTML", "NODE_JS": "NODE_HTML"}
    for script_name, html_name in pages.items():
        html = getattr(webassets, html_name)
        # Seulement la partie propre à la page : le runtime partagé garde tous
        # ses accès derrière un `if(element)`, précisément parce que toutes les
        # pages ne portent pas tout le châssis.
        source = getattr(webassets, script_name)[len(webassets.ui.JS):]
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


def test_the_rights_panel_is_wired_to_a_real_element():
    """La vue « qui peut contrôler cette node » est le seul endroit où un droit
    s'ajoute : si son conteneur manque, elle disparaît en silence."""
    assert 'id="operators"' in webassets.FLEET_HTML
    assert 'data-tab="access"' in webassets.FLEET_HTML
    assert "function paintOperators" in webassets.FLEET_JS
    for route in ("/api/fleet/caps-set", "/api/fleet/caps-request",
                  "/api/fleet/caps-drop"):
        assert route in webassets.FLEET_JS, route


# ── la CSP stricte, appliquée aux assets eux-mêmes ──────────────────────────
# `default-src 'self'` sans `unsafe-inline` : un attribut `style=` est ignoré
# par le navigateur **en silence**. Une barre de progression écrite comme ça ne
# se remplit jamais et personne ne voit d'erreur. Les assignations CSSOM
# (`element.style.x = …`) ne sont pas concernées et restent permises.

STYLE_ATTRIBUTE = re.compile(r"""style\s*=\s*["']""")


@pytest.mark.parametrize("name", ["INDEX_HTML", "CHAT_HTML", "FLEET_HTML",
                                  "NODE_HTML", "APP_JS", "CHAT_JS", "FLEET_JS",
                                  "NODE_JS", "STYLE_CSS", "CHAT_CSS",
                                  "FLEET_CSS", "NODE_CSS"])
def test_no_inline_style_attribute_anywhere(name):
    source = getattr(webassets, name)
    # Le commentaire qui explique la règle a le droit de la citer.
    lines = [line for line in source.splitlines()
             if STYLE_ATTRIBUTE.search(line) and "attribute silently" not in line]
    assert not lines, f"{name}: attribut style inline — {lines[:2]}"


def test_the_console_still_forbids_inline_anything():
    """Si la CSP s'assouplissait, la règle ci-dessus perdrait son sens."""
    from src.webconsole import _SECURITY_HEADERS
    policy = _SECURITY_HEADERS["Content-Security-Policy"]
    assert "default-src 'self'" in policy
    assert "unsafe-inline" not in policy


def test_every_page_offers_a_skip_link_and_a_focus_ring():
    """Deux garanties clavier qu'on perd sans s'en rendre compte : sauter le
    rail pour atteindre le contenu, et voir où est le focus."""
    for html in (webassets.INDEX_HTML, webassets.CHAT_HTML, webassets.FLEET_HTML):
        assert 'class="skip"' in html
        assert 'id="main"' in html
    for css in (webassets.STYLE_CSS, webassets.CHAT_CSS, webassets.FLEET_CSS,
                webassets.NODE_CSS):
        assert ":focus-visible{outline:2px solid var(--ring)" in css


def test_the_three_pages_share_one_design_system():
    """Le contrat du paquet : une seule source pour les jetons, les composants
    et le runtime. Si une page cessait de la charger, elle divergerait en
    silence."""
    for css in (webassets.STYLE_CSS, webassets.CHAT_CSS, webassets.FLEET_CSS,
                webassets.NODE_CSS):
        assert css.startswith(webassets.ui.CSS)
    for script in (webassets.APP_JS, webassets.CHAT_JS, webassets.FLEET_JS,
                   webassets.NODE_JS):
        assert script.startswith(webassets.ui.JS)


def test_the_two_maps_share_one_drawing_routine():
    """La petite carte et la carte étendue sont la même fonction à deux tailles.
    Deux implémentations divergeraient au premier changement."""
    source = webassets.APP_JS
    assert "function renderGraph(" in source
    assert source.count("function renderGraph(") == 1
    assert "GRAPH_SMALL" in source and "GRAPH_BIG" in source
    assert 'id="map-dialog"' in webassets.INDEX_HTML
    assert 'class="mesh-graph"' in webassets.INDEX_HTML


def test_the_console_renders_whatever_a_transport_reports():
    """Les compteurs d'un transport sont affichés par leurs propres noms : la
    console ne connaît ni « retransmits » ni « SNR », et c'est le point."""
    source = webassets.APP_JS
    assert "statsHTML(link)" in source
    assert "Object.entries(stats)" in source


# ── la navigation étroite et les menus ───────────────────────────────────────
# Chacun de ces tests correspond à un bug réellement rencontré dans un vrai
# navigateur : ils sont ici pour qu'il ne revienne pas.

PAGES = {"INDEX_HTML": "APP_JS", "CHAT_HTML": "CHAT_JS", "FLEET_HTML": "FLEET_JS",
         "NODE_HTML": "NODE_JS"}


@pytest.mark.parametrize("html_name", list(PAGES))
def test_every_menu_starts_closed(html_name):
    """Un panneau `.menu` sans attribut `hidden` s'affiche au chargement et
    intercepte les clics du bouton censé l'ouvrir."""
    html = getattr(webassets, html_name)
    for match in re.finditer(r'<div id="([a-z-]+)" class="menu"([^>]*)>', html):
        assert "hidden" in match.group(2), match.group(1)


@pytest.mark.parametrize("html_name", list(PAGES))
def test_every_menu_button_points_at_a_panel(html_name):
    html = getattr(webassets, html_name)
    for match in re.finditer(r'data-menu="([a-z-]+)"', html):
        assert f'id="{match.group(1)}" class="menu"' in html, match.group(1)


@pytest.mark.parametrize("html_name", ["INDEX_HTML", "FLEET_HTML"])
def test_every_tab_has_a_short_name_for_the_tab_bar(html_name):
    """En barre d'onglets, le libellé long est masqué et `data-label` prend sa
    place via `::before` : sans lui, l'onglet est vide."""
    html = getattr(webassets, html_name)
    # Seulement la navigation principale : les sous-onglets d'une section ne
    # descendent pas dans la barre du bas.
    tabs = re.findall(r'<button role="tab"[^>]*data-tab="[^"]+".*?</button>', html, re.S)
    assert tabs
    for tab in tabs:
        assert 'data-label="' in tab, tab
        # Le libellé long doit être enveloppé, sinon il n'y a rien à masquer.
        assert '<span class="lbl">' in tab, tab[:90]


def test_the_topbar_does_not_capture_its_own_menus():
    """`backdrop-filter` sur un élément en fait le bloc conteneur de tous ses
    descendants `position:fixed` : la feuille de notifications s'ancrait alors
    sous la barre au lieu du bas de l'écran. Le flou vit sur un pseudo-élément."""
    block = ui.SHELL.split(".topbar{", 1)[1].split("}", 1)[0]
    assert "backdrop-filter" not in block
    assert "backdrop-filter" in ui.SHELL.split(".topbar::before{", 1)[1].split("}", 1)[0]


def test_the_overflow_button_defaults_to_hidden_before_the_query_shows_it():
    """À spécificité égale, la dernière règle gagne — media query ou pas. Le
    défaut doit donc être déclaré avant la requête qui l'active."""
    default = ui.SHELL.index(".more-wrap{display:none}")
    shown = ui.SHELL.index(".more-wrap{display:inline-flex}")
    assert default < shown


def test_the_tab_bar_hides_what_cannot_fit_and_the_page_ends_above_it():
    narrow = ui.SHELL.split("@media (max-width:900px){", 1)[1]
    assert ".rail .brand,.rail .rail-foot" in narrow
    assert "--tabbar-h" in narrow


# ── la vue d'une node, partagée ──────────────────────────────────────────────
# Elle est montée à deux endroits : le dialogue de la console et la page
# `/node` qu'ouvrent chat et fleet. Deux copies qui divergent était l'autre
# option ; ces tests sont là pour qu'on n'y retombe pas.

def test_one_node_view_mounted_twice_and_never_copied():
    for script in (webassets.APP_JS, webassets.NODE_JS):
        assert "const NODEVIEW = {" in script
        assert script.count("const NODEVIEW = {") == 1
    assert 'NODEVIEW.mount("node-detail"' in webassets.APP_JS
    assert 'NODEVIEW.mount("view"' in webassets.NODE_JS


def test_the_view_only_offers_what_an_app_declares():
    """Un bouton qui appelle une app absente ne doit pas être dessiné : la vue
    lit le catalogue avant de décider quoi proposer."""
    source = webassets.NODE_JS
    assert '"/api/app-api"' in source
    assert 'this.has("chat", "peer")' in source
    assert 'this.has("fleet", "relation")' in source


def test_the_view_hides_the_button_pointing_back_where_it_came_from():
    source = webassets.NODE_JS
    assert 'get("from")' in source
    assert 'hide.indexOf("chat")' in source and 'hide.indexOf("fleet")' in source


def test_the_addresses_are_folded_away_by_default():
    """La question « quelles adresses » vient après « ce lien va bien ? ». Un
    tableau déplié repoussait les réponses sous le pli."""
    source = webassets.NODE_JS
    assert 'foldHTML("Addresses"' in source
    assert "<details class=\\\"card\\\"><summary>" in source or \
           '<details class="card"><summary>' in source


# ── les trajets d'une app à l'autre ──────────────────────────────────────────

def test_every_page_mounts_the_same_view_and_hides_the_way_it_came():
    """Le bouton qui ramène là d'où l'on vient n'est pas dessiné : depuis chat
    on ne propose pas chat, depuis fleet on ne propose pas fleet."""
    assert 'NODEVIEW.mount("peer-view"' in webassets.CHAT_JS
    assert 'hide:["chat"]' in webassets.CHAT_JS
    assert 'NODEVIEW.mount("fleet-node-view"' in webassets.FLEET_JS
    assert 'hide:["fleet"]' in webassets.FLEET_JS


def test_chat_can_show_a_node_beside_a_window_or_a_tab():
    assert 'id="peer-panel"' in webassets.CHAT_HTML
    assert 'id="set-details"' in webassets.CHAT_HTML
    for mode in ('value="panel"', 'value="window"', 'value="tab"'):
        assert mode in webassets.CHAT_HTML, mode
    # Sortir de chat passe par la page, pas par un cadre.
    assert 'openLinked("/node?from=chat#"' in webassets.CHAT_JS


def test_the_console_keeps_its_browser_preferences_in_the_browser():
    """Thème et mode d'ouverture ne sont pas des réglages du nœud : deux
    machines connectées à la même console gardent chacune les siens."""
    assert 'data-subtab="appearance"' in webassets.INDEX_HTML
    assert 'id="pref-open"' in webassets.INDEX_HTML and 'id="pref-theme"' in webassets.INDEX_HTML
    assert 'localStorage.getItem("nmesh_open_mode")' in webassets.ui.JS
    assert "/api/pref" not in webassets.APP_JS


def test_a_list_painted_on_a_timer_is_not_rebuilt_for_nothing():
    """Remplacer une ligne sous le pointeur perd le clic en cours. Les listes
    qui se repeignent au sondage écrivent seulement si le contenu a changé."""
    assert "function setHTML(" in webassets.ui.JS
    for source, holder in ((webassets.FLEET_JS, '"nodes"'),
                           (webassets.FLEET_JS, '"operators"'),
                           (webassets.FLEET_JS, '"inbox"'),
                           (webassets.CHAT_JS, '"chat-list"')):
        assert "setHTML(" + holder in source, holder


# ── auto-refresh, and what a refresh is not allowed to do ────────────────────

def test_the_refresh_interval_is_a_number_here_and_a_list_there():
    """Un champ numérique est le bon contrôle au clavier et le mauvais sur un
    téléphone (cible de 12 px, clavier qui couvre la page)."""
    for html in (webassets.INDEX_HTML, webassets.FLEET_HTML):
        assert 'id="refresh-secs"' in html and 'type="number"' in html
        assert 'max="30"' in html
        assert 'id="refresh-pick"' in html
        assert 'value="0">Off' in html
        # Off n'est pas une impasse : une pression lit quand même le nœud.
        assert 'id="refresh-now"' in html
    narrow = webassets.ui.CSS.split("@media (max-width:720px){", 1)[1]
    assert ".refresh select{display:block}" in narrow


def test_the_interval_is_clamped_and_remembered_in_the_browser():
    source = webassets.ui.JS
    assert 'localStorage.getItem("nmesh_refresh")' in source
    assert "Math.min(this.MAX, Math.max(0, seconds))" in source
    assert "/api/refresh" not in webassets.APP_JS      # pas un réglage du nœud


def test_a_refresh_repaints_values_without_rebuilding_what_is_open():
    """Le contrat : rafraîchir met à jour des valeurs. Les listes repeintes au
    sondage passent par `setHTML`, qui n'écrit que si le contenu a changé."""
    source = webassets.APP_JS
    for holder in ('"network-summary"', '"map-links"'):
        assert "setHTML(" + holder in source, holder
    assert "setHTML(body," in source          # les tables de pairs


def test_only_a_vanished_thing_may_be_deselected():
    source = webassets.APP_JS
    assert "if(MAP_PICK && !direct.some(" in source
    assert "if(!group || group.links.length < 2) unfolded.delete(id)" in source


# ── les liens actifs, groupés par node ───────────────────────────────────────

def test_active_links_are_one_row_per_node_openable_onto_its_links():
    source = webassets.APP_JS
    assert "function groupByNode(" in source
    assert "const LINKS_OPEN = {active: new Set(), known: new Set()}" in source
    # Le repère affiché est le meilleur lien, et la gigue est *la sienne*.
    assert "group.best == null || rtt < group.best.rtt_ms" in source
    assert "data-fold=" in source


# ── la carte et sa liste ─────────────────────────────────────────────────────

def test_the_map_and_its_list_share_one_selection():
    source = webassets.APP_JS
    assert "MAP_PICK = MAP_PICK === id ? null : id" in source
    assert "function revealPick(" in source
    assert "data-link-details=" in source


def test_a_captured_pointer_does_not_swallow_the_click_on_a_node():
    """Capturer le pointeur (pour que le glissé survive à la sortie de
    l'élément) redirige aussi le `click` sur l'élément capturant : sans
    mémoriser la cible à l'appui, cliquer un nœud n'atteignait plus le nœud."""
    source = webassets.APP_JS
    assert "let MAP_DOWN_ON = null" in source
    assert "MAP_DOWN_ON = (event.target.closest" in source
    assert "const node = MAP_DOWN_ON ||" in source


def test_a_node_on_the_map_has_a_target_a_finger_can_hit():
    source = webassets.APP_JS
    assert 'class:"hit"' in source
    assert "Math.max(size.r * 2.2, 18)" in source
    assert "circle.hit{fill:transparent" in webassets.STYLE_CSS


# ── ce qui appartient à un transport vit dans ce transport ───────────────────

def test_transport_facts_left_the_node_card():
    assert 'id="relay-state"' not in webassets.INDEX_HTML
    source = webassets.APP_JS
    assert "const SCHEME_FACTS = {" in source
    assert '"Public IP"' in source and '"Public UDP"' in source
    # La carte du nœud ne garde que ce qui est vrai du nœud.
    summary = source.split('const summary = [', 1)[1].split("];", 1)[0]
    assert '"Internet"' in summary and '"Pending seeks"' in summary
    assert "public_ip" not in summary and "stun_addr" not in summary


def test_a_transport_opens_on_its_status_then_its_settings():
    source = webassets.APP_JS
    assert 'data-view="status"' in source and 'data-view="settings"' in source
    assert 'data-panel="status"' in source and 'data-panel="settings"' in source
    # Le choix de vue survit à un redraw, comme le pli.
    assert "views[scheme] || \"status\"" in source
