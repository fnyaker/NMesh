"""
Le contraste du thème n'est pas une affaire de goût.

Les jetons de couleur sont lus dans la feuille de style, résolus (ils se
référencent entre eux), puis chaque paire texte/fond est mesurée selon WCAG 2.1
dans **les deux** thèmes. Sous 4.5 pour du texte courant, le test échoue : une
console qu'on lit mal à 3 h du matin est un défaut, pas une préférence.
"""
import re

import pytest

from src.webassets import ui

# (avant-plan, arrière-plan, ratio minimum). 4.5 = AA texte normal, 3.0 = AA
# grand texte et composants d'interface (bordures, pastilles).
TEXT_PAIRS = [
    ("--text", "--canvas", 4.5),
    ("--text", "--surface", 4.5),
    ("--text", "--surface-2", 4.5),
    ("--text", "--surface-3", 4.5),
    ("--text-muted", "--surface", 4.5),
    ("--text-muted", "--canvas", 4.5),
    ("--text-muted", "--surface-2", 4.5),
    ("--text-faint", "--surface", 4.5),
    ("--accent-fg", "--accent", 4.5),
    ("--accent", "--surface", 4.5),
    ("--accent", "--accent-soft", 4.5),
    ("--ok", "--surface", 4.5),
    ("--ok", "--ok-soft", 4.5),
    ("--warn", "--surface", 4.5),
    ("--warn", "--warn-soft", 4.5),
    ("--danger", "--surface", 4.5),
    ("--danger", "--danger-soft", 4.5),
    ("--info", "--surface", 4.5),
    ("--info", "--info-soft", 4.5),
]

UI_PAIRS = [
    ("--border-strong", "--surface", 3.0),
    ("--accent", "--canvas", 3.0),
]


def _declarations(block: str) -> dict:
    return dict(re.findall(r"(--[a-z0-9-]+)\s*:\s*([^;}]+)", block))


def _blocks():
    """Les jetons du thème clair, puis ceux du sombre (clair + surcharges)."""
    root = ui.TOKENS.split(":root{", 1)[1].split("\n}", 1)[0]
    light = _declarations(root)
    dark = dict(light)
    dark.update(_declarations(ui.TOKENS.split('[data-theme="dark"]{', 1)[1]))
    return {"light": light, "dark": dark}


def _resolve(name: str, table: dict, depth: int = 0) -> str:
    value = table[name].strip()
    match = re.fullmatch(r"var\((--[a-z0-9-]+)\)", value)
    if match:
        assert depth < 8, f"boucle de référence sur {name}"
        return _resolve(match.group(1), table, depth + 1)
    return value


def _rgb(value: str) -> tuple:
    value = value.strip().lstrip("#")
    if len(value) == 3:
        value = "".join(c * 2 for c in value)
    assert re.fullmatch(r"[0-9a-fA-F]{6}", value), f"couleur illisible: {value}"
    return tuple(int(value[i:i + 2], 16) for i in (0, 2, 4))


def _luminance(rgb: tuple) -> float:
    channels = []
    for raw in rgb:
        c = raw / 255
        channels.append(c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4)
    r, g, b = channels
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(front: str, back: str) -> float:
    a, b = _luminance(_rgb(front)), _luminance(_rgb(back))
    high, low = max(a, b), min(a, b)
    return (high + 0.05) / (low + 0.05)


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("front,back,minimum", TEXT_PAIRS + UI_PAIRS)
def test_pair_is_readable(theme, front, back, minimum):
    table = _blocks()[theme]
    ratio = contrast(_resolve(front, table), _resolve(back, table))
    assert ratio >= minimum, (
        f"{theme}: {front} sur {back} = {ratio:.2f}:1, minimum {minimum}")


def test_both_themes_define_the_same_semantic_tokens():
    """Un jeton défini d'un seul côté est une couleur qui traverse le thème."""
    light, dark = _blocks()["light"], _blocks()["dark"]
    assert set(dark) == set(light)


def test_no_page_redefines_a_token():
    """Les jetons ont un seul point de définition : le reste les consomme."""
    from src import webassets
    for name in ("CONSOLE_PAGE_CSS", "CHAT_PAGE_CSS", "FLEET_PAGE_CSS"):
        page = getattr(webassets, name)
        for declaration in re.findall(r"(--[a-z0-9-]+)\s*:", page):
            assert declaration.startswith("--page-"), f"{name} redéfinit {declaration}"
