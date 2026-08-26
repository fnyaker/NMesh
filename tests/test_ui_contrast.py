"""
A theme's contrast is not a matter of taste.

The colour tokens are read from the stylesheet, resolved (they reference each
other), then every text/background pair is measured against WCAG 2.1 in **both**
themes. Below 4.5 for body text the test fails: a console that is hard to read
at 3 a.m. is a defect, not a preference.
"""
import re

import pytest

from src.webassets import ui

# (foreground, background, minimum ratio). 4.5 = AA body text, 3.0 = AA large
# text and interface components (borders, dots).
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
    """The light theme's tokens, then the dark one's (light + overrides)."""
    root = ui.TOKENS.split(":root{", 1)[1].split("\n}", 1)[0]
    light = _declarations(root)
    dark = dict(light)
    dark.update(_declarations(ui.TOKENS.split('[data-theme="dark"]{', 1)[1]))
    return {"light": light, "dark": dark}


def _resolve(name: str, table: dict, depth: int = 0) -> str:
    value = table[name].strip()
    match = re.fullmatch(r"var\((--[a-z0-9-]+)\)", value)
    if match:
        assert depth < 8, f"reference loop on {name}"
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
        f"{theme}: {front} on {back} = {ratio:.2f}:1, minimum {minimum}")


def test_both_themes_define_the_same_semantic_tokens():
    """A token defined on one side only is a colour that crosses the theme."""
    light, dark = _blocks()["light"], _blocks()["dark"]
    assert set(dark) == set(light)


def test_no_page_redefines_a_token():
    """Tokens have one definition point: everything else consumes them."""
    from src import webassets
    for name in ("CONSOLE_PAGE_CSS", "CHAT_PAGE_CSS", "FLEET_PAGE_CSS"):
        page = getattr(webassets, name)
        for declaration in re.findall(r"(--[a-z0-9-]+)\s*:", page):
            assert declaration.startswith("--page-"), f"{name} redefines {declaration}"
