"""
The one way a string reaches a person.

Every sentence the product shows lives in a catalogue under ``src/locales/``,
one JSON file per language, and is asked for by key. Nothing here knows what a
page or an app is: a page asks the browser's ``t()`` (``webassets/ui.py``), an
app asks :func:`t` or is handed the language it was started under.

**The catalogues are data, and data is checked.** A file is read once, bounded
in size and in shape (a flat map of keys to a string or a map of plural forms),
and anything that is not that is refused whole rather than half-used — a
catalogue a person can edit is a catalogue that can be wrong. English is the
reference: a key missing in another language falls back to it, and a key
missing everywhere is shown as itself, which is ugly on purpose.

**A language is chosen, never guessed from the network.** The operator's
``language`` setting wins; with none, the browser's ``Accept-Language`` picks
among the languages we ship; with neither, English. Nothing a peer sends can
change it.

The module imports nothing of its own: ``config.py`` is loaded from its file by
the installer, and the web console and the apps load this one the same way.
"""
from __future__ import annotations

import json
import os
import re

DEFAULT = "en"

# Code -> the language's name in itself, so a person who cannot read the current
# language can still find their own in a list.
NAMES = {
    "en": "English",
    "fr": "Français",
    "de": "Deutsch",
    "ru": "Русский",
    "zh": "中文",
    "pl": "Polski",
    "sk": "Slovenčina",
}
LANGUAGES = tuple(NAMES)

_DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "locales")
_MAX_FILE = 512 * 1024
_MAX_KEYS = 20000
_MAX_VALUE = 4000
_KEY_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")
_PARAM_RE = re.compile(r"\{([a-z][a-z0-9_]*)\}")
_FORMS = ("zero", "one", "two", "few", "many", "other")

_cache: dict[str, dict] = {}


class CatalogueError(ValueError):
    """A catalogue that is not the shape we read."""


def _check(data) -> dict:
    if not isinstance(data, dict) or len(data) > _MAX_KEYS:
        raise CatalogueError("a catalogue is a bounded map of keys")
    for key, value in data.items():
        if not isinstance(key, str) or not _KEY_RE.match(key):
            raise CatalogueError("not a usable key: %r" % (key,))
        forms = value if isinstance(value, dict) else {"other": value}
        if "other" not in forms or set(forms) - set(_FORMS):
            raise CatalogueError("%s: plural forms need 'other' and no stranger" % key)
        for text in forms.values():
            if not isinstance(text, str) or len(text) > _MAX_VALUE:
                raise CatalogueError("%s: a form is a short string" % key)
    return data


def load(language: str, directory: str | None = None) -> dict:
    """The catalogue of ``language`` as written, or ``{}`` when there is none.

    Never raises: a missing or broken file costs that language its strings (the
    reader falls back to English), not the page or the node."""
    if language not in NAMES:
        return {}
    if directory is None and language in _cache:
        return _cache[language]
    path = os.path.join(directory or _DIRECTORY, language + ".json")
    try:
        if os.path.getsize(path) > _MAX_FILE:
            raise CatalogueError("too large")
        with open(path, "r", encoding="utf-8") as handle:
            data = _check(json.load(handle))
    except (OSError, ValueError):
        data = {}
    if directory is None:
        _cache[language] = data
    return data


def plural_form(language: str, count) -> str:
    """The CLDR plural category of ``count`` in ``language``.

    Only the categories our languages use. The browser asks ``Intl.PluralRules``
    for the same answer; ``tests/test_i18n.py`` holds the two in step."""
    try:
        number = float(count)
    except (TypeError, ValueError):
        return "other"
    whole = number.is_integer()
    n = int(number) if whole else 0
    if language in ("en", "de"):
        return "one" if whole and n == 1 else "other"
    if language == "fr":
        return "one" if number >= 0 and number < 2 else "other"
    if language in ("ru", "pl", "sk"):
        if not whole:
            return "many" if language == "sk" else "other"
        if language == "sk":
            if n == 1:
                return "one"
            return "few" if 2 <= n <= 4 else "other"
        if language == "pl" and n == 1:
            return "one"
        if language == "ru" and n % 10 == 1 and n % 100 != 11:
            return "one"
        if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
            return "few"
        return "many"
    return "other"


def _fill(text: str, params: dict) -> str:
    """``{name}`` replaced from ``params``; a name nobody gave stays as written.

    A regex, not ``str.format``: a catalogue is data, and ``{a.b}`` or ``{0!r}``
    in data must not be a way to read attributes of what the caller passed."""
    return _PARAM_RE.sub(
        lambda found: str(params[found.group(1)]) if found.group(1) in params
        else found.group(0), text)


def t(key: str, language: str = DEFAULT, **params) -> str:
    """The sentence for ``key`` in ``language``, parameters filled in.

    A plural entry is chosen by the ``count`` parameter."""
    for code in (language, DEFAULT):
        value = load(code).get(key)
        if value is None:
            continue
        if isinstance(value, dict):
            form = plural_form(code, params.get("count"))
            value = value.get(form, value["other"])
        return _fill(value, params)
    return key


def negotiate(header: str | None) -> str | None:
    """The shipped language an ``Accept-Language`` header prefers, or ``None``.

    Bounded: a header is read to a length and a count of entries, since it is
    the one input here that a stranger's browser writes."""
    if not isinstance(header, str):
        return None
    ranked = []
    for index, part in enumerate(header[:512].split(",")[:32]):
        tag, _, rest = part.strip().partition(";")
        weight = 1.0
        match = re.match(r"\s*q=([0-9.]+)", rest)
        if match:
            try:
                weight = float(match.group(1))
            except ValueError:
                continue
        primary = tag.strip().lower().split("-")[0]
        if primary in NAMES and weight > 0:
            ranked.append((-weight, index, primary))
    return min(ranked)[2] if ranked else None


def effective(setting: str | None, header: str | None = None) -> str:
    """The language to speak: the operator's choice, else the browser's, else
    English."""
    if setting in NAMES:
        return setting
    return negotiate(header) or DEFAULT


def bundle(language: str) -> dict:
    """What a page needs: the language's strings laid over English, so a key
    missing in a translation is still a sentence in the browser."""
    merged = dict(load(DEFAULT))
    if language != DEFAULT:
        merged.update(load(language))
    return merged
