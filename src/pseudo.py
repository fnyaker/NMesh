"""
Pseudos — the changeable name a node shows, next to the id it cannot change.

A node's identity is its :class:`~src.node_id.NodeID`, the hash of its ML-DSA
public key: unique, unforgeable, and impossible to choose. A pseudo is the
opposite of all three — it is a **label**, freely picked and freely changed, and
several nodes may wear the same one. Everything the network decides (routing,
authentication, trust) keeps using the id; the pseudo only ever decides what a
human reads. Wherever one is displayed, the id must be displayed with it, so a
lookalike name buys an attacker nothing.

Because a pseudo travels between nodes, its **form is part of the protocol**. A
single function, :func:`canonical`, defines it, and a receiver re-derives it
from what arrived: a peer that sends anything else is not merely sloppy — it is
trying to smuggle a name that renders as somebody else's (a trailing space, a
right-to-left override, a zero-width joiner splitting a word invisibly). So a
non-canonical pseudo is treated as hostile, not repaired. Hence the rules below
are deliberately narrow:

- **NFC**, so the same glyphs always give the same bytes.
- **No characters from the C categories** (control, format, surrogate, private
  use, unassigned): this is what removes the invisible and the directional.
- **Only the plain space U+0020 separates words**, never a no-break or
  ideographic space that renders identically.
- **Single spaces, no edges**, so "bob" and "bob " cannot coexist.
- **At most 50 characters**, counted on the normalised form.

:func:`fold` derives the search/lookup key: case-insensitive and
accent-insensitive, so somebody who types ``jose`` finds ``José``. It is only
ever a key — it never replaces the pseudo that gets displayed.
"""
from __future__ import annotations

import unicodedata

MAX_PSEUDO = 50

# Categories a pseudo may never contain. Cc/Cf cover the invisible and the
# directional (U+200B zero width space, U+200E left-to-right mark, U+202E
# right-to-left override, newlines, tabs); Cs/Co/Cn cover surrogates, private
# use and the unassigned, none of which render predictably anywhere.
_FORBIDDEN_CATEGORIES = frozenset(("Cc", "Cf", "Cs", "Co", "Cn"))
# Zl/Zp are line and paragraph separators; a Zs other than U+0020 is a space
# that looks like a space but is not one (U+00A0, U+3000…).
_SEPARATOR_CATEGORIES = frozenset(("Zl", "Zp", "Zs"))


class PseudoError(ValueError):
    """A pseudo that cannot be used, phrased for whoever typed it."""


def canonical(text) -> str:
    """The one accepted form of ``text``, or :class:`PseudoError`.

    Deterministic and side-effect free: two nodes running this on the same input
    must always agree, because that agreement is what lets a receiver call a
    mismatch a lie."""
    if not isinstance(text, str):
        raise PseudoError("a pseudo is text")
    normalised = unicodedata.normalize("NFC", text)
    out: list[str] = []
    for ch in normalised:
        category = unicodedata.category(ch)
        if category in _FORBIDDEN_CATEGORIES:
            raise PseudoError("a pseudo cannot contain invisible or control characters")
        if category in _SEPARATOR_CATEGORIES:
            if ch != " ":
                raise PseudoError("a pseudo separates words with a plain space")
            # Collapsing here rather than rejecting: a double space is a typing
            # slip, not an attempt at anything, and rejecting it would only
            # teach people to distrust the field.
            if out and out[-1] == " ":
                continue
        out.append(ch)
    pseudo = "".join(out).strip(" ")
    if not pseudo:
        raise PseudoError("a pseudo cannot be empty")
    if len(pseudo) > MAX_PSEUDO:
        raise PseudoError(f"a pseudo is at most {MAX_PSEUDO} characters")
    return pseudo


def is_canonical(text) -> bool:
    """Is ``text`` exactly what :func:`canonical` produces? Never raises — this
    is the gate applied to everything that arrives from the network."""
    try:
        return canonical(text) == text
    except PseudoError:
        return False


def fold(text) -> str:
    """The search key of a pseudo: case- and accent-insensitive.

    Returns ``""`` for anything unusable, so a caller can key on it without
    guarding every call."""
    try:
        pseudo = canonical(text)
    except PseudoError:
        # A query is typed by a human and may still be mid-word or oddly spaced;
        # fold what can be folded rather than refusing to search.
        if not isinstance(text, str):
            return ""
        pseudo = " ".join(unicodedata.normalize("NFC", text).split())[:MAX_PSEUDO]
        if not pseudo:
            return ""
    decomposed = unicodedata.normalize("NFD", pseudo.casefold())
    stripped = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return unicodedata.normalize("NFC", stripped)


# How well a pseudo answers a query, best first. The caller sorts on this, so
# the order of the constants *is* the ranking.
EXACT, PREFIX, WORD, CONTAINS = 0, 1, 2, 3


def rank(query: str, pseudo: str):
    """How well ``pseudo`` matches ``query`` — one of the constants above, or
    ``None`` when it does not match at all. Both are folded here, so callers
    pass what the user typed and what the claim carried."""
    return rank_folded(fold(query), fold(pseudo))


def rank_folded(q: str, p: str):
    """:func:`rank` on two already-folded strings.

    Folding is NFC, casefold, NFD, a filter and NFC again — one of the more
    expensive things in the standard library, and a caller ranking a query
    against a whole book folds the same query once per entry and re-folds
    entries that never change. Both are worth doing once."""
    if not q or not p:
        return None
    if q == p:
        return EXACT
    if p.startswith(q):
        return PREFIX
    if any(word.startswith(q) for word in p.split(" ")):
        return WORD
    if q in p:
        return CONTAINS
    return None
