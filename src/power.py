"""
Ten steps between "spend as little as possible" and "as fast as it goes".

Almost nobody wants to type a keepalive floor in milliseconds. What they want
is to say how much this machine may spend — a phone on a battery, a server on
mains — and have the node pick the numbers. A **profile** is that sentence: a
named set of values for settings that already exist and already apply to a
running node. It adds no mechanism of its own, which is the point — the node
does exactly what it would have done had an operator typed those values.

Nothing is stored for it. Which step a node is on is **read off the values it
holds**: a node whose settings match a step is on that step, and one that
matches none is *custom*. Storing the step beside the values would be two
answers to one question, and the first hand edit would make one of them a lie.

Only settings that take effect live belong in a profile (``config.LIVE``): a
slider that moved and changed nothing until a restart would be lying to the
person who moved it. ``tests/test_power.py`` holds that rule.

Imports nothing of the project's: the console's tests and the config module's
loader both read this table, and neither should have to start a node for it.
"""
from __future__ import annotations

# The settings a profile decides. Everything else is left exactly as it was.
FIELDS = (
    "keepalive_fast_min_ms",
    "keepalive_fast_max_ms",
    "keepalive_slow_min_ms",
    "keepalive_slow_max_ms",
    "mlo_always",
    "dynamic_address",
    "update_check_minutes",
    "update_when_active",
)

LOWEST = 1
HIGHEST = 10

# Step → (short name, one sentence, values). The idle cadence is what a link at
# rest costs, and it is what moves most: a probe every minute against one every
# five seconds is the difference a battery feels. Every idle ceiling is still
# capped by the medium's own timeout (`MeshNode._idle_ceiling`), so a frugal
# step cannot talk a link into being reaped. A fast floor above what a peer
# offers as its fast ceiling means no bundling with it — which on the frugal
# steps is the intended outcome, not a side effect.
#
# Step 6 is exactly the defaults in `config.SETTINGS`, so a node nobody touched
# reads as "Balanced" rather than "custom" (`test_the_default_is_a_step`).
PROFILES = {
    1: ("Minimal", "Spends as little as it can. Connections are checked about "
        "once a minute, two connections to one node are never combined, and "
        "updates are looked for once a day, only while the node is in use.",
        (2000, 5000, 60000, 120000, False, False, 1440, True)),
    2: ("Frugal", "Connections checked every 45 seconds or so, never "
        "combined. Updates twice a day, only while the node is in use.",
        (1500, 5000, 45000, 90000, False, False, 720, True)),
    3: ("Saving", "Connections checked every half minute at rest. Two "
        "connections to one node may be combined, tested twice a second at "
        "most. Updates every four hours while in use.",
        (500, 3000, 30000, 60000, False, False, 240, True)),
    4: ("Light", "Connections checked every 25 seconds at rest. Hourly "
        "updates while in use.",
        (250, 2000, 25000, 40000, False, False, 60, True)),
    5: ("Moderate", "A little quieter than the defaults at rest. Updates "
        "every half hour.",
        (200, 1000, 20000, 30000, False, False, 30, False)),
    6: ("Balanced", "The defaults. Connections checked every 15 to 20 "
        "seconds at rest, extra work only while somebody is using the node, "
        "updates every five minutes.",
        (100, 1000, 15000, 20000, False, False, 5, False)),
    7: ("Responsive", "Connections checked every ten seconds, and a live "
        "connection moves to a faster address of the same node when one "
        "measures better.",
        (100, 1000, 10000, 15000, False, True, 5, False)),
    8: ("Fast", "Two connections to one node stay combined even when nobody "
        "is using this one, so the second is ready the moment traffic starts.",
        (100, 500, 8000, 12000, True, True, 5, False)),
    9: ("Faster", "Connections checked every five seconds at rest, up to "
        "twenty times a second while combined. Updates every two minutes.",
        (50, 500, 5000, 10000, True, True, 2, False)),
    10: ("Maximum", "Notices trouble and recovers as fast as it can, "
         "whatever it costs. For a machine on mains with bandwidth to spare.",
         (50, 300, 3000, 6000, True, True, 1, False)),
}


def values_for(step) -> dict:
    """The settings a step stands for. Raises ``ValueError`` for anything that
    is not one of the ten — a step is chosen, never guessed at."""
    try:
        step = int(step)
    except (TypeError, ValueError):
        raise ValueError("a profile is a whole number from 1 to 10") from None
    if step not in PROFILES:
        raise ValueError("a profile is a whole number from 1 to 10")
    return dict(zip(FIELDS, PROFILES[step][2]))


def match(values: dict):
    """The step these values are exactly, or ``None`` for custom.

    Exact on purpose: "nearest step" would show an operator who tuned one
    number by hand a slider position that does not describe their node."""
    if not isinstance(values, dict):
        return None
    for step, (_name, _text, row) in PROFILES.items():
        if all(_same(values.get(field), want) for field, want in zip(FIELDS, row)):
            return step
    return None


def _same(have, want) -> bool:
    if isinstance(want, bool):
        return have is want
    if isinstance(have, bool) or not isinstance(have, (int, float)):
        return False
    return int(have) == want


def describe() -> list:
    """The table as the console shows it: step, name, sentence, values."""
    return [{"step": step, "name": name, "text": text,
             "values": dict(zip(FIELDS, row))}
            for step, (name, text, row) in PROFILES.items()]
