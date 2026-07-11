"""
Content-addressed store for the DHT.

Values are keyed by their own hash (``sha256(value)[:20]``). ``put`` refuses any
value whose key doesn't match its content, so a peer can never store arbitrary
data under a key it chose — the classic DHT poisoning vector is closed by
construction (see CLAUDE.md). The store is bounded in both entry count and total
bytes, evicting least-recently-used entries under pressure, so a flood of STOREs
can't exhaust memory.
"""
from __future__ import annotations

from collections import OrderedDict

from .app_package import content_key, KEY_LEN

MAX_VALUE = 60_000                       # fits one packet payload
_MAX_ENTRIES = 8192
_MAX_BYTES = 128 * 1024 * 1024           # 128 MiB


class ContentStore:
    def __init__(self, max_entries: int = _MAX_ENTRIES,
                 max_bytes: int = _MAX_BYTES) -> None:
        self._d: "OrderedDict[bytes, bytes]" = OrderedDict()
        self._bytes = 0
        self._max_entries = max_entries
        self._max_bytes = max_bytes

    def put(self, key: bytes, value: bytes) -> bool:
        if len(key) != KEY_LEN or len(value) > MAX_VALUE:
            return False
        if content_key(value) != key:
            return False  # not content-addressed — reject (anti-poisoning)
        if key in self._d:
            self._d.move_to_end(key)
            return True
        self._d[key] = value
        self._bytes += len(value)
        while len(self._d) > self._max_entries or self._bytes > self._max_bytes:
            _, evicted = self._d.popitem(last=False)
            self._bytes -= len(evicted)
        return True

    def get(self, key: bytes) -> bytes | None:
        value = self._d.get(key)
        if value is not None:
            self._d.move_to_end(key)
        return value

    def __contains__(self, key: bytes) -> bool:
        return key in self._d

    def __len__(self) -> int:
        return len(self._d)
