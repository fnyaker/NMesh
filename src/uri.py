import re

_MAX_URI_LEN  = 256
_MAX_ADDRESSES = 8
_MAX_SCHEME_LEN = 16

_SCHEME_RE = re.compile(r'^[a-z][a-z0-9]{0,15}$')


def _validate_uri(s: str) -> tuple[str, str] | None:
    """Return (scheme, opaque) or None if the URI is invalid."""
    if len(s.encode('utf-8')) > _MAX_URI_LEN:
        return None
    sep = s.find('://')
    if sep < 0:
        return None
    scheme = s[:sep]
    opaque = s[sep + 3:]
    if not _SCHEME_RE.match(scheme):
        return None
    for ch in s:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            return None
    return scheme, opaque
