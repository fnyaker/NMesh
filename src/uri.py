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


# The scheme of an address, remembered. Asked per link per packet sent — a
# route is chosen by scoring every link, and a link's score starts from what its
# medium is worth — and the answer is a pure function of the string, so there is
# nothing to invalidate. Bounded twice: only a string of at most `_MAX_URI_LEN`
# characters is kept, and a full table is dropped rather than walked.
_SCHEME_MEMO_MAX = 1024
_scheme_memo: dict[str, str | None] = {}


def uri_scheme(s: str) -> str | None:
    """The scheme of a valid URI, ``None`` for an invalid one."""
    try:
        return _scheme_memo[s]
    except KeyError:
        pass
    result = _validate_uri(s)
    scheme = None if result is None else result[0]
    if len(s) <= _MAX_URI_LEN:
        if len(_scheme_memo) >= _SCHEME_MEMO_MAX:
            _scheme_memo.clear()
        _scheme_memo[s] = scheme
    return scheme
