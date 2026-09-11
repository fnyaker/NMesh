"""
What a refused control call says, and in what vocabulary.

One exception type with a **code from a closed set**, never an HTTP status. The
plane is reached over more than one channel — a page on this machine, a peer
driving us through the fleet relay, tomorrow a command line — and a status
number is one channel's word for a refusal. Each channel translates the code
into whatever it speaks (:mod:`src.webconsole` holds the HTTP mapping); nothing
inside the plane knows there is such a thing as a 404.

The message is written for whoever made the call, so it never carries an
exception's text or a path from this machine: a refusal is answered before
anybody has proved anything on some channels.
"""
from __future__ import annotations

# The closed set. A code is a *kind* of refusal, not a description: the
# description is the message beside it.
CODES = (
    "bad_request",    # the caller's frame or arguments are wrong
    "unauthorized",   # no session, or one that has expired
    "refused",        # understood, allowed nowhere near this origin
    "not_found",      # no such operation, or no such thing to act on
    "conflict",       # the node cannot do this in the state it is in
    "unavailable",    # the node did not answer in time
    "failed",         # it was attempted and did not work
)


# Keys a refusal's structured half may carry. Bounded because it travels: a
# refusal from a node somebody else runs reaches us through this same shape.
MAX_DETAIL = 8


class ControlError(Exception):
    """A control call that will not be answered, and why.

    ``code`` is one of :data:`CODES`; anything else is a bug here rather than
    in the caller, so it is normalised to ``failed`` instead of travelling as a
    name no channel knows how to translate.

    ``detail`` is for the refusal that has a *shape* as well as a sentence —
    the settings form is the case that matters: "some settings were refused"
    is not actionable, and ``{"rejected": ["console_port: …"]}`` is, because the
    page can mark the two fields that were wrong and leave the rest alone. It
    stays optional and bounded: a refusal is a sentence first, and anything
    reading only the sentence must still be told the truth."""

    def __init__(self, code: str, message: str = "", detail=None) -> None:
        self.code = code if code in CODES else "failed"
        self.message = str(message)[:200]
        self.detail = {}
        if isinstance(detail, dict):
            self.detail = {str(key): value for key, value
                           in list(detail.items())[:MAX_DETAIL]}
        super().__init__(self.message or self.code)


class FrameError(ControlError):
    """The bytes were not a frame this plane speaks.

    Always ``bad_request``: a frame that cannot be decoded has not named an
    operation, so there is nothing else it could be refused *for*."""

    def __init__(self, message: str = "malformed frame") -> None:
        super().__init__("bad_request", message)
