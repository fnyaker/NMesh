"""
What two nodes agree they can say to each other.

A version number would have been the obvious thing and the wrong one. It puts
every build on one line and forces a comparison — *newer* or *older* — which
answers the wrong question twice over. It has nothing to say about a node that
implements half the protocol and one thing of its own, and it turns "I do not
know this message" into "you are ahead of me", which is one short step from
treating an unfamiliar peer as a broken one.

So a node does not announce a version. It announces **a set of names for the
things it can speak**, and two nodes work in the intersection. A build with an
extra feature and a build without it agree on everything they share and simply
never use the rest; a node with something entirely of its own is not
mis-versioned, it is a node whose set contains a name we do not recognise, and
that costs nobody anything.

Why this belongs next to the abuse machinery
--------------------------------------------
Because without it, **"a message I do not understand" and "a message I should
not have been sent" are the same event**, and anything that judges behaviour has
to guess which one it is looking at. Guess one way and a node running tomorrow's
build gets reported by every node running today's. Guess the other way and the
judgement is worth nothing, because everything unrecognised is excused. The
agreed set is what separates them: inside it, an unexpected message means
something; outside it, it means the other side knows something we do not.

The three rules
---------------
1. **This envelope never changes.** ``BASE_VERSION`` exists so that a node can
   refuse a negotiation it cannot parse, and for no other purpose. Everything
   that evolves, evolves as a name in the set — which is the point of having a
   set. A second version of this format would be the very problem it removes.
2. **Silence means the classic set.** A node that says nothing is not a node
   with no features; it is a node from before this existed, and it must keep
   working exactly as it did. Absence is never read as refusal.
3. **Negotiation may only ever add.** No feature name may switch off a check,
   weaken a cipher, skip a verification or widen an authorisation — otherwise
   the negotiation, which happens before anybody has proved anything, becomes
   the way in. Everything security-critical is unconditional and stays that way;
   what is negotiated is only ever which *optional* messages are worth sending.
"""
from __future__ import annotations

import re
import struct

# The envelope. Frozen — see rule 1.
BASE_VERSION = 1

# Bounds. This arrives from an unauthenticated peer on a link that has proved
# nothing yet, so it is parsed like any hostile input.
MAX_FEATURES = 64
MAX_NAME = 16
_NAME_RE = re.compile(rb"\A[a-z0-9_]{1,%d}\Z" % MAX_NAME)
_HDR = struct.Struct("!BH")     # version, count
MAX_RECORD = _HDR.size + MAX_FEATURES * (1 + MAX_NAME)

# What this build speaks. A name per plane of the protocol, not per message:
# the unit that evolves together is the plane, and a node either has the pseudo
# directory or it does not.
CORE = "core"              # challenge, handshake, data, ping — never optional
KADEMLIA = "kad"           # FIND_NODE / FOUND_NODE / STORE / FIND_VALUE
E2E = "e2e"                # routed end-to-end sessions
DIRECTORY = "dir"          # the pseudo directory (DIR_STORE / FIND / FOUND)
PSEUDO = "pseudo"          # gossip of signed name claims
CATALOG = "catalog"        # app-store catalogue gossip
RELEASE = "release"        # the node's own code: gossip and transfer
PUNCH = "punch"            # UDP hole punching
REACH = "reach"            # reachability probes
RELAY = "relay"            # relayed invitation and carry
RENEW = "certren"          # membership renewal
REVOKE = "revoke"          # membership revocation gossip
ABUSE = "abuse"            # signed abuse reports

SPOKEN = frozenset({CORE, KADEMLIA, E2E, DIRECTORY, PSEUDO, CATALOG, RELEASE,
                    PUNCH, REACH, RELAY, RENEW, REVOKE, ABUSE})


class FeatureError(Exception):
    """Raised only when *building* a record, on caller misuse."""


def encode(names) -> bytes:
    """Serialise a feature set. Order is not meaningful, so it is sorted —
    two nodes with the same features produce the same bytes, which makes a
    record comparable and a test readable."""
    tokens = sorted({str(name).encode("ascii", "ignore") for name in names})
    if len(tokens) > MAX_FEATURES:
        raise FeatureError("too many features")
    parts = [_HDR.pack(BASE_VERSION, len(tokens))]
    for token in tokens:
        if not _NAME_RE.match(token):
            raise FeatureError(f"bad feature name {token!r}")
        parts.append(bytes([len(token)]))
        parts.append(token)
    return b"".join(parts)


def decode(data) -> frozenset | None:
    """Parse a peer's announcement. ``None`` for anything that does not check
    out — never raises, because this is a gate on an unauthenticated link.

    **Names we do not recognise are kept.** They are the whole reason a custom
    build is not a broken one: dropping them would leave us unable to tell "this
    peer speaks something I have never heard of" from "this peer speaks
    nothing", and those two call for opposite judgements."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    if not (_HDR.size <= len(data) <= MAX_RECORD):
        return None
    data = bytes(data)
    version, count = _HDR.unpack_from(data, 0)
    if version != BASE_VERSION or count > MAX_FEATURES:
        return None
    names = set()
    offset = _HDR.size
    for _ in range(count):
        if offset >= len(data):
            return None
        length = data[offset]
        offset += 1
        if length == 0 or offset + length > len(data):
            return None
        token = data[offset:offset + length]
        offset += length
        if not _NAME_RE.match(token):
            return None
        names.add(token.decode("ascii"))
    if offset != len(data):
        return None      # trailing bytes are a second encoding of one record
    return frozenset(names)


def agree(theirs, ours=SPOKEN) -> frozenset:
    """What the two of us can actually use.

    ``CORE`` is in the result whatever either side said. It is not negotiable —
    it is the messages that carry the negotiation itself — and a peer that
    omitted it is old, not mute (rule 2)."""
    return frozenset(theirs) & frozenset(ours) | {CORE}
