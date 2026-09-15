"""
The message vocabulary: every packet type this node can speak.

One number per kind of message, and the name each carries in a trace.
Split out of ``node.py`` so the protocol's vocabulary has a module of
its own: it is what a transport, an app and the console all name a
message by, and none of them should have to import the node to name
one.
"""

DATA          = 0x00
PING          = 0x01
PONG          = 0x02
FIND_NODE     = 0x03
FOUND_NODE    = 0x04
FIND_VALUE    = 0x05
FOUND_VALUE   = 0x06
STORE         = 0x07
HANDSHAKE     = 0x08
HANDSHAKE_ACK = 0x09
INVITE        = 0x0A
INVITE_ACK    = 0x0B
CHALLENGE         = 0x0C
E2E_HANDSHAKE     = 0x0D
E2E_HANDSHAKE_ACK = 0x0E
OBSERVED_ADDR     = 0x0F
PUNCH_REQUEST     = 0x10
PUNCH_RELAY       = 0x11
PUNCH_PROBE       = 0x12
PUNCH_ACK         = 0x13
INVITE_SEEK       = 0x14   # relayed invitation seek — routable PRE-auth, token-gated
RELAY_CARRY       = 0x15   # carries a handshake packet between two nodes via a relay
REACH_PROBE       = 0x16   # ask a peer to dial us back and confirm we're reachable
REACH_PROBE_ACK   = 0x17   # reply: did the dial-back succeed?
CATALOG_ANNOUNCE  = 0x18   # gossip a signed app-store release descriptor
DIR_STORE         = 0x19   # store a signed pseudo-directory claim
DIR_FIND          = 0x1A   # look up pseudo-directory claims by key
DIR_FOUND         = 0x1B   # reply: the claims held for a pseudo key
ECHO_REQUEST      = 0x1C   # routed liveness probe to a node id (multi-hop)
ECHO_REPLY        = 0x1D   # routed reply to an ECHO_REQUEST
RELEASE_ANNOUNCE  = 0x1E   # gossip a signed descriptor for the node's own code
RELEASE_FETCH     = 0x1F   # "send me this release's package, from here"
RELEASE_DATA      = 0x20   # a slice of a package, answering a fetch
PSEUDO_ANNOUNCE   = 0x21   # gossip a signed claim binding a pseudo to its node
CERT_RENEW        = 0x22   # "re-issue the membership certificate you signed for me"
CERT_RENEWED      = 0x23   # reply: the fresh certificate
CERT_REVOKE       = 0x24   # gossip a signed revocation of a membership
ABUSE_REPORT      = 0x25   # gossip a signed accusation: "this node is misbehaving"
CAPABILITIES      = 0x26   # "here is what I can speak" — the base negotiation
KA_PROPOSE        = 0x27   # "the keepalive cadences I can work with" (min, max)
KA_REQUEST        = 0x28   # "slow your keepalive down to this" — never speed up
PKG_STORE         = 0x29   # store a signed package-directory record
PKG_FIND          = 0x2A   # look up package-directory records by key
PKG_FOUND         = 0x2B   # reply: the records held for a package key
PKG_ANNOUNCE      = 0x2C   # gossip a signed record: "this key publishes that"
KEY_OFFER         = 0x2D   # "I hold this publisher key and offer it to you"
KEY_ACCEPT        = 0x2E   # "I want it — seal it to this KEM key" (signed)
KEY_GRANT         = 0x2F   # the publisher secret, sealed to that key
INVITE_OFFER      = 0x30   # "expect a seek for this code" — the inviter, to a relay
SPEED_PROBE       = 0x31   # padding, to measure a link by loading it
SPEED_ECHO        = 0x32   # the same padding back — one for one, never more

# Built from this module's own constants so a message type added above can never
# be missing here — a trace showing "0x1e" for a type the code knows the name of
# is exactly the moment a trace stops being useful.
MESSAGE_NAMES = {
    value: name for name, value in list(globals().items())
    if isinstance(value, int) and name.isupper() and not name.startswith("_")
    and 0x00 <= value <= 0xFF
}


__all__ = [
    "ABUSE_REPORT",
    "CAPABILITIES",
    "CATALOG_ANNOUNCE",
    "CERT_RENEW",
    "CERT_RENEWED",
    "CERT_REVOKE",
    "CHALLENGE",
    "DATA",
    "DIR_FIND",
    "DIR_FOUND",
    "DIR_STORE",
    "E2E_HANDSHAKE",
    "E2E_HANDSHAKE_ACK",
    "ECHO_REPLY",
    "ECHO_REQUEST",
    "FIND_NODE",
    "FIND_VALUE",
    "FOUND_NODE",
    "FOUND_VALUE",
    "HANDSHAKE",
    "HANDSHAKE_ACK",
    "INVITE",
    "INVITE_ACK",
    "INVITE_OFFER",
    "INVITE_SEEK",
    "KA_PROPOSE",
    "KA_REQUEST",
    "KEY_ACCEPT",
    "KEY_GRANT",
    "KEY_OFFER",
    "MESSAGE_NAMES",
    "OBSERVED_ADDR",
    "PING",
    "PKG_ANNOUNCE",
    "PKG_FIND",
    "PKG_FOUND",
    "PKG_STORE",
    "PONG",
    "PSEUDO_ANNOUNCE",
    "PUNCH_ACK",
    "PUNCH_PROBE",
    "PUNCH_RELAY",
    "PUNCH_REQUEST",
    "REACH_PROBE",
    "REACH_PROBE_ACK",
    "RELAY_CARRY",
    "RELEASE_ANNOUNCE",
    "RELEASE_DATA",
    "RELEASE_FETCH",
    "SPEED_ECHO",
    "SPEED_PROBE",
    "STORE",
]
