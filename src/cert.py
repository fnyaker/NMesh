import struct
import time
import oqs
from .node_id import NodeID

_DSA_ALG = "ML-DSA-65"
_CERT_HEADER = struct.Struct('!20sH20sHQQH')
# subject_id(20) | subject_pub_len(H) | issuer_id(20) | issuer_pub_len(H)
# | issued_at(Q) | expires_at(Q) | sig_len(H)


def _verify_dsa(message: bytes, signature: bytes, public_key: bytes) -> bool:
    with oqs.Signature(_DSA_ALG) as v:
        return v.verify(message, signature, public_key)


class Certificate:

    def __init__(self,
                 subject_id: NodeID,
                 subject_pub: bytes,
                 issuer_id: NodeID,
                 issuer_pub: bytes,
                 issued_at: int,
                 expires_at: int,
                 signature: bytes) -> None:
        self.subject_id = subject_id
        self.subject_pub = subject_pub
        self.issuer_id = issuer_id
        self.issuer_pub = issuer_pub
        self.issued_at = issued_at
        self.expires_at = expires_at
        self.signature = signature

    @property
    def is_self_signed(self) -> bool:
        return self.subject_id == self.issuer_id

    def is_expired(self) -> bool:
        if self.expires_at == 0:
            return False
        return int(time.time()) > self.expires_at

    def signed_body(self) -> bytes:
        return (
            self.subject_id.raw
            + struct.pack('!H', len(self.subject_pub)) + self.subject_pub
            + self.issuer_id.raw
            + struct.pack('!H', len(self.issuer_pub)) + self.issuer_pub
            + struct.pack('!QQ', self.issued_at, self.expires_at)
        )

    @classmethod
    def _build(cls,
               subject_id: NodeID, subject_pub: bytes,
               issuer_id: NodeID, issuer_pub: bytes,
               issued_at: int, expires_at: int,
               signature: bytes) -> 'Certificate':
        """Validate all three invariants then construct. Raises ValueError on any failure."""
        if NodeID.from_public_key(subject_pub) != subject_id:
            raise ValueError("subject_id does not match subject_pub")
        if NodeID.from_public_key(issuer_pub) != issuer_id:
            raise ValueError("issuer_id does not match issuer_pub")
        cert = cls(subject_id, subject_pub, issuer_id, issuer_pub,
                   issued_at, expires_at, signature)
        if not _verify_dsa(cert.signed_body(), signature, issuer_pub):
            raise ValueError("invalid certificate signature")
        return cert

    def serialize(self) -> bytes:
        header = _CERT_HEADER.pack(
            self.subject_id.raw, len(self.subject_pub),
            self.issuer_id.raw, len(self.issuer_pub),
            self.issued_at, self.expires_at,
            len(self.signature),
        )
        return header + self.subject_pub + self.issuer_pub + self.signature

    @classmethod
    def deserialize(cls, data: bytes) -> 'Certificate':
        if len(data) < _CERT_HEADER.size:
            raise ValueError("cert too short")
        raw_sid, spub_len, raw_iid, ipub_len, issued_at, expires_at, sig_len = (
            _CERT_HEADER.unpack_from(data, 0)
        )
        offset = _CERT_HEADER.size
        if offset + spub_len + ipub_len + sig_len > len(data):
            raise ValueError("cert data truncated")
        subject_pub = data[offset:offset + spub_len]; offset += spub_len
        issuer_pub = data[offset:offset + ipub_len];  offset += ipub_len
        signature  = data[offset:offset + sig_len]
        return cls._build(
            NodeID(raw_sid), subject_pub,
            NodeID(raw_iid), issuer_pub,
            issued_at, expires_at, signature,
        )

    def to_json(self) -> dict:
        return {
            "subject_pub": self.subject_pub.hex(),
            "issuer_id":   self.issuer_id.raw.hex(),
            "issuer_pub":  self.issuer_pub.hex(),
            "issued_at":   self.issued_at,
            "expires_at":  self.expires_at,
            "signature":   self.signature.hex(),
        }

    @classmethod
    def from_json(cls, subject_id_hex: str, data: dict) -> 'Certificate':
        return cls._build(
            NodeID.from_hex(subject_id_hex),
            bytes.fromhex(data["subject_pub"]),
            NodeID.from_hex(data["issuer_id"]),
            bytes.fromhex(data["issuer_pub"]),
            data["issued_at"],
            data["expires_at"],
            bytes.fromhex(data["signature"]),
        )
