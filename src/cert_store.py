import json
import os
import time
from collections import deque
from .node_id import NodeID
from .cert import Certificate
from . import revocation


# Bounds. Certificates arrive from the network — three handlers absorb them
# (`_handle_handshake`, `_handle_handshake_ack`, `_handle_found_node`) — and a
# post-quantum certificate is ~7 kB. Unbounded, the store grew on demand, and
# `get_chain_to_root` is a BFS over it called once per candidate entry of every
# FIND_NODE: a 28-byte packet buying an unbounded graph walk.
MAX_SUBJECTS = 4096          # distinct subjects we keep certificates for
MAX_PER_SUBJECT = 8          # certificates kept for one subject
# Revocations are kept for issuer/subject pairs whose certificates we may never
# have seen — that is the whole point, since forgetting one means accepting the
# certificate it voided the next time somebody presents it. So this bound is
# separate from the certificates', and revocations signed by a root we trust are
# pinned: an attacker minting revocations of its own members must not be able to
# push out the one that matters.
MAX_REVOCATIONS = 4096


def _life(cert) -> float:
    """How long a certificate has left, as a sort key. ``expires_at == 0`` is a
    root: it never dies, so it outranks everything."""
    return float("inf") if cert.expires_at == 0 else float(cert.expires_at)


def _earliest_expiry(chain) -> int:
    """When the first certificate of ``chain`` dies. 0 when none of them does.

    A chain is worth exactly its shortest-lived link: one expired certificate
    and every `verify_chain` on the network refuses the whole thing."""
    stamps = [c.expires_at for c in (chain or ()) if c.expires_at]
    return min(stamps) if stamps else 0


class CertStore:
    """
    Holds the known certificates and the trusted roots — the whole of what this
    node will accept as proof of membership, in a self-rooted P2P PKI.
    """

    def __init__(self, own_id: NodeID,
                 max_subjects: int = MAX_SUBJECTS,
                 max_per_subject: int = MAX_PER_SUBJECT,
                 max_revocations: int = MAX_REVOCATIONS) -> None:
        self._own_id = own_id
        # Insertion-ordered, oldest first: eviction takes the subject nobody has
        # mentioned for longest. Roots and every subject our own chain runs
        # through are pinned (see `_pinned`) — a bound that can make us unable
        # to authenticate is not a bound, it is an outage.
        self._certs: dict[bytes, list[Certificate]] = {}  # subject_id.raw → [Certificate]
        self._roots: set[bytes] = {own_id.raw}
        self._max_subjects = max_subjects
        self._max_per_subject = max_per_subject
        # `get_chain_to_root` memoised per subject, as (chain, good_until).
        # Cleared on any change: a stale chain is a chain that no longer
        # verifies, which is worse than recomputing one. `good_until` closes the
        # one way a cached chain can rot with nothing changing — a certificate
        # in it expiring — so the walk is redone once the clock passes it rather
        # than serving a chain every peer now refuses. 0 means "nothing in it
        # expires"; a `None` result is only ever undone by an `add`, which
        # clears the cache anyway.
        self._chains: dict[bytes, tuple[list[Certificate] | None, int]] = {}
        # (issuer_id.raw, subject_id.raw) → {"issued_at", "reason", "record"}.
        # The raw record is kept so the revocation can be re-gossiped verbatim:
        # re-signing somebody else's statement is not something we could do, and
        # a revocation nobody passes on protects only the node that heard it.
        self._revoked: dict[tuple[bytes, bytes], dict] = {}
        self._max_revocations = max_revocations

    def add_root(self, node_id: NodeID) -> None:
        self._roots.add(node_id.raw)
        self._chains.clear()

    def is_root(self, node_id: NodeID) -> bool:
        return node_id.raw in self._roots

    def remove_root(self, node_id: NodeID) -> bool:
        """Stop trusting an anchor. Returns whether it was one.

        The counterpart to a revocation, and the only thing that works on a
        root: a root's certificate is self-signed, so the one node entitled to
        revoke it is itself — no use when the point is that it has gone bad.
        There is nobody above a root to appeal to, so distrusting one is a
        decision by whoever runs this node and nobody else. Our own id is not
        removable: a node that is not its own root can no longer present
        anything at all."""
        if node_id == self._own_id or node_id.raw not in self._roots:
            return False
        self._roots.discard(node_id.raw)
        self._chains.clear()
        return True

    def roots(self) -> list[str]:
        """The anchors this node trusts, as hex. For the console."""
        return sorted(raw.hex() for raw in self._roots)

    def root_count(self) -> int:
        return len(self._roots)

    # -- revocation -------------------------------------------------------

    def revoke(self, record: bytes, verify) -> dict | None:
        """Absorb a signed revocation. Returns the parsed record if it told us
        something new, ``None`` if it was invalid, stale or already known.

        "New" is what decides whether the caller re-gossips, so an epidemic dies
        out instead of circulating for ever — the same shape as a pseudo claim.
        And like a pseudo claim, a revocation may only move **forward** in time
        per issuer/subject pair: replaying an older one must not walk back a
        newer statement by the same issuer."""
        parsed = revocation.parse(record, verify)
        if parsed is None:
            return None
        key = (parsed["issuer_id"].raw, parsed["subject_id"].raw)
        held = self._revoked.get(key)
        if held is not None and parsed["issued_at"] <= held["issued_at"]:
            return None
        self._revoked[key] = {"issued_at": parsed["issued_at"],
                              "reason": parsed["reason"],
                              "record": bytes(record)}
        self._chains.clear()
        self._enforce_revocation_bound()
        # Drop what it just voided. Filtering them out of every walk would be
        # enough to be *correct*, but they would go on occupying slots in a
        # bounded list and being written to disk for ever — the same reason
        # `prune_expired` exists.
        voided = [c for c in self._certs.get(parsed["subject_id"].raw, ())
                  if self.is_revoked(c)]
        if voided:
            live = [c for c in self._certs[parsed["subject_id"].raw]
                    if c not in voided]
            if live:
                self._certs[parsed["subject_id"].raw] = live
            else:
                del self._certs[parsed["subject_id"].raw]
        return parsed

    def _enforce_revocation_bound(self) -> None:
        """Oldest heard goes first, except what a trusted root said.

        Without the exception, anyone able to mint revocations of their own
        members could flush the table and bring a revoked node back."""
        while len(self._revoked) > self._max_revocations:
            victim = next((k for k in self._revoked if k[0] not in self._roots),
                          None)
            if victim is None:
                return          # everything left was said by an anchor we trust
            del self._revoked[victim]

    def is_revoked(self, cert: Certificate) -> bool:
        """Has this certificate's issuer taken it back?

        A revocation names a **moment**, not a certificate: everything that
        issuer signed for that subject at or before it is void. Naming one
        certificate would leave whichever copy the attacker kept quiet about,
        and a subject may hold several from one issuer. A certificate issued
        *after* the revocation stands — an issuer that changes its mind does so
        by signing again, which keeps readmission a deliberate act."""
        held = self._revoked.get((cert.issuer_id.raw, cert.subject_id.raw))
        return held is not None and cert.issued_at <= held["issued_at"]

    def revocation_for(self, subject: NodeID) -> dict | None:
        """The most recent revocation held against a subject, whoever issued
        it — what the console shows and what a link check asks."""
        best = None
        for (_issuer, subject_raw), held in self._revoked.items():
            if subject_raw != subject.raw:
                continue
            if best is None or held["issued_at"] > best["issued_at"]:
                best = held
        return best

    def revocations(self) -> list[bytes]:
        """Every record we hold, verbatim — for catching a peer up."""
        return [held["record"] for held in self._revoked.values()]

    def ancestors(self, node_id: NodeID) -> set[bytes]:
        """Who vouched for this node, directly or through however many hands.

        The certificate store has always been a graph of who vouched for whom,
        and nothing has ever queried it as one. This is the cheap half: the
        chain we would present for a node already names its whole line of
        descent, and it is memoised, so an ancestry lookup costs a dictionary
        hit. Roots are excluded — everybody in a network shares its root, so
        "they have a common ancestor" is only ever interesting below it."""
        chain = self.get_chain_to_root(node_id)
        if not chain:
            return set()
        line = {cert.issuer_id.raw for cert in chain}
        line.discard(node_id.raw)
        return line - self._roots

    def shared_ancestor(self, node_ids) -> tuple[bytes | None, int]:
        """The issuer the most of these nodes descend from, and how many.

        ``(None, 0)`` when they have nothing below a root in common — which is
        what a set of genuinely unrelated nodes looks like, and the answer that
        should reassure. What the caller does with a high count is never to
        accuse the nodes: a family is not a conspiracy. It is to notice that
        several voices it was about to count as independent are one."""
        counts: dict[bytes, int] = {}
        for node_id in node_ids:
            for ancestor in self.ancestors(node_id):
                counts[ancestor] = counts.get(ancestor, 0) + 1
        if not counts:
            return None, 0
        best = max(counts, key=counts.get)
        return best, counts[best]

    def certs_for(self, node_id: NodeID) -> list[Certificate]:
        """Every certificate held for one subject, expired ones included. A
        copy: the caller must not be able to edit the store by iterating it."""
        return list(self._certs.get(node_id.raw, ()))

    def knows(self, node_id: NodeID) -> bool:
        """Do we hold any certificate at all for this subject?

        Asked on the path that absorbs a routing answer (rule A1 counts
        subjects that are new *to us*), so it answers from the index and never
        builds the list `certs_for` returns."""
        return bool(self._certs.get(node_id.raw))

    def add(self, cert: Certificate) -> bool:
        # An expired certificate proves nothing and never will again, but it
        # still costs a slot in a bounded list — so a peer replaying old
        # certificates could crowd out the live one for a subject it chose.
        if cert.is_expired() or self.is_revoked(cert):
            return False
        key = cert.subject_id.raw
        existing = self._certs.setdefault(key, [])
        for e in existing:
            if e.signature == cert.signature:
                self._touch(key)
                return True  # already present
        existing.append(cert)
        # Cleared before the bounds run, not after: both of them ask what our
        # own chain is made of, and a chain computed from the graph as it was a
        # certificate ago can name the wrong certificates to keep.
        self._chains.clear()
        # Oldest first within a subject: a peer presenting chain after chain
        # cannot make one subject's list grow without end. The one certificate
        # our own chain runs through is not a candidate — a chain visits a
        # subject once, so there is always something else to drop.
        if len(existing) > self._max_per_subject:
            load_bearing = self._chain_signatures()
            while len(existing) > self._max_per_subject:
                victim = next((c for c in existing
                               if c.signature not in load_bearing), existing[0])
                existing.remove(victim)
        self._touch(key)
        self._enforce_bounds()
        return True

    def _touch(self, key: bytes) -> None:
        entry = self._certs.pop(key, None)
        if entry is not None:
            self._certs[key] = entry

    def _chain_signatures(self) -> set[bytes]:
        """The certificates our own chain is made of. Memoised with the chain."""
        return {c.signature for c in (self.get_chain_to_root(self._own_id) or [])}

    def _own_chain_subjects(self) -> set[bytes]:
        """Every subject our own chain runs through.

        Not just us and the root: the issuers in between are what joins the two.
        Losing one leaves us presenting a chain that stops short of a root,
        which no peer can verify — we would go on authenticating everyone else
        while nobody could authenticate us, and no error would be raised
        anywhere. Memoised with the chain, so this costs a lookup."""
        chain = self.get_chain_to_root(self._own_id) or []
        subjects = {c.subject_id.raw for c in chain}
        subjects.update(c.issuer_id.raw for c in chain)
        subjects.add(self._own_id.raw)
        return subjects

    def _pinned(self, key: bytes) -> bool:
        """Subjects eviction may never take: the roots, and our own chain.

        Losing a root means every chain anchored there stops verifying; losing
        any link of our own chain means we can no longer present one at all."""
        return key in self._roots or key in self._own_chain_subjects()

    def _enforce_bounds(self) -> None:
        while len(self._certs) > self._max_subjects:
            victim = next((k for k in self._certs if not self._pinned(k)), None)
            if victim is None:
                return          # everything left is load-bearing
            del self._certs[victim]

    def add_all(self, certs) -> None:
        """Absorb a chain in one go — one bound check, one cache clear."""
        for cert in certs:
            self.add(cert)

    def get_chain_to_root(self, target: NodeID,
                          now: int | None = None) -> list[Certificate] | None:
        """
        A BFS over the issuance graph, looking for a path from target up to a
        known root.

        ``now`` answers "what would we present at that moment?" — the renewal
        sweep and the console use it to see an expiry coming. It bypasses the
        cache rather than poisoning it with an answer for another time.

        We prefer a chain anchored on an **external** root (the network): a node
        that joined a network is also its own self-signed root, but presenting
        ``[own_self_signed_cert]`` authenticates nothing to peers (nobody trusts
        that root). The network chain (through the issuer that invited us) is
        the only one others can verify; the self-root is kept only as a
        fallback.

        Returns [cert_target, ..., cert_root_self_signed] or None.

        **Expired certificates are not walked.** A chain carrying one is refused
        by every `verify_chain` on the network, so returning it is not a
        degraded answer, it is a wrong one: the node would go on presenting a
        chain nobody accepts while a shorter live path sat unused beside it.

        **Of the live ones, the longest-lived wins.** A renewal arrives beside
        the certificate it replaces, both valid; walking insertion order kept
        presenting the old one until the day it died, so the renewal changed
        nothing an operator could see, the countdown never moved, and the sweep
        went on asking every six hours for the rest of the old one's life.

        Memoised per subject: this is a BFS over the issuance graph and
        `_handle_find_node` runs it once per candidate it considers (up to
        `_FIND_NODE_SCAN`), so recomputing it per query made one small packet
        buy a great deal of walking. The cache is dropped whenever the graph or
        the root set changes, and expires with the earliest certificate in it.
        """
        if now is not None:
            return self._build_chain_to_root(target, now)
        now = int(time.time())
        cached = self._chains.get(target.raw)
        if cached is not None and (cached[1] == 0 or now <= cached[1]):
            return cached[0]
        chain = self._build_chain_to_root(target, now)
        self._chains[target.raw] = (chain, _earliest_expiry(chain))
        return chain

    def chain_expires_at(self, target: NodeID) -> int | None:
        """When the chain we would present for ``target`` stops verifying.

        ``0`` for a chain nothing expires (a bare self-signed root), ``None``
        when there is no chain at all. This is what tells a node its own
        membership is running out while it can still do something about it —
        the alternative is finding out from peers that stop authenticating it,
        which looks exactly like a network fault."""
        chain = self.get_chain_to_root(target)
        if chain is None:
            return None
        return _earliest_expiry(chain)

    def prune_expired(self, now: int | None = None) -> int:
        """Drop every certificate that has expired. Returns how many went.

        Nothing verifies against them any more, but `save` wrote them back for
        ever and they still counted against `MAX_PER_SUBJECT` — so a subject
        whose certificate had been renewed a few times could fill its own slot
        list with corpses and start evicting the live one."""
        stamp = int(time.time()) if now is None else now
        removed = 0
        for key, certs in list(self._certs.items()):
            live = [c for c in certs if not c.is_expired(stamp)]
            if len(live) == len(certs):
                continue
            removed += len(certs) - len(live)
            if live:
                self._certs[key] = live
            else:
                del self._certs[key]
        if removed:
            self._chains.clear()
        return removed

    def _build_chain_to_root(self, target: NodeID,
                             now: int | None = None) -> list[Certificate] | None:
        now = int(time.time()) if now is None else now
        target_certs = [c for c in self._certs.get(target.raw, ())
                        if self._usable(c, now)]
        if not target_certs:
            return None

        visited: set[bytes] = {target.raw}
        # An external issuer first (the network chain is the only one a peer can
        # verify), then the longest-lived — a renewal must take over from the
        # certificate it replaces, not wait for it to die.
        sorted_certs = sorted(
            target_certs, key=lambda c: (1 if c.is_self_signed else 0, -_life(c)))
        queue: deque[tuple[bytes, list[Certificate]]] = deque(
            (c.issuer_id.raw, [c]) for c in sorted_certs
        )
        self_anchored: list[Certificate] | None = None  # fallback: our own root

        while queue:
            current_raw, path = queue.popleft()

            if current_raw in self._roots:
                last = path[-1]
                if last.is_self_signed:
                    chain = path
                else:
                    chain = None
                    for rc in self._live(current_raw, now):
                        if rc.is_self_signed:
                            chain = path + [rc]
                            break
                    if chain is None:
                        # Root known but no self-signed cert yet — keep BFS going
                        if current_raw not in visited:
                            visited.add(current_raw)
                            for cert in self._live(current_raw, now):
                                queue.append((cert.issuer_id.raw, path + [cert]))
                        continue
                if current_raw != self._own_id.raw:
                    return chain            # anchored on the network root — best
                if self_anchored is None:
                    self_anchored = chain   # only good if nothing external exists
                continue

            if current_raw in visited:
                continue
            visited.add(current_raw)

            for cert in self._live(current_raw, now):
                queue.append((cert.issuer_id.raw, path + [cert]))

        return self_anchored

    def _usable(self, cert: Certificate, now: int) -> bool:
        """Is this certificate worth walking? One predicate, asked everywhere
        the graph is traversed: an expired or revoked certificate is refused by
        every `verify_chain` on the network, so a chain built on one is not a
        weaker answer but a wrong one."""
        return not cert.is_expired(now) and not self.is_revoked(cert)

    def _live(self, key: bytes, now: int) -> list[Certificate]:
        """The certificates held for one subject that are still worth
        presenting, longest-lived first — so a walk that stops at the first
        usable one stops at the best one."""
        return sorted((c for c in self._certs.get(key, ())
                       if self._usable(c, now)), key=_life, reverse=True)

    def verify_chain(self, chain: list[Certificate]) -> NodeID | None:
        """
        Verify a chain presented by a peer.
        Returns the anchor (the root's NodeID) if it is valid, None otherwise.

        Invariants:
          1. Every cert holds its own invariants (already checked at parse time).
          2. Unbroken issuance links.
          3. The last cert is self-signed.
          4. The last cert.subject_id is in roots.
          5. No expired cert, and none its issuer has taken back.

        A revoked link anywhere voids the whole chain, not just the hop it sits
        on: everything below it was vouched for *through* the node that has just
        been disowned.
        """
        if not chain:
            return None

        now = int(time.time())
        for cert in chain:
            if not self._usable(cert, now):
                return None

        for i in range(len(chain) - 1):
            if chain[i].issuer_id != chain[i + 1].subject_id:
                return None
            if chain[i].issuer_pub != chain[i + 1].subject_pub:
                return None

        last = chain[-1]
        if not last.is_self_signed:
            return None
        if last.subject_id.raw not in self._roots:
            return None

        return last.subject_id

    def save(self, path: str) -> None:
        roots = [r.hex() for r in self._roots]
        certs_json: dict[str, list[dict]] = {
            raw.hex(): [c.to_json() for c in cert_list]
            for raw, cert_list in self._certs.items()
        }
        tmp = path + ".tmp"
        with open(tmp, 'w') as f:
            json.dump({"roots": roots, "certs": certs_json,
                       "revocations": [held["record"].hex()
                                       for held in self._revoked.values()]}, f)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str, own_id: NodeID) -> 'CertStore':
        """Read a store back, treating the file as hostile: anything that does
        not parse, or no longer verifies, is skipped rather than raised. Expired
        certificates never make it in — `add` refuses them — so a file does not
        accumulate corpses across restarts.

        **Revocations are read before the certificates**, and re-verified like
        everything else here. A revocation that only took effect while the
        process happened to be running would be undone by a restart, which is
        the one moment a compromised member most wants us to have."""
        from .crypto import verify_signature
        store = cls(own_id)
        try:
            with open(path) as f:
                data = json.load(f)
            for root_hex in data.get("roots", []):
                try:
                    store._roots.add(bytes.fromhex(root_hex))
                except ValueError:
                    pass
            for record_hex in data.get("revocations", []):
                try:
                    store.revoke(bytes.fromhex(record_hex), verify_signature)
                except ValueError:
                    pass
            for subject_hex, cert_list in data.get("certs", {}).items():
                for cert_data in cert_list:
                    try:
                        cert = Certificate.from_json(subject_hex, cert_data)
                        store.add(cert)
                    except (ValueError, KeyError):
                        pass
        except FileNotFoundError:
            pass
        return store
