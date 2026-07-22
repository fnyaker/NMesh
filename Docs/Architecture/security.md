# Identité, crypto & confiance

Source : `crypto.py`, `node_id.py`, `cert.py`, `cert_store.py`, `trust.py`,
`invite.py`, et les handlers de handshake dans `node.py`.

## Identité

- `CryptoIdentity` (`crypto.py`) détient une paire **ML-DSA-65** (signature).
  La clé privée reste en mémoire ; `save/load` la persiste en binaire brut sous
  le répertoire d'état (`node.key`).
- `NodeID = sha256(clé_publique_DSA)[:20]` (`NodeID.from_public_key`). Donc
  **l'ID est dérivable de la clé** : un `NodeID` qui ne correspond pas à la clé
  présentée est un mensonge → rejet (`claimed_id != NodeID(packet.src_id)`).
- ML-KEM-768 sert **uniquement** à négocier un secret au handshake ; le débit
  se fait ensuite en AES-256-GCM.

## Clés de session (`SessionKey`)

- `SessionKey(shared_secret)` dérive une clé AES-256 via **HKDF-SHA256**
  (`info = b"nmesh-session-key"`).
- `from_key` reconstruit une session depuis la clé 32o déjà dérivée (persistance
  — on stocke la clé, jamais le secret ML-KEM brut).
- `derive_secret` (HKDF sur la clé DSA) produit des sous-clés at-rest sous la
  même frontière de confiance que l'identité (chiffrement du session store).

## Certificats & PKI P2P auto-racinée

Il n'y a **pas d'autorité centrale**. Chaque nœud est racine auto-signée de
lui-même ; la confiance se propage par chaînes de certificats.

- `Certificate` (`cert.py`) : `subject_id/pub`, `issuer_id/pub`, `issued_at`,
  `expires_at`, `signature`. `signed_body()` couvre tout sauf la signature.
  `_build()` **revalide 3 invariants** à chaque (dé)sérialisation : `subject_id`
  dérive de `subject_pub`, `issuer_id` de `issuer_pub`, et la signature de
  l'émetteur est valide. → un certificat mal formé lève avant d'entrer en RAM.
- `issue_cert` : à la fin d'un handshake accepté par invitation, l'hôte émet un
  certificat pour le nouveau nœud (l'atteste comme membre), inclus dans le
  `HANDSHAKE_ACK`. `self_signed_cert` : racine.
- `CertStore` (`cert_store.py`) : `subject_id → [certs]` + ensemble de racines
  (`_roots`, contient au moins soi).
  - `get_chain_to_root(target)` : **BFS** dans le graphe d'émission jusqu'à une
    racine. **Préfère une racine externe** (le réseau) : présenter sa propre
    racine auto-signée n'authentifie rien auprès des pairs ; la chaîne réseau
    (via l'émetteur qui nous a invités) est la seule vérifiable par autrui.
  - `verify_chain(chain)` : liens d'émission continus + dernier cert self-signed
    + dernier `subject_id ∈ roots` + aucun expiré → retourne l'ancre, sinon None.
- `TrustTable` (`trust.py`) : **TOFU** `NodeID → clé DSA`. Première vue → stocke ;
  vue suivante avec **clé différente** → `False` (compromission/usurpation).

## Invitation (`invite.py`)

Rejoindre = prouver la connaissance d'un code **sans l'envoyer en clair**.

- `generate_code()` : code de 10 caractères, TTL 5 min, plusieurs codes
  simultanés possibles (réseaux en étoile).
- Challenge/réponse : `response = HMAC-SHA256(code, challenge)`
  (`compute_response`). `verify_response` compare en **temps constant**
  (`hmac.compare_digest`), purge les codes expirés.
- **Usage unique** : `consume(challenge, response)` supprime le code qui matche.
- Anti-bruteforce : `_MAX_FAILURES = 3` → lockout `_LOCKOUT_TTL = 60 s`.

## Handshake par-saut (établissement d'une session entre 2 pairs directs)

Flux (voir `_on_new_transport`, `_handle_challenge`, `initiate_handshake`,
`_handle_handshake`, `_handle_handshake_ack`) :

1. Le serveur qui accepte une connexion envoie un **CHALLENGE** (aléatoire, +
   marque `pending_challenge`).
2. Le client répond via `initiate_handshake` : **HANDSHAKE** = clé pub ML-KEM +
   clé pub ML-DSA + chaîne de certs + `sign(challenge‖kem_pub‖dsa_pub)`.
   Si le client rejoignait par invitation, la réponse HMAC au challenge prouve
   le code.
3. Le serveur (`_handle_handshake`) vérifie la signature, vérifie `claimed_id`,
   vérifie la chaîne (ou émet un cert si `invite_accepted`), encapsule ML-KEM →
   `HANDSHAKE_ACK` = ciphertext ML-KEM + sa clé DSA + sa chaîne + cert émis +
   signature. `peer.session = SessionKey(shared_secret)`.
4. Le client (`_handle_handshake_ack`) vérifie, décapsule → même `SessionKey`.

À partir de là, `peer.authenticated_id` est posé des deux côtés et tout le
trafic du lien est chiffré AES-256-GCM. La confiance est **mutuelle** (chacun
challenge l'autre).

> **Note d'invariant adresses** : le handshake **ne transporte pas** encore
> l'ensemble des adresses annoncées du pair. Après authentification, on ne
> connaît que l'adresse composée (client) ou aucune (serveur : `_routing.add(id,
> [], pub)`). L'ensemble complet arrive par **gossip** (PING portant
> `advertised_uris`, FOUND_NODE). Voir `routing.md` §propagation d'adresses pour
> l'invariant visé et son mécanisme.

## Session E2E (de bout en bout)

`_initiate_e2e_handshake` / `_handle_e2e_handshake(_ack)` : ML-KEM + signature +
chaîne, mais **routés** à travers le mesh (types `_ROUTABLE_TYPES`) jusqu'à la
destination finale. Résultat : `_e2e_sessions[peer]`. Les DATA sont chiffrées
sous cette session E2E (`create_encrypted`) : **les relais ne déchiffrent
jamais** — ils ne voient que le header de routage.
</content>
