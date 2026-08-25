# Identité, crypto & confiance

Source : `crypto.py`, `node_id.py`, `cert.py`, `cert_store.py`, `trust.py`,
`invite.py`, et les handlers de handshake dans `node.py`.

## Identité

- `CryptoIdentity` (`crypto.py`) détient une paire **ML-DSA-65** (signature).
  La clé privée reste en mémoire ; `save/load` la persiste en binaire brut sous
  le répertoire d'état (`node.key`), **créée en 0600 dès l'ouverture** (pas un
  `chmod` après coup, qui laisserait une fenêtre de lecture) et re-serrée si un
  fichier plus permissif traîne d'une version antérieure. Le répertoire d'état
  lui-même est en 700 et appartient au compte dédié du nœud quand il a été posé
  par `install.sh` (voir [`../Setup/guide`](../Setup/guide)).
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
- **TTL par code.** `generate_code(ttl)` allonge la fenêtre d'un code précis,
  borné par `_MAX_TTL` (6 h). C'est pour les invitations qui ne sont pas tapées
  à la main : celle qu'une node dépose sur une machine en cours de provisioning
  n'est redeemée qu'après l'installation des dépendances, bien au-delà des
  5 minutes par défaut. Usage unique et lockout s'appliquent inchangés ; seule
  la fenêtre bouge, et c'est un choix explicite de l'appelant.

## Ticket de join (`join_ticket.py`)

Même invitation, transportée autrement : une seule chaîne courte qui porte
l'adresse **et** le code, pour un QR code ou une dictée.

- `generate_seeded_code(ttl)` émet un code ordinaire — usage unique, même
  lockout, jamais transmis en clair — mais dérivé de 8 octets aléatoires, pour
  qu'un ticket le porte en 8 octets plutôt qu'en caractères. Les deux côtés
  dérivent la chaîne du code de la même façon (`code_from_seed`).
- **Le ticket est le secret.** Il vaut exactement le code qu'il contient : qui
  le lit peut rejoindre jusqu'à expiration ou usage unique. 64 bits d'entropie
  derrière un code à usage unique et un lockout à 3 échecs.
- **Émis seulement depuis une adresse `world` confirmée** (`public_endpoints`) :
  pas « on croit que cette adresse est publique », mais « une connexion entrante
  authentifiée est arrivée dessus ». Un ticket vers une adresse injoignable
  échouerait après avoir été partagé.
- L'expiration inscrite dans le ticket est un **indice** pour le lecteur, jamais
  une autorité : seul le nœud émetteur décide si le code marche encore.
- Le checksum (2 octets) attrape une faute de frappe avant de composer quoi que
  ce soit. Ce n'est **pas** de l'intégrité contre un attaquant — il le
  recalculerait.
- Un ticket porte une **adresse numérique**, jamais un nom d'hôte : un nom
  demanderait un résolveur côté scanner et pourrait pointer ailleurs plus tard.
- Décodage traité comme une entrée hostile : longueur bornée, chaque champ
  validé avant usage, et rien d'autre qu'une `TicketError` ne peut sortir.

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

### Re-clé côté répondeur : candidat probé, jamais d'écrasement à l'aveugle

Un handshake valide qui arrive alors qu'une session est **déjà vivante** peut
être un doublon tardif (retry toutes les 5 s, chemin relayé lent) ou une vraie
re-clé (le pair a perdu sa session). Écraser la session à l'aveugle empoisonne
le lien dans le cas du doublon (l'initiateur ignore l'ACK, garde l'ancienne
clé → désaccord de clés permanent → tout DATA dropé au GCM, silencieusement).
Le répondeur dérive donc une session **candidate** (`_e2e_rekey`, bornée
`_E2E_REKEY_MAX`, TTL `_E2E_REKEY_TTL`), ACK normalement, et ne **promeut** le
candidat que lorsqu'un DATA **déchiffre** sous lui (`_handle_data`) — preuve
que le pair détient réellement la nouvelle clé.

Pourquoi c'est sûr : planter un candidat exige l'identité ML-DSA du pair
(signature fraîche + chaîne ancrée, comme pour une établissement normal) ;
promouvoir exige de décapsuler le KEM (seul le détenteur du secret KEM génère
un DATA valide). Un handshake **rejoué** produit un candidat que l'attaquant ne
peut jamais promouvoir (il ne décapsule pas notre ciphertext frais) → il
expire. Un doublon légitime ne casse rien : la session vivante est conservée.
</content>

## Identité applicative (au-dessus de la session E2E)

Source : `app_auth.py`, exposé par `node.app_auth(app_id)` et par les trames
`AUTH_*` du connecteur. Détail complet : [`Docs/AppAuth/guide`](../AppAuth/guide).

La session E2E authentifie le **transport** : quand une payload DATA arrive à une
app, son `src_id` est prouvé. Mais cette preuve est confinée à une session
vivante — irrécupérable après redémarrage, intransmissible, et muette sur
l'**intention**. `app_auth` ajoute une **assertion** : un énoncé signé ML-DSA
« le nœud S affirme, dans l'app A, à B, pour le purpose P, sur le contexte C, à
l'instant T », portable, scopé, frais et à usage unique.

Deux invariants de sécurité, à ne pas casser :

- **Ce n'est pas un oracle de signature.** La même clé ML-DSA signe certificats,
  handshakes, releases et réclamations d'annuaire. Rien dans `app_auth` ne signe
  des octets fournis par l'app : l'entrée signée est toujours
  `b"nmesh-app-auth-v1" ‖ <champs structurés bornés>`, et le contexte libre
  n'entre que par un hash 32 o. Le domaine est distinct de tous les autres du
  dépôt. Une app ne peut donc pas faire signer un corps de certificat.
- **L'`app_id` vient de la session, jamais de la trame** — comme pour le tiroir
  et la DHT par-app. Une app ne peut pas émettre pour la section d'une autre.

L'identité du signataire n'est pas un champ séparé : `NodeID` dérive de la clé
présentée, donc il n'y a pas d'id à mentir (même invariant que le handshake).

`verify_assertion` ordonne ses contrôles du moins cher au plus cher et ne brûle
le nonce anti-rejeu **qu'après** les contrôles bon marché — sinon un flot
d'assertions invalides évincerait des entrées vivantes d'un cache borné.

**Authentification n'est pas autorisation.** Une assertion prouve « qui, pour
quoi » ; décider si ce « qui » a le droit reste à l'app. L'app Fleet
(`Docs/Apps/fleet`) tient pour ça un ledger de capabilities local et persistant,
et exige les **trois** portes : mesh authentifié, enrôlé avec la capability, et
signature fraîche sur les octets exacts de la commande.

La capability `manage` ajoute une deuxième clé au lieu d'élargir la première :
le grant mesh ouvre le canal, le **mot de passe console de la cible** ouvre la
session, et les deux sont détenus par des personnes différentes. L'appel relayé
est **rejoué contre la console de la cible** (loopback, certificat épinglé), donc
la vérification de session, les plafonds et le lockout anti-bruteforce sont ceux
de la console elle-même — un relais qui répondrait lui-même serait une seconde
porte d'entrée avec ses propres bugs.

Ce ledger n'est jamais élargi par le réseau. Un droit ne s'ajoute que par une
décision locale sur la machine qui le subit ; le seul message qui touche aux
capabilities sans humain (`ENROL_NARROW`) est **intersecté** avec ce que son
émetteur détient déjà, donc ne peut que lui en retirer. Sans cette asymétrie, la
capability la plus faible suffirait à atteindre toutes les autres.
