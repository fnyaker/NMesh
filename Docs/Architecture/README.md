# NMesh — Architecture (comment ça marche vraiment)

> **À lire AVANT toute modification ou débogage.** Ces documents décrivent le
> fonctionnement réel du code (pas une cible idéale). Si tu changes un
> comportement décrit ici, **mets le document à jour dans le même commit**.
> Une doc fausse est pire qu'absente.

Les guides d'usage (comment brancher une app, écrire un transport…) restent
dans les autres dossiers de `Docs/`. Ici on décrit la **mécanique interne**.

## Carte du code (`src/`)

| Fichier | Rôle |
|---|---|
| `node.py` | Le cœur (~3600 lignes) : boucle de réception, dispatch, handshake, routage, DHT, E2E, hole punching, keepalive, reachability. |
| `packet.py` | Format de paquet, `msg_id`, AAD GCM, (dé)chiffrement d'un paquet. |
| `node_id.py` | `NodeID` = sha256(clé pub DSA)[:20] ; distance XOR Kademlia. |
| `crypto.py` | `CryptoIdentity` (ML-DSA sign, ML-KEM), `SessionKey` (AES-256-GCM + HKDF). |
| `cert.py` / `cert_store.py` | Certificats + PKI P2P auto-racinée (chaînes, vérif, racines). |
| `trust.py` | TOFU `NodeID → clé DSA` (table de confiance simple). |
| `invite.py` | Codes d'invitation (HMAC challenge/réponse, usage unique, lockout). |
| `routing.py` | Table de routage Kademlia (k-buckets, `last_seen`). |
| `dht.py` | Store DHT adressé par contenu (`key = sha256(valeur)[:20]`). |
| `app_dht.py` | DHT par-app (overlay) : namespace par `app_id`, entrées publiques (clair) ou privées (AES-256-GCM sous clé fournie par l'app). |
| `pseudo_dir.py` | Annuaire de pseudos à clé sur Kademlia : réclamations signées auto-authentifiées (pseudo→node_id lié à la clé pub), find-by-pseudo réseau. |
| `transport.py` / `transport_manager.py` | Interfaces `BaseTransport`/`BaseServer` + registre par schéma d'URL. |
| `tcp_transport.py` / `udp_transport.py` / `spool_transport.py` | Transports concrets. |
| `net_monitor.py` / `stun.py` / `ip_utils.py` | Suivi d'adressage, STUN, IPs locales. |
| `webconsole.py` / `webassets.py` | Console web de gestion (HTTPS, stdlib). |
| `app_channel.py` | Sections d'app : cadrage `app_id ‖ payload` dans la payload DATA, ids intégrés/déployés (démux du connecteur). |
| `data_connector.py` / `process_launcher.py` / `apps/` | Brancher des apps sur le mesh (une section par app). |
| `apps/chat*.py` | App de chat intégrée : messages/fichiers/flux (`chat.py`), couche sociale contacts/pseudo/groupes (`chat_state.py`), UI console (`chat_web.py`). |
| `app_package.py` | Packages adressés par contenu + **release signée** (déploiement : app_id lié à l'auteur ML-DSA, `ts` signé pour l'ordre des versions). |
| `app_catalog.py` | App store : catalogue réseau (releases signées, gossipé, anti-rollback) + registre local d'apps installées. |
| `app_storage.py` | Store local par app (« tiroir ») : clé→valeur chiffré au repos (AES-256-GCM, clé par app dérivée de l'identité), isolé par `app_id`, borné. |
| `session_store.py` | Persistance chiffrée (sessions E2E + pairs). |

## Les documents

1. **[protocol.md](protocol.md)** — paquet, `msg_id`, AAD, types de messages,
   portes de validation du dispatch, TTL, déduplication, forwarding.
2. **[security.md](security.md)** — identité, crypto post-quantique, certificats
   & chaînes de confiance, invitation, handshake, session E2E.
3. **[routing.md](routing.md)** — table de routage, `last_seen`, routage à la
   demande, lookup Kademlia, DHT, **propagation des adresses**.
4. **[transports.md](transports.md)** — abstraction transport, TCP/UDP/spool,
   NAT hole punching, STUN, reachability/AutoNAT, net monitor, keepalive.
5. **[gotchas.md](gotchas.md)** — les pièges durement appris (asyncio 3.12,
   sondes réseau bloquantes, courses du hole punch, parallélisation des tests).
   **Commence par là avant de déboguer un blocage ou une flakiness.**

## Les 4 couches (de bas en haut)

```
   Apps (chat, call, data connector)         ── charge utile applicative
   ────────────────────────────────
   E2E (E2E_HANDSHAKE / DATA chiffré)         ── secret de bout en bout, relais aveugles
   ────────────────────────────────
   Mesh (routage Kademlia, DHT, hole punch)   ── atteindre un NodeID par n'importe quel medium
   ────────────────────────────────
   Lien (handshake par saut + session AES)    ── un pair authentifié sur un transport
   ────────────────────────────────
   Transport (tcp/udp/spool/…)                ── transporter des octets
```

Deux niveaux de chiffrement : **par-saut** (session négociée au handshake entre
deux pairs directs) et **de bout en bout** (E2E, entre source et destination
finale ; les relais ne voient que des métadonnées de routage).
</content>
