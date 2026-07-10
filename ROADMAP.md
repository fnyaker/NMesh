# NMesh — Roadmap

Priorités directrices : voir `CLAUDE.md`. Ordre non-négociable :
**sécurité > solidité > flexibilité > rapidité**, dépendances minimales.

## Fait

### Socle cryptographique et réseau
- Crypto post-quantique E2E (ML-KEM-768 / ML-DSA-65 / AES-256-GCM).
- PKI P2P auto-racinée (chaînes de certificats, racines de confiance).
- Invitation → handshake → session, Kademlia + routage on-demand multi-hop.
- Transport enfichable par schéma d'URL (`BaseTransport` / `BaseServer`).

### Durcissement sécurité / solidité (session en cours)
- **Zéro-crash sur input hostile** : un paquet mal formé ne tue plus la boucle
  de réception ; il est compté et jeté.
- **Rejet de nœud** : au-delà d'un seuil de trames invalides, le pair est coupé.
- **Auto-recovery** : les pairs morts (lien fermé / abus) sont purgés
  automatiquement ; le routage on-demand reconstruit les liens au besoin.
- **Anti-amplification** : `msg_id` vérifié à la réception (il commite le
  contenu) — un relais ne peut plus forger des `msg_id` pour échapper à la
  déduplication.
- **Bornes mémoire** : buffers E2E plafonnés par cible et au global.
- **Glare E2E** : les ouvertures simultanées convergent sur une clé unique
  (tie-break par NodeID) au lieu de deadlocker ; flush des données en attente
  côté répondeur.
- **Fuzzing** : `tests/test_fuzz.py` prouve qu'aucun octet hostile ne crashe
  (Packet, tous les codecs, certificats, nœud vivant sous flot aléatoire).
- **Intégration réelle** : `tests/integration/test_local.py` remis à niveau —
  invite/handshake, data E2E, gros payloads, routage A→B→C, self-healing.

### Console web de gestion (`src/webconsole.py`)
- Plan de gestion local : graphe réseau, liste des pairs, débit temps réel,
  charge de la node ; actions invite / join / trust cert.
- Sécurité : HTTPS auto-signé (empreinte affichée), mot de passe généré +
  haché scrypt, jetons Bearer (pas de cookie → pas de CSRF), lockout
  anti-bruteforce, bind loopback par défaut, CSP stricte, assets same-origin,
  **zéro dépendance externe** (stdlib + `cryptography`).
- Métriques nœud (`src/metrics.py`) : compteurs débit + charge process.
- Démo : `scripts/console_demo.py`. Doc : `Docs/WebConsole/guide`.

## En cours / à valider
- Test Docker multi-nœuds (10) : rebuild `--build`, valider invitation →
  handshake → data sur les 9 guests.
- Topologie chaîne A→B→C→D pour le forwarding multi-hop en conditions réelles.

## Prochaines étapes (vision « Jarvis / Edith »)

### Conditions dégradées & transport asynchrone
- Transport **store-and-forward** (delay-tolerant) : file persistante de
  paquets à remettre plus tard, tolérant à des latences de plusieurs jours
  (scénario « clé USB portée à la main »). Correction d'erreur + retry.
- File d'émission persistante par pair + reprise après coupure.

### Intégration applicative (voie données — distincte de la console de gestion)
1. **Connecteur socket local** : le nœud écoute sur une socket (TCP loopback /
   Unix), authentifiée par certificat auto-généré en RAM, pour brancher des
   apps locales ou des conteneurs Docker sur le flux **de données** du mesh
   (la console web, elle, est le plan de *gestion*).
2. **Lanceur de sous-processus** : le nœud lance des programmes déclarés et les
   raccorde au réseau (le nœud devient le pont réseau de l'app).

### Écosystème d'applications
- App de démonstration : chat texte + échange de fichiers.
- Format de paquetage d'app déclaratif (manifeste + fichiers), partageable et
  re-partageable sur le mesh via une table de hachage distribuée (DHT).

### Long terme
- Trust score par nœud + révocation en cas de trahison.
- Persistance de la trust/cert table sur disque.
- meshnet-daemon : embarque la lib, écoute sur socket, multi-clients.
</content>
