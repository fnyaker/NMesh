# Plan de conception — Joignabilité agnostique + invitation relayée

> **Statut : PLAN, pas encore implémenté.** Document de travail à valider avant
> tout code. Objectif : permettre à deux nœuds de se joindre même derrière
> CGNAT / double NAT / NAT symétrique, **sans dépendre d'un transport concret**,
> et sans usine à gaz (pas de base de données de quotas dédiée).

## 0. Principes directeurs (rappel charte)

1. **Sécurité d'abord.** Tout paquet est présumé hostile. `NodeID = hash(clé DSA)`.
   Rejet par défaut. Bornes partout.
2. **Agnostique du transport.** Le cœur ne connaît **aucun** transport concret.
   La joignabilité, le broadcast, le hole punching sont des **détails de
   transport** exposés au cœur via une interface générique.
3. **Le plus automatique possible.** Le réglage fin est expert ; par défaut tout
   s'organise seul.

Le constat qui motive tout : le hole punching direct échoue par construction
quand les deux pairs sont derrière NAT symétrique (4G CGNAT, double NAT). La
seule réponse robuste, universellement adoptée (Tailscale DERP, WebRTC TURN,
libp2p circuit-relay), est le **relais** du trafic chiffré E2E. NMesh route déjà
des paquets chiffrés E2E à travers des intermédiaires : on s'appuie dessus.

---

## 1. Modèle de joignabilité agnostique (`reachability`)

### 1.1 Le descripteur

Chaque **serveur de transport** (`BaseServer`) peut décrire comment on le joint,
sous forme d'une liste de descripteurs opaques pour le cœur :

```
Reachability = {
  "transport": str,     # schéma, ex. "tcp", "udp", "ble"
  "scope":     str,     # "world" | "lan" | "broadcast" | "none"
  "anchor":    str,     # discriminateur d'audience (voir plus bas)
  "address":   str|None,# URI joignable en direct si applicable, sinon None
  "confirmed": bool,    # joignabilité prouvée (dial-back / inbound accepté) vs supposée
}
```

- **`scope`** = largeur d'audience, ordonnée : `world` > `lan` > `broadcast` > `none`.
- **`anchor`** = ce qui distingue deux audiences de même portée. **C'est la clé du
  problème `192.168.0.0/24`** : mon LAN porte l'ancre `<mon-IP-publique>`, celui du
  voisin `<son-IP-publique>` → même sous-réseau privé, **audiences distinctes**.

Exemples concrets :

| Situation | Descripteur |
|---|---|
| Port TCP ouvert au monde | `(tcp, world, "", tcp://IP:port, confirmed)` |
| LAN derrière mon IP publique | `(tcp, lan, "<ip-pub>/24", tcp://192.168.x:port, confirmed)` |
| UDP + STUN, mapping public | `(udp, world, "", udp://IP:port, confirmed)` |
| Bluetooth (à venir) | `(ble, broadcast, "", None, confirmed)` |
| Derrière NAT, pas joignable | `(udp, none, "", None, False)` |

### 1.2 Le contrat sur les transports

On ajoute deux capacités **optionnelles** aux interfaces (défauts sûrs pour ne
rien casser des transports existants) :

```python
class BaseServer:
    def reachability(self) -> list[Reachability]:
        """Comment ce serveur est joignable, et par quelle audience.
        Défaut : []  (le transport ne sait pas / n'est pas joignable)."""
        return []

    async def broadcast(self, data: bytes) -> bool:
        """Diffuse data à l'aveugle dans le domaine du medium (LAN UDP, BLE…).
        Retourne True si le transport sait broadcaster. Défaut : False."""
        return False

class BaseTransport:
    @classmethod
    def can_reach(cls, desc: Reachability, local_ctx: dict) -> bool:
        """Depuis notre contexte réseau (local_ctx), peut-on tenter de joindre
        un nœud annonçant desc ? Défaut : desc a une address + scope != none."""
```

- **`reachability()`** : le transport IP la remplit à partir de ce qu'on a déjà
  (adresse observée via `remote_ip()`/OBSERVED_ADDR, STUN keepalive, et surtout
  **connexion entrante authentifiée acceptée** = preuve passive de joignabilité).
- **`can_reach()`** : IP renvoie `True` pour `world`, et pour `lan` seulement si
  l'ancre correspond à notre IP publique observée. `broadcast` → traité à part
  (on broadcast, on ne « route » pas vers).
- **`broadcast()`** : UDP/BLE l'implémentent ; TCP/spool non. Le cœur l'appelle
  sans savoir comment c'est fait.

Le cœur **agrège** les `reachability()` de tous ses serveurs → sa propre
joignabilité → l'annonce (dans le routing/presence) et s'auto-tague
**relais-capable** s'il a ≥1 descripteur `confirmed` à portée `world` (ou une
portée définie utile).

### 1.3 Auto-détection du rôle relais

- **Passif (gratuit, sûr)** : un nœud qui a accepté une connexion entrante
  authentifiée qu'il n'a pas initiée est *prouvé* joignable → `confirmed=True`.
- **Actif (phase 2, façon AutoNAT)** : `REACH_PROBE` — on demande à un pair de se
  reconnecter à notre adresse annoncée et de confirmer. Garde-fous anti-
  amplification : seulement l'adresse revendiquée dans la même famille que la
  source observée, jamais les plages privées, borné, rate-limité, et la
  reconnexion tente un vrai handshake (échec 1:1 sur une victime au hasard).

---

## 2. Invitation relayée + broadcast (bloc unique)

### 2.1 Principe

**Relayer une invitation ≈ relayer un paquet.** Aucun nœud n'a de rôle spécial
imposé ; pas de base de données de quotas. Un **seul** bloc b64, généré par
l'inviteur A, remis à l'invité B hors-bande. B « tente tout » : il **broadcast**
la demande sur les transports capables **et** la **route** vers une liste de
relais de secours. N'importe quel nœud du réseau qui reçoit la demande la
vérifie et la fait suivre vers A.

### 2.2 Contenu du bloc b64

```
InviteBlock = {
  "v":      3,
  "code":   <code d'invitation>,        # capacité anti-abus (existant, TTL 5 min)
  "cert":   <cert auto-signé de A, hex>, # porte la clé pub ; NodeID(A)=hash(clé)
  "exp":    <timestamp d'expiration>,
  "token":  <sig_A( TAG || H(code) || exp ), hex>,  # autorisation de rendez-vous
  "relays": [ Reachability, ... ]        # nœuds à portée large, secours si pas de broadcast
}
```

- `cert` donne la clé publique de A ⇒ tout récepteur vérifie `NodeID(A)=hash(clé)`
  et la validité de `token`.
- `token` = **A signe l'autorisation de rendez-vous**. C'est le garde-fou anti-
  spam : un extérieur ne peut pas forger une invitation « émise par un membre »
  sans la clé de A. Un récepteur qui **partage le root** de A vérifie en plus
  l'appartenance réseau ; sinon il vérifie au moins l'auto-cohérence (sig valide
  pour la clé fournie) et **rate-limite par clé**.
- `relays` : uniquement des nœuds à **portée définie et large** (`world`, ou une
  audience que B a des chances de partager). **Jamais** de `broadcast` (on ne
  route pas vers un domaine indéfini — il ne sert qu'en opportuniste).

### 2.3 Nouveau type de paquet : `INVITE_SEEK` (pré-auth, borné)

C'est le seul paquet **routable avant authentification** — il porte sa propre
preuve (`token`), il est TTL-borné, dédupliqué, rate-limité.

```
INVITE_SEEK payload = {
  inviter_id,           # NodeID(A) — vers qui router
  cert_A, exp, token,   # recopiés du bloc (vérifiables par tout nœud)
  rdv_id,               # ID de rendez-vous ÉPHÉMÈRE généré par B (pas son vrai ID)
  rdv_pub               # clé pub éphémère de B pour ce join
}
```

**Choix important : `rdv_id` éphémère.** B ne diffuse **pas** son vrai NodeID
(anti-traçage). Il génère une identité jetable pour ce seul join ; son vrai
certificat n'apparaît que **dans le handshake chiffré**, plus tard.

### 2.4 Machine à états du join

```
B (invité)                    R (relais / témoin)              A (inviteur)
   │                             │                                │
   │ 1. broadcast INVITE_SEEK ───┤ (sur transports broadcast-capables)
   │ 1'. + envoi direct aux relays de la liste                    │
   │                             │                                │
   │                             │ 2. vérifie token+cert+exp      │
   │                             │    (sinon drop + rate-limit)   │
   │                             │ 3. note rdv_id → lien(B)       │
   │                             │    (table rendez-vous, bornée) │
   │                             │ 4. route SEEK vers inviter_id ─┤
   │                             │    (Kademlia/on-demand, TTL,   │
   │                             │     dédup)                     │
   │                             │                                │ 5. A reconnaît
   │                             │                                │  H(code), token OK
   │                             │ 6. CHALLENGE adressé à rdv_id ◄┤
   │                             │ 7. route retour via table rdv  │
   │ 8. CHALLENGE reçu ◄─────────┤                                │
   │                             │                                │
   │ 9. INVITE(code) / HANDSHAKE (signés ML-DSA) tunnelés A↔B via R (E2E)
   │        … déroulé d'invitation existant, bout-en-bout …       │
   │ 10. session E2E établie (routée par R) — fiable immédiatement│
   │                             │                                │
   │ 11. (optionnel) tentative de punch direct → bascule si succès│
```

Points clés :
- **R n'est qu'un tuyau** : il route des paquets signés qu'il ne peut pas forger
  (invariant NMesh : « un relais ne voit que des métadonnées de routage »).
- **Le chemin retour** : R garde une **table de rendez-vous** `rdv_id → (lien, exp)`,
  bornée et à courte durée de vie (anti-DoS). A adresse sa réponse à `rdv_id` ; R
  la renvoie sur le lien d'où venait le SEEK.
- **B est joint par le lien qu'il a lui-même ouvert vers R** (sortant → traverse
  tout NAT). Aucune joignabilité entrante requise côté B.
- **Broadcast opportuniste** : si un nœud du réseau entend le SEEK sur le même
  medium (BLE, LAN UDP), il devient R spontanément. Sinon, la liste `relays`
  prend le relais (sans jeu de mots).

### 2.5 Sélection des relais dans le bloc (réponse à « pas en aléatoire »)

A choisit les relais par critères déterministes :
1. Candidats = nœuds connus de A ayant ≥1 descripteur `reachability` **`confirmed`,
   scope `world`** (joignables par n'importe qui, donc par B où qu'il soit).
2. À défaut de `world`, des scopes définis **variés** (ancres différentes) pour
   **couvrir plusieurs audiences** — maximiser la chance que B en partage une.
3. Borné (ex. 5, configurable). Trié par fraîcheur de confirmation.
4. Jamais de `broadcast`/`none`.

### 2.6 Côté invité, après le join

B **garde la liste des relais utilisés** (pour communiquer au début), puis
**étoffe sa propre vue** au fil des découvertes mesh (routing/DHT existants).
Aucune base dédiée : c'est le routing table + presence déjà là.

---

## 3. Modèle de sécurité (points de revue)

| Risque | Réponse |
|---|---|
| Extérieur qui spamme des SEEK pour tuer un nœud | `token` signé par un membre requis ; sinon drop. Rate-limit **par clé** de cert. TTL + dédup sur le routage du SEEK. |
| Amplification (SEEK routé à l'infini) | TTL décrémenté par hop, dédup borné (déjà en place pour les paquets routés), table de rendez-vous bornée. |
| Relais malveillant | Ne peut que **jeter/retarder** (jamais lire ni forger : handshake signé ML-DSA, E2E). C'est déjà dans le modèle de menace. |
| Rejeu du bloc | `code` à usage unique + `exp`. A peut invalider (le code expire ; annulation = on laisse expirer / on régénère). |
| Fuite de métadonnée (ID de A diffusé) | Accepté en v1 (ID = adresse, pas de compromission de clé). `rdv_id` **éphémère** protège déjà l'invité. ID éphémère pour A = amélioration future. |
| Pré-auth traversant le mesh | **Un seul** type (`INVITE_SEEK`) autorisé pré-auth, strictement token-gated, borné, rate-limité. Revue de sécurité dédiée à l'implémentation. |

**Annulation d'invitation** (demande utilisateur) : pas de DB à purger — le
`code` est à usage unique et expire. « Annuler » = régénérer/laisser expirer.
Si on veut une révocation active plus tard, elle passera par le même canal
signé (hors scope v1).

---

## 4. Refactor web UI — statut/config **génériques** par transport

Aujourd'hui la section « Transports » est câblée sur IP (punch, STUN, IP
publique). On la rend agnostique :

- **`console_snapshot`** expose, par transport actif, un bloc **générique** :
  `{ scheme, reachability: [...], status: {<clés libres>}, config: {<clés libres>} }`.
  Le cœur ne fabrique pas ces clés : **chaque transport** fournit son `status()`
  et son `config_schema()`. La web UI les **rend génériquement** (tableau
  clé/valeur + contrôles typés depuis le schéma).
- Le hole punching / STUN / manual holes deviennent le `status()`/`config()` **du
  transport UDP**, plus des concepts du cœur. La section Transports affiche « ce
  que le transport déclare », quel qu'il soit.
- **Config spécifique par transport depuis l'UI** : un `config_schema()` standard
  (liste de champs `{clé, type, label, défaut}`) → l'UI génère les contrôles ;
  `console_set_transport_config(scheme, {...})` applique. Un futur transport BLE
  n'exige **aucune** modif de l'UI.

Panneau invitation : « Connect a node » (générer un bloc / coller un bloc),
progression du join, et — en **expert** — la liste des relais choisis et l'état.

---

## 5. Plan d'implémentation (incréments testés)

Chaque étape est autonome, testée (dont entrées hostiles), suite verte avant de
merger.

- **Étape 1 — Modèle de joignabilité (cœur + IP).** `Reachability`, `reachability()`
  sur `BaseServer`, agrégation dans le cœur, signal passif (inbound accepté),
  auto-tag relais. Snapshot expose la joignabilité. *Aucun changement de
  comportement réseau — juste de l'observabilité.*
- **Étape 2 — `INVITE_SEEK` + table de rendez-vous + routage pré-auth borné.**
  Le paquet, sa vérification (token/cert/exp), le routage vers `inviter_id`, la
  table `rdv_id→lien`. Tests hostiles (token forgé, expiré, flood, TTL).
- **Étape 3 — Bloc d'invitation v3 + join « tente tout ».** Génération/validation
  du bloc, envoi aux relays + `broadcast()` sur transports capables, réponse de A,
  handshake tunnelé, session E2E via relais. Test e2e A↔B via un relais, **sans
  lien direct**.
- **Étape 4 — `broadcast()` sur UDP (LAN)** + capacité générique. (BLE hors scope.)
- **Étape 5 — Refactor web UI générique** (status/config par transport, UDP
  migré derrière l'interface, panneau invitation).
- **Étape 6 — Bonus** : préférence IPv6 directe ; `REACH_PROBE` actif (AutoNAT) ;
  ID de rendez-vous éphémère pour A.

## 6. Hors scope (pour être explicite)

- Implémentation d'un transport Bluetooth/LoRa (on prépare l'interface, on ne
  code pas le medium).
- Base de données de quotas/DB d'invitations par nœud (abandonnée — inutile).
- Révocation active d'invitation (le TTL suffit en v1).
- ID permanent de A masqué (amélioration future, notée).
