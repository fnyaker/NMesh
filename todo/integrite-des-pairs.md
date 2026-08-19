# TODO — Vérification d'intégrité / santé entre pairs (cœur & apps)

> **Statut : brainstorm, rien n'est implémenté.** Ce document liste des pistes
> pour que les pairs s'assurent mutuellement que le code qu'ils exécutent n'a
> pas été modifié (machine compromise par un adversaire, app vérolée,
> supply chain). Il ne décrit pas le fonctionnement actuel du code : il n'a donc
> pas sa place dans `Docs/Architecture/`. Tout mécanisme retenu et implémenté
> devra y être documenté, dans le même commit que le code.

## Le point de départ honnête

**L'attestation logicielle pure ne prouve rien contre un adversaire qui possède
la machine.** S'il contrôle le processus, il rejoue le « bon » hash. C'est le
problème du *lying endpoint*, et il n'a pas de solution sans racine matérielle
(TPM / Secure Enclave).

L'objectif n'est donc pas « prouver l'intégrité » mais :

1. **rendre le mensonge coûteux** — l'attaquant doit garder une copie pristine
   du code, répondre en temps borné, et rester cohérent devant N vérifieurs ;
2. **rendre l'incohérence indélébile** — des preuves de fraude signées que
   n'importe qui vérifie hors-ligne ;
3. **dégrader le pair suspect** plutôt que de trancher par un booléen.

Les sections suivantes vont de « vraie valeur, pas cher » vers « cher, valeur
décroissante ».

---

## 1. Attestation de build (statique) — la base

- **`build_root`** : arbre de Merkle sur les fichiers source/bytecode du cœur
  (exactement le mécanisme de `app_package.build` : chunking adressé par contenu
  + manifest). Un seul hash racine identifie « quel code tourne ».
- **Annonce au handshake** : `build_root` + version transportés dans
  `HANDSHAKE`/`HANDSHAKE_ACK`, donc **signés** par l'identité ML-DSA. Gratuit,
  aucun round-trip supplémentaire.
- **Release signée du cœur** : réutiliser `build_release` / l'anti-rollback de
  `app_catalog` pour le cœur lui-même. Un `build_root` non couvert par une
  release signée d'un auteur connu = code inconnu → pair « non attesté ».
- **Plancher de version** : refus (ou dégradation) des pairs sous une version
  minimale signée → tue la downgrade attack vers un bug connu.
- **Consensus statistique** : gossip des `(build_root, version)` observés. Un
  `build_root` unique dans tout le mesh est un signal fort (soit un dev, soit un
  nœud patché). Ne jamais bannir là-dessus — alimenter un score.

## 2. Challenge/réponse résistant à la précalculation

- **Merkle-path challenge à nonce** : « donne-moi `H(nonce ‖ chunk[i])` + le
  chemin Merkle vers `build_root` », `i` tiré au hasard. Réponse minuscule,
  vérification en O(log n). L'attaquant doit conserver **une copie intacte
  complète** du code, en permanence.
- **Nonce + plage aléatoire** : jamais deux fois la même question → pas de cache
  de réponses.
- **Attester la mémoire, pas le disque** : hasher le bytecode réellement chargé
  (`co_code` des modules importés), pas les fichiers. Un patch à chaud ne touche
  jamais le disque.
- **Détection d'instrumentation** : hooks d'audit, `sys.settrace`, `sys.path`
  anormal, fonctions monkey-patchées (fingerprint des `__code__` comparé au
  manifest), modules importés hors liste. Ce sont des **signaux**, pas des
  preuves.
- **Attestation temporisée** (SWATT-like : parcours pseudo-aléatoire du code
  avec deadline stricte) : à considérer comme du théâtre en Python pur — l'écart
  introduit par l'attaquant se noie dans le bruit du GC et du réseau. À réserver
  à un éventuel shim natif, sinon c'est de la complexité pour rien.

## 3. Attestation *comportementale* — la couche la plus efficace en pratique

Colle à la charte : « l'authentification n'est pas de la confiance ». On teste
ce que le pair **fait**, pas ce qu'il **dit**.

- **Sondes-pièges (négatives)** : envoyer des paquets qu'une implémentation
  correcte **doit jeter en silence** — `msg_id` incohérent, TTL épuisé, type
  inattendu, certificat expiré, section d'app inconnue. Un nœud modifié (relais
  qui logge, proxy qui réécrit) réagit là où il devrait se taire. L'attaquant ne
  peut pas distinguer un piège d'un vrai paquet corrompu.
- **Accusés de réception E2E signés** : la destination signe `H(ciphertext)`
  reçu. La source détecte un relais qui altère, perd sélectivement, ou duplique
  — sans jamais lui faire confiance.
- **Scorecard de santé** : généraliser le compteur de trames invalides existant
  en un vecteur (taux d'invalides, violations de déduplication, TTL trafiqué,
  mensonges de routage, latence hors profil, refus d'attestation, `build_root`
  qui change sans redémarrage).
- **Profil temporel** : baseline RTT / temps de réponse par pair ; une couche
  d'interposition dérive. Signal faible → score uniquement, jamais de décision
  seule.

## 4. Vérification distribuée & preuves de fraude

- **Multi-vérificateurs** : plusieurs pairs challengent indépendamment et
  comparent les réponses via DHT/gossip. Un attaquant ne peut plus mentir
  « sur mesure » à un seul vérificateur.
- **Ne gossiper que des preuves vérifiables, jamais des accusations.** Une
  accusation nue est une arme de DoS Sybil. En revanche, **deux déclarations
  signées contradictoires par la même clé** (deux `build_root` pour la même
  époque, deux usages du même compteur d'époque, deux certificats incompatibles)
  forment une **preuve de fraude auto-portante** : n'importe qui la vérifie
  hors-ligne, elle est donc sûre à propager et à archiver.
- **Détection de clone d'identité** : compteur d'époque monotone signé. Deux
  usages du même compteur = clé dupliquée = preuve de fraude → alerte réseau et
  révocation.
- **Quarantaine par quorum** local (k-bucket), jamais sur un seul accusateur.

## 5. Journal chaîné + témoins (meilleur rapport valeur/complexité)

- Journal local **append-only chaîné par hash** (état d'intégrité, redémarrages,
  versions, anomalies). Réécrire l'histoire exige de recalculer la chaîne.
- **Témoignage croisé** : publier périodiquement `signe(époque, tête_de_chaîne,
  build_root)` dans la DHT ; les pairs conservent les têtes vues. L'attaquant qui
  réécrit le passé **contredit des témoins** → détection *a posteriori*, même
  s'il était indétectable sur le moment. Même logique que les transparency logs,
  et ça marche sans TPM.
- **Bail d'intégrité** (*integrity lease*) : une attestation réussie vaut N
  minutes. Bail expiré → le pair retombe automatiquement en « non attesté ».
  Aucun état de confiance permanent.

## 6. Le volet Apps

Le socle est déjà là : `app_package` (packages adressés par contenu + release
signée liant `app_id` à l'auteur ML-DSA) et `app_catalog` (anti-rollback).

- **Attestation au niveau de la section d'app** : chaque app déclare
  `(app_id, version, package_root)`. Un pair refuse le trafic d'une section dont
  le root ne correspond pas à une release signée connue du catalogue.
- **Challenge Merkle par app**, dans le canal d'app : même mécanique qu'au §2,
  mais sur le package — et sur les modules chargés en mémoire, pas seulement sur
  le paquet au repos.
- **Manifeste de capacités signé** : la release déclare ce que l'app a le droit
  de faire (chemins, storage, réseau, transports). Le runtime observe ; tout
  dépassement est une violation attribuable à une version signée précise.
- **Intégrité du « tiroir »** (`app_storage`) : racine de Merkle ou chaîne de MAC
  + compteur anti-rollback dans l'en-tête chiffré → détecte la restauration d'un
  ancien état, pas seulement l'altération.
- **Révocation signée** d'une version compromise par son auteur, gossipée avec
  l'anti-rollback existant → les nœuds la refusent / la désinstallent.
- **Validation croisée N-versions** : deux nœuds sur la même version d'app
  comparent un calcul déterministe canari. Divergence = l'un des deux est
  modifié.
- **Isolation** : plus une app est isolée (process séparé, cf.
  `process_launcher`), plus son attestation a du sens ; un cœur compromis ment
  pour toutes les apps qu'il héberge.

## 7. Réaction graduée (jamais binaire)

Des niveaux, avec retour automatique en arrière après ré-attestation réussie :

| Niveau | Effet |
|---|---|
| Attesté | tout autorisé |
| Non attesté | pas d'émission de certificat, pas d'installation d'app depuis lui |
| Suspect | plus de relais de trafic sensible, plus de partage de routes |
| Quarantaine | lien maintenu, données refusées |
| Rejeté | déconnexion (mécanisme de rejet de nœud existant) |

Côté local, sur échec d'auto-vérification : **panic mode** — wipe des clés de
session, arrêt du relais, alerte signée aux contacts. Mieux vaut un nœud qui se
tait qu'un nœud qui fuit.

## 8. Les pièges à ne pas créer

- **Amplification** : un challenge court ne doit jamais produire une réponse
  longue. Réponse plafonnée, budget par pair, rate-limit — sinon l'attestation
  devient elle-même un vecteur de DoS.
- **Oracle de lecture** : ne jamais permettre de hasher un fichier arbitraire ;
  seulement les chunks du manifest signé. Sinon on offre un lecteur de disque
  distant.
- **Bannissement sur accusation** : cf. §4 — uniquement observations locales et
  preuves de fraude.
- **Fausse assurance** : ne jamais afficher « pair vérifié ✅ », mais
  « code connu, attesté il y a 40 s » — c'est-à-dire l'information réelle.
- **Fingerprinting du réseau** : un `build_root` en clair au handshake dit à un
  observateur qui tourne quoi. À envisager sous chiffrement de lien, ou en
  engagement (commitment) révélé seulement après authentification.

## 9. Ordre de construction proposé

1. `build_root` signé + version au handshake, plancher de version, affichage
   console. *(peu de code, valeur immédiate contre le pair négligent et la
   supply chain)*
2. Vérification du `package_root` des apps contre le catalogue signé +
   révocation.
3. Scorecard de santé + sondes-pièges + accusés de réception E2E signés.
4. Journal chaîné + têtes témoignées dans la DHT.
5. Challenges Merkle à nonce (cœur, puis apps).
6. Multi-vérificateurs, preuves de fraude, quarantaine par quorum.
7. Attestation temporisée / racine matérielle — seulement si un shim natif entre
   un jour dans le projet.

Les points 1→4 couvrent l'essentiel du réalisable ; 5→6 haussent le coût pour
l'attaquant ; 7 est le seul qui viserait une vraie preuve, et il sort du
périmètre stdlib-only fixé par `CLAUDE.md`.
