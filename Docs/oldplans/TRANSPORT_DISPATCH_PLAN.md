# NMesh — Refonte multi-transport (TransportManager comme registre)

## 1. Principe directeur

**Le core mesh ne sait rien d'un transport spécifique.** Aucun import de `TCPTransport` dans `node.py`. Aucune mention de "TCP", "socket", "port" dans la logique mesh.

Un nœud peut écouter et se connecter via **plusieurs transports en parallèle** (TCP + BLE + WebSocket + LoRa + …). Chaque adresse est une **URI** dont le schéma sélectionne le transport.

Modèle : **registre de transports + dispatcher**. `TransportManager` est élargi de wrapper-mono-connexion vers registre des schémas pour le nœud.

---

## 2. Format d'adresse universel : URI

Toute adresse mesh est une URI :
```
scheme://opaque
```

- `scheme` : `[a-z][a-z0-9]{0,15}` — minuscules, alphanumérique, 1 à 16 caractères.
- `opaque` : tout ce qui suit `://`, interprété **uniquement** par le transport correspondant.
- URI totale : longueur max **256 octets** en représentation UTF-8.

Exemples valides :
- `tcp://192.168.1.5:9000`
- `tcp://[::1]:9000`
- `ble://AA:BB:CC:DD:EE:FF`
- `ws://example.com/mesh`

**Invariants vérifiés à toute désérialisation/réception** :
1. Présence de `://`.
2. Schéma conforme à la regex `^[a-z][a-z0-9]{0,15}$`.
3. Longueur totale ≤ 256.
4. Aucun caractère de contrôle ASCII (`< 0x20` ou `0x7F`) dans l'URI complète.

Si un seul invariant casse → URI rejetée silencieusement (drop, jamais d'exception remontée à un appelant non préparé).

⚠️ **POINT SENSIBLE SONNET** : la validation se fait **avant** toute utilisation. Ne jamais passer une URI non validée à `manager.connect()` ou à un transport. Centraliser la validation dans un seul `_validate_uri(s: str) -> tuple[str, str] | None` qui retourne `(scheme, opaque)` ou `None`.

---

## 3. La classe `TransportManager` (refonte complète)

Le fichier `src/transport_manager.py` actuel est jeté. On le réécrit.

```
TransportManager
  registry : dict[str, tuple[type[BaseTransport], type[BaseServer]]]
  servers  : dict[str, BaseServer]            # serveurs actifs, un par schéma
  on_new_connection : Callable[[BaseTransport], Awaitable[None]] | None

  register(scheme: str, transport_cls, server_cls)  -> None
  is_supported(scheme: str)                          -> bool
  connect(uri: str)                                  -> BaseTransport
  listen(uri: str)                                   -> None
  close_all()                                        -> None
```

### 3.1 `register(scheme, transport_cls, server_cls)`
- Valide le schéma (regex).
- Refuse l'enregistrement si le schéma existe déjà → `TransportError`.
- Refuse si `transport_cls` ne dérive pas de `BaseTransport` ou `server_cls` ne dérive pas de `BaseServer`.

### 3.2 `connect(uri) -> BaseTransport`
1. `scheme, opaque = _validate_uri(uri)` — si invalide → `TransportError`.
2. Si `scheme` n'est pas dans `registry` → `TransportError("scheme not registered")`.
3. `transport_cls, _ = registry[scheme]`
4. `transport = transport_cls()`
5. `try: await transport.connect(opaque)` — **si échec : appeler `transport.close()` puis raise**. Pas de fuite.
6. Retourner `transport`.

### 3.3 `listen(uri)`
1. Valide URI.
2. Refuse si déjà en écoute sur ce schéma (`scheme in servers`) → `TransportError`.
3. `_, server_cls = registry[scheme]`
4. `server = server_cls()`
5. `server.on_new_connection = self._dispatch_incoming`
6. `await server.listen(opaque)` — si échec : ne pas stocker dans `servers`, propager.
7. `servers[scheme] = server`

### 3.4 `_dispatch_incoming(transport)`
- Si `on_new_connection` est `None` → `await transport.close()` (refus net).
- Sinon → `await self.on_new_connection(transport)`.

### 3.5 `close_all()`
- Itère sur tous les serveurs, ferme chacun, ignore les exceptions individuelles (continuer le nettoyage).
- Vide `servers`.

⚠️ **POINT SENSIBLE SONNET** :
- `connect()` doit toujours fermer le transport partiellement initialisé en cas d'erreur. Test à ajouter pour ça.
- `listen()` ne doit JAMAIS modifier `servers` si l'écoute échoue.
- `register()` peut être appelée plusieurs fois pour différents schémas mais jamais deux fois pour le même.

---

## 4. Changements dans `MeshNode`

### 4.1 Signature `__init__`
```
MeshNode(
    transport_manager: TransportManager,
    identity_path: str | None = None,
    cert_store_path: str | None = None,
)
```
- **Supprimer** les paramètres `transport_factory` et `server_factory`.
- `transport_manager` est obligatoire. Pas de défaut.
- `manager.on_new_connection = self._on_new_transport` est branché ici.

### 4.2 `_address: str` → `_addresses: list[str]`
- Initialisé à `[]`.
- Une seule liste d'URI sur lesquelles le nœud écoute.

### 4.3 `start(addresses: list[str])`
- Signature change : accepte une liste d'URIs.
- Pour chaque URI : `await self._transport_manager.listen(uri)`.
- Mémorise dans `self._addresses` **uniquement les URI dont `listen()` a réussi**.

### 4.4 `join(address: str, code: str)`
- Signature inchangée mais `address` est désormais une URI complète.
- `transport = await self._transport_manager.connect(address)` — remplacer toute instanciation directe.

### 4.5 `_connect_routing(node_id)`
- Récupère la liste d'adresses du nœud cible depuis `_routing`.
- Itère sur les adresses : essaie `manager.connect(uri)` jusqu'à succès.
- Si toutes échouent → retourne `None`.
- Le premier transport supporté ET joignable gagne.

⚠️ **POINT SENSIBLE SONNET** : il faut ignorer silencieusement les adresses dont le schéma n'est pas enregistré (`manager.is_supported(scheme)`) **avant** d'appeler `connect()` pour éviter de lever une exception sur chaque adresse incompatible.

### 4.6 `stop()`
- `await self._transport_manager.close_all()` après l'arrêt des peers.

---

## 5. Changements `NodeEntry`

```
@dataclass
class NodeEntry:
    node_id: NodeID
    addresses: list[str] = field(default_factory=list)   # plusieurs URIs possibles
    dsa_pub: bytes = b""
    cert_chain: list = field(default_factory=list)
```

- `address: str` est **remplacé** par `addresses: list[str]`.
- Toute lecture/écriture de `entry.address` dans le code → migrer vers `entry.addresses`.

⚠️ **POINT SENSIBLE SONNET** : grep tout le code pour `\.address\b` et `entry\.address` — tout doit être migré. Idem dans les tests.

---

## 6. Changements wire format

### 6.1 PING payload
Avant : `payload = self._address.encode()` (string UTF-8 brute).

Après : liste binaire d'URIs :
```
addr_count(B) || [addr_len(H) || addr_bytes]*addr_count
```

À la réception (`_handle_ping`) :
1. Décoder.
2. Pour chaque URI : `_validate_uri(uri)` — si invalide, drop l'URI (continue les autres).
3. Limiter à **max 8 adresses par entrée** ; au-delà → drop tout le PING (paquet malformé).
4. `self._routing.add(src, addresses=valid_uris, ...)`

### 6.2 FOUND_NODE entry format
Avant :
```
node_id(20) || addr_len(B) || chain_bytes_len(H) || address || chain_bytes
```

Après :
```
node_id(20) || addr_count(B) || chain_bytes_len(H)
  || [addr_len(H) || addr_bytes]*addr_count
  || chain_bytes
```

Limites de sécurité (à enforcer à la désérialisation) :
- `addr_count ≤ 8`
- Chaque `addr_len ≤ 256`
- Chaque URI passe `_validate_uri` — sinon drop l'entrée complète

⚠️ **POINT SENSIBLE SONNET** : si **une** adresse de l'entrée échoue à la validation, on drop **l'entrée entière** (pas juste l'adresse). Sinon un attaquant peut empoisonner une partie de la liste pour passer ses autres URI malicieuses.

### 6.3 RoutingTable.add()
- Signature : `add(node_id, addresses: list[str], dsa_pub: bytes = b"")`.
- Si `addresses` est vide → ne pas ajouter (un nœud sans moyen d'être joint n'a pas d'intérêt pour le routage).

---

## 7. Suppressions et nettoyage

1. Supprimer le contenu actuel de `src/transport_manager.py` — réécrire complètement.
2. Retirer **tous** les imports de `TCPTransport` et `TCPServer` dans `node.py`.
3. Retirer les paramètres par défaut `TCPTransport`/`TCPServer` de `MeshNode.__init__`.
4. **Garder** `src/tcp_transport.py` tel quel — il sert d'implémentation de référence.
5. Le `__init__.py` du package n'expose **pas** `TCPTransport` par défaut. L'utilisateur l'importe explicitement s'il en veut.

---

## 8. Tests à modifier

### 8.1 `tests/conftest.py`
- Créer un `FakeServer(BaseServer)` minimal (qui ne fait rien de réel — utile pour `register()` mais pas pour `listen()`).
- Ajouter helper `make_manager() -> TransportManager` qui enregistre `("fake", FakeTransport, FakeServer)`.
- `make_node()` instancie `MeshNode(transport_manager=make_manager())`.
- Les tests qui font `_inject_peer(fake)` continuent à marcher (injection directe d'un transport).

### 8.2 Tests existants à rapatrier
- `test_node.py::TestHandlePing::test_handle_ping_adds_sender_to_routing` : PING payload est maintenant un format binaire — refaire l'encodage.
- `test_node.py::TestHandleFoundNode` : entrée a une liste d'adresses désormais.
- `test_handshake.py` : pas d'impact direct, mais `MeshNode()` n'a plus les paramètres par défaut TCP.
- `test_data.py::make_connected_pair` : utiliser `make_node()` mis à jour.
- `test_cert.py` : idem.

### 8.3 Tests nouveaux à ajouter (`tests/test_transport_manager.py`)
- `test_register_valid_scheme`
- `test_register_invalid_scheme_rejected` (caractères majuscules, vide, trop long)
- `test_register_duplicate_scheme_rejected`
- `test_connect_unknown_scheme_raises`
- `test_connect_malformed_uri_raises`
- `test_connect_failure_closes_transport` ← critique
- `test_listen_starts_server`
- `test_listen_failure_no_server_stored`
- `test_listen_duplicate_scheme_rejected`
- `test_close_all_stops_all_servers`
- `test_incoming_connection_dispatched_to_callback`

### 8.4 Tests nouveaux à ajouter (`tests/test_uri.py`)
- `test_valid_uris_parsed` (tcp, ble, ws, lora schemes)
- `test_uppercase_scheme_rejected`
- `test_no_scheme_rejected`
- `test_empty_opaque_accepted` (certains transports n'ont pas besoin d'opaque)
- `test_control_chars_rejected`
- `test_too_long_uri_rejected` (> 256)
- `test_scheme_with_digit_first_rejected`

---

## 9. Risques et décisions

### 9.1 Empoisonnement multi-adresse
Un nœud peut annoncer **plusieurs URIs**. Un attaquant pourrait annoncer un nœud "légitime" avec une URI redirigeant ailleurs. **Mitigation** : la chaîne de certs vérifiée par `CertStore.verify_chain` valide **l'identité** ; le transport ne valide que l'adresse atteinte. Une mauvaise adresse mène à un handshake qui échoue → aucun accès. C'est OK.

### 9.2 Resource exhaustion
- Plafond 8 adresses par entrée FOUND_NODE.
- Plafond 256 octets par URI.
- Total max par entrée : `20 + 1 + 2 + 8*(2+256) + chain_bytes = ~2 KB` (sans chain) — raisonnable.

### 9.3 Schémas non enregistrés annoncés via FOUND_NODE
Pas une faille — un nœud reçoit une URI `ble://...` mais n'a pas BLE → l'ignore silencieusement. **Ne pas dropper l'entrée entière** dans ce cas, juste cette URI parmi la liste, **sauf** si toutes les adresses de l'entrée sont inutilisables → là drop. Sinon le nœud loupe des entries valides.

Distinction critique :
- URI **malformée** (validation échoue) → drop l'entrée entière (signe d'attaque).
- URI **valide mais schéma inconnu localement** → drop cette URI seule, garder les autres.

⚠️ **POINT SENSIBLE SONNET** : différencier ces deux cas. Test pour chacun.

### 9.4 Connexion partielle qui fuit
Un `connect()` qui échoue après avoir alloué un socket/handle doit garantir le close. Test obligatoire (mock un transport qui raise après `connect()`).

### 9.5 `_handle_handshake` continue à utiliser `self._address`
Bug existant non lié à cette refonte : le serveur ajoute le client au routing avec `self._address` (ses propres adresses). On garde la même logique mais avec `self._addresses[0]` si non vide. **À fixer dans une autre passe**, hors scope.

---

## 10. ⚠️ Points sensibles consolidés pour Sonnet

À garder en tête pendant l'implémentation (ne pas avoir à les redécouvrir) :

1. **Validation centralisée** : une seule fonction `_validate_uri(s) -> tuple[str, str] | None`. Toute autre vérif est interdite. Pas de `if "://" in addr` ailleurs.

2. **`connect()` qui échoue ferme le transport**. Toujours. Test dédié.

3. **`listen()` qui échoue ne pollue pas `servers`**. Toujours. Test dédié.

4. **URI malformée vs schéma inconnu** : malformée = drop entrée ; schéma inconnu = drop URI seule.

5. **Caps de taille stricts** : 256 octets/URI, 8 URIs/entrée, 16 caractères/schéma. Hardcodés constantes en haut de fichier.

6. **Pas de transport par défaut dans MeshNode**. L'application enregistre explicitement ses transports.

7. **NodeEntry.address → addresses**. Grep `\.address\b` après refonte pour vérifier qu'il ne reste rien.

8. **Validation au moment de la désérialisation**, pas au moment de l'usage. Si une entrée FOUND_NODE arrive avec une URI mauvaise, l'entrée est droppée **avant** d'atteindre `_routing.add`. Jamais d'URI mauvaise stockée.

9. **`register()` est synchrone**. `connect()`, `listen()`, `close_all()` sont async.

10. **Aucun import circulaire** : `transport_manager.py` importe `transport.py`. `node.py` importe `transport_manager.py`. Le sens reste descendant.

11. **Pas de logique TCP/scheme-spécifique dans `TransportManager`**. Le manager est neutre. Tout ce qui est spécifique est dans le transport implémentation.

12. **Les tests `_inject_peer` continuent à marcher** : injection directe d'un `BaseTransport` bypass le manager — c'est volontaire pour les tests unitaires.

---

## 11. Ordre d'exécution recommandé

1. Créer `src/uri.py` — module dédié à `_validate_uri` + constantes.
2. Tests `tests/test_uri.py` (pas d'autre dépendance, valider en premier).
3. Réécrire `src/transport_manager.py` à zéro avec la nouvelle API.
4. Tests `tests/test_transport_manager.py` (utilise `FakeTransport` + un `FakeServer` minimal).
5. Modifier `src/routing.py` : `NodeEntry.address` → `addresses: list[str]`, `RoutingTable.add(...)`.
6. Modifier `src/node.py` :
   - Imports
   - `__init__` (paramètre `transport_manager`)
   - `start(addresses: list[str])`
   - `join(uri, code)`
   - `_connect_routing` (itère sur addresses)
   - `_address` → `_addresses`
   - Encodage/décodage PING payload (nouveau format binaire)
   - Encodage/décodage FOUND_NODE entry (multi-addresses)
   - `_handle_found_node` (validation par entrée)
   - `_handle_ping` (validation des URIs)
7. Adapter `tests/conftest.py` : `make_node()` utilise un manager pré-configuré.
8. Mettre à jour tous les tests cassés (test_node, test_handshake, test_data, test_cert).
9. Ajouter les nouveaux tests de la section 8.3 et 8.4.
10. Lancer la suite complète. Tout doit passer.

---

## 12. Compatibilité

Aucune. Le format PING et FOUND_NODE change, les signatures `MeshNode.__init__` et `start()` changent, `NodeEntry.address` est remplacé. Tout réseau non patché est incompatible. Acceptable — projet pré-déploiement.

---

## 13. Hors scope (explicite)

- Implémentation de transports concrets autres que TCP (BLE, WS, LoRa) — chacun fera l'objet d'un PR séparé une fois le manager en place.
- Politique de retry/fallback entre adresses du même nœud (pour l'instant : essayer dans l'ordre).
- Normalisation d'URI (case, trailing slashes) — comparaison string brute.
- Découverte locale (mDNS, BLE scan) — feature à part.
- Fix du bug `_handle_handshake` qui utilise `self._address` pour le routing du peer — fix séparé.
