# NMesh — Roadmap

## En attente (mis de côté pendant fix sécurité)


### Point 4 — Test Docker 10 nœuds
Rebuild avec `--build` pour valider le fix multi-code `InviteManager`.
Vérifier que les 9 guests complètent invitation → handshake → data.

### Point 5 — Topologie chaîne (B)
Chaque nœud rejoint le précédent (A→B→C→D…).
Valide le vrai forwarding multi-hop une fois C1 résolu.

### Futur (long terme)
- Trust score par nœud + suppression en cas de trahison
- Persistance de la trust table sur disque (H7)
- meshnet-daemon : embarque la lib, écoute sur socket Unix, multi-clients
