"""
Template pour créer un transport NMesh personnalisé.

Copiez ce fichier, renommez les classes, implémentez les méthodes abstraites.
Les commentaires TODO indiquent ce que vous devez écrire.
"""
import asyncio
from src.transport import BaseTransport, BaseServer
from src.packet import Packet


# ---------------------------------------------------------------------------
# 1. Transport (une connexion)
# ---------------------------------------------------------------------------

class MyTransport(BaseTransport):
    """
    Un transport point-à-point sur [votre medium].

    Contrat :
    - send() envoie exactement un Packet, receive() en retourne exactement un.
    - Si le medium est un flux (TCP, UART...), vous devez implémenter un framing.
    - Si le medium est un datagramme (UDP, LoRa...), pas de framing nécessaire.
    """

    def __init__(self) -> None:
        super().__init__()
        # TODO: initialiser vos ressources (socket, handle, file descriptor…)

    async def connect(self, address: str) -> None:
        """Ouvrir une connexion sortante vers `address`."""
        # TODO: parser l'adresse et ouvrir la connexion
        # Exemple TCP : host, port = address.rsplit(':', 1)
        raise NotImplementedError

    async def listen(self, address: str) -> None:
        """Écouter sur `address` et attendre une connexion entrante (bloquant)."""
        # Optionnel si vous utilisez MyServer pour le multi-connexion.
        # Implémenter si vous avez besoin du mode mono-connexion.
        raise NotImplementedError

    async def send(self, packet: Packet) -> None:
        """Sérialiser et envoyer le paquet."""
        data = packet.pack()
        # TODO: si flux → préfixer la taille
        #   frame = struct.pack('!H', len(data)) + data
        #   await self._writer.write(frame)
        # TODO: si datagramme → envoyer directement
        raise NotImplementedError

    async def receive(self) -> Packet:
        """Bloquer jusqu'à la réception d'un paquet et le retourner."""
        # TODO: si flux → lire le préfixe de taille, puis les N octets
        #   length = struct.unpack('!H', await read(2))[0]
        #   data = await read(length)
        # TODO: si datagramme → lire un datagramme complet
        # Puis désérialiser :
        #   return Packet.unpack(data)
        raise NotImplementedError

    async def close(self) -> None:
        """Fermer la connexion et libérer les ressources."""
        # TODO: fermer le socket/handle proprement
        raise NotImplementedError


# ---------------------------------------------------------------------------
# 2. Serveur (plusieurs connexions entrantes)
# ---------------------------------------------------------------------------

class MyServer(BaseServer):
    """
    Serveur [votre medium] : écoute et crée un MyTransport par client accepté.

    Après listen(), chaque nouvelle connexion déclenche :
        await self.on_new_connection(transport)
    où `transport` est une instance de MyTransport déjà connectée.
    """

    def __init__(self) -> None:
        super().__init__()
        # TODO: initialiser vos ressources serveur

    async def listen(self, address: str) -> None:
        """Démarrer l'écoute — retour immédiat après bind."""
        # TODO: binder l'adresse et démarrer la boucle d'acceptation en tâche de fond
        #
        # Exemple asyncio TCP :
        #   self._server = await asyncio.start_server(_accept, host, port)
        #
        # async def _accept(reader, writer):
        #     transport = MyTransport._from_accepted(reader, writer)
        #     if self.on_new_connection:
        #         await self.on_new_connection(transport)
        raise NotImplementedError

    async def close(self) -> None:
        """Arrêter d'accepter de nouvelles connexions."""
        # TODO: fermer le serveur proprement
        raise NotImplementedError


# ---------------------------------------------------------------------------
# 3. Enregistrer avec MeshNode
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import asyncio
    from src import MeshNode

    async def demo():
        # Nœud hôte
        host = MeshNode(
            transport_factory=MyTransport,
            server_factory=MyServer,
        )
        code = host.generate_invite()
        await host.start("mon://adresse:1234")

        # Nœud invité
        guest = MeshNode(
            transport_factory=MyTransport,
            server_factory=MyServer,
        )
        await guest.join("mon://adresse:1234", code)
        await guest.wait_for_session(timeout=10.0)

        await guest.send_data(b"hello via mon transport")
        data = await host.receive_data()
        print(f"reçu : {data}")

        await guest.stop()
        await host.stop()

    asyncio.run(demo())


# ---------------------------------------------------------------------------
# 4. Transport en mémoire (utile pour les tests unitaires)
# ---------------------------------------------------------------------------

class InMemoryTransport(BaseTransport):
    """
    Transport en mémoire — deux instances connectées via des queues asyncio.
    Pratique pour tester la logique sans réseau réel.

    Usage :
        a, b = InMemoryTransport.make_pair()
        # a.send() → b.receive(), b.send() → a.receive()
    """

    def __init__(self) -> None:
        super().__init__()
        self._inbox: asyncio.Queue[Packet] = asyncio.Queue()
        self._other: 'InMemoryTransport | None' = None

    @classmethod
    def make_pair(cls) -> tuple['InMemoryTransport', 'InMemoryTransport']:
        a, b = cls(), cls()
        a._other = b
        b._other = a
        return a, b

    async def connect(self, address: str) -> None:
        pass  # connexion déjà établie via make_pair()

    async def listen(self, address: str) -> None:
        pass

    async def send(self, packet: Packet) -> None:
        if self._other is None:
            raise ConnectionError("not paired")
        await self._other._inbox.put(packet)

    async def receive(self) -> Packet:
        return await self._inbox.get()

    async def close(self) -> None:
        pass
