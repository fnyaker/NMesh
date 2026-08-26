"""
Run a MeshNode with the web console attached.

    python scripts/nmesh_node.py [--listen 0.0.0.0:9000] [--console-host 127.0.0.1]
                                   [--console-port 8787] [--no-tls] [--data DIR]

On first run the console password is generated and printed once — save it.
The TLS certificate is self-signed; its SHA-256 fingerprint is printed so you
can verify it in your browser. The console binds to loopback by default; pass
--console-host 0.0.0.0 to reach it from another machine (do this knowingly).
"""
import argparse
import asyncio
import os
import shlex
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
from src import MeshNode
from src.transport_manager import TransportManager
from src.tcp_transport import TCPTransport, TCPServer
from src.spool_transport import SpoolTransport, SpoolServer
from src.udp_transport import UDPTransport, UDPServer
from src.webconsole import WebConsole
from src.data_connector import DataConnector, ConnectorClient
from src.process_launcher import ProcessLauncher
from src.app_channel import CHAT_APP_ID
from src.app_registry import FLEET_APP_ID, AppHost, AppRegistry
from src.apps import fleet_console
from src.apps.chat import ChatApp
from src.apps.chat_state import ChatState, DrawerStore
from src.apps.chat_web import ChatBridge
from src.apps.fleet import FleetApp
from src.apps.fleet_state import FleetState
from src.apps.fleet_web import FleetBridge
from src.apps import fleet_provision
from src import config


def _chat_factory(node, connector):
    """Build the chat app on demand (the app host calls this when enabling it).

    State and message history live in the node's encrypted per-app drawer
    (``CHAT_APP_ID``) — contacts and pseudos never sit in the clear, and the feed
    survives restarts. With no ``--data`` the drawer is RAM-only."""
    async def build():
        client = ConnectorClient(connector.host, connector.port,
                                 connector.token, CHAT_APP_ID)
        await client.connect()
        store = DrawerStore(node.app_storage, CHAT_APP_ID)
        state = ChatState(store=store)
        app = ChatApp(client, node_id=node.id, state=state)
        return app, ChatBridge(app, store=store)
    return build


def _fleet_factory(node, connector, data_dir, local_console=None):
    """Build the fleet app on demand.

    The trust ledger lives in the fleet drawer, encrypted at rest like every
    other app's state. ``repo_root`` is the tree this node would push when
    provisioning; without one the provision capability reports itself
    unavailable instead of half working."""
    async def build():
        client = ConnectorClient(connector.host, connector.port,
                                 connector.token, FLEET_APP_ID)
        await client.connect()
        store = DrawerStore(node.app_storage, FLEET_APP_ID)
        app = FleetApp(client, node.app_auth(FLEET_APP_ID),
                       state=FleetState(store=store), repo_root=ROOT,
                       mesh_invite=lambda: _mesh_invitation(node),
                       local_console=local_console)
        return app, FleetBridge(app)
    return build


# A provisioned machine redeems its invitation only after installing its
# dependencies, which on a small box can take far longer than the 5 minutes a
# hand-typed code lives. This one is single-use, delivered over an authenticated
# SSH channel to one machine, and deleted after use — so a longer window is the
# right trade, and it is bounded by `invite._MAX_TTL`.
PROVISION_INVITE_TTL = 3 * 3600


def _mesh_invitation(node) -> dict:
    """A fresh single-use invitation to this node's mesh, plus where to reach it.

    Redeeming it runs the ordinary invite → handshake path, so the newcomer's
    certificate is **issued and signed by this node** — the one that scanned and
    installed it — and chains from there to the network's root."""
    return {"uris": node.advertised_uris()[:8],
            "code": node.generate_invite(PROVISION_INVITE_TTL)}


async def _join_mesh(node, preauth) -> bool:
    """Redeem the invitation left by the provisioner, and wait for the session.

    ``join`` returning is not proof of anything: the handshake that issues our
    certificate completes afterwards. We wait for a live session before saying
    we joined, and we try each advertised address in turn — the provisioner may
    advertise several and only the LAN one is reachable from here."""
    for uri in preauth.get("join_uris") or []:
        try:
            await node.join(uri, preauth.get("join_code") or "")
            await node.wait_for_session(timeout=30.0)
            return True
        except Exception:
            continue          # unreachable address, or a code already redeemed
    return False


async def _adopt_operator(node, host, preauth, path) -> None:
    """First start after provisioning: join the mesh the operator named, adopt
    them as an operator, prove which provisioning run we came from, and delete
    the pre-authorisation.

    The file is removed whatever happens. It is single-use by construction — the
    operator only honours the token once — so keeping it around after the
    attempt would leave a stale secret on disk for no benefit."""
    try:
        joined = await _join_mesh(node, preauth)
        if not joined:
            # Claiming would go nowhere with no route to anyone. Say so plainly
            # rather than leaving a machine that looks provisioned and is not.
            print("  Fleet         : could not join the mesh — not adopted")
            return
        app = host.app("fleet")
        if app is not None:
            await app.claim_preauth(preauth)
            print(f"  Fleet         : joined the mesh and adopted operator "
                  f"{preauth['operator_id'].hex()[:16]}…")
    except Exception as exc:
        print(f"  Fleet         : pre-authorisation failed ({type(exc).__name__})")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _apply_transport_settings(manager, values: dict) -> list:
    """Hand each transport its own section of the file, before anything runs.

    The file carries these as text and never validates them: the medium is the
    only thing that knows what it takes. A value it refuses is reported and
    dropped — a node that will not start because one timeout was mistyped is a
    worse outcome than one running that setting at its default."""
    problems = []
    for scheme, fields in (values or {}).items():
        if not manager.is_supported(scheme):
            problems.append(f"config: no transport named '{scheme}' — ignored")
            continue
        try:
            result = manager.configure(scheme, fields)
        except Exception as exc:
            problems.append(f"config: {scheme} — {type(exc).__name__}")
            continue
        for name, reason in result["rejected"].items():
            problems.append(f"config: {scheme}.{name} — {reason}")
    return problems


def _settle(args) -> tuple:
    """Fill in everything the command line did not say, from the config file.

    Every option below defaults to ``None`` in the parser precisely so "absent"
    can be told from "set to the value that happens to be the default". Order is
    command line > file > built-in default, so a unit or a script that passes
    flags keeps behaving exactly as it did before the file existed.

    Returns ``(path, problems, overridden)`` for the banner: a configuration
    that is silently ignored is how a node ends up running settings nobody
    chose, so both the problems and the flags that won are said out loud."""
    path = config.path_for(ROOT, args.config)
    values, problems = config.load(path)
    settled = config.defaults()
    settled.update(values)
    overridden = []
    for name in config.SETTINGS:
        given = getattr(args, name, None)
        if given is not None and given != []:
            # `data` comes from start.sh on every launch; saying it is overriding
            # the file every time would be noise, not information.
            if name in values and name != "data":
                overridden.append(name)
            settled[name] = given
    for name, value in settled.items():
        if name != "transports":
            setattr(args, name, value)
    return path, problems, overridden, values.get("transports") or {}


async def main() -> None:
    ap = argparse.ArgumentParser()
    # Defaults live in src/config.py, not here: the parser must be able to say
    # "this flag was not given" so the file can speak. See _settle().
    ap.add_argument("--config", default=None,
                    help=f"configuration file (default: {config.FILENAME} next "
                         "to the install, or $NMESH_CONFIG)")
    ap.add_argument("--listen", default=None, help="node TCP listen addr")
    ap.add_argument("--udp", default=None, type=int,
                    help="UDP listen port for hole punching (default 9001)")
    ap.add_argument("--no-udp", action="store_true", default=None,
                    help="disable the UDP listener (punching stays controllable from the console)")
    ap.add_argument("--stun", action="store_true", default=None,
                    help="use STUN to discover public UDP address (fallback)")
    ap.add_argument("--punch-keepalive", action="store_true", default=None,
                    help="keep the UDP NAT mapping open continuously (stay "
                         "reachable / relay behind NAT)")
    ap.add_argument("--transport-balance", type=int, default=None,
                    help="how addresses are chosen: 0 weighs measured latency "
                         "alone, 100 the transport priority alone (default 50)")
    ap.add_argument("--dynamic-address", action="store_true", default=None,
                    help="move a live link onto a lower-latency address of the "
                         "same node when one measures better")
    ap.add_argument("--lan-discovery", action="store_true", default=None,
                    help="answer LAN relay-discovery beacons (be findable as a "
                         "relay by joiners on the same network)")
    ap.add_argument("--spool", default=None, help="also listen on a spool:// directory (store-and-forward)")
    ap.add_argument("--console-host", default=None)
    ap.add_argument("--console-port", type=int, default=None)
    ap.add_argument("--connector-port", type=int, default=None,
                    help="expose a data connector on this loopback port for apps")
    ap.add_argument("--launch", action="append", default=[], metavar="CMD",
                    help="launch an app wired to the mesh (repeatable); needs --connector-port")
    ap.add_argument("--pseudo", default=None,
                    help="display name for this node, shown beside its id "
                         "(at most 50 characters; the id stays the identity)")
    ap.add_argument("--no-chat", action="store_true", default=None,
                    help="disable the built-in chat app (served at /chat on the console)")
    ap.add_argument("--fleet", action="store_true", default=None,
                    help="enable the built-in fleet app (remote management + "
                         "deployment, served at /fleet). Off by default: it can "
                         "open a shell, so it is enabled deliberately. The "
                         "console's Apps page toggles it too.")
    ap.add_argument("--no-tls", action="store_true", default=None)
    ap.add_argument("--data", default=None, help="state dir (persists identity + console creds)")
    # Read from the environment so a password never lands in the process args
    # (visible in `ps`); a CLI flag still overrides it when given explicitly.
    ap.add_argument("--console-password",
                    default=os.environ.get("NMESH_CONSOLE_PASSWORD") or None,
                    help="console password (default: $NMESH_CONSOLE_PASSWORD, "
                         "else a strong one is generated and printed once)")
    args = ap.parse_args()
    config_path, config_problems, config_overridden, transport_values = _settle(args)

    if args.data:
        os.makedirs(args.data, exist_ok=True)

    mgr = TransportManager()
    mgr.register("tcp", TCPTransport, TCPServer)
    mgr.register("spool", SpoolTransport, SpoolServer)
    mgr.register("udp", UDPTransport, UDPServer)
    transport_problems = _apply_transport_settings(mgr, transport_values)
    node = MeshNode(
        mgr,
        identity_path=os.path.join(args.data, "node.key") if args.data else None,
        cert_store_path=os.path.join(args.data, "node.certs") if args.data else None,
        session_store_path=os.path.join(args.data, "node.sessions") if args.data else None,
        app_storage_path=os.path.join(args.data, "app_store") if args.data else None,
        app_store_dir=os.path.join(args.data, "appstore") if args.data else None,
        # Pinned release publishers live with the node's state: what may
        # replace this node's code is not something to forget on restart.
        release_dir=args.data if args.data else None,
        pseudo=getattr(args, "pseudo", "") or None,
    )
    # `--listen` takes host:port, but "tcp://host:port" is the spelling every
    # other address in this project uses, so it gets typed here too. Accept it
    # rather than building "tcp://tcp://…", which binds but prints an address
    # nobody can connect to.
    listen_addr = args.listen.removeprefix("tcp://")
    listen_uris = [f"tcp://{listen_addr}"]
    if args.spool:
        listen_uris.append(f"spool://{args.spool}")
    await node.start(listen_uris)
    # Discover public IP before printing so advertised URIs include it
    pub_ip = await node.discover_public_ip()
    if args.udp is not None and not args.no_udp:
        await node.start_udp(args.udp)
        if args.punch_keepalive:
            node.console_set_punch_keepalive(True)
    if args.transport_balance is not None:
        try:
            node.set_transport_balance(args.transport_balance)
        except ValueError as exc:
            print(f"  transport-balance: {exc} — keeping the default")
    if args.dynamic_address:
        node.set_dynamic_address(True)
    if args.lan_discovery:
        await node.start_lan_discovery()
        if args.stun:
            pub = await node.discover_public_udp_addr()
            if pub:
                print(f"  STUN          : public UDP addr {pub[0]}:{pub[1]}")

    # A data connector backs every built-in app and any --launch'd apps. When
    # only the built-ins need it, bind an ephemeral loopback port;
    # --connector-port exposes a fixed one for external apps.
    registry = AppRegistry(args.data)
    if args.no_chat:
        registry.set_enabled("chat", False)
    if args.fleet:
        registry.set_installed("fleet", True)
        registry.set_enabled("fleet", True)

    # A machine provisioned by an operator carries a pre-authorisation: it names
    # who to trust and proves which provisioning run this node came from. Its
    # presence is also what turns the fleet app on for a headless box nobody can
    # click "enable" on.
    preauth = None
    if args.data:
        preauth_path = os.path.join(args.data, fleet_provision.PREAUTH_FILENAME)
        preauth = fleet_provision.read_preauth(preauth_path)
        if preauth is not None:
            registry.set_installed("fleet", True)
            registry.set_enabled("fleet", True)

    connector = None
    launcher = None
    host = None
    wants_apps = registry.is_enabled("chat") or registry.is_enabled("fleet")
    if wants_apps or args.connector_port is not None:
        connector = DataConnector(node, host="127.0.0.1", port=args.connector_port or 0)
        await connector.start()
        launcher = ProcessLauncher(connector, node_id=node.id)
        for cmd in args.launch:
            await launcher.launch(shlex.split(cmd))
    elif args.launch:
        print("  NOTE          : --launch ignored (requires --connector-port or an app)")

    # The fleet app can drive this node's own console for an operator holding
    # `manage`. It is built before the console exists, so it gets the client
    # empty and the console binds itself into it below.
    local_console = fleet_console.LocalConsole()

    if connector is not None:
        host = AppHost(registry, app_storage=node.app_storage)
        host.register("chat", _chat_factory(node, connector))
        host.register("fleet", _fleet_factory(node, connector, args.data,
                                              local_console))
        await host.apply()

    console = WebConsole(node, host=args.console_host, port=args.console_port,
                         state_dir=args.data, use_tls=not args.no_tls,
                         password=args.console_password, app_host=host,
                         config_path=config_path)
    console.start(loop=asyncio.get_running_loop())
    local_console.bind(console)

    if preauth is not None and host is not None:
        await _adopt_operator(node, host, preauth, preauth_path)

    print("=" * 60)
    print(f"  NMesh node    : {node.id.raw.hex()[:16]}…  listening tcp://{listen_addr}")
    print(f"  Config        : {config_path}")
    # An ignored configuration file is how a node ends up running settings
    # nobody chose. Say it here, where the operator is already looking, not in a
    # line scrolled past twenty seconds earlier.
    for problem in config_problems + transport_problems:
        print(f"  Config warn   : {problem}")
    if config_overridden:
        print(f"  Config warn   : overridden on the command line: "
              f"{', '.join(config_overridden)}")
    if pub_ip:
        print(f"  Public IP     : {pub_ip}   (self-discovered)")
    for uri in node.advertised_uris():
        print(f"  Advertised    : {uri}")
    if args.spool:
        print(f"  Spool link    : spool://{args.spool}   (store-and-forward)")
    if args.udp is not None and not args.no_udp:
        print(f"  UDP listener  : udp://0.0.0.0:{args.udp}   (NAT hole punching)")
    print(f"  Web console   : {console.url}")
    for app in (host.overview() if host is not None else []):
        if app["running"]:
            print(f"  App           : {app['name']:<6} {console.url.rstrip('/')}"
                  f"{app['path']}")
    if console.generated_password:
        print(f"  Password      : {console.generated_password}   (shown once — save it)")
    elif args.console_password:
        print("  Password      : (the one you set via NMESH_CONSOLE_PASSWORD)")
    else:
        print("  Password      : (existing — from console.cred)")
    if not args.no_tls:
        print(f"  TLS SHA-256   : {console.cert_fingerprint}")
    if connector is not None:
        print(f"  Data connector: 127.0.0.1:{connector.port}   token={connector.token}")
    if launcher is not None and launcher.processes:
        print(f"  Launched apps : {', '.join(p.name for p in launcher.processes)}")
    if args.console_host not in ("127.0.0.1", "localhost", "::1"):
        print("  WARNING       : console is reachable off-host — protect the network path.")
    print("=" * 60, flush=True)

    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        console.stop()
        if host is not None:
            await host.stop_all()   # stops each app + its console bridge
        if launcher is not None:
            await launcher.stop_all()
        if connector is not None:
            await connector.stop()
        await node.stop()  # also stops UDP listener + cleans up punch state


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
