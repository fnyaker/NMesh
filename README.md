# NMesh

**A decentralised, transport-agnostic, end-to-end encrypted mesh network —
built to work in hostile territory.**

NMesh moves data between nodes over *any medium that can carry bytes* — TCP/IP,
and equally a shared directory on a USB stick (store-and-forward). Routing is
transport-agnostic: if A talks to B over Bluetooth and B to C over Wi-Fi, A
reaches C through B. Everything is encrypted end to end with **post-quantum**
cryptography; relays never see the content.

> The guiding principles (security > solidity > flexibility > speed, minimal
> dependencies) are in [`CLAUDE.md`](CLAUDE.md). Progress is tracked in
> [`ROADMAP.md`](ROADMAP.md).

## Highlights

- **Post-quantum end to end** — ML-KEM-768, ML-DSA-65, AES-256-GCM.
- **Transport-agnostic** — anyone can implement a transport
  (`BaseTransport` / `BaseServer`) and register it by URL scheme.
- **Store-and-forward** — the mesh also runs over a directory or a file
  (`spool://`), for offline or very high-latency links.
- **Zero crash / self-repair** — no hostile packet brings a node down; abusive
  peers are cut off, dead links purged, links rebuilt on demand.
- **Self-rooted P2P PKI** — invitations, certificate chains, trust roots; no
  central authority.
- **Opt-in persistence** — sessions and peers survive a restart (encrypted at
  rest).
- **Quick join** — a 34-character string (or a QR code you can scan with a
  camera) carrying the address and a single-use code, issued by a publicly
  reachable node.
- **Web management console** + **data connector** for plugging apps in.
- **Application identity (SSO)** — an app uses the node's mesh identity to
  authenticate its peers: signed assertions, scoped, fresh, single-use.
- **Fleet management & deployment** — the *Fleet* app: enrol nodes with
  capabilities, read their status, update them, open a shell — full screen in a
  tab, usable from a phone, with the machine's files behind the same right —
  discover the LAN and install NMesh over SSH. A machine deployed this way comes up trusting the
  operator who installed it, accepting their release publishers, and reachable
  from their console without a password nobody ever typed on it.
- **Minimal dependencies** — Python stdlib + `liboqs-python` + `cryptography`.

## Quick start

```bash
./start.sh                         # creates a venv, installs deps, runs a node + console
```

On a fresh machine the script copes on its own: it detects the distribution
(apt, dnf/yum, pacman, zypper, apk, xbps, Homebrew, FreeBSD, Termux), installs
what is missing — **including `pip`/`venv` where the distro ships them
separately (Ubuntu, Debian, Alpine, Arch)** — and builds liboqs. The full list
of cases it handles is in [`Docs/Setup/guide`](Docs/Setup/guide).

On the first run the console password is **generated and printed once** — write
it down. Then open the URL it prints (the web console, over HTTPS). (A machine
installed remotely from another node's *Fleet* page prints it where nobody is
looking, which is why that route grants the deploying operator a way in that
does not need it — see [`Docs/Apps/fleet`](Docs/Apps/fleet).)

Useful options (every argument is passed through to the launcher):

```bash
./start.sh --connector-port 8790          # expose a connector for plugging apps in
./start.sh --spool /mnt/usb/mesh          # add a store-and-forward link (USB stick)
./start.sh --console-host 0.0.0.0         # console reachable from the LAN
./start.sh --fleet                        # enable the fleet management app (/fleet)
```

Check an installation without starting a node (useful in CI):

```bash
NMESH_SETUP_ONLY=1 ./start.sh
```

Without the script, by hand (in a venv — since PEP 668 most distributions
refuse installs into the system Python):

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python scripts/nmesh_node.py --data ./data
```

## Installing for good (the recommended way)

For a machine that is meant to **host** a node, `install.sh` copies the tree to
a durable location, enables start-at-boot (systemd, OpenRC or launchd) and then
starts the node:

```bash
./install.sh                       # install, enable at boot, start
./install.sh --fleet               # …and enable the fleet management app
./install.sh --uninstall           # remove the service and the files
```

It reimplements nothing from `start.sh`: it delegates dependencies to it, and
the service it writes points at `start.sh`, so a node that restarts re-checks
and repairs its own installation. Running `install.sh` again updates in place —
**the node's state is never touched**.

As root, the node gets **a system account of its own** (`nmesh`, no shell, no
password) which alone owns the installation and the state, mode 700: the
identity key is unreadable by any other account on the machine. Use
`--run-as root` or `--run-as someone` to decide otherwise.

### Where the files live

| | Installation | Configuration | State (identity, certs, sessions) |
|---|---|---|---|
| root | `/opt/nmesh` | `/opt/nmesh/nmesh.conf` | `/var/lib/nmesh` |
| user | `~/.local/share/nmesh` | `~/.local/share/nmesh/nmesh.conf` | `~/.local/share/nmesh/data` |
| from a checkout (`./start.sh`) | the current directory | `./nmesh.conf` | `./data` |

The configuration file carries **every launch option**. The installer writes it
and the console edits it (**Settings → Configuration**) — no more opening a
systemd unit to change a port. It survives updates and reinstalls.

```bash
./install.sh --prefix /srv/nmesh          # move the installation, and the config with it
NMESH_CONFIG=/etc/nmesh.conf ./start.sh   # or name the file directly
./start.sh --config /etc/nmesh.conf       # same, as an argument
```

Precedence: **command line > file > default**. A flag passed explicitly always
wins, and at startup the node announces which settings from the file a
command-line option overrode. Settings and their bounds:
[`Docs/Setup/guide`](Docs/Setup/guide).

Console password: changeable from the console (**Settings → Console password**,
the current one is required), or resettable on the machine itself with
`./install.sh --reset-password` if you have lost it.

The node can also update itself from GitHub: web console →
**Settings → Updates**. Checking is manual, installing asks for a confirmation
that names the version, and nothing is ever installed without that click.
Details: [`Docs/Setup/guide`](Docs/Setup/guide).

Better: **updates over the mesh itself**. A node signs its own code into one
package and announces it — publishing touches no network at all. Whoever pinned
that publisher's key asks for the package, from the publisher or from any node
that already kept a copy, checks every byte against the signature, and installs
it — automatically if asked. One publisher becomes a swarm, and no web host is
in the trusted set. Same page in the console; the mechanism is in
[`Docs/Updates/guide`](Docs/Updates/guide).

Docker is still possible (`docker/`), but it is no longer the recommended route
for a dedicated machine.

## Names

A node is identified by its id — twenty bytes from its signing key, unique and
impossible to choose. Beside it sits a **pseudo**: a name you pick, change
whenever you like, and see everywhere the node appears (console, chat, fleet).
Set it in **Settings → Identity**, with `--pseudo`, or in `nmesh.conf`.

A pseudo is a label, never an identity — names are not unique and decide
nothing, so the id is always shown with them. What is guaranteed is that nobody
can put a name on *your* node: a name travels as a claim signed by the identity
it names. Names are searched **whole or partially** (`ali` finds `Alice Ada`,
`jose` finds `José`), instantly, from what the node has already learned by
gossip.

→ [`Docs/Pseudos/guide`](Docs/Pseudos/guide)

## Web console

A **responsive** management interface (four sections: Overview, Network, Apps,
Settings):

- Overview: local status, live throughput (chart), a **clickable mesh map**
  (click a node to open its details; click the map itself for a bigger one you
  can pan and zoom), the table of active peers (direction, session, RTT, bytes).
- Network: peers and known nodes, reachability, one block per transport (what
  is bound, what it carries, what it takes), and how to add a node.
- Apps: installed apps + a **scalable store** (server-paginated catalogue,
  search, install/uninstall actions).
- Settings: this node's name and a search for other nodes' names, updates,
  console password, this browser's preferences, the startup configuration file,
  diagnostics.

→ [`Docs/WebConsole/guide`](Docs/WebConsole/guide)

## Plugging an application in

The **data** plane: an app (same host or a container) connects to the connector
and sends/receives E2E messages over the mesh. The node becomes its network
bridge.
→ [`Docs/DataConnector/guide`](Docs/DataConnector/guide)

An app can also expose named operations that other apps, the core and the
console can call — one door, declared by the app itself, rejecting by default.
→ [`Docs/AppAPI/guide`](Docs/AppAPI/guide)

## Transports

A transport is anything that moves bytes. Shipped:

| Scheme     | Medium                              | Use                            |
|------------|-------------------------------------|--------------------------------|
| `tcp://`   | TCP/IP                              | ordinary network links         |
| `udp://`   | UDP/IP (reliability + NAT hole punching) | direct links behind NAT   |
| `spool://` | shared directory / file             | store-and-forward, USB stick   |

Writing your own: [`Docs/Transports/guide`](Docs/Transports/guide) +
[`template.py`](Docs/Transports/template.py). Spool:
[`Docs/Transports/spool`](Docs/Transports/spool).

## Deployments

### System service (recommended)

`./install.sh` — see [Installing for good](#installing-for-good-the-recommended-way)
above.

### Docker (hosting a relay node)

```bash
docker compose -f docker/docker-compose.yml up -d --build
```

Opens mesh port `9000` (relay); the console stays on the host's loopback by
default (see the compose comments to expose it). State (identity, certificates,
sessions, console password) persists in the `/data` volume. The image is
published to GHCR on every tag (`ghcr.io/<owner>/nmesh`).

### Zipapp (`.pyz`)

```bash
python scripts/build_pyz.py          # produces nmesh.pyz
python nmesh.pyz --data ./data       # needs liboqs-python + cryptography installed
```

A single file carrying the NMesh code. Note: the native crypto
(`liboqs-python`, `cryptography`) must be installed in the interpreter — for a
fully self-contained artefact, prefer the Docker image.

## FAQ

The failures people actually hit, with the exact message and the command that
fixes them: [`FAQ.md`](FAQ.md).

## Audit

A full audit that follows the execution order — every packet field from the
socket to the app, then the console and the apps — with each finding written up
next to the invariant a fix must not break: [`BUGSVULNS.MD`](BUGSVULNS.MD).

68 findings, 48 security and 20 performance, all addressed. Five are recorded
there as *partly* closed, with the reason next to each: what is left in those
five is a design decision (authenticating the UDP frame header, serving a node
that has not yet joined), not an unfinished patch. The last three were not found
by reading the code — one CI failure turned them up when the base image's Python
moved to 3.13.

## Tests

```bash
pytest                     # unit tests (fast, no network)
pytest tests/integration   # integration: real nodes (TCP + spool), real crypto
```

GitHub CI runs both on every push and PR. See [`TEST.md`](TEST.md).

## Security

The threat model: *the moment data leaves the node, it is in hostile
territory*. Nothing arriving from the network or from disk is presumed sound;
everything is validated, bounded, and rejected by default. Fuzzing proves that
no hostile byte crashes a parser. Details and priorities:
[`CLAUDE.md`](CLAUDE.md).

## Project layout

```
src/              the core: node, crypto, packets, routing, transports, console, connector
scripts/          nmesh_node.py (launcher), nmesh_config.py, nmesh_password.py, build_pyz.py
start.sh          installs dependencies and runs a node from the current tree
install.sh        installs the tree for good + a start-at-boot service, then runs it
docker/           relay-node image and compose file
Docs/             guides (setup, transports, console, connector, packets)
tests/            unit tests + tests/integration (real nodes)
```
