# FAQ — the failures people actually hit

The exact symptoms, what they mean, and the command that fixes them. Every
entry starts from the message you have in front of you.

For everything else: [`Docs/Setup/guide`](Docs/Setup/guide) (installation),
[`Docs/WebConsole/guide`](Docs/WebConsole/guide) (console),
[`Docs/Apps/fleet`](Docs/Apps/fleet) (remote management),
[`Docs/Architecture/gotchas.md`](Docs/Architecture/gotchas.md) (internal traps).

---

## Updates

### `sudo: The "no new privileges" flag is set, which prevents sudo from running as root`

**When:** you click **Update** on a managed node (the `update` capability).

**What is happening.** The systemd unit `install.sh` writes is hardened, and one
of its directives is `NoNewPrivileges=yes`. The kernel then refuses **every
setuid binary** for that process and all its children, permanently — and `sudo`
is one of them. The right to update does exist (the root wrapper, the sudoers
rule); it is simply unusable from that process. Two hardening decisions in the
same project were contradicting each other.

**The fix.** On the machine concerned:

```bash
cd /opt/nmesh            # or your installation prefix
sudo ./install.sh --allow-update
```

The unit is rewritten with confinement compatible with the right that was
granted, and the service restarts. Check it:

```bash
systemctl cat nmesh | grep -E 'NoNewPrivileges|ProtectSystem'
#   NoNewPrivileges=no
#   ProtectSystem=no
```

Since that fix, confinement **follows the grant**: hardened in full by default,
relaxed only for a node whose operator explicitly asked for system updates.
Running `./install.sh` again **without** `--allow-update` removes the sudoers
rule *and* re-hardens the unit — the two choices can no longer be made
separately.

**Why three directives and not one.** `NoNewPrivileges=yes` blocks `sudo`;
`ProtectSystem=full` mounts `/usr` read-only, so a package manager could write
nothing even if `sudo` worked; `PrivateDevices=yes` hides devices some
post-install scripts need. `PrivateTmp=yes` stays — it gets in nobody's way.

**Without restarting right now?** There is no workaround: the flag is set when
the process starts and the kernel never removes it. An update run by hand on the
machine (`sudo apt update && sudo apt dist-upgrade`) still works — that is your
shell, not the node's process.

**In a container.** The same message appears with
`--security-opt no-new-privileges` (sometimes set by default). Remove it, or
update the image rather than the container: a node running from an image updates
by pulling a newer image, and the console says so.

### "cannot self-update" on a node's card

The node answered that it cannot update itself. The exact reason is in the
refusal shown when you click Update. The three cases:

| Message | Cause | Fix |
|---|---|---|
| `no package manager this node knows how to drive` | unrecognised distribution (or a minimal image with no `apt`/`dnf`/`apk`…) | update the machine some other way; NMesh does not guess a package manager |
| `no sudo or doas on this machine, and the node is not root` | the node runs under an unprivileged account and nothing allows escalation | `sudo ./install.sh --allow-update` on the machine |
| `NoNewPrivileges` | see the entry above | `sudo ./install.sh --allow-update` |

### The node updates, then does not come back

After an update **of NMesh** (Settings → Updates) the node replaces its own
files and restarts. If it is managed by a service (`systemd`, OpenRC, launchd)
it comes back on its own and the console says so. Otherwise the old version is
kept: the post-update message gives the backup path.

---

## Installation & startup

### `PermissionError: [Errno 13] … '/…/node.key.tmp'`

The state directory belongs to root while the node runs under another account —
typically an installation done with `sudo` before the node had its own service
account. Run `./install.sh` again: it repairs ownership as it goes.

### `start.sh: line …: HOME: unbound variable`

A systemd service starts with no `HOME`. Fixed: `start.sh` now derives the home
directory from the account's passwd entry. If you still see this message your
tree predates the fix — update, or add `Environment=HOME=<prefix>` to the unit.

### liboqs rebuilds on every installation

It should not any more: the result is cached per wrapper version
(`/var/cache/nmesh/liboqs-<v>` as root). If the build starts again, either the
cache is not writable or the wrapper version changed. The message from
`start.sh` says which.

### I lost the console password

On the machine:

```bash
cd /opt/nmesh && sudo ./install.sh --reset-password
```

A new password is generated and printed **once**. This is deliberately the only
route: it requires access to the state directory, which is exactly the level of
privilege such a power deserves.

---

## Network & reachability

### `this node has no confirmed public address` when creating a join ticket

A ticket carries only an address and a code: the scanner has nothing else to go
on. Issuing one therefore requires a **confirmed `world` address** — an inbound
connection has actually arrived on it — not an address believed to be public. On
a node behind NAT with no port forwarding, use the full join (block exchange) or
a relay.

### Two nodes cannot see each other although the addresses look right

Open the peer's details (**Network → Peers → Details**): the **Addresses** table
says what each address did — `in-use`, `timeout`, `refused`, `untried` — with
the reason and the duration. That is nearly always enough to tell "firewall"
from "wrong address" from "never tried".

### A link has good latency but the traffic is bad

Look at **jitter** and **loss** in the same view, and the transport's own
counters below them: on UDP, *retransmits* climbing while the RTT looks fine is
the signature of a path losing packets. The expanded map (click the map on
Overview) turns those links amber.

### The console says "Offline" although the machine has internet

`internet` comes from a bounded outbound probe. On a network that filters
probes it fails with the mesh entirely unaffected. **Re-check network** runs it
again; actual reachability is the business of the **Reachability** line just
above it.

---

## Console

### The context picker does not appear

It appears only if the **fleet** app is running **and** at least one node has
granted you the `manage` capability. Otherwise there is nothing to pick. See
[`Docs/Apps/fleet`](Docs/Apps/fleet).

### "no session on that node — connect to it again"

The remote session expired (an hour of inactivity), the remote node restarted,
or its console password changed. Select it again: it will ask for the password.
That is deliberate — the grant opens the channel, the password opens the
session.

### A progress or memory bar stays empty

Fixed. The console's CSP (`default-src 'self'`, without `unsafe-inline`) makes
the browser ignore **silently** any `style=` attribute, so bars written that way
never filled. They are `<progress>` elements now. If you still see it, your tree
predates the fix.

### The browser refuses the console's certificate

It is self-signed, which is expected. Its SHA-256 fingerprint is printed when
the node starts: compare it, then accept it. Over loopback, `--no-tls` is a
reasonable option.

---

## Fleet & deployment

### `dependency setup failed` when deploying to a machine

Remote deployment installs nothing itself: it delivers the tree and calls its
`install.sh`. On failure the console keeps the **last lines of output from the
target machine** — the real cause is nearly always in there (a missing package,
a full disk, no compiler for liboqs).

### `sudo: a terminal is required`

Fixed: deployment allocates a pty and answers the prompts without ever writing
the secret to disk or onto a command line. If you still see it, update the
**operating** node — that is the one driving SSH.

### A deployed machine does not appear in the list

It joins after installing its dependencies, which can take several minutes on a
small machine (building liboqs). Its invitation lives far longer than a
hand-typed code, precisely for that. The **Activity** tab shows where the
deployment has got to.

---

## Miscellaneous

### Two idle nodes were exchanging megabytes

Fixed (a `FIND_NODE`/`FOUND_NODE` loop): ~3 Mbit/s at rest became ~2 kbit/s. To
check on your own machine: **Settings → Diagnostics → Protocol trace**, which
gives the volume per message type without ever recording any content.

### Where are the files?

| What | Where (system installation) |
|---|---|
| the tree | `/opt/nmesh` |
| the state (identity, sessions, certificates) | `/var/lib/nmesh`, mode 700 |
| the configuration | `<prefix>/nmesh.conf` |
| the update wrapper | `/usr/local/lib/nmesh/nmesh-update` (root) |
| the sudoers rule | `/etc/sudoers.d/nmesh` |
