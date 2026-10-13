# Security policy

NMesh carries sensitive data through a network it assumes hostile; the threat
model and the principles are in [`AGENTS.md`](AGENTS.md), the mechanisms in
[`Docs/Architecture/security.md`](Docs/Architecture/security.md).

## Reporting a vulnerability

Report it **privately**, through GitHub's *Report a vulnerability* button on
the repository's **Security** tab
(<https://github.com/fnyaker/NMesh/security/advisories/new>). Do not open a
public issue, and do not post it in a pull request. The report stays between
you and the maintainers until a fix is published, and the advisory then
credits you unless you ask otherwise.

Please include what an adversary gains, how to reproduce it, and the version
(`src/version.py`). Write addresses from 192.0.2.0/24, 198.51.100.0/24 or
203.0.113.0/24 and placeholder node names: never those of a live mesh.

Only the latest release is supported; a fix ships as a new patch version, which
nodes following GitHub pick up through the updater.

## Checking what you downloaded

The zipapp attached to a release and every image pushed to GHCR carry a build
provenance attestation, signed through Sigstore: which commit, which workflow.

```
gh attestation verify nmesh.pyz --repo fnyaker/NMesh
gh attestation verify oci://ghcr.io/fnyaker/nmesh:latest --repo fnyaker/NMesh
```

That proves where a file came from, not that its code is right; what a node
installs from the mesh is decided by the publishers its operator pinned
([`Docs/Updates/guide`](Docs/Updates/guide)).

## What the repository runs on its own

- **CodeQL** code scanning (extended query suite) on Python, JavaScript and the
  workflows themselves, on every push, every pull request and weekly — plus the
  same security queries run with **what a peer sends** as their source
  (`.github/codeql/nmesh`): the standard models know HTTP servers, not the
  mesh's sockets, spool frames and message handlers.
- **Secret scanning** with **push protection**: a push carrying a known
  credential format is refused.
- **Dependabot** alerts and security updates for the dependencies of
  `requirements.txt`, the base image and the workflow actions.
- Every workflow action is pinned to a full commit SHA, and each workflow starts
  with no token permission, granting each job only what it uses.
- liboqs is compiled only from the commit and archive digest in
  `scripts/liboqs.lock`, and a node with no liboqs refuses to start rather than
  let the wrapper fetch one; the base image installs a hash-locked package set
  (`docker/requirements.lock`) that `pip-audit` checks every week.
- The image a node runs carries no compiler or build tools, and is scanned by
  Trivy on every build and every week: a fixable HIGH or CRITICAL fails it.
- The console is scanned by OWASP ZAP every week, its API included and signed
  in, against a throwaway node.
- **OpenSSF Scorecard** grades how the repository itself is kept, weekly,
  into the Security tab.
