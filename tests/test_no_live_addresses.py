"""
No real address in the repository.

The repository is public, and the live mesh it is tested against is somebody's
own: an incident written down with the addresses it was seen on publishes them.
So an address in code, tests or documentation is either one reserved for
documentation (RFC 5737), a private or loopback one, IANA's `example.com` block
for a test that needs a routable one, or one of the few public landmarks a test
needs by name (public resolvers, a placeholder).
Anything else is an address somebody actually has.

IPv4 only, and only the literal form: it is what an incident gets copied in
with. Node names, hostnames and IPv6 prefixes need the same care and have no
pattern to check — `AGENTS.md` says so where incidents are written.
"""
import ipaddress
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
_LITERAL = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_DOCUMENTATION = tuple(ipaddress.ip_network(net) for net in
                       ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
# A test that needs an address the internet routes (`is_global`) cannot use
# RFC 5737, which is not global; IANA's own example.com block is, and is nobody's.
_EXAMPLE = ipaddress.ip_network("93.184.216.0/24")
_LANDMARKS = {"1.1.1.1", "8.8.8.8", "8.8.8.0", "9.9.9.9", "1.2.3.4"}
_TEXT = (".py", ".md", ".MD", ".sh", ".txt", ".yml", ".yaml", ".toml", ".js",
         ".html", ".css", ".json", ".cfg", ".conf")


def _tracked() -> list[pathlib.Path]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                         text=True, check=True).stdout.split("\n")
    return [ROOT / name for name in out
            if name.endswith(_TEXT) or "." not in pathlib.Path(name).name]


def _real(literal: str) -> bool:
    try:
        ip = ipaddress.ip_address(literal)
    except ValueError:
        return False                      # a version number, a dotted count
    return (ip.is_global and literal not in _LANDMARKS and ip not in _EXAMPLE
            and not any(ip in net for net in _DOCUMENTATION))


def test_the_check_reads_the_repository():
    assert len(_tracked()) > 100


def test_no_real_ipv4_address_is_written_down():
    found = []
    for path in _tracked():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            found += [f"{path.relative_to(ROOT)}:{number}: {literal}"
                      for literal in _LITERAL.findall(line) if _real(literal)]
    assert not found, ("use 192.0.2.x, 198.51.100.x or 203.0.113.x (RFC 5737):\n"
                       + "\n".join(found))
