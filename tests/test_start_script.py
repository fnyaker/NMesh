"""Le lanceur ./start.sh doit s'installer seul sur n'importe quelle distro.

Les pièges couverts ici sont ceux qui cassent une machine *neuve* : pas de pip
(Debian/Ubuntu/Alpine/Arch découpent venv et pip hors de l'interpréteur), pip
interdit sur le système (PEP 668), pas de sudo (conteneurs root), noms de
paquets différents partout. On source start.sh en mode bibliothèque
(NMESH_START_LIB=1) : rien n'est installé, rien n'est lancé.
"""

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

START = Path(__file__).resolve().parent.parent / "start.sh"
# Chemin absolu : les tests isolent le PATH, bash ne serait plus trouvable.
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash requis pour tester le lanceur")


def run_snippet(tmp_path, snippet, *, os_release=None, fake_bins=(),
                isolate=False, env=None):
    """Source start.sh en mode bibliothèque puis exécute `snippet`.

    `isolate` coupe le PATH système : seuls les stubs (plus le minimum vital
    emprunté à /usr/bin) sont visibles. C'est ainsi qu'on simule une machine où
    sudo — ou le compilateur — n'existe pas.
    """
    stub_dir = tmp_path / "stubbin"
    stub_dir.mkdir(exist_ok=True)
    base_path = "/usr/bin:/bin:/usr/sbin:/sbin"
    if isolate:
        # Le strict nécessaire pour que start.sh se source et que les helpers
        # tournent ; tout le reste doit venir des stubs.
        for tool in ("dirname", "uname", "mktemp", "rm", "cat", "awk", "head", "cut", "mkdir", "env"):
            real = shutil.which(tool)
            if real and not (stub_dir / tool).exists():
                (stub_dir / tool).symlink_to(real)
        base_path = ""
    for name, body in fake_bins:
        path = stub_dir / name
        if path.is_symlink():
            path.unlink()
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o755)
    environ = {
        "NMESH_START_LIB": "1",
        "PATH": f"{stub_dir}:{base_path}".rstrip(":"),
        "HOME": str(tmp_path),
    }
    if os_release is not None:
        release = tmp_path / "os-release"
        release.write_text(os_release)
        environ["OS_RELEASE_FILE"] = str(release)
    environ.update(env or {})
    script = f'. "{START}"\n' + textwrap.dedent(snippet)
    proc = subprocess.run(
        [BASH, "-c", script],
        capture_output=True,
        text=True,
        env=environ,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def test_script_is_syntactically_valid():
    subprocess.run([BASH, "-n", str(START)], check=True)


# ── détection de la distro ───────────────────────────────────────────────────

DISTROS = [
    ('ID=ubuntu\nID_LIKE=debian\n', "apt-get", "apt"),
    ('ID=debian\n', "apt-get", "apt"),
    ('ID=linuxmint\nID_LIKE="ubuntu debian"\n', "apt-get", "apt"),
    ('ID=fedora\n', "dnf", "dnf"),
    ('ID=rocky\nID_LIKE="rhel centos fedora"\n', "dnf", "dnf"),
    ('ID=centos\nID_LIKE="rhel fedora"\n', "yum", "yum"),
    ('ID=arch\n', "pacman", "pacman"),
    ('ID=manjaro\nID_LIKE=arch\n', "pacman", "pacman"),
    ('ID=opensuse-tumbleweed\nID_LIKE="opensuse suse"\n', "zypper", "zypper"),
    ('ID=alpine\n', "apk", "apk"),
    ('ID=void\n', "xbps-install", "xbps"),
]


@pytest.mark.parametrize("os_release,binary,expected", DISTROS)
def test_package_manager_detection(tmp_path, os_release, binary, expected):
    """os-release fait foi — un apt-get qui traîne ne doit pas décider à sa place."""
    out = run_snippet(
        tmp_path,
        "detect_os; echo $PKG",
        os_release=os_release,
        fake_bins=[(binary, "exit 0")],
        isolate=True,
    )
    assert out == expected


@pytest.mark.parametrize("os_release,expected", [
    ('ID=debian\nID_LIKE=debian\n', "apt"),
    ('ID=fedora\n', "dnf"),
    ('ID=arch\n', "pacman"),
    ('ID=opensuse-leap\nID_LIKE=suse\n', "zypper"),
])
def test_detection_falls_back_to_id_like(tmp_path, os_release, expected):
    """Aucun gestionnaire dans le PATH : ID/ID_LIKE reste exploitable."""
    out = run_snippet(tmp_path, "detect_os; echo $PKG", os_release=os_release,
                      isolate=True)
    assert out == expected


def test_declarative_distros_are_never_touched(tmp_path):
    """NixOS et Gentoo se configurent en déclaratif : on n'installe rien."""
    for ident, expected in (("nixos", "nix"), ("gentoo", "gentoo")):
        out = run_snippet(
            tmp_path,
            "detect_os; echo $PKG",
            os_release=f"ID={ident}\n",
            # Même avec un pacman qui traîne, on ne bascule pas dessus.
            fake_bins=[("pacman", "exit 0")],
            isolate=True,
        )
        assert out == expected


def test_unknown_distro_is_reported_not_guessed(tmp_path):
    """Distro inconnue et aucun gestionnaire connu : on le dit au lieu de deviner."""
    out = run_snippet(tmp_path, "detect_os; echo $PKG", os_release="ID=exotic\n",
                      isolate=True)
    assert out == "unknown"


def test_unknown_distro_still_uses_an_installed_tool(tmp_path):
    """Dérivée exotique mais avec apk : on s'en sert."""
    out = run_snippet(tmp_path, "detect_os; echo $PKG", os_release="ID=exotic\n",
                      fake_bins=[("apk", "exit 0")], isolate=True)
    assert out == "apk"


def test_centos7_without_dnf_falls_back_to_yum(tmp_path):
    out = run_snippet(tmp_path, "detect_os; echo $PKG",
                      os_release='ID=centos\nVERSION_ID="7"\n',
                      fake_bins=[("yum", "exit 0")], isolate=True)
    assert out == "yum"


# ── noms de paquets ──────────────────────────────────────────────────────────

def test_every_family_names_a_pip_or_venv_package(tmp_path):
    """Le cas du rapport : machine neuve sans pip. Chaque famille sait le poser.

    (Homebrew livre pip avec python : rien à installer là-bas.)
    """
    families = ["apt", "dnf", "yum", "pacman", "zypper", "apk", "xbps", "termux"]
    for family in families:
        out = run_snippet(tmp_path, f'PKG={family}; pkg_names pipvenv')
        assert out, f"{family} n'installe pas pip/venv"


@pytest.mark.parametrize("family,needle", [
    ("apt", "python3-venv"),      # Ubuntu/Debian : venv absent de python3
    ("apk", "py3-pip"),           # Alpine : pip dans un paquet séparé
    ("pacman", "python-pip"),     # Arch : ensurepip a besoin de python-pip
    ("dnf", "python3-pip"),
    ("zypper", "python3-pip"),
])
def test_pip_package_names_per_family(tmp_path, family, needle):
    out = run_snippet(tmp_path, f'PKG={family}; pkg_names pipvenv')
    assert needle in out.split()


@pytest.mark.parametrize("family", ["apt", "dnf", "yum", "pacman", "zypper", "apk", "xbps"])
def test_every_family_can_build_liboqs(tmp_path, family):
    """cmake + compilateur + git : sans eux, pas de crypto post-quantique."""
    out = run_snippet(tmp_path, f'PKG={family}; pkg_names build').split()
    assert "cmake" in out
    assert "git" in out
    assert any(cc in out for cc in ("gcc", "clang"))


@pytest.mark.parametrize("family", ["apt", "dnf", "pacman", "zypper", "apk"])
def test_native_extras_cover_a_source_build_of_cryptography(tmp_path, family):
    """Pas de wheel (musl, ARM32, RISC-V) → cryptography se compile : Rust + headers."""
    out = run_snippet(tmp_path, f'PKG={family}; pkg_names native').split()
    assert any("ssl" in pkg for pkg in out)
    assert any(pkg in ("rust", "rustc", "cargo") for pkg in out)


# ── sudo ─────────────────────────────────────────────────────────────────────

def test_root_needs_no_sudo(tmp_path):
    out = run_snippet(
        tmp_path,
        'detect_sudo; echo "[$SUDO]"',
        os_release="ID=debian\n",
        fake_bins=[("id", "echo 0")],
        isolate=True,
    )
    assert out == "[]"


def test_missing_sudo_is_refused_not_ignored(tmp_path):
    """Conteneur non-root sans sudo : on le dit, on ne tente pas d'installer."""
    out = run_snippet(
        tmp_path,
        'detect_os; detect_sudo; pkg_install cmake && echo INSTALLED || echo REFUSED',
        os_release="ID=debian\n",
        fake_bins=[("id", "echo 1000"), ("apt-get", "echo APT-RAN")],
        isolate=True,
    )
    assert "REFUSED" in out
    assert "APT-RAN" not in out


def test_non_root_with_sudo_uses_it(tmp_path):
    out = run_snippet(
        tmp_path,
        'detect_os; detect_sudo; echo "[$SUDO]"',
        os_release="ID=debian\n",
        fake_bins=[("id", "echo 1000"), ("sudo", "exit 0"), ("apt-get", "exit 0")],
        isolate=True,
    )
    assert out == "[sudo]"


# ── installation ─────────────────────────────────────────────────────────────

def test_arch_never_does_a_partial_upgrade(tmp_path):
    """`pacman -Sy` puis install = mise à jour partielle, non supportée par Arch."""
    log = tmp_path / "pacman.log"
    out = run_snippet(
        tmp_path,
        'detect_os; detect_sudo; pkg_install cmake; cat "%s"' % log,
        os_release="ID=arch\n",
        fake_bins=[("id", "echo 0"), ("pacman", f'echo "$@" >> {log}')],
        isolate=True,
    )
    lines = [line for line in out.splitlines() if line]
    assert any(line.startswith("-Syu") for line in lines), lines
    assert not any(line.startswith("-Sy ") for line in lines), lines


def test_install_role_retries_package_by_package(tmp_path):
    """Un nom inconnu d'une release (ninja vs ninja-build) ne doit pas tout couler."""
    log = tmp_path / "apt.log"
    stub = f'''
for a in "$@"; do
  case "$a" in ninja-build) exit 100;; esac
done
echo "$@" >> {log}
'''
    out = run_snippet(
        tmp_path,
        'detect_os; detect_sudo; pkg_install_role optional; cat "%s"' % log,
        os_release="ID=debian\n",
        fake_bins=[("id", "echo 0"), ("apt-get", stub)],
        isolate=True,
    )
    # Le lot complet échoue à cause de ninja-build, mais les autres passent.
    assert "python3-dev" in out
    assert "pkg-config" in out


def test_apt_install_is_non_interactive(tmp_path):
    """Sans DEBIAN_FRONTEND=noninteractive, apt peut bloquer sur un prompt."""
    log = tmp_path / "env.log"
    out = run_snippet(
        tmp_path,
        'detect_os; detect_sudo; pkg_install cmake; cat "%s"' % log,
        os_release="ID=debian\n",
        fake_bins=[
            ("id", "echo 0"),
            ("apt-get", f'echo "DEBIAN_FRONTEND=$DEBIAN_FRONTEND" >> {log}'),
        ],
        isolate=True,
    )
    assert "DEBIAN_FRONTEND=noninteractive" in out


# ── venv / pip ───────────────────────────────────────────────────────────────

def test_venv_capability_probe_requires_pip(tmp_path):
    """Le cas Ubuntu neuf : `python3 -m venv` produit un venv sans pip."""
    out = run_snippet(
        tmp_path,
        'PYTHON=fakepy; venv_capable && echo CAPABLE || echo MISSING',
        fake_bins=[("fakepy", 'case "$2" in venv) mkdir -p "$3/bin"; exit 0;; esac; exit 1')],
    )
    assert out == "MISSING"


def test_venv_capability_probe_accepts_a_working_python(tmp_path):
    import sys

    out = run_snippet(
        tmp_path,
        f'PYTHON={sys.executable}; venv_capable && echo CAPABLE || echo MISSING',
    )
    assert out == "CAPABLE"


def test_broken_virtualenv_is_detected(tmp_path):
    """Un venv dont l'interpréteur a disparu (upgrade de distro) est recréé."""
    venv = tmp_path / "deadvenv"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").write_text("#!/bin/sh\nexit 1\n")
    (venv / "bin" / "python").chmod(0o755)
    out = run_snippet(
        tmp_path,
        f'VENV="{venv}"; venv_broken && echo BROKEN || echo FINE',
    )
    assert out == "BROKEN"


def test_missing_virtualenv_directory_counts_as_broken(tmp_path):
    out = run_snippet(
        tmp_path,
        f'VENV="{tmp_path}/nope"; venv_broken && echo BROKEN || echo FINE',
    )
    assert out == "BROKEN"


# ── cmake ────────────────────────────────────────────────────────────────────

def test_ancient_cmake_is_rejected(tmp_path):
    """CentOS 7 & co livrent cmake 2.8 : liboqs ne se configure pas avec."""
    out = run_snippet(
        tmp_path,
        'have_build_tools && echo OK || echo TOO_OLD',
        fake_bins=[
            ("cmake", 'echo "cmake version 2.8.12"'),
            ("make", "exit 0"), ("git", "exit 0"), ("cc", "exit 0"),
        ],
        isolate=True,
    )
    assert out == "TOO_OLD"


def test_recent_cmake_is_accepted(tmp_path):
    out = run_snippet(
        tmp_path,
        'have_build_tools && echo OK || echo TOO_OLD',
        fake_bins=[
            ("cmake", 'echo "cmake version 3.28.3"'),
            ("make", "exit 0"), ("git", "exit 0"), ("cc", "exit 0"),
        ],
        isolate=True,
    )
    assert out == "OK"


def test_missing_compiler_is_detected(tmp_path):
    out = run_snippet(
        tmp_path,
        'have_build_tools && echo OK || echo MISSING',
        fake_bins=[
            ("cmake", 'echo "cmake version 3.28.3"'),
            ("make", "exit 0"), ("git", "exit 0"),
            # Aucun cc/gcc/clang : PATH isolé, uniquement les stubs ci-dessus.
        ],
        isolate=True,
    )
    assert out == "MISSING"


# ── un service n'hérite pas d'un environnement de session ────────────────────
# systemd ne transmet ni HOME ni USER par défaut. Sous `set -u`, un `$HOME` nu
# tuait le script au démarrage — « HOME : variable sans liaison » — et le nœud
# repartait en boucle de redémarrage sans jamais se lancer.

def test_home_unset_does_not_kill_the_script(tmp_path):
    """Le cas exact du bug : aucun HOME dans l'environnement."""
    out = run_snippet(tmp_path, "node_home", env={"HOME": ""})
    assert out, "node_home doit toujours répondre quelque chose"
    assert Path(out).is_dir()


def test_home_is_used_when_it_is_usable(tmp_path):
    home = tmp_path / "real-home"
    home.mkdir()
    out = run_snippet(tmp_path, "node_home", env={"HOME": str(home)})
    assert out == str(home)


def test_a_home_that_does_not_exist_is_not_trusted(tmp_path):
    """Un compte système pointe souvent sur /nonexistent : écrire là échouerait
    plus tard, au pire moment."""
    out = run_snippet(tmp_path, "node_home",
                      env={"HOME": str(tmp_path / "nonexistent")})
    assert out != str(tmp_path / "nonexistent")
    assert Path(out).is_dir()


def test_an_unwritable_home_is_not_trusted(tmp_path):
    home = tmp_path / "readonly-home"
    home.mkdir(mode=0o500)
    try:
        out = run_snippet(tmp_path, "node_home", env={"HOME": str(home)})
    finally:
        home.chmod(0o700)
    assert Path(out).is_dir()


def test_the_whole_script_survives_an_empty_environment(tmp_path):
    """Plus large que node_home : sourcer start.sh avec un environnement nu ne
    doit lever aucune variable sans liaison."""
    proc = subprocess.run(
        [BASH, "-c", f'. "{START}"; echo SOURCED'],
        capture_output=True, text=True, timeout=60,
        env={"NMESH_START_LIB": "1", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"})
    assert proc.returncode == 0, proc.stderr
    assert "SOURCED" in proc.stdout
    assert "unbound" not in proc.stderr and "sans liaison" not in proc.stderr


# ── ne pas recompiler liboqs pour rien ───────────────────────────────────────
# Compiler liboqs prend des minutes et produit la même bibliothèque à chaque
# fois. Changer de préfixe (install utilisateur qui passe en /opt, second nœud,
# --prefix différent) ne doit pas repayer ce prix.

def test_candidates_split_the_list_and_skip_the_destination(tmp_path):
    out = run_snippet(tmp_path, """
        OQS_PREFIX=/dest/_oqs
        OQS_REUSE_FROM="/a/_oqs:/b/_oqs::/dest/_oqs"
        liboqs_candidates 1.2.3
    """, env={"NMESH_LIBOQS_CACHE": str(tmp_path / "cache")})
    lines = out.splitlines()
    assert "/a/_oqs" in lines and "/b/_oqs" in lines
    assert "/dest/_oqs" not in lines          # inutile : c'est là qu'on écrit
    assert "" not in lines


def test_a_missing_candidate_is_not_usable(tmp_path):
    out = run_snippet(tmp_path, f"""
        liboqs_usable_at "{tmp_path}/nowhere" && echo USABLE || echo NOT_USABLE
    """)
    assert out == "NOT_USABLE"


def test_adoption_copies_the_library_instead_of_building(tmp_path):
    source = tmp_path / "old" / "_oqs"
    (source / "lib").mkdir(parents=True)
    (source / "lib" / "liboqs.so").write_text("ELF")
    (source / "include").mkdir()
    (source / "include" / "oqs.h").write_text("header")
    dest = tmp_path / "new" / "_oqs"
    out = run_snippet(tmp_path, f"""
        OQS_PREFIX="{dest}"
        OQS_REUSE_FROM="{source}"
        # Le contrôle est fonctionnel : la bibliothèque doit être *là* et se
        # charger. On simule les deux états successifs.
        pq_ready() {{ [ -f "${{OQS_INSTALL_PATH:-}}/lib/liboqs.so" ]; }}
        adopt_liboqs 1.2.3 && echo "ADOPTED:$ADOPTED_FROM" || echo NOT_ADOPTED
    """, env={"NMESH_LIBOQS_CACHE": str(tmp_path / "cache")})
    assert out == f"ADOPTED:{source}"
    assert (dest / "lib" / "liboqs.so").read_text() == "ELF"
    assert (dest / "include" / "oqs.h").exists()


def test_an_unloadable_candidate_is_never_adopted(tmp_path):
    """Un répertoire qui *ressemble* à une install liboqs ne suffit pas : si le
    wrapper ne le charge pas, on recompile."""
    source = tmp_path / "old" / "_oqs"
    (source / "lib").mkdir(parents=True)
    (source / "lib" / "liboqs.so").write_text("not really a library")
    dest = tmp_path / "new" / "_oqs"
    out = run_snippet(tmp_path, f"""
        OQS_PREFIX="{dest}"
        OQS_REUSE_FROM="{source}"
        pq_ready() {{ return 1; }}
        adopt_liboqs 1.2.3 && echo ADOPTED || echo NOT_ADOPTED
    """, env={"NMESH_LIBOQS_CACHE": str(tmp_path / "cache")})
    assert out == "NOT_ADOPTED"


def test_nothing_to_adopt_is_not_an_error(tmp_path):
    out = run_snippet(tmp_path, f"""
        OQS_PREFIX="{tmp_path}/dest/_oqs"
        OQS_REUSE_FROM=""
        pq_ready() {{ return 1; }}
        adopt_liboqs 1.2.3 && echo ADOPTED || echo NOT_ADOPTED
    """, env={"NMESH_LIBOQS_CACHE": str(tmp_path / "cache")})
    assert out == "NOT_ADOPTED"


def test_the_cache_is_keyed_by_the_wrapper_version(tmp_path):
    """Une montée de version du wrapper doit recompiler : wrapper et
    bibliothèque restent appariés autour de la crypto."""
    cache = tmp_path / "cache"
    first = run_snippet(tmp_path, "liboqs_cache_dir 0.16.0",
                        env={"NMESH_LIBOQS_CACHE": str(cache)})
    second = run_snippet(tmp_path, "liboqs_cache_dir 0.17.0",
                         env={"NMESH_LIBOQS_CACHE": str(cache)})
    assert first != second
    assert first.endswith("liboqs-0.16.0")


def test_a_build_fills_the_cache(tmp_path):
    built = tmp_path / "prefix"
    (built / "lib").mkdir(parents=True)
    (built / "lib" / "liboqs.so").write_text("ELF")
    cache = tmp_path / "cache"
    run_snippet(tmp_path, f"""
        OQS_PREFIX="{built}"
        cache_liboqs 0.16.0
    """, env={"NMESH_LIBOQS_CACHE": str(cache)})
    assert (cache / "liboqs-0.16.0" / "lib" / "liboqs.so").read_text() == "ELF"


def test_an_unwritable_cache_does_not_break_the_install(tmp_path):
    """Un /var/cache plein ou en lecture seule coûte un rebuild la prochaine
    fois — jamais l'échec de l'installation en cours."""
    built = tmp_path / "prefix"
    (built / "lib").mkdir(parents=True)
    (built / "lib" / "liboqs.so").write_text("ELF")
    blocked = tmp_path / "blocked"
    blocked.mkdir(mode=0o500)
    try:
        out = run_snippet(tmp_path, f"""
            OQS_PREFIX="{built}"
            cache_liboqs 0.16.0 && echo SURVIVED
        """, env={"NMESH_LIBOQS_CACHE": str(blocked / "cache")})
    finally:
        blocked.chmod(0o700)
    assert out == "SURVIVED"
