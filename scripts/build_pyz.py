"""
Build a self-launching zipapp: ``nmesh.pyz``.

    python scripts/build_pyz.py [-o nmesh.pyz]

Run it with:  python nmesh.pyz --data ./data [--console-host 0.0.0.0] ...

The archive bundles the NMesh source and the console launcher into one file.
It is *not* fully standalone: the two runtime dependencies (liboqs-python,
cryptography) provide compiled crypto and must be installed in the interpreter
that runs the .pyz. For a truly turnkey artifact, use the Docker image instead.
"""
import argparse
import os
import shutil
import tempfile
import zipapp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build(output: str) -> None:
    with tempfile.TemporaryDirectory() as work:
        shutil.copytree(os.path.join(ROOT, "src"), os.path.join(work, "src"))
        # nmesh_node becomes the archive's entry point.
        shutil.copy(os.path.join(ROOT, "scripts", "nmesh_node.py"),
                    os.path.join(work, "__main__.py"))
        zipapp.create_archive(
            work, target=output, interpreter="/usr/bin/env python3",
        )
    os.chmod(output, 0o755)
    print(f"built {output}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", default=os.path.join(ROOT, "nmesh.pyz"))
    build(ap.parse_args().output)
