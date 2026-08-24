"""
Set or reset the web console password for a node's state directory.

Used by ``install.sh --reset-password``, and usable on its own when a console
password has been lost — the only other way in is the state directory itself,
which is exactly the level of access this requires.

    python scripts/nmesh_password.py /var/lib/nmesh              # generate one
    python scripts/nmesh_password.py /var/lib/nmesh --stdin      # read one

The password is printed on **stdout** and nothing else is, so a caller can
capture it. With ``--stdin`` the new password is read from standard input and
never appears in the process arguments, where every user on the machine can see
it in ``ps``.

The node reads its credential at startup, so a change takes effect when it
restarts.
"""
import importlib.util
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Loaded from its file rather than as ``src.console_auth``: importing the
# package pulls in the mesh node and, with it, liboqs, which prints a banner on
# stdout — and stdout here carries the password.
_spec = importlib.util.spec_from_file_location(
    "nmesh_console_auth", os.path.join(ROOT, "src", "console_auth.py"))
console_auth = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(console_auth)


def main(argv) -> int:
    args = list(argv)
    from_stdin = "--stdin" in args
    if from_stdin:
        args.remove("--stdin")
    if len(args) != 1:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: nmesh_password.py <state-dir> [--stdin]", file=sys.stderr)
        return 2
    state_dir = args[0]
    if not os.path.isdir(state_dir):
        print(f"no such state directory: {state_dir}", file=sys.stderr)
        return 1

    if from_stdin:
        password = sys.stdin.readline().rstrip("\n")
        try:
            console_auth.validate(password)
        except console_auth.CredentialError as exc:
            print(f"password refused: {exc}", file=sys.stderr)
            return 1
    else:
        password = console_auth.generate()

    path = console_auth.path_for(state_dir)
    try:
        console_auth.write(path, password)
    except OSError as exc:
        print(f"could not write {path}: {exc.strerror or 'error'}",
              file=sys.stderr)
        return 1
    print(password)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
