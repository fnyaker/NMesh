"""
Merge launcher-style options into the node's configuration file.

Used by ``install.sh`` so that ``./install.sh --fleet --console-host 0.0.0.0``
ends up in ``nmesh.conf`` rather than baked into a service unit nobody can edit
afterwards. The console then edits the same file, which is the point: one place
holds the node's options, and it is not the unit.

Options this does not recognise are printed on stdout, one per line, so the
caller can keep passing them on the command line instead of silently dropping
them. Everything else goes to stderr, so that stdout stays parseable.

    python scripts/nmesh_config.py nmesh.conf --fleet --console-host 0.0.0.0
"""
import importlib.util
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Loaded from its file rather than as ``src.config``: importing the package
# pulls in the mesh node and, with it, liboqs — which prints a banner on stdout.
# stdout here is a contract with install.sh (the options we could not handle),
# so nothing else may ever be written to it.
_spec = importlib.util.spec_from_file_location(
    "nmesh_config_module", os.path.join(ROOT, "src", "config.py"))
config = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(config)


def _flag_to_name(flag: str):
    """``--console-host`` → ``console_host``, or None if we don't know it."""
    if not flag.startswith("--"):
        return None
    name = flag[2:].replace("-", "_")
    return name if name in config.SETTINGS else None


def merge(path: str, argv: list) -> tuple[dict, list, list]:
    """``(values, unhandled, problems)``.

    Only the options actually given are changed; everything already in the file
    is preserved. An option whose value does not validate is left out and
    reported rather than written — the file must never be the reason a node
    refuses to start."""
    stored, problems = config.load(path)
    values = config.defaults()
    values.update(stored)

    unhandled: list = []
    index = 0
    while index < len(argv):
        token = argv[index]
        name = _flag_to_name(token)
        if name is None:
            unhandled.append(token)
            index += 1
            continue
        kind = config.SETTINGS[name][0]
        if kind is config._as_bool:
            values[name] = True
            index += 1
            continue
        if index + 1 >= len(argv):
            problems.append(f"{token} needs a value")
            index += 1
            continue
        raw = argv[index + 1]
        index += 2
        try:
            values[name] = config.validate(name, raw)
        except config.ConfigError as exc:
            # `data` and `launch` are not console-writable, but the installer is
            # entitled to set them: validate() guards the console, not this.
            if name in ("data", "launch"):
                unhandled.extend([token, raw])
            else:
                problems.append(f"{token} {raw}: {exc}")
    return values, unhandled, problems


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: nmesh_config.py <file> [launcher options…]", file=sys.stderr)
        return 2
    path = sys.argv[1]
    values, unhandled, problems = merge(path, sys.argv[2:])
    for problem in problems:
        print(f"config: {problem}", file=sys.stderr)
    try:
        config.save(path, values)
    except OSError as exc:
        print(f"config: could not write {path}: {exc.strerror or 'error'}",
              file=sys.stderr)
        # Not fatal: the caller keeps the options on the command line, and the
        # node starts. A missing config file is a worse day, not a broken one.
        for token in sys.argv[2:]:
            print(token)
        return 0
    for token in unhandled:
        print(token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
