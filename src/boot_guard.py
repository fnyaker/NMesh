"""
A tree on trial — and the way back to the one that worked.

An update writes a new tree and restarts onto it. Everything up to the restart
is checked: every byte against a signed hash, the paths, the shape of the tree,
and that it imports (`updater.preflight`). What none of that can prove is that
the new code *runs*: a module that raises once the node is listening, a
dependency the new version needs and this machine does not have, a start script
that fails on this distribution. On a machine nobody is watching that is the
worst outcome there is — the service manager starts the node, it dies, it is
started again, for ever, and the machine is off the mesh until somebody walks up
to it. An unattended update has to be able to undo itself.

So the tree that was just swapped in is **on trial**. The swap writes
:data:`TRIAL_FILE` beside it; every start counts itself against it (:func:`begin`,
called by ``start.sh`` and by the launcher before either imports anything of the
node); a node that has stayed up for :data:`HEALTHY_AFTER` seconds clears it
(:func:`confirm`). A tree that has been started :data:`MAX_TRIAL_BOOTS` times
without ever getting there is **put back**: the previous tree, which the swap
kept in :data:`BACKUP_DIR`, goes back in place, the failed one is kept in
:data:`FAILED_DIR` for whoever wants to know why, and a note says what happened
(:data:`ROLLBACK_FILE`) so the node can say so once it is up.

Why this file is shaped the way it is:

* **Standard library only, and loadable by path.** It runs exactly when the new
  code cannot be trusted to import. ``src/__init__.py`` pulls in the whole node
  and liboqs, so neither ``start.sh`` nor the launcher import it as part of the
  package; both load this file on its own.
* **Every step is resumable.** A rollback interrupted part-way (power cut, full
  disk) leaves the trial file in place, and the next start finishes the job: an
  entry already moved back is simply not in the backup any more.
* **It never stops a node from starting.** A guard that cannot read its own
  file, or cannot put a tree back, says so and lets the start go on — the
  alternative is a guard that bricks the machines it exists to protect.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time

# What a release replaces, and therefore what a rollback puts back. The
# updater's list, defined here because this file must import nothing of the
# project and the updater can import this one.
REPLACE_ENTRIES = ("src", "scripts", "start.sh", "install.sh",
                   "requirements.txt", "pyproject.toml", "Docs", "docker",
                   "README.md", "CLAUDE.md")
BACKUP_DIR = ".nmesh-previous"
FAILED_DIR = ".nmesh-failed"
TRIAL_FILE = ".nmesh-trial.json"
ROLLBACK_FILE = ".nmesh-rolledback.json"

# Starts a new tree gets before it is put back. More than one, because a
# machine rebooting or an operator restarting by hand during the trial is not
# the release failing; few enough that a crash loop ends within a minute of
# restarts (systemd waits 5 s between two).
MAX_TRIAL_BOOTS = 3
# How long a node has to stay up before its tree is trusted. Long enough to be
# past everything a start does once (listening, the first peers, the console),
# short enough that a reboot an hour later is not counted against a tree that
# has been working all along.
HEALTHY_AFTER = 120.0
MAX_FILE_BYTES = 16 * 1024

# What `begin` says, and what `main` turns into an exit status.
NOT_ON_TRIAL = ""
ON_TRIAL = "trial"
ROLLED_BACK = "rolled_back"
EXIT_ROLLED_BACK = 3


def _path(root: str, name: str) -> str:
    return os.path.join(root, name)


def _read(path: str) -> dict | None:
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except OSError:
        return None
    if len(raw) > MAX_FILE_BYTES:
        return None
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return doc if isinstance(doc, dict) else None


def _write(path: str, doc: dict) -> None:
    tmp = f"{path}.tmp.{os.getpid()}"
    descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(doc, handle)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, path)


def _remove(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _text(value, limit: int = 64) -> str:
    return str(value)[:limit] if isinstance(value, (str, int, float)) else ""


def start_trial(root: str, version: str, previous: str,
                added=()) -> None:
    """Put the tree just swapped in on trial. Called by the swap, once the new
    tree is in place and has imported, before anything restarts onto it.

    ``added`` names what the new tree brought that the old one never had: a
    rollback has nothing to put back in their place, and has to take them out
    rather than leave half of the failed release beside the restored one."""
    _write(_path(root, TRIAL_FILE), {
        "version": _text(version), "previous": _text(previous),
        "added": [entry for entry in added if entry in REPLACE_ENTRIES],
        "boots": 0, "at": int(time.time())})


def trial(root: str) -> dict | None:
    """The tree on trial, or None. A file that cannot be read is no trial: the
    guard fails towards starting the node, never towards stopping it."""
    doc = _read(_path(root, TRIAL_FILE))
    if doc is None:
        return None
    boots = doc.get("boots")
    if not isinstance(boots, int) or isinstance(boots, bool) or boots < 0:
        boots = 0
    added = doc.get("added")
    # Only names a release can carry: this list decides what a rollback moves
    # out of the install directory, and a doctored file must not be able to
    # point it at anything else.
    added = [entry for entry in added if entry in REPLACE_ENTRIES] \
        if isinstance(added, list) else []
    return {"version": _text(doc.get("version")),
            "previous": _text(doc.get("previous")),
            "added": added,
            "boots": min(boots, MAX_TRIAL_BOOTS + 1),
            "at": doc.get("at") if isinstance(doc.get("at"), int) else 0}


def begin(root: str) -> str:
    """Count one start against the tree on trial, if there is one.

    Returns :data:`NOT_ON_TRIAL`, :data:`ON_TRIAL`, or :data:`ROLLED_BACK` when
    this start found the tree out of chances and put the previous one back — in
    which case whoever called this must start again from the restored tree
    rather than go on with the code it has already loaded."""
    current = trial(root)
    if current is None:
        return NOT_ON_TRIAL
    boots = current["boots"] + 1
    if boots > MAX_TRIAL_BOOTS:
        reason = (f"started {MAX_TRIAL_BOOTS} times without staying up for "
                  f"{int(HEALTHY_AFTER)} seconds")
        return ROLLED_BACK if rollback(root, current, reason) else NOT_ON_TRIAL
    try:
        _write(_path(root, TRIAL_FILE), {**current, "boots": boots})
    except OSError:
        pass            # an uncounted start costs one more chance, never a node
    return ON_TRIAL


def confirm(root: str) -> bool:
    """The node has stayed up: its tree is the one this machine runs now.

    Returns whether a trial was ended. The previous tree stays in
    :data:`BACKUP_DIR` — going back by hand is still possible, and the next
    update replaces it anyway."""
    path = _path(root, TRIAL_FILE)
    if not os.path.exists(path):
        return False
    _remove(path)
    return True


def rollback(root: str, current: dict, reason: str) -> bool:
    """Put the previous tree back in place of the one on trial.

    Returns whether the node now has the previous tree. Resumable: an entry
    already moved back is no longer in the backup, so a rollback cut short is
    finished by the next start, which still finds the trial file."""
    backup = _path(root, BACKUP_DIR)
    kept = [entry for entry in REPLACE_ENTRIES
            if os.path.lexists(os.path.join(backup, entry))]
    if not kept:
        # Nothing to go back to — an install that never had a previous tree,
        # or a backup somebody removed. Stop counting: restarting this tree
        # for ever is the outcome the trial exists to end, and it cannot.
        _note(root, current, reason, restored=False,
              detail="no previous tree to go back to")
        _remove(_path(root, TRIAL_FILE))
        return False
    failed = _path(root, FAILED_DIR)
    try:
        if not os.path.isdir(failed):
            os.makedirs(failed, exist_ok=True)
        for entry in kept + [e for e in current.get("added", ()) if e not in kept]:
            target = os.path.join(root, entry)
            if os.path.lexists(target):
                aside = os.path.join(failed, entry)
                if os.path.lexists(aside):
                    _discard(aside)
                shutil.move(target, aside)
            if entry in kept:
                shutil.move(os.path.join(backup, entry), target)
    except OSError as exc:
        print(f"boot guard: could not put the previous tree back: {exc}",
              file=sys.stderr)
        return False
    _remove(_path(root, TRIAL_FILE))
    _note(root, current, reason, restored=True)
    return True


def _discard(path: str) -> None:
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path, ignore_errors=True)
    else:
        _remove(path)


def _note(root: str, current: dict, reason: str, *, restored: bool,
          detail: str = "") -> None:
    try:
        _write(_path(root, ROLLBACK_FILE), {
            "version": current.get("version", ""),
            "previous": current.get("previous", ""),
            "restored": restored, "reason": _text(reason, 200),
            "detail": _text(detail, 200), "at": int(time.time())})
    except OSError:
        pass


def take_note(root: str) -> dict | None:
    """What the last rollback said, once. Read by the node when it is up, so an
    update that quietly undid itself is said where an operator looks."""
    path = _path(root, ROLLBACK_FILE)
    doc = _read(path)
    _remove(path)
    if doc is None:
        return None
    return {"version": _text(doc.get("version")),
            "previous": _text(doc.get("previous")),
            "restored": doc.get("restored") is True,
            "reason": _text(doc.get("reason"), 200),
            "detail": _text(doc.get("detail"), 200),
            "at": doc.get("at") if isinstance(doc.get("at"), int) else 0}


def main(argv) -> int:
    """``boot_guard.py begin <root>`` — what ``start.sh`` runs before anything
    else touches the tree. Exit status 3 means "the previous tree is back, start
    again"; everything else is 0, because a guard must never be why a node did
    not start."""
    if len(argv) != 3 or argv[1] != "begin":
        print("usage: boot_guard.py begin <install root>", file=sys.stderr)
        return 0
    try:
        outcome = begin(os.path.abspath(argv[2]))
    except Exception as exc:                  # noqa: BLE001 — never block a start
        print(f"boot guard: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 0
    if outcome == ROLLED_BACK:
        print("boot guard: the new version did not stay up — the previous "
              "tree is back in place")
        return EXIT_ROLLED_BACK
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
