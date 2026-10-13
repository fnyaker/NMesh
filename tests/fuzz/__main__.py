"""
Run the coverage-guided fuzzer for longer than the suite does.

    python -m tests.fuzz                      # every target, 60 s each
    python -m tests.fuzz packet chain -s 600  # two targets, ten minutes each
    python -m tests.fuzz --list

The corpus each target grew is kept under ``--corpus`` and fed back next time;
a finding is written under ``--findings`` as the input that triggers it and
its traceback. Exit status 1 when anything was found.
"""
from __future__ import annotations

import argparse
import os
import sys

from .engine import Fuzzer
from .targets import BY_NAME, TARGETS


def _load(directory: str) -> list[bytes]:
    if not os.path.isdir(directory):
        return []
    out = []
    for name in sorted(os.listdir(directory)):
        with open(os.path.join(directory, name), "rb") as handle:
            out.append(handle.read())
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tests.fuzz")
    parser.add_argument("targets", nargs="*")
    parser.add_argument("-s", "--seconds", type=float, default=60.0)
    parser.add_argument("--corpus", default=".fuzz/corpus")
    parser.add_argument("--findings", default=".fuzz/findings")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(argv)
    if args.list:
        for target in TARGETS:
            print(target.name)
        return 0
    unknown = [name for name in args.targets if name not in BY_NAME]
    if unknown:
        parser.error(f"no such target: {', '.join(unknown)}")
    chosen = [BY_NAME[name] for name in args.targets] or TARGETS
    found = 0
    for target in chosen:
        corpus_dir = os.path.join(args.corpus, target.name)
        fuzzer = Fuzzer(target, seed=args.seed)
        report = fuzzer.run(seconds=args.seconds, corpus=_load(corpus_dir))
        os.makedirs(corpus_dir, exist_ok=True)
        for index, data in enumerate(fuzzer.corpus):
            with open(os.path.join(corpus_dir, f"{index:05d}"), "wb") as handle:
                handle.write(data)
        print(f"{target.name:16} runs {report.runs:8}  corpus {report.corpus:5}  "
              f"coverage {report.coverage:6}  findings {len(report.findings)}")
        for finding in report.findings:
            found += 1
            os.makedirs(args.findings, exist_ok=True)
            stem = os.path.join(args.findings, f"{target.name}-{finding.key}")
            with open(stem + ".bin", "wb") as handle:
                handle.write(finding.data)
            with open(stem + ".txt", "w") as handle:
                handle.write(finding.summary + "\n\n" + finding.detail)
            print(f"  {finding.kind}: {finding.summary}  -> {stem}.bin")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
