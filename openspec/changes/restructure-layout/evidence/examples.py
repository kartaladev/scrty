#!/usr/bin/env python3
"""Writes the inventory of Example functions to stdout: "<import path>\t<name>" per line, sorted.

usage: examples.py [ROOT]

go test reports only the examples that have an output comment; the rest are compiled and never
listed. This reads every *_test.go of every workspace module (skipping testdata/ and
dot-directories) for top-level "func Example…" declarations. The package of an external
_test file is the package of its directory.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from decls import modules  # noqa: E402

EXAMPLE = re.compile(r"^func (Example\w*)\(\)", re.M)


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    mod_dirs = sorted(((d, p) for p, d in modules(root)), key=lambda x: -len(x[0]))
    rows = []
    for mdir, mpath in mod_dirs:
        for dirpath, dirnames, filenames in os.walk(mdir):
            dirnames[:] = [d for d in dirnames
                           if not d.startswith(".") and d != "testdata"
                           and not os.path.exists(os.path.join(dirpath, d, "go.mod"))]
            rel = os.path.relpath(dirpath, mdir)
            pkg = mpath if rel == "." else mpath + "/" + rel
            for f in filenames:
                if f.endswith("_test.go"):
                    for name in EXAMPLE.findall(open(os.path.join(dirpath, f), encoding="utf-8").read()):
                        rows.append(f"{pkg}\t{name}")
    rows.sort()
    sys.stdout.write("".join(r + "\n" for r in rows))


if __name__ == "__main__":
    main()
