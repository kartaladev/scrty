#!/usr/bin/env python3
"""Writes the D13 declaration inventory of the working tree to stdout.

usage: decls.py [ROOT]

One "<import path>\t<kind>\t<name>" line per top-level declaration in every non-generated
production .go file of every workspace module, sorted. Kind is func, method, type, var,
const or embed. A method's name is "Recv.Method"; an embed's name is its pattern. The blank
identifier is skipped. A name declared twice in a package (init) is listed twice.

The parser reads gofmt'ed source, which `make check` enforces: a top-level declaration starts
in column 0, and a member of a grouped var, const or type declaration starts after exactly one
tab. Skipped: *_test.go, files with a "Code generated ... DO NOT EDIT." header, testdata/
directories, dot-directories, and the tools module (outside go.work by design).
"""
import os
import re
import subprocess
import sys

GENERATED = re.compile(r"^// Code generated .* DO NOT EDIT\.$", re.M)
FUNC = re.compile(r"^func\s+([A-Za-z_]\w*)\s*[\[(]")
METHOD = re.compile(r"^func\s+\(\s*(?:\w+\s+)?\*?\s*([A-Za-z_]\w*)(?:\[[^\]]*\])?\s*\)\s*([A-Za-z_]\w*)\s*[\[(]")
SINGLE = re.compile(r"^(var|const|type)\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)")
GROUP_OPEN = re.compile(r"^(var|const|type)\s*\($")
MEMBER = re.compile(r"^\t([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)")
EMBED = re.compile(r"^//go:embed\s+(.+)$")


def modules(root):
    out = subprocess.run(["go", "list", "-m", "-f", "{{.Path}}\t{{.Dir}}"], cwd=root,
                         capture_output=True, text=True, check=True).stdout
    return [tuple(l.split("\t")) for l in out.splitlines() if l]


def decls(path):
    src = open(path, encoding="utf-8").read()
    if GENERATED.search(src.split("\npackage ", 1)[0] + "\n"):
        return
    group = None
    for line in src.splitlines():
        if group:
            if line == ")":
                group = None
                continue
            m = MEMBER.match(line)
            if m:
                for name in re.split(r"\s*,\s*", m.group(1)):
                    yield group, name
            continue
        m = EMBED.match(line)
        if m:
            for pat in m.group(1).split():
                yield "embed", pat
            continue
        m = GROUP_OPEN.match(line)
        if m:
            group = m.group(1)
            continue
        m = METHOD.match(line)
        if m:
            yield "method", m.group(1) + "." + m.group(2)
            continue
        m = FUNC.match(line)
        if m:
            yield "func", m.group(1)
            continue
        m = SINGLE.match(line)
        if m:
            for name in re.split(r"\s*,\s*", m.group(2)):
                yield m.group(1), name


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    mods = modules(root)
    # A directory belongs to the module with the longest matching root.
    mod_dirs = sorted(((d, p) for p, d in mods), key=lambda x: -len(x[0]))
    rows = []
    for mdir, mpath in mod_dirs:
        for dirpath, dirnames, filenames in os.walk(mdir):
            # Nested modules are walked on their own; skip them, testdata and dot-directories here.
            dirnames[:] = [d for d in dirnames
                           if not d.startswith(".") and d != "testdata"
                           and not os.path.exists(os.path.join(dirpath, d, "go.mod"))]
            rel = os.path.relpath(dirpath, mdir)
            pkg = mpath if rel == "." else mpath + "/" + rel
            for f in filenames:
                if not f.endswith(".go") or f.endswith("_test.go"):
                    continue
                for kind, name in decls(os.path.join(dirpath, f)):
                    if name != "_":
                        rows.append(f"{pkg}\t{kind}\t{name}")
    rows.sort()
    sys.stdout.write("".join(r + "\n" for r in rows))


if __name__ == "__main__":
    main()
