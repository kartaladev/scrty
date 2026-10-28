#!/usr/bin/env python3
"""Compares a fresh D13 inventory with the baseline through rename-map.tsv.

usage: check.py EVIDENCE_DIR FRESH_DIR [tests|api|decls|coverage|all]...

Every check prints the entries it cannot account for and the script exits 1 if any check
found one. Old names are normalised to their final form (path move first, then identifier
rename), and so are the fresh tree's names, so a check gives the same answer whichever phases
have run, including none.
"""
import collections
import json
import os
import re
import subprocess
import sys

ROOT = "github.com/kartaladev/scrty"
IDENT = re.compile(r"(?<![\w./])[A-Za-z_]\w*")
QUALIFIED = re.compile(r"((?:[\w.-]+/)*[\w.-]+)\.([A-Za-z_]\w*)")


def enc(path):
    return path.replace(ROOT, "scrty", 1).replace("/", "__")


def dec(name):
    return name.replace("__", "/").replace("scrty", ROOT, 1)


class Map:
    def __init__(self, path):
        self.paths, self.idents, self.tests, self.splits, self.merged = [], {}, [], [], {}
        for line in open(path):
            if not line.strip() or line.startswith("#"):
                continue
            kind, old, new = line.rstrip("\n").split("\t")
            if kind == "path":
                self.paths.append((old, new))
            elif kind == "ident":
                self.idents[old] = new
            elif kind == "test":
                self.tests.append((old, new))
            elif kind == "split":
                self.splits.append((old, new))
            elif kind == "merged":
                self.merged[old] = new
        self.paths.sort(key=lambda p: -len(p[0]))
        # Keys in the moved-but-not-renamed form too, so a half-applied rename normalises.
        self.final = {}
        for old, new in self.idents.items():
            self.final[old] = new
            opkg, oname = split_qualified(old)
            self.final[self.path(opkg) + "." + oname] = new
            npkg, _ = split_qualified(new)
            self.final[npkg + "." + oname] = new
        self.values = set(self.idents.values())
        # Merged copies keyed in their moved form too, so a copy normalises after phase 1.
        self.merged_final = {}
        for old, new in self.merged.items():
            opkg, oname = split_qualified(old)
            self.merged_final[self.path(opkg) + "." + oname] = new
            self.merged_final[new] = new

    def path(self, p):
        for old, new in self.paths:
            if p == old or p.startswith(old + "/"):
                return new + p[len(old):]
        return p

    def ident(self, q):
        """Final form of a qualified name pkg.Name or pkg.Type.Member."""
        pkg, name = split_qualified(q)
        pkg = self.path(pkg)
        head, _, rest = name.partition(".")
        full = self.final.get(pkg + "." + name)
        if full:
            return full
        owner = self.final.get(pkg + "." + head)
        if owner and rest:
            return owner + "." + rest
        return pkg + "." + name


def split_qualified(q):
    # The package path ends at the last "/" segment's first ".": scrty/token/onetime.Manager.X
    slash = q.rfind("/")
    dot = q.find(".", slash + 1)
    return q[:dot], q[dot + 1:]


def load_list(d, pkg):
    f = os.path.join(d, "api-list", enc(pkg) + ".txt")
    return set(open(f).read().split()) if os.path.exists(f) else set()


def normalise_type(m, s, pkg, names):
    # "...T" (variadic) would otherwise read as part of a package path.
    s = s.replace("...", "\u2026 ")
    s = IDENT.sub(lambda mo: pkg + "." + mo.group(0) if mo.group(0) in names else mo.group(0), s)
    return QUALIFIED.sub(lambda mo: m.ident(mo.group(1) + "." + mo.group(2))
                         if mo.group(1).startswith(ROOT) else mo.group(0), s)


def member_name(name):
    # "(*T).M" -> "T.M"
    return re.sub(r"^\(\*?(\w+)\)\.", r"\1.", name)


def check_api(m, ev, fresh, apidiff, empty):
    problems = []
    base_api = os.path.join(ev, "baseline", "api")
    fresh_api = os.path.join(fresh, "api")
    base_pkgs = {dec(f[:-7]) for f in os.listdir(base_api)}
    # A fresh package is keyed by its final path, so a tree in any phase compares the same way.
    fresh_pkgs = {m.path(p): p for p in (dec(f[:-7]) for f in os.listdir(fresh_api))}
    targets = {m.path(p): p for p in base_pkgs}
    pairs = [(p, m.path(p)) for p in sorted(base_pkgs)]
    pairs += [(None, p) for p in sorted(set(fresh_pkgs) - set(targets))]
    for old, final in pairs:
        if final not in fresh_pkgs:
            problems.append(f"package {old}: no package at {final}")
            continue
        new = fresh_pkgs[final]
        old_file = os.path.join(base_api, enc(old) + ".export") if old else empty
        new_file = os.path.join(fresh_api, enc(new) + ".export")
        report = subprocess.run([apidiff, old_file, new_file], capture_output=True, text=True, check=True).stdout
        old_names = load_list(os.path.join(ev, "baseline"), old) if old else set()
        new_names = load_list(fresh, new)
        for line in report.splitlines():
            if not line.startswith("- "):
                continue
            name, _, msg = line[2:].partition(": ")
            name = member_name(name)
            if msg == "removed":
                if m.ident(old + "." + name) == m.path(old) + "." + name and (old + "." + name) not in m.idents:
                    problems.append(f"{old}: {name} removed, and the map names no successor")
            elif msg == "added":
                if m.ident(new + "." + name) not in m.values:
                    problems.append(f"{new}: {name} added, and the map names no predecessor")
            elif msg.startswith("changed from "):
                a, sep, b = msg[len("changed from "):].partition(" to ")
                if not sep or normalise_type(m, a, old, old_names) != normalise_type(m, b, new, new_names):
                    problems.append(f"{new}: {name} {msg}")
            else:
                problems.append(f"{new}: {name}: {msg}")
    return problems


def map_test(m, pkg, name):
    best = None
    for old, new in m.tests:
        opkg, oname = split_test(old)
        if m.path(opkg) == m.path(pkg) and (name == oname or name.startswith(oname + "/")):
            if best is None or len(oname) > len(best[0]):
                best = (oname, new)
    if best:
        npkg, nname = split_test(best[1])
        return npkg, nname + name[len(best[0]):]
    return m.path(pkg), name


def split_test(q):
    pkg, _, name = q.partition("#")
    return pkg, name


def check_tests(m, ev, fresh):
    problems = []
    base = [json.loads(l) for l in open(os.path.join(ev, "baseline", "tests.jsonl"))]
    now = {map_test(m, e["package"], e["test"]): e["result"]
           for e in map(json.loads, open(os.path.join(fresh, "tests.jsonl")))}
    mapped = set()
    for e in base:
        key = map_test(m, e["package"], e["test"])
        mapped.add(key)
        got = now.get(key)
        if got is None:
            problems.append(f"missing: {e['package']} {e['test']} (expected {key[0]} {key[1]})")
        elif got == "fail":
            problems.append(f"fails: {key[0]} {key[1]}")
        elif e["result"] == "pass" and got != "pass":
            problems.append(f"{got} (was pass): {key[0]} {key[1]}")
    for key, got in sorted(now.items()):
        if got == "fail" and key not in mapped:
            problems.append(f"fails (new test): {key[0]} {key[1]}")
    added = sorted(k for k in now if k not in mapped)
    base_list = [l.rstrip("\n").split("\t") for l in open(os.path.join(ev, "baseline", "testlist-test-module.txt"))]
    now_list = {map_test(m, *l.rstrip("\n").split("\t")) for l in open(os.path.join(fresh, "testlist-test-module.txt"))}
    for pkg, name in base_list:
        key = map_test(m, pkg, name)
        if key not in now_list:
            problems.append(f"missing from the test module: {pkg} {name} (expected {key[0]} {key[1]})")
    return problems, added


def load_decls(path):
    rows = collections.Counter()
    for line in open(path):
        pkg, kind, name = line.rstrip("\n").split("\t")
        rows[(pkg, kind, name)] += 1
    return rows


def decl_target(m, pkg, name):
    """Final (package, name) of a declaration, from the baseline or a fresh tree alike."""
    npkg = m.path(pkg)
    merged = m.merged_final.get(npkg + "." + name)
    if merged:
        return split_qualified(merged)
    return split_qualified(m.ident(pkg + "." + name))


def check_decls(m, ev, fresh):
    """Every baseline declaration maps to one that exists; a merged copy maps to its successor.

    Both sides are normalised to their final form, so the check gives the same answer whichever
    phases have run. A name moved by a split may be found in either package of the split.
    """
    base = load_decls(os.path.join(ev, "baseline", "decls.tsv"))
    now = load_decls(os.path.join(fresh, "decls.tsv"))
    have = collections.Counter()
    for (pkg, kind, name), n in now.items():
        if kind == "embed":
            have[(m.path(pkg), "embed:" + name)] += n
        else:
            have[decl_target(m, pkg, name)] += n
    splits = collections.defaultdict(list)
    for old, new in m.splits:
        splits[m.path(old)].append(new)
    need = collections.Counter()
    problems = []
    for (pkg, kind, name), n in sorted(base.items()):
        if kind == "embed":
            key = (m.path(pkg), "embed:" + name)
            if have[key] < n:
                problems.append(f"missing: embed {name} of {pkg} (expected in {key[0]})")
            continue
        npkg, nname = decl_target(m, pkg, name)
        # Copies merged into one successor all map to it: one successor satisfies every copy.
        if (pkg + "." + name) in m.merged:
            if have[(npkg, nname)] == 0:
                problems.append(f"missing: merged {kind} {pkg}.{name} (expected {nname} in {npkg})")
            continue
        for _ in range(n):
            hit = next((c for c in [npkg] + splits.get(npkg, []) if have[(c, nname)] > need[(c, nname)]), None)
            if hit is None:
                where = " or ".join([npkg] + splits.get(npkg, []))
                problems.append(f"missing: {kind} {pkg}.{name} (expected {nname} in {where})")
                break
            need[(hit, nname)] += 1
    return problems


def validate_map(m, ev):
    """Every left-hand side of the map must name something the baseline declares."""
    base = load_decls(os.path.join(ev, "baseline", "decls.tsv"))
    names = {(pkg, name) for pkg, _, name in base}
    pkgs = {pkg for pkg, _, _ in base}
    problems = []
    for old in list(m.idents) + list(m.merged):
        pkg, name = split_qualified(old)
        head = name.split(".")[0]
        if (pkg, name) not in names and not ("." in name and (pkg, head) in names):
            problems.append(f"map key {old} is not declared in the baseline")
    for old, _ in m.paths + m.splits:
        if old not in pkgs and not any(p.startswith(old + "/") for p in pkgs):
            problems.append(f"map path {old} holds no baseline package")
    return problems


def check_coverage(m, ev, fresh):
    def load(d):
        return {p: (int(c), int(t)) for p, c, t in (l.split() for l in open(os.path.join(d, "coverage.tsv")))}
    base, now = load(os.path.join(ev, "baseline")), load(fresh)
    # Union the packages that share code: a package and its path successor, and every split.
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        parent[find(a)] = find(b)
    for p in base:
        union(("old", p), ("new", m.path(p)))
    for old, new in m.splits:
        union(("old", old), ("new", new))
    for old, new in m.merged.items():
        union(("old", split_qualified(old)[0]), ("new", split_qualified(new)[0]))
    groups = collections.defaultdict(lambda: [[0, 0], [0, 0], [], []])
    for p, (c, t) in base.items():
        g = groups[find(("old", p))]
        g[0][0] += c; g[0][1] += t; g[2].append(p)
    for p, (c, t) in now.items():
        g = groups[find(("new", m.path(p)))]
        g[1][0] += c; g[1][1] += t; g[3].append(p)
    problems = []
    for (bc, bt), (nc, nt), olds, news in groups.values():
        if not olds:
            continue
        if not news:
            problems.append(f"coverage: no package reports coverage for {', '.join(sorted(olds))}")
            continue
        if bt and nc * bt < bc * nt:
            problems.append(f"coverage drops: {', '.join(sorted(olds))} {bc}/{bt} ({100*bc/bt:.2f}%) -> "
                            f"{', '.join(sorted(news))} {nc}/{nt} ({100*nc/nt:.2f}%)")
    return problems


def main():
    ev, fresh, *which = sys.argv[1:]
    which = set(which or ["all"])
    if "all" in which:
        which = {"tests", "api", "decls", "coverage"}
    m = Map(os.path.join(ev, "rename-map.tsv"))
    failed = False
    problems = validate_map(m, ev)
    print(f"== map: {len(problems)} keys the baseline does not declare")
    for p in problems:
        print("  " + p)
    failed |= bool(problems)
    if "tests" in which:
        problems, added = check_tests(m, ev, fresh)
        print(f"== tests: {len(problems)} unaccounted, {len(added)} not in the baseline")
        for p in problems:
            print("  " + p)
        for pkg, name in added:
            print(f"  (new) {pkg} {name}")
        failed |= bool(problems)
    if "api" in which:
        problems = check_api(m, ev, fresh, os.environ["APIDIFF"], os.environ["EMPTY_EXPORT"])
        print(f"== api: {len(problems)} unaccounted")
        for p in problems:
            print("  " + p)
        failed |= bool(problems)
    if "decls" in which:
        problems = check_decls(m, ev, fresh)
        print(f"== decls: {len(problems)} unaccounted")
        for p in problems:
            print("  " + p)
        failed |= bool(problems)
    if "coverage" in which:
        problems = check_coverage(m, ev, fresh)
        print(f"== coverage: {len(problems)} unaccounted")
        for p in problems:
            print("  " + p)
        failed |= bool(problems)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
