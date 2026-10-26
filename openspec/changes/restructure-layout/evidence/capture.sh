#!/usr/bin/env bash
# capture.sh OUTDIR
#
# Captures the D13 inventory of the working tree into OUTDIR:
#   tests.jsonl              one {"module","package","test","result"} per test and subtest,
#                            from `go test -json` over every workspace module except test/
#   testlist-test-module.txt "<package>\t<test>" from `go test -list` in the test module
#   coverage.tsv             "<package>\t<covered statements>\t<total statements>"
#   api/<pkg>.export         apidiff export data for every public package (internal/ excluded)
#   api-list/<pkg>.txt       the top-level exported names of each package, one per line
#
# <pkg> encodes the import path: github.com/kartaladev/scrty -> scrty, "/" -> "__".
# Needs APIDIFF (path to the apidiff binary) and EMPTY_EXPORT (export data of an empty package).
set -euo pipefail

out=${1:?usage: capture.sh OUTDIR}
: "${APIDIFF:?set APIDIFF to the apidiff binary}"
: "${EMPTY_EXPORT:?set EMPTY_EXPORT to the export data of an empty package}"
root=$(git rev-parse --show-toplevel)
mkdir -p "$out/api" "$out/api-list" "$out/raw"
out=$(cd "$out" && pwd)
: > "$out/raw/tests.json"
: > "$out/raw/cover.out"

enc() { sed 's#^github.com/kartaladev/scrty#scrty#; s#/#__#g' <<<"$1"; }

cd "$root"
for m in $(go list -m -f '{{.Dir}}'); do
	case "$m" in "$root/test") continue ;; esac
	prof=$(mktemp)
	# The exit status is ignored here: a failing test is recorded as "fail" and check.sh reports it.
	(cd "$m" && go test -json -count=1 -coverprofile="$prof" ./... >>"$out/raw/tests.json") || true
	if [ -s "$prof" ]; then grep -v '^mode:' "$prof" >>"$out/raw/cover.out" || true; fi
	rm -f "$prof"
	(cd "$m" && for p in $(go list ./... | grep -v '/internal/'); do
		f="$out/api/$(enc "$p").export"
		"$APIDIFF" -w "$f" "$p"
		"$APIDIFF" "$EMPTY_EXPORT" "$f" | sed -n 's/^- \(.*\): added$/\1/p' >"$out/api-list/$(enc "$p").txt"
	done)
done

(cd "$root/test" && go test -list '.*' ./... 2>&1) | awk '
	/^ok[ \t]/ || /^\?[ \t]/ { pkg = $2; for (i = 0; i < n; i++) print pkg "\t" names[i]; n = 0; next }
	/^(Test|Example|Benchmark|Fuzz)/ { names[n++] = $1 }
' >"$out/testlist-test-module.txt"

python3 - "$out" <<'EOF'
import collections, json, os, sys
out = sys.argv[1]
with open(os.path.join(out, "tests.jsonl"), "w") as w:
    for line in open(os.path.join(out, "raw/tests.json")):
        line = line.strip()
        if not line.startswith("{"):
            continue
        e = json.loads(line)
        if e.get("Test") and e.get("Action") in ("pass", "fail", "skip"):
            w.write(json.dumps({"package": e["Package"], "test": e["Test"], "result": e["Action"]}, sort_keys=True) + "\n")
blocks = {}
for line in open(os.path.join(out, "raw/cover.out")):
    line = line.strip()
    if not line:
        continue
    loc, stmts, count = line.rsplit(" ", 2)
    prev = blocks.get(loc)
    blocks[loc] = (int(stmts), max(int(count), prev[1] if prev else 0))
cov = collections.defaultdict(lambda: [0, 0])
for loc, (stmts, count) in blocks.items():
    pkg = os.path.dirname(loc.split(":")[0])
    cov[pkg][1] += stmts
    if count > 0:
        cov[pkg][0] += stmts
with open(os.path.join(out, "coverage.tsv"), "w") as w:
    for pkg in sorted(cov):
        w.write(f"{pkg}\t{cov[pkg][0]}\t{cov[pkg][1]}\n")
EOF
rm -rf "$out/raw"
echo "tests: $(wc -l <"$out/tests.jsonl")  test-module tests: $(wc -l <"$out/testlist-test-module.txt")  packages with coverage: $(wc -l <"$out/coverage.tsv")  api packages: $(ls "$out/api" | wc -l)"
