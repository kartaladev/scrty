# restructure-layout evidence

The D13 proof that nothing broke. `baseline/` is the inventory of the tree before phase 1;
`check.sh` captures a fresh inventory of the working tree and compares it with the baseline
through `rename-map.tsv`.

## Files

| File | What it is |
|---|---|
| `capture.sh OUTDIR` | Writes an inventory: `tests.jsonl`, `testlist-test-module.txt`, `coverage.tsv`, `api/`, `api-list/`, `decls.tsv` |
| `decls.py [ROOT]` | The declaration inventory: every top-level declaration (func, method, type, var, const, `//go:embed` pattern), exported or not, of every non-generated production file in the workspace modules |
| `check.sh [tests\|api\|decls\|coverage\|all]... [-- FRESH_DIR]` | Captures (or reuses) a fresh inventory and runs `check.py` |
| `check.py` | The comparison. It first checks the map itself: every left-hand side must be declared in the baseline |
| `rename-map.tsv` | `kind<TAB>old<TAB>new`. Kinds: `path` (D1), `pkgname`, `split` (D3: `policy` → `policy/lockout`), `ident` (D3, D8–D10), `test` (D7 case names, added per lane), `errprefix` (D11, informational), `merged` (D5 copies and their `storekit` successor), and for phase 6 `added` and `changed` (old is `-`), and `coverage` (old is a baseline package, new is the `covered/total` floor a decision accepts, with the reason in a comment above the row) |
| `examples.py [ROOT]` | The `Example` function inventory, read from source: `go test` lists only the examples that have an output comment, and the rest are compiled but never run |
| `empty.export` | `apidiff` export data of an empty package, used to list a package's exported names |

## apidiff (task 1.2)

Installed outside the module graph, into the session scratchpad:

```sh
GOBIN=<scratch>/bin GOWORK=off go install golang.org/x/exp/cmd/apidiff@latest
# golang.org/x/exp v0.0.0-20261014143641-f0251eb4aa3e, built with go1.27.3
```

The invocation, confirmed on 2026-10-28 against the unchanged `pkg/clock`, run from the module
root that contains the package (apidiff consults the module cache otherwise):

```sh
cd <module dir>
apidiff -w clock.export github.com/kartaladev/scrty/pkg/clock   # write export data
apidiff clock.export clock.export                               # empty report, exit 0
apidiff clock.export github.com/kartaladev/scrty/pkg/clock      # empty report, exit 0
```

`check.sh` needs `APIDIFF` set to that binary, or `apidiff` on `PATH`.

## Baseline (task 1.3)

Captured on 2026-10-28 from `03674a1` (the code of `origin/main` at `16d5e9a`; the commit between
them touches `openspec/` only), with `APIDIFF=<scratch>/bin/apidiff ./capture.sh baseline`.

| File | Count |
|---|---|
| `tests.jsonl` | 8,723 tests and subtests (1,339 top-level) over the core and the eight nested modules: 8,719 pass, 4 skip, 0 fail. The skips are the opt-in `ratelimit` measurements `TestMemoryLimiterMeasure_{Heap,HeapAfterSweep,SweepStall,SingleLockReference}` |
| `testlist-test-module.txt` | 426 top-level tests in the test module (`go test -list`; their results come from CI) |
| `coverage.tsv` | 44 packages with statements |
| `api/`, `api-list/` | 37 public packages (`internal/` excluded) |
| `examples.tsv` | 34 `Example` functions. Added after phase 1 started, so it was taken from the baseline commit `257a4ea` with `git archive` and `examples.py`, not by `capture.sh` |
| `decls.tsv` | 5,553 declarations in 52 packages: 1,705 func, 1,707 method, 795 type, 324 var, 1,019 const, 3 embed |

`make check` on the same tree: fmt, vet, lint, the race tests of the core and the eight nested
modules, vuln, generate-check and the isolated test pass. In the test module, four Docker
tests (`TestKeycloak`; `TestIdentityStore_Interrupted` in `pgxstore` and `sqlstore`;
`TestAttemptStore_IDs` in `sqlstore`) hit container start-up and teardown deadlines while every
package ran against one local Docker daemon. Each passes when rerun alone, and CI on `main`
(run 40273226980) is green with the Docker suites.

## Map and check (task 1.4)

`rename-map.tsv` holds 248 rows: 20 `path`, 4 `pkgname`, 1 `split`, 175 `ident`, 5 `errprefix`
and 41 `merged`. Every left-hand side is declared in the baseline (`check.py` checks this on
every run). Rows of kind `test` are added as the D7 conversions name their cases.

Both sides of every comparison are normalised to their final names, so the check reads the
same before, between and after the phases. On 2026-10-28:

- **Unchanged tree:** `check.sh all` against a fresh capture: 0 unaccounted in every check, exit 0.
- **Declarations control:** in a scratch copy of the tree, `expiry.skipReason` was deleted from
  `expiry/runner.go`. `check.py … decls` reported
  `missing: func github.com/kartaladev/scrty/expiry.skipReason`, exit 1. Restored by editing,
  the file was byte-identical to the repository's and the check exited 0.
- **Other controls,** on a copy of the fresh capture: a test removed, a test marked failed, a
  test-module test removed, `pkg/clock`'s export data emptied and one `expiry` statement
  uncovered. Each was reported (`missing`, `fails`, `missing from the test module`,
  `Clock/System/Timed removed`, `coverage drops`), exit 1.
