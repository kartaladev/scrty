# Rule: Run the affected tests while a change is in progress, and the full suite once at the end

The full suite is slow (`httpsec` alone takes minutes, and the durable suites start containers).
Running all of it after every step costs development time without catching anything a scoped run
misses. So:

## While a change is in progress

After each step, dispatch or fix, run only:

1. **The packages the step changed**, and
2. **every package that transitively depends on them**, in this module and in the other workspace
   modules that import them (`test/`, `store/pgxstore`, `store/gormstore`, `httpsec/*sec`, …).

Find the dependents with the toolchain rather than by guessing:

```sh
# in-module dependents of a changed package
go list -f '{{.ImportPath}} {{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}' ./... \
  | awk '/github.com\/kartaladev\/scrty\/<changed>( |$)/{print $1}'
```

Then repeat it in each workspace module that may import the package. Add `go vet` and `gofmt -l` for
the packages touched. The red step of test-first still uses a focused `go test -run '<Name>'`
before anything wider (`golang-tdd.md`).

A change's `plans.md` states the scoped commands for each lane, so dispatches don't have to work
them out again.

## At the end of a change

Run the **full suite** once, as the change's final gate, before the whole-branch review and before
archive: `make check` (and `make spec-check` when OpenSpec artifacts changed). A finding fixed after
the gate means running the gate again.

## Never

- Run the full suite as a routine step in the middle of a change.
- Skip a transitive dependent because it is slow: a scoped run that leaves out a dependent is not
  a scoped run, it is an incomplete one.
- Archive a change, or call it done, without a full-suite run whose output was read after its last
  code edit.
- Delegate the reading of that output (`subagent-delegation.md`): the main session runs it and
  judges it.
