# Rule: Write Go test-first — red → green → refactor

**Always** drive Go code in this repository with TDD. This applies to new packages, new functions,
bug fixes, and one-line changes alike.

## The loop

1. **Red** — write the failing test first, then *run it and watch it fail*. Confirm it fails for the
   reason you intended, not because the package does not compile or a fixture is missing.
2. **Green** — make the smallest change that turns it green. Resist writing the code you know you
   will eventually need; the next red test will ask for it.
3. **Refactor** — with the tests green, clean up. **Consider invoking `/simplify`** on the code you
   just touched: it reviews for reuse, simplification, efficiency and altitude, and applies the
   fixes. Re-run the tests afterwards.

Never skip the red step. A test that has never been seen to fail has not been shown to test
anything — it may be asserting something that is true no matter what the code does. When a test is
awkward to make fail, invert the implementation temporarily and confirm the test notices.

## Coverage

- **Every hot path must be covered by test cases.** At minimum that means: state changes and the
  rules that reject them, transaction and concurrency boundaries, every platform-, dialect- or
  driver-specific branch, request handling and its error-to-status mapping, and the error paths
  that change an observable outcome.
- **There is no hard coverage threshold**, and no build gate on a percentage. Exceeding 90% is a
  nice achievement, not a requirement.
- Never write a test whose purpose is to move the number. Coverage is a symptom of testing the
  behaviour that matters, not a target to optimise.

## Mechanics

- Table-driven tests follow the project's `table-test` skill — the `assert` closure form, a `ctx`
  modifier where context matters, and `t.Context()` over `context.Background()`. It overrides the
  general `cc-skills-golang:golang-testing` guidance.
- Test doubles come from the `use-mockgen` skill; heavy external services come from
  `use-testcontainers`, never hand-rolled fakes.
- See the red step with a focused run before widening:

  ```sh
  go test -run 'TestTheThingYouAreBuilding' -count=1 ./...
  ```

- Prefer commits where the test and the code that satisfies it land together, with the message
  saying what behaviour is now guaranteed. The discipline is in the order you *wrote* them, not in
  splitting the commit.

## Where this does not apply

Generated files (`mockgen` output, generated OpenAPI documents), pure documentation and
configuration changes, and mechanical renames already covered by existing tests. Everything else is
test-first — including changes that look too small to be worth it, which are exactly the changes
that ship bugs.
