---
name: table-test
description: Project-specific Go table-driven test rules — MANDATORY whenever a test has two or more cases that exercise the same SUT call with varying inputs or expected outcomes. Imposes the `assert` closure form (not `want`/`wantErr` fields), a `ctx` context modifier for context-sensitive components, and `t.Context()` over `context.Background()`. Use BEFORE writing the second `TestXxx` function that calls the same function/handler with different inputs — fold the cases into a table. Use also when reviewing or refactoring existing tests that violate this rule. Overrides `cc-skills-golang:golang-testing`'s table-test guidance; when the two conflict, prefer this one.
---

# Table-Driven Tests (project preferences)

These preferences override the defaults from `cc-skills-golang:golang-testing` for code in this repository. When that skill and this one conflict, this one wins.

## When this skill applies (non-negotiable)

The table form is **mandatory** — not a style preference — whenever:

- A test file has, or is about to have, **two or more `TestXxx` functions that call the same function, method, or HTTP handler** with different inputs and/or expected outcomes. The cases share a call shape; that's the trigger.
- A new test would duplicate the setup-and-call boilerplate of an existing test in the same file but vary only the inputs or assertions.

You may write a single standalone `TestXxx` only when:

- There is exactly one case for the SUT in this file (no second variant exists or is imminent), or
- Each "variant" has structurally different setup (different injector graph, different fs scaffolding, different mocks) such that the shared-shape assumption breaks down. In that case, document the divergence in a one-line comment at the top of the test file so the next reader doesn't second-guess.

### Anti-patterns and rejected excuses

The following are NOT valid reasons to skip the table form. They are common rationalizations that surface in code review and must be rejected at write time:

| Excuse | Why it's rejected |
|---|---|
| "Individual tests give a clearer failure narrative." | `t.Run(tc.name, ...)` produces the exact same subtest path on failure. The narrative comes from the case name, not from the function name. |
| "The project mostly uses individual `TestXxx` funcs." | Prevailing-style arguments lose to a mandatory rule. The existing tests are pre-skill; new tests are post-skill. |
| "Each case has subtly different assertions." | The `assert` closure receives `(*testing.T, result, err)` and can do whatever each case needs. Asymmetric assertions are exactly what the closure form is for. |
| "Some cases want extra setup steps the others don't." | Either pull setup into the closure body, or — if the divergence is large — split into two tables, one per setup shape. Don't fall back to individual functions. |
| "It's only two cases — not worth a table." | Two is the threshold. The boilerplate ratio gets worse with three; setting the precedent at two prevents drift. |
| "The first case is a happy path and the others are error cases." | That is the prototypical reason for a table. The happy-path row sits alongside the error rows; the `assert` closure handles the asymmetry. |

If you find yourself constructing one of these excuses while writing tests, stop and convert to a table.

### Self-audit before committing

Ask: *"Does my test file contain two or more `TestXxx` functions whose body shape is essentially `setup → call SUT → assert`?"* If yes and the SUT call is the same, the file must use the table form. Refactor before staging.

## Why this style

We standardize on **assert closures** instead of `want` / `wantErr` struct fields because:

- Some components return values that aren't trivially comparable (channels, time-sensitive structs, errors with embedded stack traces). A closure lets each case assert exactly what matters.
- Error inspection is more expressive (`require.ErrorIs(t, err, ErrFoo)` vs. a boolean `wantErr`).
- The closure runs inside the per-case subtest, so failure output is local to the failing row.

## Canonical shape

For a component returning `(T, error)`:

```go
func TestThing(t *testing.T) {
    t.Parallel()

    type testCase struct {
        name   string
        input  Input
        ctx    func(ctx context.Context) context.Context // nil means identity
        assert func(t *testing.T, result T, err error)
    }

    cases := []testCase{
        {
            name:  "happy path",
            input: Input{ /* ... */ },
            assert: func(t *testing.T, result T, err error) {
                require.NoError(t, err)
                assert.Equal(t, expected, result)
            },
        },
        {
            name:  "canceled context returns ctx error",
            input: Input{ /* ... */ },
            ctx: func(ctx context.Context) context.Context {
                cctx, cancel := context.WithCancel(ctx)
                cancel()
                return cctx
            },
            assert: func(t *testing.T, _ T, err error) {
                require.ErrorIs(t, err, context.Canceled)
            },
        },
    }

    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()

            ctx := t.Context()
            if tc.ctx != nil {
                ctx = tc.ctx(ctx)
            }

            result, err := ComponentUnderTest(ctx, tc.input)
            tc.assert(t, result, err)
        })
    }
}
```

For components returning only `error`, drop `result` from the closure signature: `assert func(t *testing.T, err error)`.

## Rules

1. **Use an `assert` closure on every case — not `want`/`wantErr` fields.**
   The closure receives `(t *testing.T, result T, err error)`, or `(t *testing.T, err error)` if the component returns only `error`. Every case must populate it; there is no "default assertion".

2. **Use `testify/assert` and `testify/require` from `github.com/stretchr/testify`.**
   Use `require` for preconditions that must halt the case (e.g., `require.NoError` before dereferencing a result); use `assert` for independent checks that should all report on failure.

3. **For context-sensitive components, declare a `ctx` modifier and add at least one canceled/expired-context case.**
   The field signature is `func(ctx context.Context) context.Context`. A nil value means "use the original `t.Context()` unchanged" — that is the default for cases that don't care about lifecycle. When the component's behavior depends on context cancellation or deadlines, you must include at least one case that cancels or expires the context, so the lifecycle path is exercised.

4. **Use `t.Context()` inside subtests, not `context.Background()` or `context.TODO()`.**
   `t.Context()` is canceled when the test finishes. This surfaces leaked goroutines, prevents cross-test pollution, and ties the test's deadline to the component's context — which is exactly what you want under `-race` and `-timeout`.

## Heavy-resource setup is a separate concern

If the test needs an externally-provisioned resource (database, object store, message broker, etc.), provision it through the owning module's `RunTestX` helper, as described in the [`use-testcontainers`](../use-testcontainers/SKILL.md) skill. Call it per test or per case as isolation requires: `RunTestPostgres` shares one server per test process and gives every call a database of its own, so a per-case call costs a database clone, not a container start. Do not wrap the table in a `testify/suite` to share the resource; a suite gives its tests no isolation from each other and does not combine with parallel table cases.
