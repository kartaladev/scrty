---
name: use-mockgen
description: Generate, regenerate, and place uber-go/mock (`mockgen`) test doubles for Go interfaces in this repository. Use whenever a test needs to mock an interface, when a mocked interface is added, modified, or removed, or when a new dependency must be substituted in tests. Covers `//go:generate` directives, the `--typed` flag, where mocks should live (decided by who consumes them, never in the production build), and the source-vs-reflect mode decision. Overrides the mock-generation steps in `cc-skills-golang:golang-testing` and `cc-skills-golang:golang-stretchr-testify`; when the two conflict, prefer this one.
---

# Generating Go Mocks with `mockgen`

This repo standardizes on [`uber-go/mock`](https://github.com/uber-go/mock) (the maintained fork of `golang/mock`). All interface test doubles for our own code are generated, never hand-written.

When this skill conflicts with `cc-skills-golang:golang-testing` or `cc-skills-golang:golang-stretchr-testify` (which lean toward `testify/mock`), this skill wins for interfaces *we* own. `testify/mock` is fine for ad-hoc doubles inside a single test file, but anything reused across tests must be generated.

## Prerequisite

`mockgen` v0.6.0 or later must be on `$PATH`. v0.6.0 is the floor because earlier versions emit subtly different code for typed mocks (`--typed`), and our generated files assume the v0.6.x shape — mixing versions across the workspace causes spurious diffs every time someone regenerates.

```shell
mockgen --version
```

Install or upgrade with:

```shell
go install go.uber.org/mock/mockgen@latest
```

## Where mocks live

**The mock's consumers decide.** Answer one question before generating: whose
tests will import this mock?

| The consumers are… | Generate the mock… |
|---|---|
| the owning package's own black-box tests | in the same package, in a `_test.go` file |
| another package's tests | in a dedicated test-double package |

Either way the mock stays **out of the production build**. That is the whole
point, and the two branches are only different means to it.

### Consumers inside the package → same package, in a `_test.go` file

The default, and it earns its keep here: our tests are black-box
(`package <name>_test`), so they already import the producer by its real path
and pick the mock up from an import they have.

```
<pkg>/
├── repository.go             // declares the interface
└── repository_mock_test.go   // generated mock, package <pkg>
```

**The `_test.go` suffix is load-bearing, not a convention.** A mock generated
into a production file puts its exported `Mock*` types on the package's API and
drags `go.uber.org/mock` into the import graph of everything that imports it —
the exact cost the other branch exists to avoid, in a smaller package. A
`_test.go` destination avoids it outright: `go/build` reports such a file under
`TestGoFiles`, never `GoFiles`, so it reaches no consumer's binary.

This is also what separates the two branches:

- from the owning package's own `package <pkg>_test` tests, the mock **is**
  visible and the test passes;
- from **any other package's** tests, it is not — that build fails.

So this branch is available exactly when the consumers are the owning package's
own tests, which is the condition it is chosen by.

- The interface and its mock evolve together; co-located files surface drift in code review.
- No second import for what is conceptually one symbol.
- The rename refactor stays trivial: move the interface, the mock moves with it.

### Consumers outside the package → a test-double package

As soon as every consumer is a different package, the branch above is not
merely worse, it is **unavailable**: a `_test.go` mock is invisible outside its
own package's tests, so a consumer elsewhere cannot compile against it at all.
That is the same fact as above, read from the other side, and it is what
makes this a structural boundary rather than a preference.

A production file would compile, which is exactly the trap: co-location then
buys nothing — each consumer adds an import either way — while the exported
`Mock*` surface costs something real, shipping to consumers of the
**production** package who never asked for test doubles.

Name the test-double package after its producer with a `test` suffix, as a
sibling subdirectory (the standard library's `net/http/httptest` convention).
Give it a `doc.go` that states why the mocks live there, so the reasoning sits
at the source.

```
<pkg>/
├── ports.go                 // declares the interfaces + the //go:generate directive
└── <pkg>test/
    ├── doc.go               // why these doubles live outside <pkg>
    └── ports_mock.go        // generated mock, package <pkg>test
```

Consider guarding the boundary with a test in `<pkg>` that fails if
`go.uber.org/mock` appears in the production import graph, if exported `Mock*`
types are declared in the production build, or if a `//go:generate` directive
targets a destination (or `-package`) other than `<pkg>test`.

**When you cannot answer the question yet**, generate into a `_test.go` file in
the same package. Nothing is published either way, so the choice stays
reversible: moving the mock to a test-double package later is a file move, and
until then no exported surface has been committed to.

## Invocation: prefer `//go:generate` directives

The default way to generate is a `//go:generate` directive at the top of the file declaring the interface, so the whole workspace can be regenerated with one command.

```go
// Package contract holds the repository contracts.
//
//go:generate mockgen -source=repository.go -package=contract -destination=repository_mock_test.go -typed
package contract

type Repository interface { /* ... */ }
```

Then regenerate with:

```shell
go generate ./...            # whole module
go generate ./<pkg>/...      # one package tree
```

Use a direct CLI invocation only when you do not own the source file (e.g., generating a mock for a third-party interface), or when scripting a one-off.

Because you do not own the file, this is the reflect-mode case (a positional
package path and interface name, not `--source`), and the destination is still a
`_test.go` file or a test-double package. Both the module path and the
destination below are placeholders.

```shell
mockgen --destination internal/sdktest/client_mock.go \
        --package sdktest \
        --typed \
        github.com/example/sdk Client
```

## Required flags

- `--typed` — always. Typed mocks give compile-time-checked expectations (`mockRepo.EXPECT().Find(ctx, id).Return(...)`) instead of `interface{}`-based ones; mistakes show up at `go build` time rather than at test runtime.
- `--source` — preferred over reflect mode (positional package + interface name) for interfaces in this repo. Source mode is hermetic (does not require the target package to build first), produces stable output across Go versions, and matches what the `//go:generate` directives use. Reserve reflect mode for cases where you cannot point `mockgen` at the source file — typically third-party interfaces in vendor or module cache.
- `--mock_names` — required only when a single source file declares multiple interfaces whose default mock names (`Mock<Name>`) would collide with something already in the destination package, or when you want a clearer naming scheme. Example: `--mock_names=Repository=MockUserRepo,Cache=MockUserCache`.

## Rules

- Generate a mock for an interface the first time a test needs it; do not hand-roll one.
- Regenerate whenever the source interface changes. Treat a stale mock as a test failure — never edit the generated file by hand to "fix" the diff.
- Delete the mock file when the interface is removed. A leftover mock is a silent maintenance trap.
- Keep the `//go:generate` directive in sync with the destination path if you move the file.

## Verification

After generating or regenerating, confirm all of the following before considering the task done:

1. `go build ./...` from the module root compiles — catches missing imports in the freshly generated file.
2. `go generate ./... && git status` shows no further diff — proves the committed mock matches what the directive produces.
3. Every interface declared in the source file has a corresponding `Mock<Name>` (or its `--mock_names` alias) in the generated file.
4. No mock files exist for interfaces that no longer appear in the source — search for orphans with `grep -rl 'MockGen' --include='*_mock*.go' .` and reconcile.
5. Tests that consume the mock compile and pass under `go test -race ./...`.
