# Design

## Context

See `proposal.md` for why. The 2026-11-09 sweep (`go doc -short` over every published package, filtering for one-letter parameter names) listed 385 signatures. The most frequent:

| Count | Parameter |
|---:|---|
| 75 | `d time.Duration` |
| 26 | `l *slog.Logger` |
| 24 | `l ratelimit.Limiter` |
| 15 | `c seal.Cipher` |
| 14 | `r io.Reader` |
| 14 | `g id.Generator` |
| 7 | `c clock.Clock` |
| 5 | `s onetime.Store` |
| 5 | `g token.Generator` |
| 5 | `f ratelimit.LimiterFactory` |
| 4 | `d *identity.Details` |
| 3 | `m *session.Sessions` |

Smaller groups: `m *magiclink.Links`, `m *apikey.Keys`, `p *oidcprovider.Provider`, `e *policy.Engine`, `a *authenticate.Authentication`. Receivers and Go's standard short names were not counted as findings.

## Goals / Non-Goals

**Goals:**
- Every parameter of an exported signature in a published module reads by its role.
- A test fails when a new one is added without a name.

**Non-Goals:**
- **Locals and the parameters of unexported functions.** That part is unbounded and invisible in godoc. A function's body changes only where a renamed parameter is used.
- **Receivers.** Go convention is one or two letters, consistent per type.
- **Two-letter names** (`id`, `ex`, `tx`). They are already words or established abbreviations in this codebase.
- **Renaming any exported identifier.**

## Decisions

### 1. Which short names stay

A parameter of an exported signature may have a one-letter name only in these cases:
- `w` for `http.ResponseWriter`;
- `r` for `*http.Request`;
- `t`, `b` or `f` for `*testing.T`, `*testing.B` or `*testing.F`;
- `_`.

Everything else gets a role name. `ctx`, `tb` and `ex` are not one letter, so they stay.

- **Why these:** they are the standard library's own conventions. A reader who knows `net/http` or `testing` reads them faster than a longer name.
- **Alternative:** the `varnamelen` linter. It judges locals by their distance from their use too, which would flag thousands of idiomatic locals outside this change's scope, and it cannot be limited to exported signatures. A layout test can be limited, and it names exactly what it wants.

### 2. How a name is chosen

- **Name the role, not the type,** where a function takes two values of one type: `window` and `cooldown`, not `d1` and `d2`.
- **A name that would shadow an imported package used in the same function** takes the short form the maintainer named: `sess`, `clk`, `ciph`. Elsewhere the full word is used: `sessions`, `clock`, `cipher`.
- **Names for one type are the same across packages:**

| Type | Name |
|---|---|
| `*session.Sessions` | `sessions` |
| `*session.Session` | `sess`, in every package, including `session` itself and function types with no body (settled in the lane review, 2026-11-09): a parameter named `session` beside the `session` package reads as the package, and one name for the type is easier to follow than a rule about bodies. A session being replaced takes its role instead (`current` in `Rotate`) |
| `*slog.Logger` | `logger` |
| `ratelimit.Limiter` | `limiter` |
| `ratelimit.LimiterFactory` | `factory` |
| `seal.Cipher` | `cipher` |
| `id.Generator` | `ids` |
| `token.Generator` | `tokens` |
| `clock.Clock` | `clock` |
| `onetime.Store` | `store` |
| `io.Reader` | `src`, or the role (`body`) |

### 3. How the renames are made

Renames go through gopls (`gopls rename`, or the `LSP` tool), which also updates every use in the function body. Doc comments that mention the old name are edited in the same pass, because gopls does not rename prose. The layout test is the red step: it is written first and lists every violation. The lanes then shrink that list to zero.

Failure modes:

| Failure | State | Outcome |
|---|---|---|
| A rename shadows an imported package | Handled | `go build`/`go vet` fails. Decision 2's short form is used |
| A doc comment still names the old parameter | Handled | The reviewer checks it. `go doc` output for each touched symbol is read |
| A new exported signature adds a one-letter name later | Handled, tested | The layout test fails, naming it |
| A conflict with an unmerged change touching the same files | Handled | This change is merged to `main` before `harden-chain-boundary` cuts its fork branch, and that change's task 1.2 checks it (proposal: Impact) |
| A consumer's code broken by the rename | Accepted, impossible | Parameter names are not API |
| Generated mocks keep the old parameter names of a renamed interface, and `make check`'s `generate-check` fails | Handled (found by the first `make check`, 2026-11-09) | The mocks are regenerated with `go generate` and committed with the renames. The diff of a generated file is mockgen's own output, never a hand edit |
| A function type nested in an exported signature's parameters or results (`func F(h func(w io.Writer, n int))`) | Handled, tested (review of 1.1, 2026-11-09) | The guard checks every function type reachable from the signature |
| The guard walks no files (wrong working directory, wrong `release-modules.txt` entry) and passes vacuously | Handled, tested | The test fails unless every walked module yielded at least one Go file |
| A method promoted to an exported type through an unexported embedded type, an exported struct field of function type, or an exported variable holding a function | Accepted | Not reported. The first needs type-checking the guard does not do; the other two are not signatures. A reviewer catches them, and none exists in the tree today (review of 1.1) |

## Risks / Trade-offs

- **[A large diff across many packages hides a behaviour change]** → Lanes rename only; the reviewer rejects any non-rename edit. `make check` and the conformance suite run after each lane.
- **[Merge conflicts with work in flight]** → Lanes are split by package, and the change merges before `harden-chain-boundary`'s fork branch exists.
- **[`v0.1.0`'s defects stay unfixed while this change runs]** → Accepted by the maintainer on 2026-11-09. The release is a day old with almost no consumers, and the delay is one change's work, well inside the timelines `SECURITY.md` promises.

## References

Reasoned from Go's own conventions as the standard library uses them. **Primary documentation:**
- [Effective Go: Names](https://go.dev/doc/effective_go#names): names should be clear, and short names are for small scopes and established conventions.
- [Go Code Review Comments: Variable Names](https://go.dev/wiki/CodeReviewComments#variable-names): the farther a name is used from its declaration, the more descriptive it must be. An exported signature is read in godoc, far from any use.
