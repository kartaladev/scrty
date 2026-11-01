# Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Traces, metrics and correlated logs of scrty's operations and security decisions. They cost nothing without an observer, never carry a secret, and come through a dependency-free seam with an OpenTelemetry adapter in a nested module.

**Architecture:**
- **The seam.** A leaf core package, `pkg/telemetry`, defines `Observer` (Start returning a context, End, Event), the operation and event names, and one `Run` helper that guarantees exactly one End.
- **The chain** wraps each request that a listed endpoint answers in `Run`, from `Chain.Assemble`, and reports events where its interceptors decide.
- **The components** take their own `WithTelemetry` option: sessions, the password authenticator, the reuse guard, the key manager and the expiry runner.
- **The adapter.** `pkg/telemetry/oteltelemetry` maps the seam to the OpenTelemetry API. Its SDK-backed tests live in the `test` module.

**Tech Stack:** Go 1.27; `go.opentelemetry.io/otel`, `otel/trace`, `otel/metric` (adapter only); the OTel SDK and its in-memory exporter and reader (`test` only); testify, gomock.

**Spec:** `openspec/changes/observability/`: `proposal.md`, `design.md` (D1–D8), `specs/{observability,http-security-chain,sessions,authentication,password-encoding,signing-keys,expiry-sweeping,diagnostic-redaction,module-layout}/spec.md` and `tasks.md`. Task numbers (1.1 … 7.1) are `tasks.md`'s.

**Builds on** `endpoint-inventory-base-path`: `Endpoint`, `PathMatch` and `(*Chain).Endpoints()` exist.

## Global Constraints

- **Test-first** for every task: the red step fails for the intended reason, not a compile error. Table tests use `table-test`. `telemetry.Observer` doubles are generated with `use-mockgen` (`--typed`) in each consuming package's `_test` files.
- **`pkg/telemetry` imports only the standard library.** It is never imported from `go.opentelemetry.io`.
- **The core module and every non-adapter module** require nothing under `go.opentelemetry.io/`. The adapter requires `otel`, `otel/trace` and `otel/metric` only, never `otel/sdk`.
- **Operation names:**
  - endpoints: the operation identifier without `scrty.` (`login`, `mfa.verify`, `reauth.verify`, …);
  - components: `password.hash`, `password.verify`, `session.create`, `session.rotate`, `session.renew`, `signingkey.rotate`, `expiry.run`.
- **Event names** (constants in `pkg/telemetry`):
  - from OWASP: `authn_login_success`, `authn_login_fail`, `authn_login_lock`, `authn_password_change`, `authn_password_change_fail`, `authn_token_reuse`, `authz_fail`, `excess_rate_limit_exceeded`, `session_created`, `session_renewed`, `session_logout`;
  - scrty additions: `authn_mfa_success`, `authn_mfa_fail`, `authn_reauth_success`, `authn_reauth_fail`, `crypt_key_rotate_fail`.
- **Refusal names** are the sentinel's identifier without `Err`, in snake case (`ErrMFAMethodNotUsable` gives `mfa_method_not_usable`, `authenticate.ErrAuthenticationFailed` gives `authentication_failed`). They come from a name column added beside `httpsec`'s `statusTable`.
- **An error outcome** names `fmt.Sprintf("%T", err)`, never `err.Error()`. A panic ends with `Outcome{Kind: OutcomeError, Name: "panic"}`, then re-panics.
- **The adapter emits:**
  - span names `scrty.` + operation name, with `SpanKindInternal`;
  - `scrty.operation.duration` in `s`, with explicit bucket boundaries `[0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10]`;
  - `scrty.security.events` in `{event}`;
  - the attributes `scrty.operation`, `scrty.method`, `scrty.outcome` (`success` | `refused` | `error`), `scrty.event` and `error.type` (unset on success);
  - opt-in span-only attributes `user.id` and `client.address`.
- **Agents** never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and never edit `openspec/`. The reference-material rule binds every dispatch.

## Review Focus

- **An observer that blocks or panics.** A panicking `Start` or `End` must not change the request's response beyond the panic the consumer caused. `Run` does not swallow it, and the panic propagates as any consumer-code panic does. Added to Task 1 (1.1).
- **A request matching no endpoint because of its method.** `GET /auth/login`, which login doesn't answer, starts no operation. Added to Task 2 (2.1).
- **A cancelled request.** A login whose context is cancelled mid-flight ends its operation exactly once, with an error outcome. Added to Task 2 (2.1).
- **A decoy whose timing gives the user away.** Under a fake clock, the unknown-user and wrong-password paths give identical operation shapes: one `password.verify`, refused. Added to Task 4 (3.2).
- **A key rotation that fails before storing.** A generation failure ends `signingkey.rotate` in error, with `crypt_key_rotate_fail`, the same as a store failure. Added to Task 5 (3.4).

## Execution lanes and dispatches

The seam comes first, because everything compiles against it. Then the chain and the four components touch disjoint packages and run **in parallel, in their own worktrees**. The adapter needs only the seam, and the conformance and secret checks need everything.

| Wave | Dispatch | Plan tasks (tasks.md) | Owns | Model, reason | Reviewer |
|---|---|---|---|---|---|
| 1 | S1 | 1 (1.1) | `pkg/telemetry/` (new: `telemetry.go`, `names.go`, `run.go`, tests) | Opus: the interface every lane compiles against, with exactly-once under panic | Opus |
| 2 | H1 | 2 (2.1–2.3) | `httpsec/telemetry.go` (new), `chain.go` (`Assemble`), `options.go` (option field), `errors.go` (name column), event call sites in the interceptor files, `httpsec/telemetry_test.go` (new) | Opus: wraps every request at one seam; ordering and exactly-once across interceptors | Opus |
| 2 | C1 | 3 (3.1) | `session/telemetry.go` (new), `sessions.go`, `reuse.go`, `sessions_options.go`, tests | Sonnet: a stated option at stated call sites | Sonnet |
| 2 | C2 | 4 (3.2, 3.3) | `authenticate/password.go`, `authenticate/password_telemetry_test.go` (new); `authenticate/password/reuse.go`, its test | Sonnet: wrapping at stated call sites | Sonnet |
| 2 | C3 | 5 (3.4, 3.5) | `token/signingkey/keys_rotate.go`, `keys.go` (option), tests; `expiry/runner.go`, tests | Sonnet: wrapping at stated call sites | Sonnet |
| 3 | A1 | 7 (5.1, 5.2) | `pkg/telemetry/oteltelemetry/` (new module), `go.work`, `layout_guard_test.go`, `layout_test.go`, `test/telemetry/otel_test.go` (new), `test/go.mod` (SDK) | Sonnet: a mapping fully pinned by the Global Constraints | Sonnet |
| 4 | A2 | 8 (5.3) | `oteltelemetry/route.go`, `example_test.go`, `README.md` telemetry section | Sonnet: a lookup over `Endpoints()` | Sonnet |
| 3 | X1 | 6 (4.1) | `httpsec/telemetry_secrets_test.go` (new), godoc lines naming the stated exception in each component | Sonnet: an end-to-end test with planted values | Sonnet |
| 3 | K1 | 9 (6.1) | `test/httpsecconformance/telemetry_scenarios.go` (new), its registration in `scenarios.go` | Sonnet: a conformance case | Sonnet |
| — | main | 10 (7.1) | — | the main session runs the gate | — |

- **What runs in parallel.** Wave 2's four dispatches are disjoint packages. Wave 3 needs the instrumented chain and components: A1's test drives refused logins through the chain. Wave 3's three dispatches own disjoint files, and A1 touches the root only in the layout guard files. Wave 4's A2 builds on A1's module.
- **Before archive,** one whole-branch review on Opus checks every requirement in the nine deltas.

---

### Task 1: The seam (tasks.md 1.1)

**Files:** create `pkg/telemetry/{telemetry.go,names.go,run.go}` and `pkg/telemetry/run_test.go`.

**Interfaces:**
- Produces:

```go
package telemetry

type Observer interface {
    Start(ctx context.Context, op Operation) context.Context
    End(ctx context.Context, out Outcome)
    Event(ctx context.Context, ev Event)
}

type Operation struct {
    Name          string // an operation name; see names.go
    Method        string
    User          string // the opaque user reference, "" when unknown
    ClientAddress string // "" when unknown
}

type OutcomeKind int
const (
    OutcomeSuccess OutcomeKind = iota + 1
    OutcomeRefused
    OutcomeError
)
type Outcome struct {
    Kind OutcomeKind
    Name string // refusal name, or the error's Go type
}
func Success() Outcome
func Refused(name string) Outcome
func Failed(err error) Outcome // Name: fmt.Sprintf("%T", err)

type EventName string // names.go: one constant per vocabulary entry
type Event struct {
    Name          EventName
    Method        string
    Outcome       Outcome
    User          string
    ClientAddress string
}

// Run starts op, runs fn under the returned context, and ends op exactly
// once with fn's outcome. On a panic it ends op with Outcome{OutcomeError,
// "panic"} and re-panics. A nil o runs fn with ctx and calls nothing.
func Run(ctx context.Context, o Observer, op Operation,
    fn func(ctx context.Context) (Outcome, error)) error

// Emit reports ev, and does nothing for a nil o.
func Emit(ctx context.Context, o Observer, ev Event)
```

- `names.go` also declares:
  - `OpPasswordHash = "password.hash"`, `OpPasswordVerify`, `OpSessionCreate`, `OpSessionRotate`, `OpSessionRenew`, `OpSigningKeyRotate` and `OpExpiryRun`;
  - `RefusalPasswordMismatch = "password_mismatch"`, the documented refusal name for a `password.verify` whose password did not match. It is the one component-level refusal name; every other refusal name comes from `httpsec`'s status table.

- [ ] **Step 1: Write the failing test.** `TestRun`, a table:
  - **nil observer:** `fn` runs, and the returned error passes through;
  - **outcomes:** success, refused and error each give one `Start` and one `End` with that outcome;
  - **panic:** `End` with `{OutcomeError, "panic"}`, then a re-panic, recovered by the test;
  - **context:** `fn` sees the context `Start` returned (a marker value);
  - **error text:** `Failed(fmt.Errorf("u-1 broke"))` has a `Name` without `u-1`;
  - **observer panics** (Review Focus): an observer whose `End` panics propagates that panic.

  `TestNames` asserts every event constant's string, verbatim from the Global Constraints.
- [ ] **Step 2: Run** `go test -run 'TestRun|TestNames' -count=1 ./pkg/telemetry/`. Expected: FAIL.
- [ ] **Step 3: Implement** it, using only the standard library.
- [ ] **Step 4: Run** `go test -race -count=1 ./pkg/telemetry/` and `go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./pkg/telemetry/`. Expected: PASS, and the second command prints only `github.com/kartaladev/scrty/pkg/telemetry`.
- [ ] **Step 5: Commit** `feat(telemetry): a dependency-free telemetry seam`.

### Task 2: The chain (tasks.md 2.1–2.3)

**Files:** create `httpsec/telemetry.go` and `httpsec/telemetry_test.go`; modify `chain.go` (`Assemble`), `options.go` (`config.telemetry`), `errors.go` (a `name` on each `statusRow`), and the event call sites in `login.go`, `basic.go`, `throttle.go`, `mfa_verify.go`, `reauth*.go`, `password_change.go`, `logout.go` and `authorization.go`.

**Interfaces:**
- Consumes: `telemetry.Run`, `telemetry.Emit`, and the names (Task 1); `Endpoints()`.
- Produces:
  - `func WithTelemetry(o telemetry.Observer) Option`; a nil `o` is a configuration error naming `WithTelemetry`;
  - `func refusalName(err error) (string, bool)`, from the status table's name column;
  - `func outcomeOf(err error) telemetry.Outcome`: nil gives `Success()`, a named refusal gives `Refused(name)`, anything else `Failed(err)`.

- [ ] **Step 1 (2.1): Write the failing test.** `TestTelemetry`, using a mockgen observer, checks that:
  - a successful login gives `Start` with `Operation{Name: "login", User: "u-1", ClientAddress: "203.0.113.7"}`, then `End(Success())`;
  - a wrong password gives `End(Refused("authentication_failed"))`;
  - `GET /projects/1` and `GET /auth/login` start nothing (Review Focus);
  - a cancelled login ends once, with an error outcome (Review Focus);
  - a chain without the option makes no observer call;
  - `refusalName` names every row of `statusTable` (a table over the rows).

  Run `go test -run 'TestTelemetry$' -count=1 ./httpsec/`: FAIL.
- [ ] **Step 2 (2.1): Implement it.** In `Assemble`'s outer closure:
  - look up the endpoint for `(ex.Request.Method(), ex.Request.Path())` with an index built once in `build()` from `Endpoints()` (exact map, then prefix entries by match kind);
  - when one matches and telemetry is set, call `telemetry.Run`, whose `fn` calls `ex.SetContext(ctx)` and then the chain, returning `outcomeOf(err), err`;
  - fill `User` and `ClientAddress` from the published caller and the attributed client address where present.

  Run `go test -race -count=1 ./httpsec/`: PASS.
- [ ] **Step 3 (2.2): Write the failing test.** `TestTelemetryEvents`, a table with one row per chain event in the Global Constraints. It includes `authz_fail` from a rule refusal, and `excess_rate_limit_exceeded` from the chain-built password-login guard. Each row asserts the event's `Name`, `Method` and `Outcome`. Run it: FAIL.
- [ ] **Step 4 (2.2): Implement it.** Call `telemetry.Emit` at each decision. The chain hands its observer to the source guards it builds, through `resolveSourceGuard`. Run `go test -race -count=1 ./httpsec/`: PASS.
- [ ] **Step 5 (2.3): Write the failing test, then make it pass.** `TestTelemetryLogContext`: a mock `Start` returns a context holding a marker, and a capturing `slog.Handler` records each record's context. The login-refusal record's context carries the marker. The suppressed-refusal summary's context does not. Run it: FAIL. Then pass `ex.Context()` (already the operation's context after Step 2) at every chain log call that currently uses another context. Run: PASS.
- [ ] **Step 6: Commit** each step pair: `feat(httpsec): endpoint operations reach a telemetry observer`, `feat(httpsec): security events`, `feat(httpsec): chain records carry the operation's context`.

### Task 3: Sessions (tasks.md 3.1)

**Interfaces:**
- Produces: `func WithTelemetry(o telemetry.Observer) Option` in `session`.

- [ ] **Step 1: Write the failing test.** `TestSessionsTelemetry` checks that:
  - `Create` gives `session.create` with `User` the session's user, and `session_created`;
  - `Rotate` gives `session.rotate`;
  - `RotateWithGrace`, renewing, gives `session.renew` and `session_renewed`;
  - a superseded identifier presented after its window gives `authn_token_reuse`, and the reuse observer still receives its `ReuseReport`;
  - no `Start`, `End` or `Event` argument, rendered with `%+v`, contains the session identifier.
- [ ] **Step 2: Run** `go test -run 'TestSessionsTelemetry' -count=1 ./session/`. Expected: FAIL.
- [ ] **Step 3: Implement** it with `telemetry.Run` around the three methods, and `Emit` at creation, renewal and the reuse judgement.
- [ ] **Step 4: Run** `go test -race -count=1 ./session/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(session): report to a telemetry observer`.

### Task 4: Password work (tasks.md 3.2, 3.3)

**Interfaces:**
- Produces:
  - `func WithPasswordTelemetry(o telemetry.Observer) PasswordOption` in `authenticate`;
  - `func WithReuseTelemetry(o telemetry.Observer) ReuseOption` in `authenticate/password`.

- [ ] **Step 1: Write the failing tests.**
  - **`TestPasswordAuthenticatorTelemetry`:**
    - a wrong password gives one `password.verify` ending `Refused(telemetry.RefusalPasswordMismatch)`, under the call's context;
    - an unknown user gives exactly the same calls: one `password.verify`, refused with the same name, with no extra or missing call (Review Focus);
    - a right password gives `Success()`;
    - no argument contains the password or the hash.
  - **`TestReuseGuardTelemetry`:**
    - a candidate matching the second history entry gives two `password.verify` operations, the first refused with `RefusalPasswordMismatch` and the second a success (it matched), and the guard refuses the candidate as before;
    - an accepted change gives one `password.hash` with success;
    - no argument contains the candidate or a hash.
- [ ] **Step 2: Run** `go test -run 'Telemetry' -count=1 ./authenticate/ ./authenticate/password/`. Expected: FAIL.
- [ ] **Step 3: Implement** `telemetry.Run` around each `Match` in `Authenticate` and `VerifyDecoy` (whose context parameter gets a name), and in `ReuseGuard.Check`, and around `Encode` in `Change`. Every `password.verify` ends in `Success()` when the password matched, and `Refused(telemetry.RefusalPasswordMismatch)` when it did not.
- [ ] **Step 4: Run** `go test -race -count=1 ./authenticate/ ./authenticate/password/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(authenticate): report password work to a telemetry observer`.

### Task 5: Key rotation and expiry runs (tasks.md 3.4, 3.5)

**Interfaces:**
- Produces: `func WithTelemetry(o telemetry.Observer) Option` in `token/signingkey` and in `expiry`.

- [ ] **Step 1: Write the failing tests.**
  - **`TestKeysTelemetry`:**
    - a scheduled `ES256` rotation gives `signingkey.rotate` with `Method: "ES256"` and success;
    - a failing key store gives an error outcome and `crypt_key_rotate_fail`;
    - a failing key generation gives the same (Review Focus);
    - no argument contains key bytes.
  - **`TestRunnerTelemetry`:**
    - the `sessions` task removing 3 gives `expiry.run` with `Method: "sessions"` and success, and the result observer still receives `Removed: 3`;
    - a failing task gives an error outcome while the next task's operation succeeds.
- [ ] **Step 2: Run** `go test -run 'Telemetry' -count=1 ./token/signingkey/ ./expiry/`. Expected: FAIL.
- [ ] **Step 3: Implement** `telemetry.Run` in `rotateAll`, per algorithm, and in `runOne`.
- [ ] **Step 4: Run** `go test -race -count=1 ./token/signingkey/ ./expiry/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(signingkey,expiry): report to a telemetry observer`.

### Task 6: No secrets reach the observer (tasks.md 4.1)

- [ ] **Step 1: Write the test.** `TestTelemetryHandsNoSecrets` builds a chain, a session manager and the password authenticator sharing one recording observer, which keeps every argument as `%+v`. It plants a password, a TOTP code and a sender error `550 5.1.1 <alice@example.com>: Recipient address rejected`, and drives a login, an MFA verification, a renewal and a failing magic-link send. It asserts:
  - no recorded string contains the password, the code, the session identifier, the issued token or `alice@example.com`;
  - the login's operation carries `u-1` and `203.0.113.7`.
- [ ] **Step 2: Red step.** Temporarily make `outcomeOf` use `err.Error()` as the name, and confirm the test fails on `alice@example.com`. Then restore it.
- [ ] **Step 3: Write the godoc.** Each `WithTelemetry`-style option names the user reference and client address as deliberately handed.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/`. Expected: PASS.
- [ ] **Step 5: Commit** `test(httpsec): no secret reaches a telemetry observer`.

### Task 7: The adapter (tasks.md 5.1, 5.2)

**Interfaces:**

```go
package oteltelemetry

func New(opts ...Option) (*Observer, error) // *Observer implements telemetry.Observer
func WithTracerProvider(tp trace.TracerProvider) Option
func WithMeterProvider(mp metric.MeterProvider) Option
func WithUserAttribute() Option
func WithClientAddressAttribute() Option
```

- [ ] **Step 1 (5.1).** In `layout_guard_test.go`:
  - add `pkg/telemetry/oteltelemetry` to the listed integrations;
  - refuse `go.opentelemetry.io/` in the core module's requirements;
  - refuse `go.opentelemetry.io/otel/sdk` in the adapter's.

  Run `go test -count=1 .`: FAIL. Create the module and add it to `go.work`. Re-run: PASS.
- [ ] **Step 2 (5.2): Write the failing test.** `test/telemetry/otel_test.go`, with `tracetest.NewInMemoryExporter` and `metric.NewManualReader`:
  - **spans:** `scrty.login` is a child of the test's parent span, with `scrty.outcome=refused` and `error.type=authentication_failed`, and success has no `error.type`;
  - **metrics:** `scrty.operation.duration` has unit `s`, and `scrty.security.events` has unit `{event}`;
  - **refusals unsampled:** fifty refused logins in one refusal-log window give a count of 50 for `authn_login_fail`, and the captured log has one record;
  - **personal data off by default:** no span or metric attribute contains `u-1` or the address;
  - **opt-in user:** `WithUserAttribute()` puts `user.id=u-1` on spans and on no metric;
  - **injected providers:** they receive everything, and a global provider set by the test receives nothing.
- [ ] **Step 3: Run** `go test -run 'TestOTel' -count=1 ./telemetry/` in `test`. Expected: FAIL.
- [ ] **Step 4: Implement** the adapter to the Global Constraints. Events become `span.AddEvent` on the span the adapter itself started, read from its own context key, never `trace.SpanFromContext` of a span it did not start, and the counter is incremented.
- [ ] **Step 5: Run** the test module's tests and `go vet ./...` in the adapter module. Expected: PASS.
- [ ] **Step 6: Commit** `build(oteltelemetry): the module` and `feat(oteltelemetry): spans and metrics`.

### Task 8: Route labels and documentation (tasks.md 5.3)

**Interfaces:**
- Produces: `func RouteLabeler(c *httpsec.Chain) func(method, path string) (route string, ok bool)`.

- [ ] **Step 1: Write the failing test.** `TestRouteLabeler`, with a chain under the base `/auth`: `("POST", "/auth/mfa/verify/totp")` gives `("/auth/mfa/verify/{method}", true)`, and `("GET", "/projects/42")` gives `("", false)`.
- [ ] **Step 2: Run** it. Expected: FAIL.
- [ ] **Step 3: Implement** it over `c.Endpoints()` with each entry's match kind. Add an `Example` using it beside the consumer's server instrumentation. Write the README telemetry section: the names, the vocabulary, the attribute policy, and wiring for `otelslog`, `otelpgx`, `otelgorm`, `redisotel` and `outbound.WithHTTPClient` with `otelhttp`.
- [ ] **Step 4: Run** `go test -race -count=1 ./...` in the adapter module, including the example. Expected: PASS.
- [ ] **Step 5: Commit** `feat(oteltelemetry): label chain routes`.

### Task 9: Conformance (tasks.md 6.1)

- [ ] **Step 1: Write the scenario.** `TelemetryLoginOperations`, on net/http, gin and fiber, with a recording observer: one `login` operation and `authn_login_success` for a good login, and one operation and `authn_login_fail` for a bad one, identical across adapters.
- [ ] **Step 2: Run** `go vet ./...` and `go test -race ./...` in `test`. Expected: PASS. Show the red step by running before `WithTelemetry` is passed, and watching the operation count assertion fail.
- [ ] **Step 3: Commit** `test(conformance): telemetry on every adapter`.

### Task 10: The gate (tasks.md 7.1)

- [ ] **Step 1: Run the gate.**
  - `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...` and `golangci-lint run ./...` in every module from `go list -m`;
  - `gofmt -l`;
  - `openspec validate observability --strict`.
- [ ] **Step 2: Check the results.** Every command exits 0. The main session records the output and ticks 7.1.
