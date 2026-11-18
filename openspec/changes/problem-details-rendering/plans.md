# Problem-Details Rendering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the opt-in module `github.com/kartaladev/scrty/httpsec/prblmsec`, which maps every refusal scrty recognises to a typed RFC 9457 problem through `github.com/kartaladev/prblm`. Two core additions support it: `httpsec.LookupStatus` and `ChallengeError.TokenType`.

**Architecture:**
- **Core.** It gains a comma-ok status lookup, with `StatusForError` built on it, and a token type on challenge errors.
- **Mapper.** The new module's mapper takes the status from the lookup, then picks a type only among the types of that status. That is what keeps the core's concealment intact. It returns nil for errors the core does not recognise.
- **gin.** `ginsec.Middleware` gains a variadic `WithRefusalsRendered()` option, so `ginprblm` can render the chain's own 404s on paths gin has no route for.
- **Parity.** The test module checks that net/http, gin (`ginprblm`) and fiber (`fiberprblm`) all render the same problem.

**Tech Stack:** Go 1.27, prblm v0.2.0 (`ginprblm` and `fiberprblm` v0.2.0 in tests only), testify, gin v1.12, fiber v3.

**Spec:** `openspec/changes/problem-details-rendering/` (`proposal.md`, `design.md`, `specs/*/spec.md`, `tasks.md`). Executors read the design's decisions and failure-mode table along with this plan.

## Global Constraints

- **Core dependencies.** The core module never requires `github.com/kartaladev/prblm`. `prblmsec`'s production code requires only prblm and the core. gin and fiber appear only in `test/`.
- **Module identity.** The module path is `github.com/kartaladev/scrty/httpsec/prblmsec`, and its package name is `prblmsec`.
- **Default prefix.** It is `security`. Sub-types and statuses come exactly from the spec's type table.
- **Problem text.** Title and detail are fixed library text. Never derive anything from `err.Error()`.
- **Extension members.** The only ones are `challenge`, `methods` (with `name`, `channel`, `begins`), `max_age`, `rule`, `access_token` and `token_type`.
- **Status.** A problem's status is always `httpsec.StatusForError(err)`.
- **Construction errors.** `New` returns errors and never panics outward. Every configuration error matches `prblmsec.ErrConfig`.
- **Rules that bind every dispatch.** Test-first (`golang-tdd.md`), with table tests in the `assert`-closure form (`table-test` skill) and `t.Context()`. Also bound: `defensive-coding.md`, `library-design.md`, `defect-claims.md` and `legacy-reference.md`, which forbids copying or citing the legacy reference. Agents never run a git command that discards work, and never edit `openspec/`.

## Review Focus

1. **A consumer-built `*ChallengeError` with odd fields** (`Token` set and `Session` nil, `Methods` nil, `Kind` a consumer kind). Expect no panic, members only where present, and no `challenge` member, since a consumer kind is outside the fixed vocabulary (design decision 4). Pinned in Task 4.3 (`consumer kind` case).
2. **An error joining two recognised refusals of different statuses**, for example `errors.Join(ErrCrossSiteRequest, mfa.ErrInvalidCode)`. Expect the type to follow `StatusForError`'s pick, never the other refusal's type. Pinned in Task 4.1 (`joined across statuses` case).
3. **The same `*Problems` used concurrently** by many requests. Expect no data race. Pinned in Task 4.5 (`-race` parallel subtest).
4. **`WithTypePrefix` with a nested prefix** (`auth/v1`). Expect it to be accepted and to produce `/probs/auth/v1/access-denied`. Pinned in Task 3.1 (`nested prefix` case).
5. **A problem served as XML** (`Accept: application/problem+xml`). Expect `methods` and `access_token` to encode without the minimal-500 replacement. Pinned in Task 4.3 (`xml encodes members` case).

---

### Task 1.1: Branch

- [ ] **Step 1:** `git fetch origin && git switch -c feat/problem-details-rendering origin/main`, then carry `openspec/changes/problem-details-rendering/` onto the branch.
- [ ] **Step 2:** Verify that `git branch --show-current` prints `feat/problem-details-rendering`, and that `git merge-base HEAD origin/main` equals `git rev-parse origin/main`.

### Task 2.1: `httpsec.LookupStatus`

**Files:**
- Modify: `httpsec/errors.go` (`StatusForError`, around line 502)
- Test: `httpsec/errors_test.go`

**Interfaces:**
- Produces: `func LookupStatus(err error) (status int, ok bool)`. For every error, `LookupStatus(err)`'s status equals `StatusForError(err)`. `StatusForError` becomes `s, _ := LookupStatus(err); return s`.

- [ ] **Step 1: Write the failing test.** `TestLookupStatus` is a table test: `err error`, `assert func(t *testing.T, status int, ok bool)`. Cases:
  - `access denied wrapped`: `fmt.Errorf("x: %w", authorize.ErrAccessDenied)` gives 403 and true;
  - `mfa challenge`: `&ChallengeError{Kind: policy.ChallengeMFA}` gives 401 and true;
  - `password change challenge`: gives 403 and true;
  - `challenge verifier down`: `fmt.Errorf("%w: %w", ErrChallengeUnavailable, errConn)` gives 500 and true;
  - `oidc provider dependency` and `recovery dependency`: give 500 and true;
  - `library fault over store error`: build it with `diag.Wrap(errConn, "fixed", authenticate.ErrUnavailable)`; it gives 401 and true;
  - `history unavailable`: `fmt.Errorf("%w: %w", password.ErrHistoryUnavailable, errConn)` gives 500 and true;
  - `consumer error`: `errors.New("app")` gives 500 and false;
  - `nil`: gives 500 and false.

  Every case also asserts `status == StatusForError(tc.err)`. Add one case per `statusTable` row by ranging over the table (internal test file) and asserting `ok` and the row's status.
- [ ] **Step 2: Watch it fail.** Add a stub, `func LookupStatus(err error) (int, bool) { return StatusForError(err), false }`. Run `go test -run TestLookupStatus -count=1 ./httpsec/`. Expected: FAIL on every `ok == true` case. That is the intended red step, not a compile error.
- [ ] **Step 3: Implement.** Move `StatusForError`'s body into `LookupStatus`, returning `true` on each existing branch. Add two recognitions before the final fallback:
  - `errors.As(err, new(*diag.Fault))` gives `(500, true)`, since a table hit has already returned;
  - the named dependency sentinels give `(500, true)`.

  Then `StatusForError` delegates to `LookupStatus`.
- [ ] **Step 4: Run.** `go test -run 'TestLookupStatus|TestStatusForError' -count=1 ./httpsec/`. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(httpsec): add LookupStatus, the recognising companion of StatusForError`

### Task 2.2: Dependency-sentinel inventory

**Files:** Modify `httpsec/errors.go`. Test `httpsec/errors_test.go`.

- [ ] **Step 1: Inventory.** Use gopls workspace symbols for `Unavailable`, `ErrDependency`, `ErrHistoryUnavailable` and `ErrLookupUnavailable` across the core, and keep the exported sentinels whose godoc says they map to 500 as dependency failures. Report the list in the dispatch report.
- [ ] **Step 2: Write the failing test.** `TestLookupStatus_DependencySentinelInventory` ranges over that list and asserts each sentinel, wrapped around `errConn`, gives `ok == true` with `status == StatusForError`. Run it, and expect FAIL naming each missing sentinel.
- [ ] **Step 3: Implement.** Add the missing sentinels to the lookup's dependency set. Re-run, and expect PASS.
- [ ] **Step 4: Commit.** `test(httpsec): pin the dependency failures LookupStatus recognises`

### Task 2.3: `ChallengeError.TokenType`

**Files:**
- Modify: `httpsec/errors.go` (the `ChallengeError` struct), `httpsec/complete.go:700`, `httpsec/mfa_verify.go:602,704`
- Test: the existing challenge tests in `httpsec`

**Interfaces:**
- Produces: the field `TokenType TokenType` on `ChallengeError`. It is non-empty whenever `Token` is, and equals `tokenTypeOf(session)`.

- [ ] **Step 1: Write the failing test.** `TestChallengeError_TokenType` is a table test. Cases:
  - a bearer-chain password login challenged for MFA gives `TokenTypeBearer`;
  - a DPoP-proofed login challenged gives `TokenTypeDPoP`;
  - an MFA verify that raises a password-change challenge gives the rotated token's type;
  - the password-change gate on a later request has an empty `TokenType` and an empty `Token`.
- [ ] **Step 2: Watch it fail.** Add the field without setting it, then run `go test -run TestChallengeError_TokenType -count=1 ./httpsec/`. Expected: FAIL, with an empty `TokenType` where `Bearer` or `DPoP` was expected.
- [ ] **Step 3: Implement.** Set `TokenType: tokenTypeOf(s)` (or the rotated session) at the three sites. Re-run, and expect PASS.
- [ ] **Step 4: Commit.** `feat(httpsec): challenge errors carry their token's type`

### Task 2.4: Core godoc and gate

- [ ] **Step 1:** Write the godoc:
  - `LookupStatus`: "recognised" means a table refusal, a challenge, or a library-reported dependency failure, and the comma-ok pairing with `StatusForError`;
  - `TokenType`;
  - one sentence in `doc.go`'s "Failing closed" section.
- [ ] **Step 2:** Run `go vet ./... && test -z "$(gofmt -l .)" && go test -count=1 ./httpsec/...`. Expected: clean.
- [ ] **Step 3: Commit.** `docs(httpsec): document LookupStatus and TokenType`

### Task 3.1: Module scaffold and `New`

**Files:**
- Create: `httpsec/prblmsec/go.mod`, `doc.go`, `prblmsec.go` (`New`, `Problems`, options, `ErrConfig`), `prblmsec_test.go`
- Modify: `go.work`

**Interfaces:**
- Produces:
  - `type Problems struct{ /* unexported */ }`
  - `func New(opts ...Option) (*Problems, error)`
  - `type Option func(*config) error`
  - `func WithTypePrefix(prefix string) Option`
  - `func WithoutChallengeToken() Option`
  - `var ErrConfig = errors.New("prblmsec: invalid configuration")`

- [ ] **Step 1: Write the failing test.** `TestNew` is a table test: `opts []Option`, `assert func(t, p *Problems, err error)`. Cases:
  - `default`: no error, and `p` is non-nil;
  - `custom prefix` (`"auth"`): ok;
  - `nested prefix` (`"auth/v1"`): ok;
  - `uppercase/dot-dot` (`"Auth/../x"`), `empty` (`""`) and `double slash` (`"a//b"`): `errors.Is(err, ErrConfig)` and `p == nil`;
  - `nil option`: `ErrConfig`;
  - `prefix given twice`: `ErrConfig`.
- [ ] **Step 2: Watch it fail.** Write `New` returning `&Problems{}, nil`, then run `go test -run TestNew -count=1 ./...` in `httpsec/prblmsec`. Expected: FAIL on the invalid cases.
- [ ] **Step 3: Implement.** Apply the options and refuse nil or repeated ones. Build every type with `prblm.DefineType(prefix+"/"+sub, status, title, description)` inside one function that recovers only that panic and returns `fmt.Errorf("%w: %v", ErrConfig, r)`. Use no grammar of scrty's own (design decision 6).
- [ ] **Step 4: Run.** Expect PASS. Add the module to `go.work`, and confirm `go build ./...` passes in the module.
- [ ] **Step 5: Commit.** `feat(prblmsec): module and construction`

### Task 3.2: `Types` and `Option` with discovery

**Interfaces:**
- Produces:
  - `func (p *Problems) Types() []*prblm.Type`, a fresh slice per call;
  - `func (p *Problems) Option() prblm.Option`, equivalent to `WithTypes(p.Types()...)` followed by `WithMappers(p.Mapper())`. `Mapper` comes from Task 4.1; stub it as `prblm.MapperFunc` returning nil here.

- [ ] **Step 1: Write the failing test.** `TestTypes_DocumentEveryType`: build `prblm.NewHandler(prblm.WithNamespace("/probs"), p.Option(), prblm.AddErrorHook(record))`. For each of the 20 sub-types in the spec table, `GET /probs/security/<sub>` with `Accept: application/json` answers 200 with JSON `status` equal to the table's status. Expected red: 404 before the types are defined from the table.
- [ ] **Step 2: Implement.** Keep one unexported table of `{sub, status, title, description}` in `types.go`, used by both `New` and the mapper.
- [ ] **Step 3: Run.** `go test -run TestTypes -count=1 ./...`. Expected: PASS.
- [ ] **Step 4: Commit.** `feat(prblmsec): problem type definitions for discovery`

### Task 4.1: Status-first type selection

**Files:** Create `httpsec/prblmsec/mapper.go`, `mapper_test.go`.

**Interfaces:**
- Consumes: `httpsec.LookupStatus` and the type table.
- Produces: `func (p *Problems) Mapper() prblm.Mapper`.

- [ ] **Step 1: Write the failing test.** `TestMapper_TypePerRefusal` is a table test: `err`, `assert func(t, prob *prblm.Problem)`. Each case asserts `prob.Status == httpsec.StatusForError(err)` and `prob.Type == "security/<sub>"`. There is one case per spec table row, with a representative refusal for each. Also include:
  - `challenge wrapping access denied` gives `mfa-required`;
  - `joined across statuses` (`errors.Join(httpsec.ErrCrossSiteRequest, mfa.ErrInvalidCode)`) gives the type of whichever status `StatusForError` returns;
  - `recognised 500` (`ErrChallengeUnavailable`) gives `Type == ""` (about:blank), status 500 and an empty detail;
  - `unrecognised` gives a nil problem.

  Expected red: the stub returns nil for everything.
- [ ] **Step 2: Implement `MapError`.** It runs three steps:
  1. `LookupStatus`, returning nil when `!ok`;
  2. the ordered candidates for that status, with challenge by kind first, then specific sentinels or types, then the status default;
  3. `about:blank` when the status has no types.

  It attaches `prblm.WithCause(err)`.
- [ ] **Step 3: Run.** `go test -run TestMapper_TypePerRefusal -count=1 ./...`. Expected: PASS.
- [ ] **Step 4: Commit.** `feat(prblmsec): map recognised refusals to typed problems`

### Task 4.2: Concealment

- [ ] **Step 1: Write the failing test.** `TestMapper_ConcealsWhatStatusConceals` renders, through `h.Write` on an `httptest` request to `/login`, three errors:
  - `authenticate.ErrAuthenticationFailed`;
  - `errors.Join(authenticate.ErrAuthenticationFailed, lockout.ErrAccountLocked)`;
  - `diag`-style `authenticate.ErrUnavailable` wrapping `errConn`.

  It asserts the three bodies are identical. Disclosed `lockout.ErrAccountLocked` alone gives 429 `account-locked`.
- [ ] **Step 2: Check the test bites.** Temporarily give `ErrUnavailable` a 401 type of its own, run, and see the test fail. Then revert by editing the code back.
- [ ] **Step 3: Run.** Expect PASS.
- [ ] **Step 4: Commit.** `test(prblmsec): problems never separate concealed refusals`

### Task 4.3: Extension members

- [ ] **Step 1: Write the failing test.** `TestMapper_Members` is a table test. Cases:
  - `methods`: two `httpsec.MFAMethod`s give `methods` equal to `[{"name":"totp","channel":"authenticator-app","begins":false},{"name":"passkey",…,"begins":true}]`. Use the actual `factor.Channel` constant values;
  - `empty methods`: gives `[]`;
  - `nil methods`: the member is absent;
  - `consumer kind`: gives `challenge == kind.String()` and no panic, with `Session` nil;
  - `max_age`: `&httpsec.ReauthenticationRequiredError{Window: 5*time.Minute}` gives 300;
  - `zero window`: the member is absent;
  - `rule`: `password.RejectedError{Rule: password.RuleBreached}` gives `rule == string(password.RuleBreached)`;
  - `typed nil challenge`: `(*httpsec.ChallengeError)(nil)` wrapped gives no panic and no members;
  - `no text leaks`: a cause quoting `alice@example.com` is absent from the marshalled JSON;
  - `xml encodes members`: rendering with `Accept: application/problem+xml` gives no `ErrEncoding` note.

  Expected red: the members are not set yet.
- [ ] **Step 2: Implement.** Set the members with `Problem.Set`. All names are fixed and valid, so `Set` cannot fail at run time. Prove that once at construction: `New` sets every member name on a throwaway problem and returns `ErrConfig` if any is refused. The mapper then ignores `Set`'s error, with a comment pointing at that check (`defensive-coding.md`: the failure is handled at construction, not swallowed).
- [ ] **Step 3: Run.** Expect PASS.
- [ ] **Step 4: Commit.** `feat(prblmsec): safe extension members`

### Task 4.4: Challenge token

- [ ] **Step 1: Write the failing test.** `TestMapper_ChallengeToken` is a table test. Cases:
  - `bearer`: `access_token == tok`, `token_type == "Bearer"`, and the problem header `Cache-Control: no-store`;
  - `dpop`: gives `"DPoP"`;
  - `no token`: neither member;
  - `token without type`: `access_token` only;
  - `withheld` (`WithoutChallengeToken()`): neither member, with `methods` still present.
- [ ] **Step 2: Implement.** Use `WithHeader("Cache-Control", "no-store")` on token-bearing problems only.
- [ ] **Step 3: Run.** Expect PASS.
- [ ] **Step 4: Commit.** `feat(prblmsec): deliver the challenge credential, opt-out`

### Task 4.5: Deferral and override

- [ ] **Step 1: Write the failing test.** `TestMapper_DefersUnrecognised` is a table test over full `prblm.Handler` responses. Cases:
  - `app error after integration` gives 404 from `prblm.Status(errApp, 404)`;
  - `unknown` gives 500 with no detail;
  - `recognised failure not remapped`: `password.ErrHistoryUnavailable` wrapping `errFake`, with a later `prblm.Status(errFake, 503)`, gives 500;
  - `consumer override first`: a `prblm.Is(lockout.ErrAccountLocked, …429 + Retry-After: 900)` mapper registered ahead gives that problem, while a wrong password gives `authentication-failed`.

  Add a `parallel` subtest that resolves 100 concurrent errors with one `*Problems`. Run it with `-race`.
- [ ] **Step 2: Run.** `go test -race -run TestMapper_Defers -count=1 ./...`. Expected: PASS. A failure here goes back to Task 4.1's logic.
- [ ] **Step 3: Commit.** `test(prblmsec): unrecognised errors are left to prblm`

### Task 4.6: Godoc for exported identifiers

- [ ] **Step 1:** Write a doc comment for every exported identifier in `prblmsec`. `WithTypePrefix` names its default (`security`), `WithoutChallengeToken` names its default (token delivered), and `ErrConfig` lists what it refuses.
- [ ] **Step 2:** In the module, run `go doc -all ./ && go vet ./... && test -z "$(gofmt -l .)" && golangci-lint run`. Expected: clean, with no undocumented exported symbol.
- [ ] **Step 3: Commit.** `docs(prblmsec): document exported identifiers`

### Task 5.1: `ginsec.WithRefusalsRendered`

**Files:**
- Create: `httpsec/ginsec/options.go`
- Modify: `httpsec/ginsec/middleware.go` (`Middleware`; `refuse` at lines 154–167)
- Test: `httpsec/ginsec/middleware_rendered_test.go`

**Interfaces:**
- Produces:
  - `type Option func(*config)`
  - `func WithRefusalsRendered() Option`
  - `func Middleware(chain *httpsec.Chain, opts ...Option) gin.HandlerFunc`

  `config` holds `refusalsRendered bool`. A nil `Option` is skipped, and a repeated option sets the same bool.

- [ ] **Step 1: Write the failing test.** `TestMiddleware_RefusalsRendered` is a table test with fields `opts []ginsec.Option`, `errorMiddleware bool`, `path string` and `assert func(t, rec *httptest.ResponseRecorder, handlerRan bool)`. It uses a chain with OIDC login enabled and one provider, `known`. When `errorMiddleware` is true, an error middleware is registered before `ginsec` that writes `{"error":"rendered"}` with `Content-Type: application/json` and the current status after `c.Next()` if `len(c.Errors) > 0` and nothing was written. Cases:
  - `default, no middleware`: `/sso/login/nope` gives 404 and an empty body;
  - `declared, middleware`: gives 404, body `{"error":"rendered"}`, `Content-Type` `application/json`;
  - `declared, no middleware`: gives 404, body `404 page not found`, `handlerRan == false`;
  - `declared, matched route`: a route `GET /v1/admin` behind a rule denying everyone, with no middleware, gives 403 and an empty body (unchanged);
  - `declared, unrouted 400`: a request refused 400 on an unrouted path, for example a dot segment, gives 400 left open (unchanged);
  - `twice`: the option given twice equals once;
  - `nil option`: `[]ginsec.Option{nil}` equals the default.
- [ ] **Step 2: Watch it fail.** Add `Option`, `WithRefusalsRendered` and the variadic parameter, all with no effect. Run `go test -race -run TestMiddleware_RefusalsRendered -count=1 ./...` in `httpsec/ginsec`. Expected: FAIL on `declared, middleware` (empty body) and `declared, no middleware` (empty instead of gin text).
- [ ] **Step 3: Implement.** Thread `config` from `Middleware` to `refuse`, and skip `gc.Writer.WriteHeaderNow()` when `refusalsRendered` is set.
- [ ] **Step 4: Run** the focused test, then `go test -race -count=1 ./...` in `httpsec/ginsec`, then `go test -run Gin -count=1 ./` in `test/`. Expected: PASS, with the settled "Not-found refusal on an unrouted path" behaviour unchanged.
- [ ] **Step 5: Commit.** `feat(ginsec): WithRefusalsRendered leaves unrouted 404s to the error middleware`

### Task 5.2: `ginsec` godoc for the option

- [ ] **Step 1:** Write the godoc:
  - `WithRefusalsRendered`: the default it replaces (an empty 404 on paths gin has no route for); the declaration; registering the error middleware before `ginsec.Middleware`; and what breaking it costs (gin's `404 page not found` text, which carries no refusal text);
  - `Middleware`'s and `doc.go`'s "Refusals" sections name it.
- [ ] **Step 2:** In `httpsec/ginsec`, run `go doc . WithRefusalsRendered && go vet ./... && test -z "$(gofmt -l .)" && golangci-lint run`. Expected: clean.
- [ ] **Step 3: Commit.** `docs(ginsec): document WithRefusalsRendered`

### Task 6.1: Three-framework parity

**Files:** Create `test/problem_parity_test.go`. Modify `test/go.mod`.

- [ ] **Step 1:** Run `go get github.com/kartaladev/prblm/adapters/ginprblm@v0.2.0 github.com/kartaladev/prblm/adapters/fiberprblm@v0.2.0` in `test/`.
- [ ] **Step 2: Write the failing test.** `TestProblemParity` is a table over cases, and each case runs on `nethttp`, `gin` and `fiber` servers built from one chain configuration with Basic, form login with MFA, bearer and DPoP. Cases:
  - `unauthenticated`;
  - `mfa challenge`, which carries `access_token` and `Cache-Control: no-store`;
  - `basic failure`, where `WWW-Authenticate` starts with `Basic` and appears exactly once;
  - `dpop nonce`, with both `DPoP-Nonce` and the `WWW-Authenticate: DPoP` challenge present;
  - `unknown handler error`, which is prblm's 500;
  - `chain endpoint 404`: `GET /sso/login/nope` (an unregistered provider) and `POST /mfa/verify/nope`. With `ginsec.WithRefusalsRendered()` on the gin server, all three give the 404 `security/not-found` problem;
  - `chain endpoint 404, gin undeclared`: the same requests on a second gin server without the option give 404 and an empty body;
  - `matched-route 404`: a guard refusing with a not-found refusal on a gin route the consumer registered gives the `not-found` problem on all three.

  For each case except `chain endpoint 404, gin undeclared`, assert that the status, JSON body and the listed headers are equal across the three frameworks. Expected red before the wiring helpers exist: the gin and fiber servers answer the bare-status defaults.
- [ ] **Step 3: Implement the per-framework server helpers** in the same file: gin uses `ginprblm.Middleware(...)` before `ginsec.Middleware(chain, ginsec.WithRefusalsRendered())`, and fiber uses `fiber.Config{ErrorHandler: fiberprblm.ErrorHandler(...)}`.
- [ ] **Step 4: Run.** `go test -run TestProblemParity -count=1 ./` in `test/`. Expected: PASS. If fiber drops a header, stop and report; the design said to go back to the user.
- [ ] **Step 5: Commit.** `test: problem rendering is the same on net/http, gin and fiber`

### Task 6.2: Guard parity

- [ ] **Step 1: Write the failing test.** `TestProblemParity_GuardRefusal` uses a privilege guard refusing on each framework, with the net/http guard built with `WithGuardErrorHandler(h.Write)`. It asserts an `access-denied` 403 problem equal to the chain's for the same error. Expected red: the bare guard default on net/http.
- [ ] **Step 2: Implement the wiring, then run.** `go test -run TestProblemParity_Guard -count=1 ./`. Expected: PASS.
- [ ] **Step 3: Commit.** `test: guard refusals render as the chain's`

### Task 6.3: Core stays prblm-free

- [ ] **Step 1: Write the failing test.** Add `github.com/kartaladev/prblm` to the forbidden lists in `TestCoreDependencies` and `TestConsumerModuleGraph` (`layout_test.go`). To see it fail, temporarily add `require github.com/kartaladev/prblm v0.2.0` to the root `go.mod`, run, and confirm the failure names the module. Then remove it by editing the file back.
- [ ] **Step 2: Run.** `go test -run 'TestCoreDependencies|TestConsumerModuleGraph' -count=1 .`. Expected: PASS.
- [ ] **Step 3: Commit.** `test(layout): the core never requires prblm`

### Task 7.1: Runnable examples

**Files:** Create `httpsec/prblmsec/example_test.go`.

**Interfaces:** Consumes `New`, `WithTypePrefix`, `WithoutChallengeToken`, `Problems.Mapper`, `Problems.Types` and `Problems.Option` (Tasks 3.1–4.4).

- [ ] **Step 1: Write the examples.** Each has an `// Output:` block written from the spec, printing the status, the `type` and the members it shows:
  - `Example_netHTTP` prints `401 /v1/probs/security/authentication-required`;
  - `Example_challengedLogin` prints `401 /v1/probs/security/mfa-required`, the `methods` names, `token_type Bearer` and `Cache-Control no-store`;
  - `ExampleWithTypePrefix` prints `/v1/probs/auth/access-denied`;
  - `ExampleWithoutChallengeToken` prints the `mfa-required` problem, with `access_token` absent;
  - `ExampleProblems_Mapper` registers `prblm.WithTypes(p.Types()...)` and `prblm.WithMappers(p.Mapper(), prblm.Status(errVesselNotFound, 404))`, and prints `404 about:blank` for the app error;
  - `Example_override` registers `prblm.Is(lockout.ErrAccountLocked, …)` ahead of `p.Option()` and prints `429 Retry-After 900`, then `401 /v1/probs/security/authentication-failed` for a wrong password.

  Each example drives the chain with `httptest`.
- [ ] **Step 2: Check each example bites.** Change one expected line, run `go test -run Example -count=1 ./...`, and see the output diff. Then edit it back.
- [ ] **Step 3: Run.** Expected: PASS.
- [ ] **Step 4: Commit.** `docs(prblmsec): runnable examples`

### Task 7.2: Package overview

**Files:** Modify `httpsec/prblmsec/doc.go`.

- [ ] **Step 1:** Write the package overview, with these godoc `#` sections in order:
  - **What it provides:** `Mapper`, `Types` and `Option`, and that the handler, encoding, headers, hooks and adapters are prblm's.
  - **net/http:** mirrors `Example_netHTTP`.
  - **gin:** `ginprblm.Middleware(opts...)` before `ginsec.Middleware(chain, ginsec.WithRefusalsRendered())`, and no `httpsec.WithErrorHandler`. Marked "Mirrors TestProblemParity".
  - **fiber:** `fiber.Config{ErrorHandler: fiberprblm.ErrorHandler(opts...)}` in place of `fibersec.ErrorHandler`. Marked "Mirrors TestProblemParity".
  - **Problem types:** the spec's table, and that status equals `httpsec.StatusForError`.
  - **Extension members.**
  - **The challenge credential:** on by default, `WithoutChallengeToken`, and that hooks see `access_token`.
  - **Ordering and overrides.**
  - **Namespaces:** always set one.
  - **Stated limits:**
    - ports must not return a `prblm.Describer` or `*prblm.Problem`;
    - on gin, leaving out `ginsec.WithRefusalsRendered()` gives the chain's own 404s an empty body;
    - context errors scrty does not recognise are prblm's to map.
- [ ] **Step 2:** Run `go doc ./` in the module. Expected: every section is shown. Record, for the reviewer, the test or example each snippet mirrors.
- [ ] **Step 3: Commit.** `docs(prblmsec): package overview`

### Task 7.3: README section

**Files:** Modify `README.md`, adding the new section after "Security events" and before "Known limitations".

- [ ] **Step 1:** Write `## Problem details (RFC 9457)`, with subsections:
  - "Install": `go get github.com/kartaladev/scrty/httpsec/prblmsec@<lockstep version>`, beside prblm;
  - "Wiring": net/http, gin and fiber, each snippet ending with an italic mirror note such as *(Mirrors `Example_netHTTP`.)*;
  - "Customising": prefix, withholding the token, a consumer override;
  - "What a client receives": a challenged-login response from `Example_challengedLogin`;
  - "Problem types": the table;
  - "Defaults";
  - "Stated limits", the same three as Task 7.2.
- [ ] **Step 2:** Run `git grep -n "## Problem details (RFC 9457)" README.md`. Expected: one hit, and every mirror note names an existing example or test.
- [ ] **Step 3: Commit.** `docs(readme): rendering refusals as problem details`

### Task 7.4: Cross-references

**Files:** Modify `httpsec/doc.go`, the `WithErrorHandler` godoc, `httpsec/ginsec/doc.go`, `httpsec/fibersec/doc.go`, the `fibersec.MapError` godoc, and `README.md`.

- [ ] **Step 1:** Add the pointers:
  - `httpsec` "Failing closed" and `WithErrorHandler`: one sentence naming `prblmsec` as the ready-made RFC 9457 renderer;
  - `ginsec` "Refusals": names `ginprblm` with `prblmsec` and `WithRefusalsRendered`;
  - `fibersec` "Refusals" and `MapError`: name `fiberprblm.ErrorHandler` with `prblmsec`;
  - the README MFA passage (around line 764) on delivering `ce.Token`: `prblmsec` does it by default;
  - the README Modules table and install list: add the module.
- [ ] **Step 2:** Run `git grep -n prblmsec httpsec/doc.go httpsec/errors.go httpsec/ginsec/doc.go httpsec/fibersec/doc.go README.md`, plus `go vet ./... && test -z "$(gofmt -l .)"` in the three modules. Expected: a hit in each file, and clean. If `WithErrorHandler`'s godoc lives elsewhere, locate it with gopls and grep that file instead.
- [ ] **Step 3: Commit.** `docs: point consumers to prblmsec where rendering is discussed`

### Task 8.1: Layout lists and Dependabot

- [ ] **Step 1: Write the failing tests.** Add `httpsec/prblmsec` and package `prblmsec` to the expectations of `TestIntegrationModulesUnderTheirConcept`, `TestNoUnlistedIntegrationModule` and `tools/repocheck`. Run them, and expect FAIL until Dependabot and the lists agree.
- [ ] **Step 2: Implement.** Add a `.github/dependabot.yml` gomod entry for `/httpsec/prblmsec`, in the same shape as `/httpsec/ginsec`.
- [ ] **Step 3: Run.** `go test -count=1 ./...` in `tools/`, then `go test -run 'TestModuleLayout|TestIntegrationModules|TestNoUnlisted|TestGoWork' -count=1 .`. Expected: PASS.
- [ ] **Step 4: Commit.** `chore: list httpsec/prblmsec in layout checks and Dependabot`

### Task 8.2: Release docs

- [ ] **Step 1:** Add `httpsec/prblmsec` to `RELEASING.md`'s module and tag lists. Add `CHANGELOG.md` Unreleased → Added entries for the module, `httpsec.LookupStatus`, `httpsec.ChallengeError.TokenType` and `ginsec.WithRefusalsRendered`. Under Changed, note that `ginsec.Middleware` is now variadic.
- [ ] **Step 2:** Run `git grep -n prblmsec RELEASING.md CHANGELOG.md .github/dependabot.yml go.work`. Expected: a hit in each file.
- [ ] **Step 3: Commit.** `docs: release lists and changelog for prblmsec`

### Task 8.3: Whole-tree gate

- [ ] **Step 1:** Run, expecting every command clean:
  - `go work sync`;
  - in each workspace module, `go vet ./... && go test -race -count=1 ./...`;
  - `gofmt -l .`, with empty output;
  - `govulncheck ./...` in `httpsec/prblmsec` and `test`.

### Task 9.1: Whole-branch review

- [ ] **Step 1:** Dispatch a fresh Opus reviewer with the five spec deltas, the consumer documentation (Tasks 7.1–6.4), `design.md` (its decisions and failure-mode table), and `git diff origin/main...HEAD`. It enumerates failures category by category before judging (`defensive-coding.md`), and marks claimed defects `REPRODUCED` or `UNREPRODUCED` (`defect-claims.md`).
- [ ] **Step 2:** Send each finding to a fresh dispatch of its owning task's group, then re-run Task 8.3. Expected: the review is clean and the gate is green.
