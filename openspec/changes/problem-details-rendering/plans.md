# Problem-Details Rendering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the opt-in module `github.com/kartaladev/scrty/httpsec/prblmsec`, which maps every refusal scrty recognises to a typed RFC 9457 problem through `github.com/kartaladev/prblm`. Two core additions support it: `httpsec.LookupStatus` and `ChallengeError.TokenType`.

**Architecture:**
- **Core.** It gains a comma-ok status lookup, with `StatusForError` built on it, and a token type on challenge errors.
- **Mapper.** The new module's mapper takes the status from the lookup, then picks a type only among the types of that status. That is what keeps the core's concealment intact. It returns nil for errors the core does not recognise.
- **gin.** `ginsec.Middleware` gains a variadic `WithRefusalsRendered()` option, so an error middleware that writes immediately can render the chain's own 404s on paths gin has no route for. `ginprblm` defers the header and renders them with or without it (design decision 10, finding of 2026-11-18).
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

### Task 2.5: A credential-carrying refusal is never cacheable

**Files:** Modify the sites that return a `ChallengeError` with a `Token` (expected `httpsec/complete.go`, `httpsec/mfa_verify.go` ×2; confirm with gopls references) and the `ChallengeError.Token` godoc. Test: a new `_test.go` in `httpsec` beside the existing challenge-error tests.

**Interfaces:** Produces the guarantee Task 6.4 tests across frameworks: after a token-bearing challenge refusal, the response header `Cache-Control` is exactly `no-store`, whatever was set before.

- [ ] **Step 1: Write the failing test.** `TestChallengeToken_NoStore` (table, `assert` closures, `t.Context()`), over a real chain with a recording error handler and an outer middleware setting `Cache-Control: public, max-age=300`. Cases: bearer challenged login → `[]string{"no-store"}`; MFA verify raising a token-bearing challenge → `[]string{"no-store"}`; DPoP-bound challenged login → `[]string{"no-store"}`; password-change gate (no token) → `[]string{"public, max-age=300"}`.
- [ ] **Step 2: Watch it fail.** `go test -run TestChallengeToken_NoStore -count=1 ./httpsec/`. Expected: FAIL on the three token-bearing cases with `[public, max-age=300]`; the no-token case passes.
- [ ] **Step 3: Implement.** At each site, before returning the refusal, call the exchange writer's replacing header set: `Cache-Control` = `no-store`. Add to `ChallengeError.Token`'s godoc that the chain sets `no-store` and a consumer error handler must keep it.
- [ ] **Step 4: Run.** `go test -race -run 'TestChallengeToken_NoStore|Challenge' -count=1 ./httpsec/`, then `go test -race -count=1 ./httpsec/...`. Expected: PASS.

### Task 2.6: The challenge walks keep `errors.As` semantics

**Files:**
- Modify `httpsec/errors.go`: `firstChallenge` (around line 289).
- Modify `httpsec/prblmsec/mapper.go`: the generic `firstNonNil[T]` (around line 345) and the comment above it.
- Test: a table test in each package, beside the existing typed-nil tests (`httpsec/lookup_status_internal_test.go`, `httpsec/prblmsec/members_test.go`).

**Interfaces:**
- Signatures stay the same: `firstChallenge(err error) *ChallengeError` and `firstNonNil[T](err error) T`.
- Invariant: both walks pick the same challenge for every error, because the mapper's members must come from the challenge whose kind decided `LookupStatus`'s status. Keep `maxChallengeWalkDepth` and `maxWalkDepth` at 100.

- [ ] **Step 1: Write the failing tests.** The test fixture is `asChallenge`, a test-only error type whose `As(target any) bool` sets `*target` to a fixed `*ChallengeError` (kind `policy.ChallengeMFA`) and which has no `Unwrap`.
  - `httpsec`: `TestStatusForError_ChallengeWalk` (table, `assert` closures). Cases:
    - `asChallenge` gives `StatusForError` 401 and `LookupStatus` `(401, true)`;
    - `errors.Join((*ChallengeError)(nil), realChallenge)` gives 401 and finds the real one;
    - a challenge under 101 `fmt.Errorf("w: %w", …)` layers gives 401, because `errors.As` has no depth limit;
    - `errors.Join((*ChallengeError)(nil), <challenge under 99 wraps>)` gives 401, because the fallback walk finds it at depth 100;
    - the same join with 100 wraps gives `LookupStatus` `ok == false` and `StatusForError` 500, with no panic;
    - `errors.Join((*ChallengeError)(nil), asChallenge)` gives 500, the accepted outcome;
    - a chain joining `asChallenge` and a direct challenge gives the first in `errors.As` order.
  - `prblmsec`: `TestMapper_ChallengeWalk`, the same cases.
    - The mapper's status equals `httpsec.StatusForError(err)` in each case.
    - `asChallenge` gives the type for its kind, and its members.
- [ ] **Step 2: Watch it fail.** Run `go test -run 'TestStatusForError_ChallengeWalk' -count=1 ./httpsec/` and `go -C httpsec/prblmsec test -run TestMapper_ChallengeWalk -count=1 ./...`. Expected: FAIL on the `As` cases (500 where 401 or 403 is wanted), on the joined `As`-plus-direct case (the direct one's status) and on the 101-wrap case (500). The typed-nil and fallback-depth cases pass and pin today's behaviour.
- [ ] **Step 3: Implement.** In each walk:
  1. First try `errors.As(err, &v)` and return `v` if it is non-nil (for `firstNonNil`, if `v != zero`).
  2. Otherwise fall back to the existing nil-skipping walk.
  3. Update the godoc. It must stop saying "no As methods". It says the walk honours `As` methods through `errors.As`, steps over a typed nil, and is bounded at depth 100 for the fallback.
- [ ] **Step 4: Run.** Run `go test -race -run 'Challenge|LookupStatus|StatusForError' -count=1 ./httpsec/`, `go -C httpsec/prblmsec test -race -count=1 ./...` and `go -C test test -race -run TestProblemParity -count=1 ./`. Expected: PASS.
- [ ] **Step 5: Commit.** `fix(httpsec,prblmsec): challenge walks honour As methods again`, with a CHANGELOG `Fixed` line if the regression is visible from a published version. It is not: the walk is new on this branch, so no line is needed.

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
  - `chain endpoint 404, gin undeclared`: the same requests on a second gin server with `ginprblm.Middleware` and without the option give the same 404 `security/not-found` problem as the declared case. Red for this case: first assert the old empty-body expectation and see it fail with the rendered problem;
  - `chain endpoint 404, gin no renderer`: the same requests on a third gin server with no error middleware and no option give 404 and an empty body (the `framework-adapters` default);
  - `matched-route 404`: a guard refusing with a not-found refusal on a gin route the consumer registered gives the `not-found` problem on all three.

  For each case except `chain endpoint 404, gin no renderer`, assert that the status, JSON body and the listed headers are equal across the three frameworks. Expected red before the wiring helpers exist: the gin and fiber servers answer the bare-status defaults.
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

### Task 6.4: Parity with an upstream cache policy, and the matched-route 404 without the option

**Files:** Modify `test/problem_parity_test.go`.

**Interfaces:** Consumes Task 2.5 (the core sets `Cache-Control: no-store` on token-bearing challenges) and the existing `ginMode` values `ginRendered`, `ginProblemsOnly`, `ginNoRenderer`.

- [ ] **Step 1: Write the failing test.** Add a case `challenged login under an upstream cache policy`: each framework's server registers, ahead of the chain, a middleware setting `Cache-Control: public, max-age=300`. Assert on all three: `access_token` present and `r.header.Values("Cache-Control")` equals `[]string{"no-store"}`. Add `extraGin: []ginMode{ginProblemsOnly}` to the existing matched-route not-found guard case.
- [ ] **Step 2: Watch it fail.** With Task 2.5's header set temporarily removed (or before it lands), run `go test -run TestProblemParity -count=1 ./` in `test/`. Expected: FAIL on the new case with `[public, max-age=300]`. Restore by editing.
- [ ] **Step 3: Run.** `go test -race -run TestProblemParity -count=1 ./` in `test/`. Expected: PASS.
- [ ] **Step 4: Commit** together with Task 2.5.

### Task 7.1: Runnable examples

**Files:** Create `httpsec/prblmsec/example_test.go`.

**Interfaces:** Consumes `New`, `WithTypePrefix`, `WithoutChallengeToken`, `Problems.Mapper`, `Problems.Types` and `Problems.Option` (Tasks 3.1–4.4).

- [ ] **Step 1: Write the examples.** Each has an `// Output:` block written from the spec, printing the status, the `type` and the members it shows:
  - `Example_netHTTP` prints `401 /v1/probs/security/authentication-required`;
  - `Example_challengedLogin` prints `401 /v1/probs/security/mfa-required`, the `methods` names, `token_type Bearer` and `Cache-Control no-store`;
  - `ExampleWithTypePrefix` prints `/probs/auth/access-denied` (namespace `/probs`, prefix `auth`);
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
  - **gin:** `ginprblm.Middleware(opts...)` before `ginsec.Middleware(chain)`, no option needed, and no `httpsec.WithErrorHandler`. Marked "Mirrors TestProblemParity".
  - **fiber:** `fiber.Config{ErrorHandler: fiberprblm.ErrorHandler(opts...)}` in place of `fibersec.ErrorHandler`. Marked "Mirrors TestProblemParity".
  - **Problem types:** the spec's table, and that status equals `httpsec.StatusForError`.
  - **Extension members.**
  - **The challenge credential:** on by default, `WithoutChallengeToken`, and that hooks see `access_token`.
  - **Ordering and overrides.**
  - **Namespaces:** always set one.
  - **Stated limits:**
    - ports must not return a `prblm.Describer` or `*prblm.Problem`;
    - on gin, `ginprblm` renders the chain's own 404s with or without `ginsec.WithRefusalsRendered()`; the option is for a consumer's own error middleware that writes immediately, and gin with no renderer at all gives those 404s an empty body;
    - context errors scrty does not recognise are prblm's to map.
- [ ] **Step 2:** Run `go doc ./` in the module. Expected: every section is shown. Record, for the reviewer, the test or example each snippet mirrors.
- [ ] **Step 3: Commit.** `docs(prblmsec): package overview`

### Task 7.3: README section

**Files:** Modify `README.md`, adding the new section after "Security events" and before "Known limitations".

- [ ] **Step 1:** Write `## Problem details (RFC 9457)`, with subsections:
  - "Install": `go get github.com/kartaladev/scrty/httpsec/prblmsec@<lockstep version>`, beside prblm;
  - "Wiring": net/http, gin (`ginprblm.Middleware` before `ginsec.Middleware(chain)`, no option) and fiber, each snippet ending with an italic mirror note such as *(Mirrors `Example_netHTTP`.)*;
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
  - `ginsec` "Refusals": names `ginprblm` with `prblmsec`, says it needs no option, and points users of an error middleware that writes immediately to `WithRefusalsRendered`;
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

---

## Group 10: one bounded, recovering walk (design decision 11)

**Spec for this group:** design.md decision 11 and its failure rows, and the `http-error-propagation` delta's two requirements: "Classifying an error never hangs, crashes or panics" and "An aborted classification is logged".

**Constants pinned by the spec:**
- The budget is 1,000 examined entries. It counts the root, repeats, nil entries and typed nils, and the 1,001st aborts. Pending entries count too: when the list plus the pending entries would pass 1,000, the walk aborts at once.
- A panicking `==` and `panic(nil)` both abort with `panic`. An aborted walk returns no list.
- The typed-nil test is `reflect` Kind `Pointer` and `IsNil`.
- The log reasons are `budget` and `panic`.
- The log record carries no error text.

**Order:**
1. 10.1.
2. 10.2, then 10.3 (same files). 10.5 runs in parallel with both.
3. 10.10, after 10.2, 10.3 and 10.5. It touches errwalk, diag, the core's log helper and fibersec's.
4. 10.9 and 10.4 in parallel: 10.9 owns the core refusal-path files, and 10.4 owns prblmsec.
5. 10.9a, after 10.9.
6. 10.12, in sequential dispatches by group, after 10.9a. These share the core.
7. 10.13, in parallel with 10.12. It only adds `_test.go` benchmark files, plus an export of `main`.
8. 10.11, after 10.4 and once nothing else is running `test/`. It changes prblmsec's go.mod and the test module.
9. 10.6, then 10.7, then 10.8.

**Review Focus:** the five things most likely to go wrong, each pinned to a task.
1. **One request logging twice.** The chain's dispatch and an auxiliary classification on the same request (events, guards) both call the lookup. 10.3 asserts the total count across both loggers.
2. **A flood of records.** A hostile error recurs on every request. The chain's record goes through the chain's existing log sampler, and 10.3 asserts that a second identical abort inside the sampling window writes nothing.
3. **fibersec classifying one refusal more than once per request.** 10.5 asserts one record per dispatch.
4. **The mapper and the lookup disagreeing on a hostile chain**, because they walk separately. 10.4 asserts agreement case by case.
5. **A typed nil inside an `As` method's result**, where an `As` sets its target to a nil pointer. It counts as no match, and the scan continues. 10.1's `TestMatch` covers it.

### Task 10.1: `internal/errwalk`

**Files:** Create `internal/errwalk/errwalk.go`. Test: `internal/errwalk/errwalk_test.go`.

**Interfaces:**
- Produces:
  - `const Budget = 1000`.
  - `var ErrBudget, ErrPanic error`. They never reach consumers.
  - `type PanicError struct{ Value any }`. `Error()` is fixed text and does not include the value. `Unwrap()` returns `ErrPanic`.
  - `type Chain []error`.
  - `func Flatten(err error) (Chain, error)`. The returned error is nil, wraps `ErrBudget`, or is a `*PanicError`.
  - `func Is(c Chain, target error) (bool, error)`.
  - `func As[T error](c Chain) (T, bool, error)`.
  - `func Reason(abort error) string`, which returns `"budget"`, `"panic"` or `""`.

- [ ] **Step 1: Write the failing tests.**
  - `TestFlatten` is a table with `assert` closures. It covers the cases in tasks.md 10.1, using these test-only fixtures:
    - `cycleOne`, whose `Unwrap() error` returns itself;
    - `cycleMany`, whose `Unwrap() []error` contains itself;
    - `fanout(n)`, which is `errors.Join(f, f)` nested n levels;
    - `bomb`, a pointer type whose every method panics, used as a typed nil to prove nothing is called;
    - `panicUnwrap`.
  - Budget rows: a linear chain of 1,000 nodes succeeds with `len == 1000`. One of 1,001 nodes gives `errors.Is(abort, ErrBudget)`.
  - Cycle and fan-out rows run under a 2 s deadline. The fan-out row asserts it takes under 100 ms.
  - `TestMatch` is a table:
    - `Is` matches by `==` and by an `Is` method.
    - `As` matches by type and by an `As` method, first in list order.
    - An `As` that sets its target to a nil pointer gives no match, and the scan continues.
    - A panicking `Is` or `As` gives a `*PanicError` carrying the panic value.
- [ ] **Step 2: Watch it fail.** First add stubs that return zero values, so the package compiles. Then run `go test -run 'TestFlatten|TestMatch' -count=1 ./internal/errwalk/`. Expected: the order, budget and abort rows FAIL on their assertions.
- [ ] **Step 3: Implement.**
  - Walk with an explicit stack, not recursion, so nodes come out in list order.
  - Count every visit.
  - Run the reflect nil-pointer check before calling any method on a node.
  - Wrap each `Unwrap`, `Is` and `As` call in a small helper that uses `recover`.
- [ ] **Step 4: Run.** `go test -race -count=1 ./internal/errwalk/`. Expected: PASS.
- [ ] **Step 5: Commit.** `feat(errwalk): one bounded, recovering walk over an error chain`.

### Task 10.2: Core lookup over the walk

**Files:**
- Modify `httpsec/errors.go`: `LookupStatus` changes, and `firstChallenge` and `findChallenge` are removed.
- Test: `httpsec/lookup_hostile_test.go`. Also update `httpsec/challenge_walk_test.go`.

**Interfaces:**
- Consumes 10.1.
- Produces `func lookup(err error) (status int, ok bool, abort error)`. It is unexported and never logs.
- `LookupStatus` and `StatusForError` keep their signatures.

- [ ] **Step 1: Write the failing test.** `TestLookupStatus_HostileChains` is a table with the cases in tasks.md 10.2. Each case asserts `(status, ok)`. The fixtures are test-only copies of 10.1's.
- [ ] **Step 2: Watch it fail.**
  - Run the cycle and fan-out rows: `go test -run 'TestLookupStatus_HostileChains' -count=1 -timeout 30s ./httpsec/`. Expected: a timeout, or `fatal error: stack overflow`.
  - Then run the panic and typed-nil rows on their own. Expected: an escaped panic, or a wrong status.
  - Report both outputs.
- [ ] **Step 3: Implement.**
  - `lookup` flattens the chain once. If the walk aborts, it returns `(500, false, abort)`.
  - Otherwise it runs every existing check, in the same order, using `errwalk.Is` and `errwalk.As` over the chain.
  - A match call that aborts is handled the same way.
  - `LookupStatus` calls `lookup`. The logging is added in 10.3.
- [ ] **Step 4: Update `TestStatusForError_ChallengeWalk`.** Its rows for a challenge behind a typed nil, at increasing depth, now find the challenge, so replace them with rows at the 1,000 and 1,001 budget boundary.
- [ ] **Step 5: Run.** `go test -race -run 'LookupStatus|StatusForError|Challenge' -count=1 ./httpsec/`, then `go test -race -count=1 ./httpsec/...`. Expected: PASS, with the agreement and inventory tests unchanged.
- [ ] **Step 6: Commit** together with 10.3.

### Task 10.3: Reporting an aborted classification

**Files:**
- Modify `httpsec/errors.go` (`LookupStatus`) and `httpsec/nethttp.go` (`handleError`).
- Modify every other in-package caller of `StatusForError` and `LookupStatus`.
- Test: `httpsec/lookup_abort_log_test.go`.

**Interfaces:**
- Consumes `lookup` from 10.2.
- Produces the constant `msgClassificationAborted = "httpsec: error classification aborted"` and the attribute key `reason`.

- [ ] **Step 1: Inventory the callers.** Find them with gopls references, and classify each one:
  - **dispatch** callers set the response status: the default branch of `handleError`, and `refuse` in `guards.go`;
  - **auxiliary** callers classify for their own purposes: events, signals, basic, oidc_consents.

  Report the list.
- [ ] **Step 2: Write the failing tests.**
  - `TestLookupStatus_AbortIsLogged` must not run in parallel, because it swaps `slog.Default()` for a recording handler.
    - A cyclic error writes exactly one Error record with `reason=budget`, and the record does not contain the fixture's error text.
    - A panicking `Is` writes one record with `reason=panic`.
  - `TestChain_AbortLogsToChainLogger` builds a chain with `WithLogger(recording)`, and an interceptor returns a cyclic error through the default error handler. It asserts:
    - the response is 500;
    - exactly 1 record goes to the chain logger and 0 to the default;
    - a second identical request inside the sampling window adds no record.
- [ ] **Step 3: Watch it fail.** `go test -run 'Abort' -count=1 ./httpsec/`. Expected: FAIL, with 0 records.
- [ ] **Step 4: Implement.**
  - `LookupStatus` logs to `slog.Default()` when the lookup aborts. For a `*errwalk.PanicError`, the record carries `diag.PanicAttrs(v)`.
  - Dispatch sites call `lookup`. They log through the chain's logger with `logSampled`, under the key `classification-aborted`. Guards have no chain logger, so they log to the default.
  - Auxiliary sites call `lookup` and ignore the abort, so one request writes one record.
- [ ] **Step 5: Run.** `go test -race -count=1 ./httpsec/...`. Expected: PASS.
- [ ] **Step 6: Commit 10.2 and 10.3.** `fix(httpsec): classifying an error never hangs, crashes or panics`.

### Task 10.4: Mapper over the walk

**Files:**
- Modify `httpsec/prblmsec/mapper.go`: `mapError`, the specifics loop and `ruleOf` change, and `firstNonNil` and `walk` are removed.
- Test: `httpsec/prblmsec/hostile_test.go`. Also update `challenge_walk_test.go`.

**Interfaces:** consumes 10.1, plus `httpsec.LookupStatus` as changed by 10.2 and 10.3.

- [ ] **Step 1: Write the failing test.** `TestMapper_HostileChains` is a table that calls `p.Mapper().MapError(t.Context(), err)` directly, never through `prblm.Respond`. It asserts:
  - the problem's status equals `httpsec.LookupStatus(err)`, and the problem is nil when `ok` is false;
  - a typed-nil `RejectedError` joined ahead of access-denied gives the type `.../security/access-denied`;
  - an aborted chain writes exactly one record, with `slog.Default()` swapped. This case must not run in parallel.
- [ ] **Step 2: Watch it fail.** `go -C httpsec/prblmsec test -run TestMapper_HostileChains -count=1 -timeout 30s ./...`. Expected: the typed-nil case fails with an escaped panic, or the lookup and the mapper disagree. Report the output.
- [ ] **Step 3: Implement.**
  - `mapError` returns nil immediately when `LookupStatus` reports `ok == false`, so it never walks a chain that aborted.
  - Otherwise it flattens the chain once and runs every selector over it, using `errwalk.Is` and `errwalk.As`.
  - `ruleOf` tries `password.RejectedError` by value, then by pointer, through `errwalk.As`.
  - If this second walk aborts, which only a nondeterministic error can cause, the mapper returns nil and logs nothing.
- [ ] **Step 4: Run.** `go -C httpsec/prblmsec test -race -count=1 ./...` and `go -C test test -race -run TestProblemParity -count=1 ./`. Expected: PASS.
- [ ] **Step 5: Commit.** `fix(prblmsec): the mapper classifies with the core's bounded walk`.

### Task 10.5: fibersec refusal unwrapping

**Files:**
- Modify `httpsec/fibersec/errors.go` (the `errors.As` at about line 74) and `httpsec/fibersec/middleware.go` (the `errors.Is(err, nextErr)` at about line 163).
- Test: `httpsec/fibersec/hostile_test.go`.

**Interfaces:** consumes 10.1 and `httpsec.StatusForError`. It must not depend on unexported names from 10.3.

- [ ] **Step 1: Write the failing test.** `TestErrorHandler_HostileChains` is a table that runs a fiber app with the chain mounted and `ErrorHandler` installed. Cases:
  - a cyclic error gives 500;
  - a panicking `As` gives 500;
  - a typed-nil `*RefusalError` joined ahead of a real one gives the real one's status.

  Every case also asserts no hang (a 2 s deadline) and no panic. With `slog.Default()` swapped, one dispatch writes at most one record.
- [ ] **Step 2: Watch it fail.** `go -C httpsec/fibersec test -run TestErrorHandler_HostileChains -count=1 -timeout 30s ./...`. Expected: a hang, a fatal error or a panic on the hostile rows. Report it.
- [ ] **Step 3: Implement.**
  - Replace those two calls with `errwalk.As` and `errwalk.Is` over a single `Flatten`.
  - If the walk aborts, answer `fiber.StatusInternalServerError`.
  - If a refusal would be classified more than once per dispatch, carry the status computed at refusal time in `RefusalError`, so the handler does not classify it again.
- [ ] **Step 4: Run.** `go -C httpsec/fibersec test -race -count=1 ./...`. Expected: PASS.
- [ ] **Step 5: Commit.** `fix(fibersec): refusal unwrapping uses the bounded walk`.

### Task 10.10: Panic frames captured at recovery

**Files:**
- Modify: `internal/errwalk/errwalk.go`, the recovering helper and `PanicError`.
- Modify: `internal/diag/panic.go`.
- Modify: the core's abort-record helper in `httpsec/errors.go`, and `reportAbort` in `httpsec/fibersec/errors.go`.
- Tests: `internal/errwalk/errwalk_test.go`, `internal/diag/panic_test.go`, `httpsec/lookup_abort_log_test.go`, `httpsec/fibersec/hostile_test.go`.

**Interfaces:**
- Produces:
  - `PanicError` gains `Frames []uintptr`. It is filled inside the deferred recover by `runtime.Callers`, starting at the frame that panicked.
  - `diag.PanicAttrsFrom(value any, pcs []uintptr) []slog.Attr` gives the same keys and the same redaction as `PanicAttrs`. It formats the given pcs rather than the current stack.
  - `PanicAttrs` stays as it is for its existing callers.

- [ ] **Step 1: Write the failing tests.**
  - `TestFlatten_PanicCarriesFrames`: for a panicking `Unwrap`, `Is` and `As`, the abort's `Frames`, resolved with `runtime.CallersFrames`, include the fixture method's function name.
  - `TestPanicAttrsFrom`: for given pcs, the keys and the redaction equal `PanicAttrs`'s.
  - In httpsec, a row in `TestLookupStatus_AbortIsLogged`: the panic record's `frames` attribute names the fixture's panicking method, and does not start at `lookup`.
  - In fibersec, a row in `TestErrorHandler_HostileChains`: a panic-abort record carries `panic_type` and `frames`.
- [ ] **Step 2: Watch them fail.**
  - `go test -run 'PanicCarriesFrames|PanicAttrsFrom|AbortIsLogged' -count=1 ./internal/... ./httpsec/`.
  - `go -C httpsec/fibersec test -run HostileChains -count=1 ./...`.
  - Expected:
    - errwalk: FAIL, because `Frames` is empty;
    - diag: FAIL, because `PanicAttrsFrom` is undefined. Stub it first, so that the test fails on its assertion and not on compilation;
    - core: FAIL, because frames name the log site;
    - fibersec: FAIL, because the keys are only `reason`.
- [ ] **Step 3: Implement.**
  - Capture the frames in the helper's defer, with a skip count that starts at the panicking frame.
  - Both log helpers call `diag.PanicAttrsFrom(p.Value, p.Frames)`.
- [ ] **Step 4: Run.** `go test -race -count=1 ./internal/... ./httpsec/` and `go -C httpsec/fibersec test -race -count=1 ./...`. Expected: PASS.
- [ ] **Step 5: Commit** together with 10.5, if 10.5 is still uncommitted. Otherwise use `fix(errwalk,diag): panic frames are captured where the panic happened`.

### Task 10.9: Every refusal-path inspection uses the walk

**Files:**
- Modify the sites the inventory names. Expected: `httpsec/events.go` (`refused`), `httpsec/authorization.go`, `httpsec/signals_retry.go`, `internal/eventsink` (`GuardRefused`), the DPoP guard challenger, and `hangup.ByCaller`.
- Test: `httpsec/refusal_path_hostile_test.go`, plus a test in each internal package that changes.

**Interfaces:** consumes errwalk, and the core's `lookup` and its log helper from 10.2 and 10.3. It must not change any exported signature.

- [ ] **Step 1: Inventory.** Use gopls references to find each stdlib `errors.Is` or `errors.As` that runs over the refused error on the refusal path. Report the list, giving for each one its trigger condition (always, or only with events on, a DPoP chain, or an ended context).
- [ ] **Step 2: Write the failing tests.** `TestRefusalPath_HostileChains` is a table with one row per site and condition, over a real chain configured to reach that site. Each row is run twice, once with a cyclic error and once with a panicking-`Is` error, each under a 2 s watchdog with a panic catch. Each asserts 500, no hang and no panic.
  - Also a session-signals row: an abort writes one record with `msgClassificationAborted` on the signals logger, and none recording a dependency failure.
  - Also a zero-value `Chain` row: one record goes to the default logger.
- [ ] **Step 3: Watch it fail.** `go test -run TestRefusalPath_HostileChains -count=1 -timeout 60s ./httpsec/`. Expected: a hang, a fatal error or an escaped panic per row. Report each.
- [ ] **Step 4: Implement.**
  - Each site checks over one `errwalk.Flatten`. If the walk aborts, it takes the fail-closed path: no outage claim, no throttle mark, no event detail beyond the status.
  - The order and outcome for every non-hostile error stay the same. Add a HEAD-parity row per site for a non-hostile error.
- [ ] **Step 5: Run.** `go test -race -count=1 ./...` in the root module. Expected: PASS.
- [ ] **Step 6: Commit.** `fix(httpsec): every refusal-path inspection uses the bounded walk`.

### Task 10.3 follow-up: quiet sites under a consumer handler, and per-reason keys

**Files:** `httpsec/errors.go` (the quiet helper and the key), the quiet call sites, and `httpsec/lookup_abort_log_test.go`.

**Interfaces:**
- The quiet helper takes the chain, `func (c *Chain) statusQuietly(ctx context.Context, err error) int` or an equivalent. When `c.errorHandler != nil`, it logs an abort through `c.logClassificationAborted`.
- The sampling key is `classification-aborted:` followed by `errwalk.Reason(abort)`.

- [ ] **Step 1: Write the failing tests.**
  - Add a row to `TestChain_AbortLogsToChainLogger`. It uses `WithLogger`, `EnableSecurityEvents`, and a `WithErrorHandler` that writes 418 without classifying, and refuses `&cycleOne{}`. Expected: one record on the chain logger.
  - Add a second row with a budget abort, then a panic abort, inside one window. Expected: two records.
- [ ] **Step 2: Watch them fail.** Expected: `expected: 1 actual: 0`, and `expected: 2 actual: 1`.
- [ ] **Step 3: Implement**, then run `go test -race -count=1 ./httpsec/`. Expected: PASS.

### Task 10.9a: 10.9 follow-up

**Files:**
- `httpsec/oidc_consents.go` (`dpopAnswersChallenge`)
- `httpsec/challenge_spend.go` (`emitResponseRefused`)
- the guard refusal path that `WithGuardErrorHandler` takes (`httpsec/guards.go`)
- `httpsec/refusal_path_hostile_test.go`

**Interfaces:** consumes `refusalWalk`, `walkRefusal`, `refusalAs` and `reportAbort` from 10.9, and `logClassificationAborted` from 10.3.

- [ ] **Step 1: Write the failing tests.**
  - `selectiveIs` is an error whose `Is` panics only for the sentinel each of the two sites checks. Route it through the DPoP-answer path and through the response-refused event path. Expected: no panic, the extra challenge or event is dropped, and exactly one record is written.
  - A guard with `WithGuardErrorHandler` refuses a cyclic error, on a chain with events on, and separately on a DPoP chain. Expected: exactly one record on the default logger.
- [ ] **Step 2: Watch them fail.** Expected: a panic escapes, or `should have 1 item(s), but has 0`.
- [ ] **Step 3: Implement.**
  - Both sites check through the walk.
  - The guard reports its own abort to `slog.Default()` when `WithGuardErrorHandler` is set, and only then.
- [ ] **Step 4: Run.** `go test -race -count=1 ./...` (root). Expected: PASS.

### Task 10.12: Consumer-port error reads use the walk

**Files:** set by the inventory. Each group's dispatch owns only its group's files and their tests.

**Interfaces:**
- Consumes `errwalk`, plus the core's `refusalWalk` helpers and its abort logging.
- One new helper, and only if a group needs it: `func portFailed(err error) (abort error)`, or an equivalent of the 10.9 helpers.
- Reuse the 10.9 helpers before adding anything.

- [ ] **Step 1: Inventory (main-session gate).** Dispatch read-only research. List every stdlib `errors.Is`, `errors.As` or `errors.AsType` in the root module whose argument is, or wraps, an error a consumer port returned.
  - Group the sites by flow: session and bearer resolution; login and lockout; Basic and API key; throttle and limiters; recovery and magic link; OIDC; anything else.
  - Give each group's size.
  - The main session splits the work into dispatches of at most six sites each.
- [ ] **Step 2: Per group, write the failing tests first.**
  - `TestPortErrors_<Group>_HostileChains` (table). For each site, a port mock (gomock, per the `use-mockgen` skill) returns:
    - a `cycleOne`;
    - a `cycleMany`, run alone or in a subprocess;
    - a `panicIs`;
    - a non-hostile parity error.
  - Each hostile row asserts:
    - status 500;
    - no hang (2 s watchdog);
    - no panic;
    - one record;
    - no throttle mark or outage claim.
  - Each parity row asserts the HEAD outcome.
- [ ] **Step 3: Watch them fail.** Expected: a hang, a fatal error or an escaped panic on every hostile row. Report each.
- [ ] **Step 4: Implement.**
  - Each read checks through one walk.
  - On abort, take the dependency-failure branch.
- [ ] **Step 5: Run.** `go test -race -count=1 ./...` (root). Expected: PASS.
- [ ] **Step 6: Review, then commit per group.** `fix(httpsec): <group> port errors are read through the bounded walk`.

### Task 10.13: Benchmark the classification

**Files:**
- Create `httpsec/lookup_bench_test.go`.
- Create `httpsec/prblmsec/mapper_bench_test.go`.

- [ ] **Step 1: Write the benchmarks.**
  - `BenchmarkLookupStatus` and `BenchmarkMapError`, each with sub-benchmarks:
    - `bare-sentinel`: `authorize.ErrAccessDenied`;
    - `wrap-5`;
    - `join-3-challenge`: a challenge joined with two sentinels;
    - `unknown`: a plain error;
    - `chain-50`.
  - Use `b.ReportAllocs()` and `b.Loop()`, or the loop the repository's existing benchmarks use.
- [ ] **Step 2: Measure on `main`.**
  - Export `main` with `git archive main | tar -x -C <scratch>/main`.
  - Copy in the same benchmark files. They use only exported APIs, so they compile on `main`.
  - Run `go test -run '^$' -bench 'LookupStatus|MapError' -count=10 -benchmem ./httpsec/ ./httpsec/prblmsec/` in that export, and save the output as `old.txt`.
  - On `main`, prblmsec does not exist. `BenchmarkMapError` therefore compares against the branch's first prblmsec commit, `c63edf3a`, exported the same way.
- [ ] **Step 3: Measure on the branch.** Run the same command and save the output as `new.txt`.
- [ ] **Step 4: Compare.** `benchstat old.txt new.txt`. Report every row.
  - Expected: no row regresses by more than 10% in time or allocations.
  - A regression goes back as a fix, or gets a design.md row that states its reason.
- [ ] **Step 5: Commit** the benchmark files: `test: benchmark the bounded classification`.

### Task 10.11: Require prblm v0.2.1

**Files:** `httpsec/prblmsec/go.mod` and `go.sum`, `test/go.mod` and `go.sum`, `go.work.sum`, `test/problem_parity_test.go`.

- [ ] **Step 1: Write the failing test.**
  - Add a `TestProblemParity` case where the route returns an error whose `As` panics.
  - With prblmsec registered, net/http and gin answer 500 `application/problem+json`, with no panic past the server.
  - fiber gets the same answer, because fibersec's own walk aborts first.
- [ ] **Step 2: Watch it fail on v0.2.0.** Run `go -C test test -run TestProblemParity -count=1 ./`. Expected: FAIL on net/http, with the panic escaping prblm's `Respond` (status hint).
- [ ] **Step 3: Bump.**
  - `go -C httpsec/prblmsec get github.com/kartaladev/prblm@v0.2.1`.
  - `go -C test get github.com/kartaladev/prblm@v0.2.1 github.com/kartaladev/prblm/adapters/ginprblm@v0.2.1`.
  - `go work sync`, then `go mod tidy` in each changed module.
  - Check that no `go.sum` lost its `/go.mod h1:` lines.
- [ ] **Step 4: Run.** `go -C httpsec/prblmsec test -race -count=1 ./...` and `go -C test test -race -run TestProblemParity -count=1 ./`. Expected: PASS.
- [ ] **Step 5: Commit.** `build: require prblm v0.2.1`.

### Task 10.6: Documentation

**Files:**
- `httpsec/errors.go`: the godoc of `LookupStatus` and `StatusForError`.
- `httpsec/prblmsec/doc.go`.
- `README.md`: the prblmsec section.
- `CHANGELOG.md`: `[Unreleased]`.

- [ ] **Step 1: Write the text** that tasks.md 10.6 names.
  - Write plain prose. Do not name internal packages; in particular, no `errwalk` in public godoc.
  - The prblm limit names v0.2.0. It says that v0.2.1 fixes three things: it recovers the core's status-hint step, the net/http `Handler.Recover` broken-connection check, and ginprblm Recovery's broken-connection check. Cycles remain until v0.3.0.
  - CHANGELOG, Fixed: the hang, the crash, the panic, and the typed-nil `RejectedError`.
  - CHANGELOG, Changed: a challenge offered through an `As` method behind a typed nil is now found. A chain of more than 1,000 links is unrecognised, and the abort is logged.
- [ ] **Step 2: Verify.**
  - `go doc ./httpsec LookupStatus` shows the bound and the fail-closed rule.
  - `gofmt -l .` and `go vet ./...` are clean.
- [ ] **Step 3: Commit.** `docs: the bounded classification and the prblm v0.2.0 limit`.

### Task 10.7: Gate

- [ ] **Step 1:** Re-run Task 8.3's commands, with the `test` module run alone on an idle machine. Expected:
  - every module passes vet and `test -race`;
  - gofmt and `go work sync` are clean;
  - govulncheck reports only the known GO-2026-5932, which nothing calls.

### Task 10.8: Whole-branch review

- [ ] **Step 1:** Dispatch a fresh Opus reviewer. Give it decision 11, its failure rows, the two new requirements, and the branch diff against `main`. It enumerates how the change can fail before judging, and labels every claim REPRODUCED or UNREPRODUCED.
- [ ] **Step 2:** Send each finding to a fresh dispatch of the task that owns it, then re-run 10.7. Expected: the review is clean.
