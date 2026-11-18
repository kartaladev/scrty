# Provider Resource Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session never writes Go: every task below is dispatched to a subagent, as `.claude/rules/subagent-delegation.md` requires.

**Goal:** Let `EnableBearerToken` accept the DPoP-bound access tokens the embedded OpenID Provider
issues, with no new chain option. Add consumer password rules and opt-in inactive-account disclosure.

**Architecture:**
- `Provider.AccessTokenVerifier(audience, opts...)` is a `token.Verifier`. It routes by shape (`at.`
  or `typ at+jwt`) to `VerifyAccessToken` and an exact audience check, and sends every other token to
  an optional first-party verifier.
- The claims it returns carry a grant-backed mark that only scrty's packages can set
  (`internal/grantclaims`).
- For a marked token, `EnableBearerToken` skips the session lookup. It keeps `admitBinding`, reloads
  the user, records the proof, publishes the caller with the token's scopes, and runs the stateless
  phase.

**Tech Stack:** Go 1.27, `github.com/lestrrat-go/jwx/v4`, testify, `go.uber.org/mock` (typed mocks),
fiber v3 and gin adapters.

**Spec:** `openspec/changes/provider-resource-server/` — `proposal.md`, `design.md` (decisions 1–13,
Failure modes F1–F31), `specs/*/spec.md`, `tasks.md`. Step numbers below are `tasks.md` task numbers.

## Global Constraints

- Test-first: write the failing test, run it, and confirm it fails for the intended reason. A compile
  error is not a red step (`golang-tdd.md`).
- Tables use the `table-test` skill: the `assert` closure, `t.Context()` and a `ctx` modifier. Mocks
  come from `use-mockgen` (`-typed`, `_mock_test.go`, never in production builds).
- Every new option's godoc names the default it replaces (`library-design.md`).
- Every listed failure mode is handled and tested, or accepted in `design.md` (`defensive-coding.md`).
- A claimed defect needs a failing test or the label `UNREPRODUCED` (`defect-claims.md`).
- No error, log or event text contains a token, a proof, a candidate password or a user identifier.
- Audience: an absolute URI, no fragment, never the issuer. Claim peek bound: 4 KiB decoded header.
- Proof lifetime default: 60 s (`DefaultDPoPProofMaxAge`). Algorithms default: ES256.
- No new module dependency. Nothing is copied from, or cited from, `.claude/.legacy`.
- Agents never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`. The main session
  commits.

## Review Focus

1. A JWT `typ` that differs only in case or prefix (`AT+JWT`, `application/at+jwt`) must route to the
   provider, and `typ xat+jwt` must not. Covered in Task 5.2.
2. A consumer verifier returning `NewClaimsWithConfirmation` must never take the session-less path.
   Covered in Task 6.3 by the unmarked-claims guard case.
3. Two concurrent requests with one proof `jti`: exactly one is accepted. Covered in Task 7.2.
4. A user deactivated between the user load and the proof record must not leave a consumed proof
   that blocks the reactivated user. Covered in Task 6.5 by the reactivate-then-same-proof case.
5. Each refusal gets exactly one `WWW-Authenticate` value, across `dpopChallenge` and the fallback
   interceptor. Covered in Task 9.1 by `assert.Len(t, res.Header.Values("WWW-Authenticate"), n)` in
   every case.

---

### Task 1: Branch and baseline (tasks 1.1–1.2) — main session

- [ ] **Step 1:** Run `git fetch origin && git log origin/main --oneline | grep -i harden-chain-boundary`.
  Expected: a merge line. If there is none, stop and ask the user.
- [ ] **Step 2:** Run `git switch -c feat/provider-resource-server origin/main`, then carry
  `openspec/changes/provider-resource-server/` onto it.
- [ ] **Step 3:** Run `go test ./... -count=1` in each module of `go.work`. Expected: all pass. Keep the
  output as the baseline.

### Task 2: Token type port, access-token kind, grant-backed mark (tasks 2.1–2.4) — Sonnet for 2.1–2.3, Opus for 2.4, lane T

**Files:**
- Modify: `token/generator.go`, `token/claims.go` (2.4), `authenticate/factor/factor.go`,
  `identity/principal.go` (godoc only)
- Create: `internal/grantclaims/grantclaims.go` (2.4)
- Test: `token/generator_test.go`, `token/claims_grant_test.go`, `authenticate/factor/factor_test.go`,
  `layout_test.go`

**Interfaces:**
- Produces:
  - `type TypedGenerator interface{ Generator; TokenType() string }` in `token`;
  - `func (g *JWTGenerator) TokenType() string`;
  - `const AccessToken Kind = "access-token"` in `factor`, with `AccessToken.Channel() == ""` and
    exemption true.
  - In `internal/grantclaims` (2.4), which imports nothing from scrty, so there is no cycle:
    - `type Mark struct{ payload any }`;
    - `func New(payload any) *Mark`;
    - `func (m *Mark) Payload() any`.
  - In `token` (2.4):
    - `func (c *Claims) WithGrant(m *grantclaims.Mark) *Claims` returns a copy;
    - `func (c *Claims) Grant() *grantclaims.Mark`.

    Outside scrty the `Mark` type cannot be named or built, so only nil can be passed, and a nil mark
    marks nothing.

- [ ] **Step 1 (2.1 red):** Write `TestGenerator_TokenType`, a table test:
  - `{name: "default", opts: nil, assert: Equal(token.TypeFirstParty)}`;
  - `{name: "retyped", opts: []token.Option{token.WithTokenType("at+jwt")}, assert: Equal("at+jwt")}`;
  - plus `var _ token.TypedGenerator = (*token.JWTGenerator)(nil)` in the test file.

  Run `go test ./token/ -run TestGenerator_TokenType -count=1`. Expected: FAIL. Make it a runtime
  failure, not a compile error: first add `TokenType()` returning `""`.
- [ ] **Step 2:** Return `cfg`'s type. Rerun. Expected: PASS.
- [ ] **Step 3 (2.2 red):** Add these rows to the existing kind table:
  - `{kind: factor.AccessToken, channel: "", exempt: true}`;
  - assert `api-key` is still exempt and `oidc` is not.

  Run `go test ./authenticate/factor/ -count=1`. Expected: FAIL on exemption.
- [ ] **Step 4:** Add the constant, and add it to the exemption method beside `APIKey`. Run
  `go test ./authenticate/factor/... ./policy/... -count=1`. Expected: PASS.
- [ ] **Step 5 (2.3):** Set the godoc of `Principal.Scopes` to "granted scopes: a service's, or for a
  user the scopes granted to the access token that authenticated the request". Run
  `go doc ./identity Principal`.
- [ ] **Step 6 (2.4 red):** Write `TestGrantClaims_Mark`:
  - `token.NewClaims("u","j").Grant()` is nil;
  - the same for `NewClaimsWithConfirmation`;
  - `c.WithGrant(grantclaims.New(p)).Grant().Payload()` gives `p`, and the original `c` is still
    unmarked;
  - `c.WithGrant(nil).Grant()` is nil.

  Add `TestGrantClaims_InternalOnly` to `layout_test.go`: the package path contains `/internal/`.
  Run `go test ./internal/grantclaims/ ./token/ . -run 'GrantClaims' -count=1`. Expected: FAIL. Stub
  `Grant` to return nil.
- [ ] **Step 7:** Implement it. Rerun, then `go test ./token/... -count=1`. Expected: PASS.
- [ ] **Step 8:** Report the files and the red output. The main session commits:
  `feat(token,factor): typed generators, the access-token kind and the grant-backed mark`.

### Task 3: Password consumer rules (tasks 3.1–3.3) — Sonnet, lane P

**Files:**
- Modify: `authenticate/password/policy.go`
- Test: `authenticate/password/policy_rule_test.go` (new), `authenticate/password/example_test.go`

**Interfaces:**
- Produces:
  - `type RuleFunc func(ctx context.Context, candidate string, user *identity.Details) (ok bool, err error)`;
  - `func WithRule(name Rule, check RuleFunc) PolicyOption`.
- Order inside `Check`: length → common → context words → consumer rules (in the order given) →
  breach → reuse.
- A refusal is `RejectedError{Rule: name}`. A rule error is wrapped as
  `fmt.Errorf("password: rule %q could not decide: %w", name, err)`. That text has no candidate and is
  not `ErrPasswordRejected`.

- [ ] **Step 1 (3.1 red):** Write `TestPolicy_ConsumerRule`, with `lettersAndDigits` a test helper:
  - `"refuses weak"`: `errors.As` gives a `RejectedError` with `Rule == "letters-and-digits"`, and
    `!errors.Is(err, ErrReused)`;
  - `"accepts"`: `abcdefghij12` gives `NoError`;
  - `"order"`: two rules record their calls into a slice, and the slice equals `["a","b"]`;
  - `"skips breach"`: a mock `BreachSource` with `.Times(0)`;
  - `"fails closed"`: the rule returns `io.ErrUnexpectedEOF`, and the error matches it, is not
    `ErrPasswordRejected`, and does not contain the candidate.

  Run `go test ./authenticate/password/ -run TestPolicy_ConsumerRule -count=1`. Expected: FAIL. Stub
  `WithRule` as a no-op so the test compiles and the failure is a missing refusal.
- [ ] **Step 2:** Implement it. Rerun. Expected: PASS.
- [ ] **Step 3 (3.2 red):** Add rows to the construction table: a nil `check`, a typed-nil `check`
  (`RuleFunc(nil)` through `any`), name `""`, name `"reused"` (check every built-in `Rule` const), and a
  duplicate name. Each gives an error matching the package's config error, with text naming the rule.
  Run. Expected: FAIL.
- [ ] **Step 4:** Validate in `NewPolicy`. Rerun. Expected: PASS.
- [ ] **Step 5 (3.3 red):** Write `TestPolicy_Change_ConsumerRuleAndReuse`. With `MinLength(10)`,
  `WithRule(lettersAndDigits)` and `NoReuse(mockHistory, 1)`:
  - the current password `abcdefghij12` gives `ErrorIs(ErrReused)`;
  - `abcdefghijkl` gives the consumer rule's refusal;
  - the `WriteFunc` mock has `.Times(0)` in both cases.

  Run, and expect PASS if steps 1–4 already cover it. In that case show it can fail by temporarily
  reordering reuse before rules, observing the FAIL, and restoring the order.
- [ ] **Step 6:** Add `ExamplePolicy_withRule` with the `// Output:` the example prints, and godoc on
  `WithRule`: "Default: no consumer rule; the library imposes no composition rule". Run
  `go test ./authenticate/password/... -count=1 && go vet ./authenticate/password/...`. Expected: PASS.
- [ ] **Step 7:** Report. The main session commits: `feat(password): consumer rules in the policy`.

### Task 4: Inactive account beneath the uniform failure (tasks 4.1–4.2) — Sonnet, lane I

**Files:**
- Modify: `authenticate/authenticate.go` (sentinel), `authenticate/password.go:382`
- Test: `authenticate/password_test.go`

**Interfaces:**
- Produces: `var ErrAccountInactive = errors.New("authenticate: account inactive")`. The provider
  returns `errors.Join(ErrAuthenticationFailed, ErrAccountInactive)` only on the post-`Match` inactive
  branch.

- [ ] **Step 1 (4.1 red):** Extend the provider refusal table with a case per outcome:
  - `inactive+correct`: `ErrorIs(ErrAuthenticationFailed)` and `ErrorIs(ErrAccountInactive)`;
  - `unknown`, `wrong`, `inactive+wrong`: `ErrorIs(ErrAuthenticationFailed)` and
    `NotErrorIs(ErrAccountInactive)`.

  Run `go test ./authenticate/ -count=1`. Expected: FAIL on `inactive+correct` only. Declare the
  sentinel first so it compiles.
- [ ] **Step 2:** Change the return at `password.go:382`. Rerun. Expected: PASS.
- [ ] **Step 3 (4.2):** Add a case asserting that the mock `Encoder.Match` call count for
  `inactive+correct` equals the count for `wrong`, which is 1. Confirm it can fail by temporarily
  adding a second `Match`, observing the FAIL, and removing it. Add godoc on `ErrAccountInactive`:
  "reachable only beneath ErrAuthenticationFailed, and only after the password verified".
- [ ] **Step 4:** Run `go test ./authenticate/... -count=1`. Expected: PASS. Report. The main session
  commits: `feat(authenticate): identify an inactive account beneath the uniform failure`.

### Task 5: The provider's access-token verifier (tasks 5.1–5.4) — Opus, lane O (after Task 2)

**Files:**
- Create: `oidcprovider/accesstoken_verifier.go`
- Test: `oidcprovider/accesstoken_verifier_test.go`, `oidcprovider/example_accesstoken_verifier_test.go`

**Interfaces:**
- Consumes: `grantclaims.New` and `(*token.Claims).WithGrant` (Task 2).
- Produces:

```go
type AccessTokenVerifier struct{ /* unexported */ }        // implements token.Verifier
type AccessTokenVerifierOption func(*AccessTokenVerifier) error
func (p *Provider) AccessTokenVerifier(audience string, opts ...AccessTokenVerifierOption) (*AccessTokenVerifier, error)
func WithFirstPartyVerifier(v token.Verifier) AccessTokenVerifierOption
func (v *AccessTokenVerifier) Verify(ctx context.Context, raw string) (*token.Claims, error)
func (v *AccessTokenVerifier) HasFirstPartyRoute() bool     // read by httpsec's construction checks
func IsProviderRefusal(err error) bool                      // true for a provider-routed token.ErrInvalid
```

- **The marked claims:** `token.NewClaimsWithConfirmation(string(at.Subject), at.ID.String() or the
  JWT jti, cnf)`, marked with `*AccessToken` as the payload.
- **A refusal:** `errors.Join(token.ErrInvalid, errProviderRouted)`, where `errProviderRouted` is
  unexported and `IsProviderRefusal` matches it.

- [ ] **Step 1 (5.1 red):** Write `TestProvider_AccessTokenVerifier_Construction`:
  - built: `https://hris.example/api` and `urn:kartala:hris:api`;
  - `ErrorIs(ErrConfig)`: `""`, `hris-api`, `https://x/api#f`, `p.Issuer()`, `WithFirstPartyVerifier(nil)`
    and a typed-nil verifier.

  Run `go test ./oidcprovider/ -run AccessTokenVerifier_Construction -count=1`. Expected: FAIL, after
  stubbing the constructor to return nil error.
- [ ] **Step 2:** Implement it with `validResource` and `!= p.Issuer()`. Rerun. Expected: PASS.
- [ ] **Step 3 (5.2 red):** Write `TestAccessTokenVerifier_Routes`, with a typed `token.Verifier` mock as
  the first-party route:
  - `scrty+jwt` gives the mock's claims, with `Grant()` nil;
  - an ID token (`typ JWT`) reaches the mock;
  - without a route, `scrty+jwt` gives `ErrorIs(token.ErrInvalid)`;
  - `at.x.y`, `typ at+jwt` and `typ application/AT+JWT` give the mock `.Times(0)`;
  - a header over 4 KiB, `!!!.x.y`, a non-JSON header and `typ xat+jwt` reach the mock.

  Then add `FuzzAccessTokenVerifierRoute`. Run. Expected: FAIL.
- [ ] **Step 4:** Implement the peek. Rerun, then
  `go test ./oidcprovider/ -run '^$' -fuzz FuzzAccessTokenVerifierRoute -fuzztime 30s`. Expected: PASS.
- [ ] **Step 5 (5.3 red):** Write `TestAccessTokenVerifier_Verify` with a real provider (an in-memory
  store, a fixed clock at 08:00, and a 5 m lifetime):
  - a valid token: the payload equals `VerifyAccessToken`'s, `Subject()` equals the user ID, and the
    `Confirmation().JKT` equals the token's;
  - refused, each with `ErrorIs(token.ErrInvalid)` and `IsProviderRefusal`: an altered signature, a
    foreign key, 08:05:00, 08:06, `RevokeUserGrants`, logout of an online grant, an opaque token revoked
    at revocation, `aud https://payroll.example/api`, and the issuer-only audience;
  - an audience of the issuer plus the configured value passes;
  - a grant store returning an error gives `ErrorIs(ErrDependency)` and `NotErrorIs(token.ErrInvalid)`;
  - a cancelled ctx gives `ErrorIs(context.Canceled)`.

  Run. Expected: FAIL.
- [ ] **Step 6:** Implement it. Rerun, then `go test ./oidcprovider/... -race -count=1`. Expected:
  PASS.
- [ ] **Step 7 (5.4):** Write the godoc for the audience rule, routing, the mark and lines F21 and F22,
  and `ExampleProvider_AccessTokenVerifier` with no output. Run
  `go test ./oidcprovider/ -run Example -count=1`. Report. The main session commits:
  `feat(oidcprovider): an access-token verifier for resource servers`.

### Task 6: The bearer's grant-backed path (tasks 6.1–6.6) — Opus, lane H (after Tasks 2 and 5)

**Files:**
- Modify: `httpsec/bearer.go`, `httpsec/errors.go` (`ErrInvalidToken`)
- Create: `httpsec/bearer_grant.go` (the grant-backed path)
- Test: `httpsec/bearer_grant_test.go`

**Interfaces:**
- Consumes: `*oidcprovider.AccessTokenVerifier`, `HasFirstPartyRoute`, `IsProviderRefusal` (Task 5);
  `(*token.Claims).Grant` and `token.TypedGenerator` (Task 2).
- Produces:
  - `var ErrInvalidToken = fmt.Errorf("httpsec: invalid access token: %w", authenticate.ErrAuthenticationFailed)`;
  - unexported `func (b *bearerToken) grantBacked(ex *Exchange, underDPoP bool, presented string, claims *token.Claims, at *oidcprovider.AccessToken) error`.

- [ ] **Step 1 (6.1):** Run `go test ./httpsec/ -run 'Bearer|DPoP|Cert|Renewal' -count=1 -v 2>&1 | grep -E '^--- ' > $SCRATCH/bearer-before.txt`.
  Expected: all PASS.
- [ ] **Step 2 (6.2 red):** Write `TestEnableBearerToken_GrantBackedConstruction`, the five cases of
  `tasks.md` 6.2, each `ErrorIs(ErrConfig)` except the first, which gives `NoError`. Run. Expected:
  FAIL.
- [ ] **Step 3:** Implement it in the bearer's `validate`, plus the change to `requireDep` for
  `Sessions`. Rerun. Expected: PASS.
- [ ] **Step 4 (6.3 red):** Write `TestBearer_GrantBackedSkipsSession`:
  - a session-store mock with `.Times(0)`, giving 200 with `ex.Session == nil`;
  - a consumer verifier returning `NewClaimsWithConfirmation`: the session store is called once;
  - nil `Sessions` with unmarked claims (a verifier wrapping the provider's): 500 with
    `ErrorIs(ErrConfig)`.

  Run. Expected: FAIL.
- [ ] **Step 5:** In `Intercept`, branch to `grantBacked` after `Verify` and `admitBinding` when
  `claims.Grant() != nil`. Rerun. Expected: PASS.
- [ ] **Step 6 (6.4 red):** Write the request-shape table of `tasks.md` 6.4. Run. Expected: FAIL. Then
  implement it, reading all `Authorization` values and the raw query (UserInfo's `queryNamesAny`).
  Rerun. Expected: PASS.
- [ ] **Step 7 (6.5 red):** Write the user table of `tasks.md` 6.5. Run. Expected: FAIL. Then implement
  it with `LoadByUserID`, the active and ID checks, `classifyReload`, and `recordProof` after them.
  Rerun. Expected: PASS.
- [ ] **Step 8 (6.6 red):** Write the log-capture test. Run, implement, and rerun. Expected: PASS.
- [ ] **Step 9:** Rerun step 1 into `bearer-after.txt` and `diff` the two files. Expected: identical
  apart from the added tests. Report. The main session commits:
  `feat(httpsec): the bearer accepts grant-backed provider tokens without a session`.

### Task 7: Binding and the grant-binding default (tasks 7.1–7.4) — Opus, lane H

**Files:**
- Modify: `httpsec/bearer_grant.go`, `httpsec/bearer.go` (the option)
- Test: `httpsec/bearer_grant_dpop_test.go`, `httpsec/bearer_grant_signin_test.go`

**Interfaces:**
- Produces: `func WithBearerUnboundGrantTokens() BearerTokenOption`.

- [ ] **Step 1 (7.1):** Write `TestBearer_GrantBackedDPoP` with K and K2 and a `PublicURL` of
  `https://hris.example`, using the cases of `tasks.md` 7.1. Run. It is expected to PASS from the
  existing `admitBinding`. Show it can fail: temporarily skip `admitBinding` on the grant path,
  observe the FAIL, and restore it.
- [ ] **Step 2 (7.2):** Write `TestBearer_GrantBackedProofRace` with a `sync.WaitGroup` barrier and the
  outage rows. Run `-race -count=20`. Expected: one 200 and one 401 each time. Prove the outage rows
  can fail by temporarily swallowing the store error, observing the FAIL, and restoring it.
- [ ] **Step 3 (7.3 red):** Write the unbound table of `tasks.md` 7.3. Run. Expected: FAIL.
- [ ] **Step 4:** Implement step 3 of decision 4 and the option. Rerun. Expected: PASS.
- [ ] **Step 5 (7.4):** Write `TestBearer_GrantBackedSignInUnaffected` as in `tasks.md` 7.4. Run. Show
  it can fail: temporarily treat the grant default as chain `Require`, observe the FAIL, and revert.
  Then rerun the Task 6 step 1 list. Report. The main session commits:
  `feat(httpsec): grant-backed tokens must be key-bound by default`.

### Task 8: Publication, policy, renewal, godoc (tasks 8.1–8.4) — Opus, lane H

**Files:**
- Modify: `httpsec/bearer_grant.go`, `httpsec/session_renewal.go`
- Create: `httpsec/accesstoken_context.go`, `httpsec/example_bearer_provider_test.go`
- Test: `httpsec/bearer_grant_publish_test.go`

**Interfaces:**
- Produces: `func AccessTokenFromContext(ctx context.Context) (*oidcprovider.AccessToken, bool)`, which
  returns a deep copy (`slices.Clone` and `maps.Clone`).

- [ ] **Step 1 (8.1 red):** Write the publication table of `tasks.md` 8.1. Run. Expected: FAIL. Then
  implement it: `WithCaller`, `Scopes` cloned, the accessor, and `RecordPresentedToken`. Rerun.
  Expected: PASS.
- [ ] **Step 2 (8.2 red):** Write the policy table. Run. Expected: FAIL. Then implement
  `evaluatePhase(..., policy.StatelessAuthentication, postAuthenticationInput(p, factor.AccessToken, ...))`.
  Rerun. Expected: PASS.
- [ ] **Step 3 (8.3 red):** Write `TestRenewal_RefusesGrantBackedCaller`: 401
  `ErrAuthenticationRequired`, with the generator mock `.Times(0)`. Run. Expected: FAIL. Implement it,
  then rerun.
- [ ] **Step 4 (8.4):** Write the godoc listed in `tasks.md` 8.4, and
  `ExampleEnableBearerToken_providerAccessTokens`. Run `go test ./httpsec/ -run Example -count=1`, then
  the Task 6 step 1 list. Report. The main session commits:
  `feat(httpsec): publish grant-backed callers and their token`.

### Task 9: Challenges and adapters (tasks 9.1–9.2) — Opus, lane H

**Files:**
- Create: `httpsec/token_challenge.go` (the fallback interceptor, registered whenever the provider's
  verifier is on a bearer)
- Modify: `httpsec/dpop_nonce.go` (the `invalid_token`/`invalid_request` mapping, the "already
  answered" skip, and the `Bearer`-offer rule)
- Test: `httpsec/bearer_grant_challenge_test.go`, `test/httpsecconformance/provider_tokens_scenarios.go`
  (new), `httpsec/fibersec/provider_tokens_test.go`, `httpsec/ginsec/provider_tokens_test.go`

**Interfaces:**
- Produces, exported: `func ProviderTokenScenarios() []Scenario` in `httpsecconformance`.

- [ ] **Step 1 (9.1 red):** Write `TestBearer_GrantBackedChallenges`, with the nine cases of `tasks.md`
  9.1, asserting the status and `res.Header.Values("WWW-Authenticate")` exactly:
  - `[DPoP error="invalid_token", algs="ES256"]`;
  - `[DPoP error="invalid_dpop_proof", algs="ES256"]`;
  - `[Bearer error="invalid_token"]`;
  - 400 `[Bearer error="invalid_request"]`;
  - `[DPoP algs="ES256"]`;
  - `[DPoP algs="ES256", Bearer]`;
  - the guard route, the same as the chain;
  - `[]` after `WithErrorHandler`;
  - `[]` for a first-party rejection.

  Run. Expected: FAIL.
- [ ] **Step 2:** Implement it. Rerun, then `go test ./httpsec/... -race -count=1`. Expected: PASS.
- [ ] **Step 3 (9.2):** Add `ProviderTokenScenarios()` and wire it into each adapter's runner. Add
  `TestFiber_ProviderTokenRefusalKeepsChallenge`, which goes through `fibersec.ErrorHandler`. Run
  `go test ./... -count=1` in `test`, `httpsec/fibersec` and `httpsec/ginsec`. If it passes at once,
  show it can fail by temporarily dropping the header in the fiber error path, observing the FAIL, and
  reverting. Report. The main session commits:
  `feat(httpsec): invalid_token challenges for provider tokens on every adapter`.

### Task 10: Inactive-account disclosure on the chain (tasks 10.1–10.2) — Sonnet, lane H (after Task 4)

**Files:**
- Modify: `httpsec/options.go`, `httpsec/login.go`, `httpsec/basic.go`, `httpsec/errors.go`
  (a `StatusForError` row: `ErrAccountInactive` alone gives 403, and the join with
  `ErrAuthenticationFailed` still gives 401)
- Test: `httpsec/inactive_disclosure_test.go`

**Interfaces:**
- Consumes: `authenticate.ErrAccountInactive` (Task 4).
- Produces: `func WithInactiveDisclosure() Option`.

- [ ] **Step 1 (10.1 red):** Write a table across form login and Basic:
  - default, inactive+correct: 401, `ErrorIs(ErrAccountInactive)` in the handler;
  - disclosed, inactive+correct: 403, `ErrorIs(ErrAccountInactive)`,
    `NotErrorIs(ErrAuthenticationFailed)`, Basic `WWW-Authenticate` empty;
  - disclosed, inactive+wrong: 401, `NotErrorIs(ErrAccountInactive)`;
  - recovery password proof, disclosed: `ErrorIs(recovery.ErrRefused)`.

  Run. Expected: FAIL.
- [ ] **Step 2:** Implement it as `WithLockDisclosure` does: on the refusal path, strip to
  `ErrAccountInactive` when the option is set. Add the status row. Rerun, then
  `go test ./httpsec/... -count=1`. Expected: PASS.
- [ ] **Step 3 (10.2):** Write godoc: "Default: undisclosed (401, as a wrong password)", what it gives
  up (that a correct password is known to belong to a disabled account), and the 403. Run
  `go doc ./httpsec WithInactiveDisclosure`. Report. The main session commits:
  `feat(httpsec): opt-in inactive-account disclosure`.

### Task 11: Release preparation (tasks 11.1–11.3) — Sonnet for 11.1; main session for 11.2; maintainer for 11.3

- [ ] **Step 1 (11.1):** Write `CHANGELOG.md` `## [Unreleased]` with *Added* and *Changed* as listed in
  `tasks.md` 11.1. Review it with `git diff -- CHANGELOG.md`.
- [ ] **Step 2 (11.2):** Run the gate commands `RELEASING.md` lists, with `VERSION=v0.2.0` and no tag.
  Save the output in the scratchpad. Expected: all clean.
- [ ] **Step 3 (11.3, maintainer):** Follow `RELEASING.md` steps 1 onward. The agent stops here.

### Task 12: Whole-branch review (task 12.1) — Opus reviewer, read-only

- [ ] **Step 1:** Dispatch a fresh Opus reviewer with the seven spec files, `design.md` § Failure modes
  and `git diff origin/main...HEAD`. It enumerates failures by category before judging, and reports
  findings as `REPRODUCED` (test name and output) or `UNREPRODUCED` (reason).
- [ ] **Step 2:** Fold the findings through a fresh dispatch of the owning lane.
- [ ] **Step 3:** Run `openspec validate provider-resource-server --strict` and
  `go test ./... -race -count=1` in every module. Expected: valid, PASS.
