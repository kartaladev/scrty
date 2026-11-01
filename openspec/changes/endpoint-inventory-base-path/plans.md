# Endpoint Inventory and Base Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One option, `WithBasePath`, moves every built-in `httpsec` endpoint under a prefix, and the chain lists the endpoints it answers. That list backs a single collision check for the whole chain and a construction-time check that each OIDC provider's redirect URL can reach the callback.

**Architecture:**
- **Paths resolve once, at assembly.** Each path-answering interceptor keeps the path its option declared. `New` resolves every path against the base path, first in `config.build()`, before anything reads a path (MFA and the password-change gate read the logout path).
- **The inventory.** Each built-in then declares its endpoints. `build()` collects them, checks every pair for a collision, and freezes the list on the `Chain`.
- **The OIDC check** reads each provider's redirect URL through a new read-only accessor on `oidc.RelyingParty`.

**Tech Stack:** Go 1.27; `net/http`, gin, fiber v3; testify, gomock (`use-mockgen`).

**Spec:** `openspec/changes/endpoint-inventory-base-path/`: `proposal.md`, `design.md` (D1–D7), `specs/{http-security-chain,oidc-login}/spec.md` and `tasks.md`. Task numbers (1.1 … 7.1) below are `tasks.md`'s, and every plan task names the ones it implements.

## Global Constraints

- **Test-first** for every task: write the failing test, run it, and confirm it fails **for the intended reason** (not a compile error). Where a task keeps behaviour, the red step is a temporary inversion that a test catches, then restored (`golang-tdd.md`).
- **Table tests** use the `table-test` skill: the `assert` closure form, `t.Context()`, and a `ctx` modifier where context matters. Mocks use `use-mockgen`.
- **Library design.** Every new option names its default in godoc, and every default and at least one override has a test (`library-design.md`).
- **Defaults:**
  - no base path;
  - `WithBasePath` given twice: the last call wins, as `EnableAuthorization`'s authorizer already does;
  - no endpoint path changes when no base path is set.
- **Base-path refusals** come from `newConfigError` naming `WithBasePath`: an empty value; `/`; a value not starting with `/`; a value where `path.Clean(p) != p` after dropping one trailing slash.
- **Prefix joins:** `joinBase("", p) == p`; `joinBase("/auth", "/login") == "/auth/login"`; a trailing slash on `p` is kept (`joinBase("/auth", "/oauth2/authorization/") == "/auth/oauth2/authorization/"`).
- **Operation identifiers** are `scrty.` + feature + `.` + step, in snake case. They are a documented contract:

  | Endpoint | Identifier |
  |---|---|
  | key set | `scrty.jwks` |
  | form login | `scrty.login` |
  | logout | `scrty.logout` |
  | session renewal | `scrty.session.renew` |
  | password-change endpoint | `scrty.password.change` |
  | magic link | `scrty.magiclink.request`, `scrty.magiclink.consume` |
  | MFA | `scrty.mfa.verify`, `scrty.mfa.begin`, `scrty.mfa.methods` |
  | enrolment | `scrty.mfa.enrol.begin`, `scrty.mfa.enrol.confirm`, `scrty.mfa.enrol.confirm_email` |
  | passkey sign-in | `scrty.passkey.login.begin`, `scrty.passkey.login.finish` |
  | passkey registration | `scrty.passkey.register.begin`, `.finish`, `.confirm`, `.confirm_email` |
  | passkey credentials | `scrty.passkey.credentials.list`, `.rename`, `.remove` |
  | recovery | `scrty.recovery.start`, `.complete`, `.finish`, `.cancel` |
  | recovery codes | `scrty.recovery.codes.count` (GET), `scrty.recovery.codes.regenerate` (POST) |
  | re-authentication | `scrty.reauth.methods`, `scrty.reauth.begin`, `scrty.reauth.verify`, `scrty.reauth.password` |
  | OIDC | `scrty.oidc.authorize`, `scrty.oidc.callback`, `scrty.oidc.handoff`, `scrty.oidc.backchannel_logout` |

  A built-in that answers a step not in this table follows the same rule. The dispatch reports the identifier it chose, and the main session adds it to the godoc table.
- **Path templates:** a segment an endpoint reads is written `{method}` (MFA, enrolment, re-authentication) or `{provider}` (OIDC).
- **Agents** never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and never edit `openspec/`. The reference-material rule binds every dispatch: consult it only on demand, never copy from it, never cite it.
- **Task 1's claim is UNREPRODUCED until its red test runs** (`defect-claims.md`). Nothing calls it a defect before then.

## Review Focus

- **Case:** a request to `/Auth/login` under the base `/auth` passes through to the handler, because paths are case-sensitive. Added to Task 3 (2.2).
- **The base itself:** a request to `/auth` or `/auth/` under the base `/auth` passes through and is answered by no built-in. Added to Task 3 (2.2).
- **Near-miss prefixes:** `/auth/mfa/verifyx/totp` under the base `/auth` is not answered by MFA verify, and `/authx/login` is not answered by login. Added to Task 4 (2.3) and Task 3 (2.2).
- **Redirect URL shape:** a redirect URL ending `/login/oauth2/callback/corp/` (trailing slash) is refused, since the callback answers exactly one segment. One with a query string (`.../callback/corp?x=1`) is judged on its path alone and accepted. Added to Task 13 (5.2).
- **An empty chain:** a chain with no built-ins returns an empty, non-nil `Endpoints()` slice. Added to Task 8 (3.1).

## Execution lanes and dispatches

Everything except Task 12 (`authenticate/oidc`) and Task 14 (`test` module) compiles package `httpsec`. Dispatches that run at the same time therefore each get **their own git worktree**, branched from the implementation branch (`isolation: "worktree"`). The main session merges each wave, runs the verification, then dispatches a fresh reviewer. Two agents never own one file.

| Wave | Dispatch | Plan tasks (tasks.md) | Owns | Model, reason | Reviewer |
|---|---|---|---|---|---|
| 1 | A1 | 2, 3 (2.1, 2.2) | `httpsec/basepath.go`, `httpsec/basepath_test.go` (new); `options.go` (config field, `build()` call); `login.go`, `login_options.go`, `logout.go`, `jwks.go`, `session_renewal.go`, `password_change.go` and their `_test.go` | Opus: introduces the resolution seam every later lane compiles against | Opus |
| 1 | R1 | 1 (1.1) | `httpsec/oidc_redirect_test.go` (new) | Sonnet: one red test the task fully specifies | Sonnet |
| 1 | O1 | 12 (5.1) | `authenticate/oidc/relying_party.go`, `authenticate/oidc/relying_party_test.go` | Sonnet: a read-only accessor with a stated contract | Sonnet |
| 2 | A2 | 4 (2.3) | `mfa_verify.go`, `mfa_begin.go`, `mfa_options.go`, `mfa_enrol.go`, `mfa_enrol_options.go` and their `_test.go` | Sonnet: applies Task 3's pattern | Sonnet |
| 2 | A3 | 5 (2.4) | `passkey.go`, `passkey_login.go`, `passkey_register.go`, `passkey_manage.go`, `magiclink.go`, `magiclink_options.go`, `recovery.go`, `recovery_options.go`, `recovery_codes.go` and their `_test.go` | Sonnet: applies Task 3's pattern | Sonnet |
| 2 | A4 | 6 (2.5) | `reauth.go`, `reauth_options.go`, `oidc.go`, `oidc_options.go`, `oidc_login.go` and their `_test.go` except `oidc_redirect_test.go`; `authorization_test.go` | Sonnet: applies Task 3's pattern | Sonnet |
| 3 | D1 | 7 (2.6) | godoc of every path option in `httpsec`, `basepath.go` godoc, `example_basepath_test.go` (new), `README.md` base-path section | Sonnet: documentation the task specifies | Sonnet |
| 3 | C1 | 14 (6.1) | `test/httpsecconformance/basepath_scenarios.go` (new), its registration in `scenarios.go` | Sonnet: conformance cases in an existing suite | Sonnet |
| 4 | A5 | 8, 9 (3.1, 3.2) | `httpsec/endpoints.go`, `httpsec/endpoints_test.go` (new); the `endpoints()` method added to each path-answering interceptor's file; `chain.go` (field, accessor); `options.go` (`build()` collection) | Opus: an exported type the later changes compile against, across every built-in | Opus |
| 5 | A6 | 10, 11 (4.1, 4.2) | `endpoints.go` (collision check), `endpoints_test.go`; `reauth_options.go`, `oidc_options.go` (local checks removed); the collision cases in `reauth_test.go`, `oidc_options_test.go`, `magiclink_options_test.go` | Opus: a refactor that keeps behaviour while extracting shared code | Opus |
| 6 | A7 | 13 (5.2) | `oidc_options.go`, `oidc_redirect_test.go`, OIDC fixtures and examples needing correction | Sonnet: the rule is fully stated (D5) | Sonnet |
| — | main | 15 (7.1) | — | the main session runs the gate | — |

- **Why waves 4 to 6 are sequential.** Wave 4 touches every interceptor file, wave 5 extends wave 4's `endpoints.go`, and wave 6 edits `oidc_options.go` after wave 5 has removed its local check.
- **What can run beside them.** Wave 3's C1 needs only `WithBasePath`.
- **Before archive,** one whole-branch review on Opus checks every requirement in both deltas.

---

### Task 1: Reproduce the OIDC redirect gap (tasks.md 1.1)

**Files:**
- Create: `httpsec/oidc_redirect_test.go`

**Interfaces:**
- Consumes: today's `EnableOIDCLogin`, `WithOIDCCallbackPath`, and the OIDC test fixtures in `helpers_test.go`.
- Produces: `TestOIDCLogin_RefusesRedirectURLThatCannotReachCallback`, red until Task 13.

- [ ] **Step 1: Write the test.** Build a chain with `EnableOIDCLogin` and `WithOIDCCallbackPath("/sso/callback/")`. Register provider `corp` with `RedirectURL: "https://app.example.com/login/oauth2/callback/corp"`. Assert that `httpsec.New` returns an error matching the configuration error and containing `corp`.
- [ ] **Step 2: Run it and record the failure.** Run `go test -run 'TestOIDCLogin_RefusesRedirectURLThatCannotReachCallback' -count=1 ./httpsec/`. Expected: FAIL, with the chain built and no error. Report the failing lines verbatim. If it PASSES, stop and report: D5 is withdrawn (`tasks.md` 1.1).
- [ ] **Step 3: Park it, and commit.** Add `t.Skip("red until tasks.md 5.2 (design D5); recorded failing in 1.1")` as the test's first line, so the merged tree stays green through waves 2–5. Commit `test(httpsec): reproduce an unreachable OIDC redirect (parked)`. Task 13 removes the skip as its red step.

### Task 2: `WithBasePath` (tasks.md 2.1)

**Files:**
- Create: `httpsec/basepath.go`, `httpsec/basepath_test.go`
- Modify: `httpsec/options.go` (`config.basePath string`)

**Interfaces:**
- Produces: `func WithBasePath(p string) Option`; `func joinBase(base, p string) string`.

- [ ] **Step 1: Write the failing test.** `TestWithBasePath`, a table with the following rows, each asserting through `New`:
  - `""`, `"/"`, `"auth"`, `"/auth/../admin"` and `"/auth//x"`: a configuration error containing `WithBasePath`;
  - `"/auth/"` and `"/auth"`: success, with the resolved base `/auth` (checked through `joinBase` and an internal accessor in `export_test.go`);
  - two calls, `/a` then `/b`: success, and the base is `/b`.
- [ ] **Step 2: Run it.** `go test -run 'TestWithBasePath' -count=1 ./httpsec/`. Expected: FAIL on the assertions, after a stub that compiles.
- [ ] **Step 3: Implement** `WithBasePath` with the Global Constraints' validation, and `joinBase` with its three stated cases.
- [ ] **Step 4: Run it again.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(httpsec): a base path option`.

### Task 3: Resolve paths at assembly (tasks.md 2.2)

**Files:**
- Modify: `httpsec/basepath.go` (the resolver seam), `httpsec/options.go` (`build()` calls `c.resolvePaths()` first), and `login.go`, `logout.go`, `jwks.go`, `session_renewal.go`, `password_change.go` with their options files
- Test: `httpsec/basepath_test.go`

**Interfaces:**
- Produces:
  - `type pathResolver interface{ resolvePaths(base string) }`, implemented by every path-answering interceptor;
  - `func (c *config) resolvePaths()`, which calls each registration's `resolvePaths(c.basePath)` and resolves `c.logoutPath`.
- Every later Task 4–6 interceptor implements `pathResolver`.

- [ ] **Step 1: Write the failing test.** `TestBasePath_ResolvesChainEndpoints`, a table over login, logout, the key set, renewal and the password-change endpoint. For each, with the base `/auth`:
  - the endpoint answers `/auth/<default>`;
  - `/<default>` reaches the handler;
  - `/Auth/<default>`, `/auth` and `/authx/<default>` reach the handler (Review Focus).

  Also:
  - a row with `WithLoginRequestPath("/signin")` expects `/auth/signin` to answer and `/signin` to pass through;
  - a row with `WithBasePath` given after `EnableFormLogin` gives the same result;
  - MFA's logout exemption still recognises `/auth/logout`.
- [ ] **Step 2: Run it.** `go test -run 'TestBasePath_ResolvesChainEndpoints' -count=1 ./httpsec/`. Expected: FAIL, with `/auth/login` passing through to the handler.
- [ ] **Step 3: Implement** `pathResolver` on the five interceptors, and call `c.resolvePaths()` as the first statement of `config.build()`.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/`. Expected: PASS, with every existing test unchanged.
- [ ] **Step 5: Commit** `feat(httpsec): resolve endpoint paths against the base path`.

### Task 4: MFA and enrolment paths (tasks.md 2.3)

**Files:** `mfa_verify.go`, `mfa_begin.go`, `mfa_options.go`, `mfa_enrol.go`, `mfa_enrol_options.go`; test in `mfa_options_test.go`.

**Interfaces:** Consumes `pathResolver` and `joinBase` (Task 3).

- [ ] **Step 1: Write the failing test.** `TestBasePath_MFAEndpoints` covers verify, begin, the listing and the three enrolment prefixes under `/auth`:
  - `POST /auth/mfa/verify/totp` reaches verify;
  - `POST /auth/mfa/verifyx/totp` and `POST /mfa/verify/totp` reach the handler.
- [ ] **Step 2: Run** with `-run 'TestBasePath_MFAEndpoints'`. Expected: FAIL.
- [ ] **Step 3: Implement** `resolvePaths` on the MFA and enrolment interceptors.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(httpsec): MFA and enrolment paths follow the base path`.

### Task 5: Passkey, magic-link and recovery paths (tasks.md 2.4)

**Files:** `passkey.go`, `passkey_login.go`, `passkey_register.go`, `passkey_manage.go`, `magiclink.go`, `magiclink_options.go`, `recovery.go`, `recovery_options.go`, `recovery_codes.go`; tests in `passkey_test.go`, `magiclink_options_test.go`, `recovery_options_test.go`.

- [ ] **Step 1: Write the failing tests.**
  - `TestBasePath_PasskeyEndpoints`, `TestBasePath_MagicLinkEndpoints` and `TestBasePath_RecoveryEndpoints`, the same shape as Task 3's test.
  - `TestBasePath_MagicLinkEmailKeepsConfirmPage`: under `/auth`, the sent message's link starts with the base URL given to `magiclink.New` followed by `/login/magic/confirm`, and the consume endpoint answers `POST /auth/login/magic/consume`.
- [ ] **Step 2: Run** with `-run 'TestBasePath_(Passkey|MagicLink|Recovery)'`. Expected: FAIL on the endpoint rows. The email row may already pass, because the link is outside the chain. It is the "does not move" guard, so confirm it fails if the resolver were wrongly applied: temporarily join the base into the confirm path, watch it fail, then restore.
- [ ] **Step 3: Implement** `resolvePaths` on these interceptors.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(httpsec): passkey, magic-link and recovery paths follow the base path`.

### Task 6: Re-authentication and OIDC paths (tasks.md 2.5)

**Files:** `reauth.go`, `reauth_options.go`, `oidc.go`, `oidc_options.go`, `oidc_login.go`; tests in `reauth_test.go`, `oidc_options_test.go`, `authorization_test.go`.

- [ ] **Step 1: Write the failing tests.**
  - `TestBasePath_ReauthEndpoints` and `TestBasePath_OIDCEndpoints`, the same shape as Task 3's test.
  - `TestBasePath_OIDCFlowCookieScopedToResolvedCallback`: the flow cookie set by `GET /auth/oauth2/authorization/corp` has `Path == "/auth/login/oauth2/callback/"`.
  - `TestBasePath_AuthorizationRulesKeepConsumerPaths`: a rule allowing `GET /projects/{id}` judges `/projects/42` under the base `/auth`.
- [ ] **Step 2: Run** with `-run 'TestBasePath_(Reauth|OIDC|Authorization)'`. Expected: FAIL on the endpoint and cookie rows. The authorization row is the guard that the base path does not reach the rules: confirm it with a temporary inversion, then restore.
- [ ] **Step 3: Implement** `resolvePaths` on both interceptors. The cookie path reads the resolved `callbackPath`.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(httpsec): re-authentication and OIDC paths follow the base path`.

### Task 7: Document the base path (tasks.md 2.6)

**Files:** godoc of `WithBasePath` and of every per-feature path option; `httpsec/example_basepath_test.go`; the `README.md` base-path section.

- [ ] **Step 1: Write the example first.** `ExampleWithBasePath` builds a chain with the base `/auth` and form login, sends `POST /auth/login`, and prints the status. Its `// Output:` fails until the example's wiring is right. Run `go test -run 'ExampleWithBasePath' ./httpsec/` and watch it fail.
- [ ] **Step 2: Write the godoc and the README.**
  - **`WithBasePath`:** the default (none); "last call wins"; what it covers; what it does not (consumer pages, authorization rules, consumer interceptors, a prefix a proxy strips).
  - **Every path option:** the line "relative to the base path (WithBasePath)".
  - **Magic link:** the confirm-page and consume-endpoint sentences.
  - **README:** the list of what does not move, and the migration steps (OIDC redirect URLs, the key set's URL).
- [ ] **Step 3: Verify.** `go test -run 'ExampleWithBasePath' ./httpsec/` passes, and `go doc ./httpsec WithBasePath` shows the default and the exclusions.
- [ ] **Step 4: Commit** `docs(httpsec): the base path`.

### Task 8: The endpoint inventory (tasks.md 3.1)

**Files:**
- Create: `httpsec/endpoints.go`, `httpsec/endpoints_test.go`
- Modify: every path-answering interceptor (one `endpoints()` method each), `chain.go`, `options.go`

**Interfaces:**
- Produces:

```go
type PathMatch int
const (
    MatchExact   PathMatch = iota + 1 // the path itself
    MatchSegment                      // the prefix followed by one non-empty segment
    MatchSubtree                      // the prefix and every path beneath it
)

type SessionState int
const (
    SessionNone    SessionState = iota + 1 // answered without a session
    SessionAny                             // any live session, whatever it owes
    SessionPending                         // a session owing a challenge or confined to binding
    SessionFull                            // a session owing nothing
)

type Endpoint struct {
    Methods     []string
    Path        string
    Match       PathMatch
    OperationID string
    EnabledBy   string
    Requires    SessionState
}

func (c *Chain) Endpoints() []Endpoint
type endpointDeclarer interface{ endpoints() []Endpoint } // unexported
```

- Each interceptor's `Match` follows how its code matches today: `==` is `MatchExact`, `underPrefix` is `MatchSubtree`, OIDC's `providerSegment` is `MatchSegment`. Its `Requires` follows its admission code. Its `OperationID` comes from the Global Constraints table.

- [ ] **Step 1: Write the failing tests.** `TestChainEndpoints`, a table:
  - **Form login and TOTP MFA under `/auth`.** The list contains `{Methods: ["POST"], Path: "/auth/login", Match: MatchExact, OperationID: "scrty.login", EnabledBy: "EnableFormLogin", Requires: SessionNone}` and `{Methods: ["POST"], Path: "/auth/mfa/verify/{method}", Match: MatchSubtree, OperationID: "scrty.mfa.verify", EnabledBy: "EnableMFA", Requires: SessionPending}`, and nothing for logout, passkeys or recovery.
  - **A consumer interceptor answering `/status`** is not listed.
  - **The returned list is a copy.** Mutating `[0].Methods[0]` and the slice changes neither a fresh `Endpoints()` nor a following request.
  - **The base path doesn't change identifiers.** The same configuration built without a base path has the same `OperationID` set.
  - **An empty chain** gives `len == 0` and a non-nil slice (Review Focus).
- [ ] **Step 2: Run** with `-run 'TestChainEndpoints'`. Expected: FAIL, after stubs that compile.
- [ ] **Step 3: Implement** `endpoints()` on every path-answering interceptor. `build()` collects them after `resolvePaths()`, in slot order and then registration order, into `Chain.endpoints`. `Endpoints()` deep-copies.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(httpsec): the chain lists the endpoints it answers`.

### Task 9: The drift guard (tasks.md 3.2)

**Files:** `httpsec/endpoints_test.go`.

- [ ] **Step 1: Write the test.** `TestChainEndpoints_EveryEntryIsAnswered` builds a chain with every built-in enabled under `/auth`. For each entry and method, it sends a request: `{method}` is replaced with `totp`, `{provider}` with `corp`, and a `MatchSubtree` entry gets the sample segment. It asserts that the terminal handler is not called.
- [ ] **Step 2: Red step.** Temporarily drop one interceptor's `endpoints()` entry and confirm the test fails, naming that path. Then restore it.
- [ ] **Step 3: Run** `go test -race -count=1 -run 'TestChainEndpoints_EveryEntryIsAnswered' ./httpsec/`. Expected: PASS.
- [ ] **Step 4: Commit** `test(httpsec): every listed endpoint is answered`.

### Task 10: One collision check (tasks.md 4.1)

**Files:** `httpsec/endpoints.go`, `httpsec/endpoints_test.go`.

**Interfaces:**
- Produces: `func checkEndpointCollisions(eps []Endpoint) error`, called in `build()` right after collection.
- Two entries collide when:
  - some path is answered by both under their `Match` kinds, and they share a method or differ in `EnabledBy`; or
  - an exact path equals the other's prefix, with or without its trailing slash.

- [ ] **Step 1: Write the failing test.** `TestChainPathCollisions`, a table:
  - **Login and magic-link request both on `/signin`:** an error containing `EnableFormLogin`, `EnableMagicLink` and `/signin`.
  - **A re-authentication prefix whose password path lies under the MFA verify prefix:** an error naming `EnableReauthentication` and `EnableMFA`.
  - **Recovery codes, GET and POST on one path:** builds.
  - **The base `/auth` with the logout path set to `/login`:** an error containing `/auth/login`.
- [ ] **Step 2: Run** with `-run 'TestChainPathCollisions'`. Expected: FAIL on the rows the local checks do not cover (the first and the last).
- [ ] **Step 3: Implement** `checkEndpointCollisions`.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(httpsec): one collision check over the resolved paths`.

### Task 11: Retire the local checks (tasks.md 4.2)

**Files:** `reauth_options.go`, `oidc_options.go`, and the collision cases in `reauth_test.go`, `oidc_options_test.go` and `magiclink_options_test.go`, moved into `TestChainPathCollisions`.

- [ ] **Step 1: Move the cases.** Each local collision case moves into `TestChainPathCollisions` with its assertion unchanged except the error text, which now names both options. A case whose expectation depended on a match kind the endpoint does not have (an `under` claim on an exact endpoint) is **reported to the main session, not silently changed**.
- [ ] **Step 2: Red step.** Remove `reauthInterceptor.checkPaths` and `oidcInterceptor.checkPaths`. Temporarily make `checkEndpointCollisions` skip pairs within one option, and confirm the moved OIDC cases fail. Then restore it.
- [ ] **Step 3: Run** `go test -race -count=1 ./httpsec/` and `golangci-lint run ./httpsec/`. Expected: PASS and no findings.
- [ ] **Step 4: Commit** `refactor(httpsec): path collisions are checked in one place`.

### Task 12: The redirect URL accessor (tasks.md 5.1)

**Files:** `authenticate/oidc/relying_party.go`, `authenticate/oidc/relying_party_test.go`.

**Interfaces:**
- Produces: `func (m *RelyingParty) RedirectURL(provider string) (string, bool)`.

- [ ] **Step 1: Write the failing test.** `TestRelyingParty_RedirectURL` registers `corp` and `acme` and reads both URLs back exactly. `RedirectURL("nope")` returns `"", false`.
- [ ] **Step 2: Run** `go test -run 'TestRelyingParty_RedirectURL' -count=1 ./authenticate/oidc/`. Expected: FAIL.
- [ ] **Step 3: Implement** it, reading `registry.Lookup(provider)`. The godoc says the URL is configuration, not a secret.
- [ ] **Step 4: Run** `go test -race -count=1 ./authenticate/oidc/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(oidc): read a provider's redirect URL`.

### Task 13: The OIDC redirect check (tasks.md 5.2)

**Files:** `oidc_options.go`, `oidc_redirect_test.go`, and the OIDC fixtures and examples to correct.

**Interfaces:**
- Consumes: `RelyingParty.Providers()` and `RedirectURL` (Task 12), and the resolved `callbackPath` (Task 6).
- Produces: `func WithoutOIDCRedirectPathCheck() OIDCOption`.

- [ ] **Step 1: Unpark and extend the red test.** Remove Task 1's `t.Skip`. Add `TestOIDCLogin_RedirectPathCheck`, a table:
  - **Matching URL, no base:** builds.
  - **Base `/auth`, URL unchanged:** an error containing `corp`, `/login/oauth2/callback/corp` and `/auth/login/oauth2/callback/corp`.
  - **`https://example.com/public/login/oauth2/callback/corp`, no base:** builds.
  - **The waiver with `https://example.com/cb?p=corp`:** builds.
  - **Trailing-slash URL:** refused (Review Focus).
  - **URL with `?x=1`:** builds (Review Focus).
- [ ] **Step 2: Run** with `-run 'TestOIDCLogin_(RefusesRedirectURLThatCannotReachCallback|RedirectPathCheck)'`. Expected: FAIL on every refusal row.
- [ ] **Step 3: Implement** the check in `config.build()`, after `resolvePaths()` and before the chain is frozen, as a `wireOIDC`-style step beside `wireMFA`. Use `strings.HasSuffix(url.Path, callbackPath+name)`. Add the waiver, with godoc stating what it gives up. Correct any fixture whose redirect URL does not match its callback path, and list each one in the report.
- [ ] **Step 4: Run** `go test -race -count=1 ./httpsec/ ./authenticate/oidc/` and `go test ./...` in `test`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(httpsec): an OIDC redirect URL must reach the callback`.

### Task 14: Conformance across adapters (tasks.md 6.1)

**Files:** `test/httpsecconformance/basepath_scenarios.go`, `test/httpsecconformance/scenarios.go`.

- [ ] **Step 1: Write the scenarios.** On net/http, gin and fiber:
  - `BasePathMovesDefaults`: login and the key set under `/auth`, and `/login` passing through;
  - `BasePathKeepsConsumerRules`: a rule on `/projects/{id}`;
  - `ProxyStrippedPrefix`: no base path, a request to `/login` answered.
- [ ] **Step 2: Run** `go test -race -run 'BasePath|ProxyStripped' ./...` in `test`. Expected: PASS once Tasks 3 and 6 are merged. Show the red step by running against the wave-1 merge with Task 3's `resolvePaths` call temporarily removed, and watch `BasePathMovesDefaults` fail.
- [ ] **Step 3: Run** `go vet ./...` and `go test -race ./...` in `test`. Expected: PASS.
- [ ] **Step 4: Commit** `test(conformance): the base path on every adapter`.

### Task 15: The gate (tasks.md 7.1)

- [ ] **Step 1: Run the gate.**
  - `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...` and `golangci-lint run ./...` in every module from `go list -m`;
  - `gofmt -l` over tracked Go files;
  - `openspec validate endpoint-inventory-base-path --strict`.
- [ ] **Step 2: Check the results.** Every command exits 0. The main session records the output and ticks 7.1.
