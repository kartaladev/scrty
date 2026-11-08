# Endpoint Inventory and Base Path Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One option, `WithBasePath`, moves every built-in `httpsec` endpoint under a prefix; defaults follow one vocabulary; the chain lists the operations it answers, and that list backs one collision check and the construction-time checks a moved endpoint needs.

**Architecture:**
- **One shape, then resolution before validation.** Every path setting passes one shape check. `New` resolves every declared path against the base path right after the option loop and before `validate`, so every check and every derived value (D11) reads resolved paths. The provider's `settlePaths` and `routers` move after resolution.
- **The inventory.** Each built-in declares one `Endpoint` per operation. `build()` collects them, runs the single collision check, and freezes a copy on the `Chain`.
- **Reach checks.** The issuer, stale-route and redirect checks read resolved paths and the inventory, each with a waiver.

**Tech Stack:** Go 1.27; `net/http`, gin, fiber v3; testify, gomock (`use-mockgen`).

**Spec:** `openspec/changes/endpoint-inventory-base-path/`: `proposal.md`, `design.md` (D1–D13, Failure modes), `specs/**` and `tasks.md`. Task numbers in parentheses (`2.1`) are `tasks.md`'s; every plan task names the ones it implements, and no plan task exists without one.

## Global Constraints

- **Test-first** for every task: write the failing test, run it, confirm it fails **for the intended reason** (a compile error is not a red step). Where a task keeps behaviour, the red step is a temporary inversion a test catches, then restored (`golang-tdd.md`).
- **Defensive coding** (`defensive-coding.md`): each row of `design.md`'s Failure modes table that a task owns is tested or handled as the table says.
- **Table tests** use the `table-test` skill (`assert` closure, `t.Context()`, `ctx` modifier). Mocks use `use-mockgen`. The conformance suite uses existing helpers; no hand-rolled fakes of heavy services (`use-testcontainers`).
- **Library design:** every new option names its default in godoc; every default and at least one override has a test.
- **Shape rule (D4):** non-empty; starts with `/`; not `/`; `path.Clean(strings.TrimSuffix(p, "/")) == strings.TrimSuffix(p, "/")`; only `[A-Za-z0-9._~/-]`. Refusal: `newConfigError` naming the setting.
- **Join (D1):** `joinBase("", p) == p`; `joinBase("/auth", "/sso/callback/") == "/auth/sso/callback/"`. Concatenation only.
- **Defaults (D3):** exactly `design.md`'s table; option names unchanged; constant names unchanged.
- **Operation identifiers (D6):** exactly `design.md`'s table.
- **Waivers:** `WithoutOIDCIssuerBasePathCheck()`, `WithoutBasePathRouteCheck()`, `WithoutOIDCRedirectPathCheck()`.
- **Agents** never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and never edit `openspec/`. The read-only reference rule binds every dispatch: consult on demand, never copy, never cite.
- **Task 1's claim is UNREPRODUCED until its red test runs** (`defect-claims.md`).

## Review Focus

- **Case:** under base `/auth`, a request to `/Auth/sign-in/password` passes through (paths are case-sensitive). Added to Task 5.
- **The base itself:** `/auth` and `/auth/` under base `/auth` are answered by no built-in. Added to Task 5.
- **Near-miss prefixes:** `/authx/sign-in/password` and `/auth/mfa/verifyx/totp` are not answered. Added to Task 5 and Task 10's drift guard.
- **Redirect URL shape:** a redirect URL ending `/sso/callback/corp/` is refused (the callback answers exactly one segment); one with a query (`.../corp?x=1`) is judged on its path and accepted. Added to Task 16.
- **An empty chain:** a chain with no built-ins returns an empty, non-nil `Endpoints()`. Added to Task 10.

## Execution lanes and dispatches

Everything but Task 15 (`authenticate/oidc`) and Tasks 4 and 18 (`test` module) compiles package `httpsec`. Dispatches in the same wave get **their own git worktree** (`isolation: "worktree"`); the main session merges the wave, runs verification, then dispatches a fresh reviewer. Two agents never own one file. Waves run in order.

| Wave | Dispatch | Plan task (tasks.md) | Owns | Model, reason | Reviewer |
|---|---|---|---|---|---|
| 1 | R1 | 1 (1.1) | `httpsec/oidc_redirect_test.go` (new; red output recorded, file **not merged** — P1 lands it in wave 10) | Sonnet: one red test the task specifies | Sonnet |
| 1 | O1 | 15 (7.1) | `authenticate/oidc/relying_party.go`, `relying_party_test.go` | Sonnet: read-only accessor with a stated contract | Sonnet |
| 1 | S1 | 2 (2.1) | `httpsec/paths.go`, `paths_test.go` (new); every path setter: `*_options.go`, `jwks.go`, `logout.go`, `mfa_begin.go`, `mfa_verify.go` (listing), `passkey.go`, `passkey_login.go`, `session_renewal.go`, `session_management.go`, `signals.go`, `password_change.go`; the shape tests in their `_test.go` | Sonnet: one stated rule applied at known sites | Sonnet |
| 2 | N1 | 3 (2.2) | `Default*` constants and suffixes (`reauth.go` included) and their tests/examples in `httpsec`, `ginsec`, `fibersec`; `authenticate/magiclink/links.go`, `links_options.go` and tests; `authenticate/oidc/doc.go`, `example_test.go`; `authenticate/passkey/example_test.go`; `policy/example_test.go`; old default paths in `README.md` | Sonnet: mechanical rename the table fixes | Sonnet |
| 3 | N2 | 4 (2.3) | `test/httpsecconformance/*`, `test/*_test.go` default-path references, `test/testdata/keycloak/realm.json` | Sonnet: mechanical | Sonnet |
| 3 | A1 | 5 (3.1, 3.2) | `httpsec/basepath.go`, `basepath_test.go` (new); `options.go` (`basePath` field, resolution call in `New`); `login.go`, `logout.go`, `jwks.go`, `session_renewal.go`, `password_change.go`, `signals.go`, `session_management.go` resolve steps and tests | Opus: the seam every later lane compiles against, and its ordering before `validate` | Opus |
| 4 | A2 | 6 (3.3) | `mfa_*.go`, `passkey*.go`, `magiclink*.go`, `recovery*.go` resolve steps; `basepath_features_test.go` (new) | Sonnet: applies Task 5's pattern | Sonnet |
| 4 | A3 | 7 (3.4) | `reauth*.go`, `oidc.go`, `oidc_options.go`, `oidc_login.go` resolve steps; `basepath_reauth_oidc_test.go` (new) | Sonnet: applies Task 5's pattern | Sonnet |
| 4 | A4 | 8 (3.5) | `oidc_provider.go`, `oidc_provider_options.go`, `oidc_metadata.go`; `basepath_provider_test.go` (new) | Opus: moves route-map construction after resolution and changes what overrides mean | Opus |
| 5 | A5 | 9 (3.6) | gate, CSRF, CORS, cookie and session-touch sites listed in Task 9 | Opus: many derived values where a miss passes tests and is still wrong | Opus |
| 6 | A6 | 10 (4.1, 4.2) | `httpsec/endpoints.go`, `endpoints_test.go` (new); one `endpoints()` method per path-answering interceptor file; `chain.go` (field, accessor); `options.go` (collection in `build()`) | Opus: exported type later changes compile against, across every built-in | Opus |
| 7 | A7 | 12 (5.1) | `httpsec/endpoints_collide.go`, `endpoints_collide_test.go` (new); `options.go` (call) | Opus: the rule other checks are retired into | Opus |
| 8 | A8 | 13 (5.2) | collision code in `mfa_options.go`, `mfa_verify.go`, `mfa_enrol.go`, `passkey.go`, `recovery.go`, `session_renewal.go`, `magiclink.go`; their collision tests; `endpoints_collide_test.go` rows | Opus: refactor keeping behaviour while extracting shared code | Opus |
| 9 | A9 | 14 (5.3) | collision code in `signals.go`, `reauth_options.go`, `oidc_options.go`, `oidc_provider.go`; their collision tests; `endpoints_collide_test.go` rows | Opus: same, across the provider | Opus |
| 10 | P1 | 16 (7.2) | `oidc_options.go` redirect check and its waiver as an `OIDCOption` field, `oidc_redirect_test.go` (from R1), OIDC fixtures needing correction | Sonnet: the rule is fully stated (D10) | Sonnet |
| 10 | P2 | 17 (6.1, 6.2) | `httpsec/reach.go`, `reach_test.go` (new); `options.go` (the two waiver fields); the route accessors in `recovery_cooldown.go`, `csrf_exemption.go`; `headers.go` godoc only | Opus: refusal logic guarding a fail-open, written for the first time | Opus |
| 11 | D1 | 19 (8.1) | godoc of every path setting and new option, `example_basepath_test.go` (new), `README.md` sections | Sonnet: documentation the task specifies | Sonnet |
| 11 | C1 | 18 (9.1) | `test/httpsecconformance/basepath_scenarios.go` (new), its registration | Sonnet: conformance cases in an existing suite | Sonnet |
| — | main | 20 (10.1) | — | the main session runs the gate | — |

- **Why waves 2–9 are sequential.** Wave 2 renames constants every later test names; wave 3's seam is what waves 4–5 call; wave 6 touches every interceptor file; waves 7–9 extend one test table and retire checks in files wave 6 edited.
- **Before archive,** one whole-branch review on Opus checks every requirement in every delta.

---

### Task 1: Reproduce the OIDC redirect gap (1.1)

**Files:** Create `httpsec/oidc_redirect_test.go`

**Interfaces:** Consumes the current `EnableOIDCLogin`, `WithOIDCCallbackPath`. Produces the test Task 16 turns green.

- [ ] **Step 1:** Write `TestOIDCLogin_RefusesRedirectURLThatCannotReachCallback`: `WithOIDCCallbackPath("/federation/callback/")`, provider `corp` with redirect URL `https://app.example.com/login/oauth2/callback/corp` (today's default path); assert `errors.Is(err, httpsec.ErrConfig)`.
- [ ] **Step 2:** Run `go test -run 'TestOIDCLogin_RefusesRedirectURLThatCannotReachCallback' -count=1 ./httpsec/`. Expected: FAIL because `New` returned nil. Record the output; do not merge the file (P1 lands it). If it passes, stop and report: D10 is removed by the main session.

### Task 2: One path shape (2.1)

**Files:** Create `httpsec/paths.go`, `httpsec/paths_test.go`; modify every path setter named in the lane table.

**Interfaces:** Produces `func checkEndpointPath(setting, p string) error` (the D4 rule).

- [ ] **Step 1:** Write `TestEndpointPathShape`, a table per form (`WithLoginRequestPath`, `WithOIDCProviderPath`, `SessionSignals.Path`, the `ListingPath` setting of `WithMFAMethodListing`, `WithPasswordChangeEndpoint`) over `signin`, `/`, `/a/../b`, `/a//b`, `/session/sig nals`, `/a%20b`, `/a?b`: each `New` error names the setting. Rows: `WithOIDCCallbackPath("/federation/callback/")` builds; `SessionSignals.Path = "/session/signals/"` builds; `WithOIDCProviderPath(OIDCToken, "/a:b")` and `"/a@b"` are refused.
- [ ] **Step 2:** Run `go test -race -count=1 -run 'TestEndpointPathShape' ./httpsec/`. Expected: FAIL on rows today's setters accept (`signin`, `/`, dot segments on `WithOIDCProviderPath`).
- [ ] **Step 3:** Implement `checkEndpointPath` per Global Constraints and call it from every setter; remove the per-setter shape checks it replaces, moving their tests into the table.
- [ ] **Step 4:** Run `go test -race -count=1 ./httpsec/`. Expected: PASS.

### Task 3: New defaults (2.2)

**Files:** `Default*` constants and suffixes in `httpsec` (`reauth.go` included); `authenticate/magiclink/links.go` (`defaultConfirmPath`) and `links_options.go` godoc; tests, examples and doc comments naming defaults in the packages N1 owns; old default paths in `README.md`.

**Interfaces:** Constant names unchanged; values per D3.

- [ ] **Step 1:** Write `TestDefaultEndpointPaths`: per built-in with defaults, the D3 path answers and the old default passes through; `magiclink` default confirm path is `/sign-in/magic-link/confirm`.
- [ ] **Step 2:** Run `go test -race -count=1 -run 'TestDefaultEndpointPaths' ./httpsec/ ./authenticate/magiclink/`. Expected: FAIL on every renamed row.
- [ ] **Step 3:** Change the constant values; update every test, example, doc comment and README line naming a default, using constants where the literal is not the point. `grep -rn '/login\|/logout\|/passkey/\|/mfa/begin\|/reauth/begin\|/oauth2/authorization\|/login/oauth2\|/logout/oauth2' --include=*.go --include=*.md .` (excluding `openspec/` and `.claude/`) returns only intended non-default uses.
- [ ] **Step 4:** Run `go test -race -count=1 ./httpsec/... ./authenticate/magiclink/...`. Expected: PASS.

### Task 4: Defaults in the test module (2.3)

**Files:** `test/httpsecconformance/*`, `test/*_test.go`.

- [ ] **Step 1:** Run `go test -race ./...` in `test`; expected: FAIL where scenarios post to old defaults (the red step comes from Task 3).
- [ ] **Step 2:** Update each reference to mirror the MODIFIED scenarios of `csrf-protection`, `framework-adapters`, `sender-constrained-tokens`, and the redirect URIs in `test/testdata/keycloak/realm.json` to end in `/sso/callback/scrty-{post,basic}`.
- [ ] **Step 3:** Run `go vet ./...` and `go test -race ./...` in `test`. Expected: PASS.

### Task 5: `WithBasePath` and the resolution seam (3.1, 3.2)

**Files:** Create `httpsec/basepath.go`, `basepath_test.go`; modify `options.go` and the resolve steps of `login.go`, `logout.go`, `jwks.go`, `session_renewal.go`, `password_change.go`, `signals.go`, `session_management.go`.

**Interfaces:**
- Produces `func WithBasePath(p string) Option` (option name `"WithBasePath"`), `func joinBase(base, p string) string`, `config.basePath string`.
- Produces `type pathResolver interface{ resolvePaths(base string) error }`; `New` calls `c.resolvePaths()` after the option loop and before `c.validate()`, which calls each registered `pathResolver` and then the D5 refusals.

- [ ] **Step 1:** Write `TestWithBasePath` (table): `/`, `auth`, `/auth/../admin`, `/auth%20x` refused naming `WithBasePath`; `/auth/` accepted as `/auth`; base on a chain answering no built-in refused; `WithLoginRequestPath("/auth/sign-in/password")` under `/auth` refused naming the option and `/auth/auth/sign-in/password`; key set `/api-keys` under `/api` answers `/api/api-keys`; given `/a` then `/b`, `/b` wins.
- [ ] **Step 2:** Write `TestBasePath_ResolvesCoreEndpoints` (table per endpoint of this task): under `/auth` it answers at `/auth` + default and the unprefixed path passes through; consumer path `/signin` answers `/auth/signin`; `WithBasePath` given last gives the same; Review Focus rows (`/Auth/...`, `/auth`, `/auth/`, `/authx/sign-in/password` pass through).
- [ ] **Step 3:** Run `go test -race -count=1 -run 'TestWithBasePath|TestBasePath_ResolvesCoreEndpoints' ./httpsec/`. Expected: FAIL on the path assertions. Declare `WithBasePath` as a no-op first, so the red step is never a compile error.
- [ ] **Step 4:** Implement the option, `joinBase`, the seam, and `resolvePaths` for this task's interceptors (each keeps its declared path and stores the resolved one).
- [ ] **Step 5:** Run `go test -race -count=1 ./httpsec/`. Expected: PASS.

### Task 6: MFA, passkey, magic-link and recovery paths (3.3)

**Interfaces:** Consumes `pathResolver`, `joinBase` (Task 5).

- [ ] **Step 1:** In `basepath_features_test.go`, write `TestBasePath_ResolvesFeatureEndpoints` as Task 5 Step 2 for these endpoints, with `/auth/mfa/verify/totp` and `/auth/mfa/challenge/email-code`; plus `TestMagicLink_ConfirmPageNotMovedByBasePath` (emailed link points at the confirm page, redeem answers `/auth/sign-in/magic-link/redeem`).
- [ ] **Step 2:** Run with `-run 'TestBasePath_ResolvesFeatureEndpoints|TestMagicLink_ConfirmPageNotMovedByBasePath'`. Expected: FAIL on path assertions.
- [ ] **Step 3:** Implement `resolvePaths` on each interceptor.
- [ ] **Step 4:** Run `go test -race -count=1 ./httpsec/`. Expected: PASS.

### Task 7: Re-authentication and OIDC login paths (3.4)

- [ ] **Step 1:** In `basepath_reauth_oidc_test.go`, write `TestBasePath_ResolvesReauthAndOIDC` as Task 5 Step 2 (`/auth/reauth/challenge/totp`, `/auth/sso/login/corp`, `/auth/sso/callback/corp`, `/auth/sso/handoff`, `/auth/sso/backchannel-logout/corp`) and `TestBasePath_AuthorizationRulesKeepConsumerPaths` (`GET /projects/{id}` judges `/projects/42`, never matches `/auth/projects/42`).
- [ ] **Step 2:** Run them. Expected: FAIL on path assertions.
- [ ] **Step 3:** Implement `resolvePaths` for `reauthInterceptor` and `oidcInterceptor`.
- [ ] **Step 4:** Run `go test -race -count=1 ./httpsec/`. Expected: PASS.

### Task 8: Provider paths (3.5)

- [ ] **Step 1:** In `basepath_provider_test.go`, write `TestOIDCProvider_BasePath` (issuer `https://id.example.com/auth` in every row): under `/auth` the token endpoint answers `/auth/oauth2/token`; `WithOIDCProviderPath(OIDCToken, "/tokens")` answers `/auth/tokens`; with issuer `https://id.example.com/auth` the metadata names `https://id.example.com/auth/oauth2/token` and `jwks_uri` `https://id.example.com/auth/.well-known/jwks.json`, the OpenID configuration answers `/auth/.well-known/openid-configuration`, the authorization server metadata `/.well-known/oauth-authorization-server/auth`; provider options given before `WithBasePath` give the same; an authorization request needing sign-in goes to the consumer's login page unchanged.
- [ ] **Step 2:** Run it. Expected: FAIL (route maps keyed by unresolved paths).
- [ ] **Step 3:** Implement `resolvePaths` on `oidcEndpoints`; move `settlePaths` and `routers` to run after resolution.
- [ ] **Step 4:** Run `go test -race -count=1 ./httpsec/`. Expected: PASS.

### Task 9: Derived values follow resolved paths (3.6)

**Files:** `options.go` (`logoutPath`), `mfa_verify.go`, `mfa_enrol.go`, `password_change.go`, `recovery_gate.go`, `csrf_exemption.go`, `oidc_cors.go`, `oidc_authorize.go`, `oidc_endsession.go`, `oidc_provider.go` (DPoP and assertion checks), `oidc.go` (flow cookie), `passkey_login.go`, `magiclink.go`, `signals.go` (`signalsPath`); `derived_paths_test.go` (new).

- [ ] **Step 1:** Write `TestBasePath_DerivedValuesFollow` (table), each under `/auth`: MFA-pending, enrolment-only, password-change-pending and recovery-pending sessions can POST `/auth/sign-out`; recovery gate exempts moved enrolment and passkey paths; cross-site POST to `/auth/sso/backchannel-logout/corp` reaches back-channel logout; provider POST endpoints exempt and CORS covers `/auth/oauth2/token`; bounce URLs, DPoP `htu` and assertion audience use moved paths; flow cookie `Path=/auth/sso/callback/`, passkey ceremony cookie path is the moved finish path, binding cookie `Path=/auth/sign-in/magic-link/redeem`; GET `/auth/session/signals` leaves last activity unchanged.
- [ ] **Step 2:** Run it. Expected: FAIL on each row whose value is still read before resolution or from the declared path.
- [ ] **Step 3:** Make each site read the resolved path.
- [ ] **Step 4:** Run `go test -race -count=1 ./httpsec/`. Expected: PASS.

### Task 10: The endpoint inventory and its drift guard (4.1, 4.2)

**Files:** Create `httpsec/endpoints.go`, `endpoints_test.go`; add `endpoints()` to each path-answering interceptor; modify `chain.go`, `options.go`.

**Interfaces:** Produces exactly D6's `Endpoint` (with D6's declared sharers and match kinds), `PathMatch` (`MatchExact`, `MatchSegment`, `MatchSubtree`), `MethodPolicy` (`OtherMethodsPassThrough`, `OtherMethodsRefused`), `Requirement` (`RequiresNothing`, `RequiresAuthentication`, `RequiresPendingSecondFactor`, `RequiresPendingEnrolment`, `RequiresSession`, `RequiresBearer`, `RequiresClientAuthentication`), `func (c *Chain) Endpoints() []Endpoint`, `type endpointDeclarer interface{ endpoints() []Endpoint }`, plus an unexported `Endpoint.consequence string` used by Task 12's error.

- [ ] **Step 1:** Write `TestChainEndpoints` covering every scenario of "The chain lists the endpoints it answers" except the last, and a table pinning every operation's identifier, methods, match, other-method policy and `Requires`; rows mutating the returned slice and an entry's `Methods[0]` leave a fresh list unchanged; Review Focus row: a chain with no built-ins returns a non-nil empty slice.
- [ ] **Step 2:** Run `-run 'TestChainEndpoints'`. Expected: FAIL (empty list).
- [ ] **Step 3:** Implement the types, declarations and collection (slot order, then registration order); discovery documents at their served paths; `Endpoints()` returns a deep copy (`slices.Clone` of the list and of each `Methods`).
- [ ] **Step 4:** Write `TestChainEndpoints_EveryEntryIsAnswered`: every built-in enabled under `/auth` with provider prerequisites; per entry, listed method and path (sample segment) answered and handler not reached; sibling path, parent path and unlisted method behave per `OtherMethods`; signal stream request cancelled.
- [ ] **Step 5:** Red step: drop one declaration, run `-run 'TestChainEndpoints_EveryEntryIsAnswered'`, see FAIL naming it; restore.
- [ ] **Step 6:** Run `go test -race -count=1 ./httpsec/`. Expected: PASS.

### Task 12: One collision check (5.1)

**Files:** Create `httpsec/endpoints_collide.go`, `endpoints_collide_test.go`; call from `options.go`.

**Interfaces:** Produces `func checkCollisions(eps []Endpoint) error`. Error text: `"%s's path %q collides with %s's path %q, so %s"` naming each entry's `PlacedBy`, with the first non-empty `consequence` or `"one endpoint would answer the other's requests"`.

- [ ] **Step 1:** Write `TestChainPathCollisions` with every scenario of "Colliding endpoint paths fail at construction".
- [ ] **Step 2:** Run `-run 'TestChainPathCollisions'`. Expected: FAIL on rows no current check covers (password sign-in vs magic-link on `/signin`, overrides on `/oauth2/me`, key set on the OpenID configuration's path).
- [ ] **Step 3:** Implement: overlap by match kind on the path before the first `{…}`; `OtherMethodsRefused` claims every method; exact-vs-prefix rule across features, with or without trailing slash; exemption only within one feature for equal non-empty `SharesPath` with disjoint methods or exact beside one-segment; first pair in inventory order.
- [ ] **Step 4:** Run `go test -race -count=1 ./httpsec/`. Expected: PASS.

### Task 13: Retire feature collision checks (5.2)

- [ ] **Step 1:** Move each collision test from the files the lane table lists into `TestChainPathCollisions` rows, assertions kept except wording.
- [ ] **Step 2:** Remove the local checks.
- [ ] **Step 3:** Red step: make `checkCollisions` skip one moved pair; run; see that row FAIL; restore.
- [ ] **Step 4:** Run `go test -race -count=1 ./httpsec/` and `golangci-lint run ./httpsec/`. Expected: PASS, no findings.

### Task 14: Retire re-authentication, signal-stream, OIDC and provider collision checks (5.3)

- [ ] **Step 1:** As Task 13 Step 1 for `signals_construction_test.go`, `reauth_test.go`, `oidc_options_test.go`, `oidc_provider_test.go`; add one row per changed verdict in D13 (among them re-authentication prefix `/passkeys/register` now built), listed in the report.
- [ ] **Step 2:** Remove `checkPaths`, `claimedPaths`, `collides`, the provider's duplicate refusals in `settlePaths`/`routers`, `checkCollisions`, `checkConsentSubtree`, `oidcForeignPaths`, `oidcForeignPrefixes`.
- [ ] **Step 3:** Red step as Task 13 Step 3.
- [ ] **Step 4:** Run `go test -race -count=1 ./httpsec/` and `golangci-lint run ./httpsec/`. Expected: PASS.

### Task 15: Redirect URL accessor (7.1)

**Interfaces:** Produces `func (rp *RelyingParty) RedirectURL(provider string) (string, bool)`.

- [ ] **Step 1:** Write `TestRelyingParty_RedirectURL`: two providers read back; unknown name returns `"", false`.
- [ ] **Step 2:** Run `go test -race -count=1 -run 'TestRelyingParty_RedirectURL' ./authenticate/oidc/`. Expected: FAIL.
- [ ] **Step 3:** Implement via the registry lookup.
- [ ] **Step 4:** Run `go test -race -count=1 ./authenticate/oidc/`. Expected: PASS.

### Task 16: OIDC redirect check (7.2)

**Interfaces:** Consumes Task 15's accessor and the resolved callback path. Produces `func WithoutOIDCRedirectPathCheck() OIDCOption`.

- [ ] **Step 1:** Add `TestOIDCLogin_RedirectPath` rows: every scenario of "A provider's redirect URL must reach the callback path", plus Review Focus rows (trailing slash refused, query accepted).
- [ ] **Step 2:** Run with Task 1's test. Expected: FAIL (no check).
- [ ] **Step 3:** Implement at assembly: `strings.HasSuffix(u.Path, callback+name)` on the decoded path; the waiver is an `OIDCOption` field (`WithoutOIDCRedirectPathCheck()` returns `OIDCOption`) and skips it. Correct fixtures whose redirect URLs do not match, listing each.
- [ ] **Step 4:** Run `go test -race -count=1 ./httpsec/ ./authenticate/oidc/` and `go test ./...` in `test`. Expected: PASS, Task 1's test green.

### Task 17: Issuer and stale-route checks (6.1, 6.2)

**Files:** Create `httpsec/reach.go`, `reach_test.go`; modify `options.go` (waiver fields); route accessors in `recovery_cooldown.go`, `csrf_exemption.go`; `headers.go` godoc.

**Interfaces:** Produces `WithoutOIDCIssuerBasePathCheck() Option`, `WithoutBasePathRouteCheck() Option`; both checks run after collection, reading resolved paths and each endpoint's declared (pre-base) path.

- [ ] **Step 1:** Write `TestOIDCProvider_IssuerBasePath` with every scenario of "Under a base path the provider's issuer must cover it", plus the waiver with a root issuer and a provider built with `AudienceIssuerOrTokenEndpoint` refused by the assertion endpoint check.
- [ ] **Step 2:** Write `TestBasePathRouteCheck` with every scenario of "A consumer route naming a moved endpoint fails at construction", covering cool-down routes (including `/Reauth/Password/`) and cross-site exemptions (including the pattern `/sso/*/x`).
- [ ] **Step 3:** Run both. Expected: FAIL (chains are built).
- [ ] **Step 4:** Implement D8's predicate (issuer path trimmed is at or under the base; every provider path and the key set lie under the issuer path) and D9's (each route, in its matcher's normal form, would match a request to a declared pre-base path; "under" only for subtree and segment endpoints). Add to `WithHeaderProfile`'s godoc that its matcher is not checked.
- [ ] **Step 5:** Run `go test -race -count=1 ./httpsec/`. Expected: PASS.

### Task 18: Conformance across adapters (9.1)

- [ ] **Step 1:** Add `basepath_scenarios.go` mirroring "Every adapter answers the same paths" and "Prefix stripped before the chain", plus the authorization-rule case; register it.
- [ ] **Step 2:** Red step: temporarily expect `/sign-in/password` instead of `/auth/sign-in/password`; run `go test -race ./...` in `test`; see FAIL on all three adapters; restore.
- [ ] **Step 3:** Run `go vet ./...` and `go test -race ./...` in `test`. Expected: PASS on net/http, gin and fiber.

### Task 19: Documentation (8.1)

- [ ] **Step 1:** Write `ExampleWithBasePath` (password sign-in under `/auth`, `// Output:` pinned); run `go test -run 'ExampleWithBasePath' ./httpsec/`; expected FAIL before the example output matches, then PASS.
- [ ] **Step 2:** Godoc per tasks.md 8.1; README default-path table, base-path section, migration steps. No old default path appears in the README as a default; the migration step lists the earlier defaults by name so client code can be found and updated.
- [ ] **Step 3:** Run `go doc ./httpsec WithBasePath`; expected: shows default and exclusions.

### Task 20: The gate (10.1)

- [ ] **Step 1:** In every module from `go list -m`: `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...`, `golangci-lint run ./...`; `gofmt -l` empty; `openspec validate endpoint-inventory-base-path --strict`. Expected: every command exits 0; record output.

---

## Group 11: Review follow-ups (tasks.md 11.1–11.9)

Groups 1–10 above are implemented. This part plans `tasks.md` group 11: corrections and cleanups found by the verification report and the code review, against `design.md` D1 "One record per path", D5's clause on a path for an endpoint left off, and D7's "One definition of each match kind" and "No unreachable backstops". Only Tasks 22 and 29 change an observable outcome (which refusal `New` reports, or that a path for an endpoint left off no longer fails under a base); every other task keeps behaviour, and its red step is a temporary inversion that an existing or new test catches, then restored.

### Global Constraints (group 11)

- Everything in **Global Constraints** above still binds: test-first, `table-test`, `defensive-coding.md`, no destructive git in agents, agents never edit `openspec/`.
- **No verdict changes.** Every test in `httpsec` that passes before group 11 passes after it, with its assertions unchanged, except `TestClaimsMeet`'s form (Task 23) and the refusals Tasks 22 and 29 change.
- **Error kinds.** Consumer mistakes wrap `ErrConfig` via `newConfigError`; a broken library invariant does not, and is worded as `checkDeclared`'s (`httpsec/endpoints.go:423`).
- **Names fixed by this plan:** `endpointPath` (Task 25), `oneSegmentBelow` (Task 26). No other new identifier is exported or shared across files.

### Review Focus (group 11)

- **Passwordless prefix that does repeat the base while passwordless login is on** (`WithBasePath("/auth")`, `WithPasskeyPasswordlessLogin(...)`, `WithPasskeyPasswordlessPrefix("/auth/pk")`): still refused by D5, naming `/auth/auth/pk`. Added to Task 22.
- **Option order for Task 22:** the prefix given before the login option, and after it, give the same refusal. Added to Task 22.
- **A path option given twice under a base** (`WithLoginRequestPath("/auth/a")` then `WithLoginRequestPath("/b")`, base `/auth`): builds and answers `/auth/b`; the first value is not judged. Added to Task 25.
- **One-segment edge cases** for the shared helper: `prefix`, `prefix/`, `prefix//x`, `prefix/a/b`, `prefixX/a` are not one segment below; `prefix/a` is, giving `a`. Added to Task 26.
- **A duplicate provider route after Task 27** still fails `New` rather than silently keeping one handler, and two declared overrides on one path are still refused by the shared collision check first. Added to Task 27.

### Execution lanes and dispatches (group 11)

Same mechanics as above: one wave at a time, worktrees within a wave, the main session verifies and a fresh reviewer checks each dispatch.

| Wave | Dispatch | Plan task (tasks.md) | Owns | Model, reason | Reviewer |
|---|---|---|---|---|---|
| 12 | F1 | 21 (11.1) | godoc in `signals.go` (`SessionSignals.Path`), `recovery_options.go` (the five recovery path options), comment in `csrf_exemption.go` (`settleExemptions`) | Sonnet: wording the task states | Sonnet |
| 12 | F2 | 22 (11.2) | `passkey.go` (declared-path reporting), `passkey_login_test.go` | Sonnet: the fix and test are stated | Sonnet |
| 12 | F3 | 23 (11.3) | `collisions_internal_test.go` | Sonnet: mechanical test-form rewrite | Sonnet |
| 12 | F4 | 24 (11.4) | `base_path_routes_test.go`, `base_path_test.go`, `endpoints_guard_test.go`, `oidc_redirect_check_test.go`, `notify/smtp_test.go` | Sonnet: test additions that strengthen coverage | Sonnet |
| 13 | R1 | 25 (11.5) | `base_path.go` and every interceptor file holding a `declared*` field (`login.go`, `logout.go`, `jwks.go`, `session_renewal.go`, `password_change.go`, `session_management.go`, `signals.go`, `mfa_verify.go`, `mfa_enrol.go`, `passkey.go`, `magiclink.go`, `recovery.go`, `reauth.go`, `oidc.go`, `oidc_provider.go`) and their option files; `base_path_internal_test.go` | Opus: refactor across every built-in that must keep behaviour | Opus |
| 14 | R2 | 26 (11.6) | `collisions.go`, `base_path_routes.go`, `oidc_provider.go` (`consentClient`), `session_management.go` (`route`), `oidc_options.go` (`providerSegment`), `collisions_internal_test.go` | Opus: extracting shared code that three checks and two endpoints rely on | Opus |
| 15 | R3 | 27 (11.7) | `oidc_provider.go` (`resolved`, `checkPaths`, `fillRouters`, `checkRoutes` godoc), an internal test file `oidc_provider_internal_test.go` | Sonnet: the decision is made by D7; removal plus one internal error | Sonnet |
| 16 | F5 | 29 (11.8) | `recovery.go` (`declaredPaths` of `recoveryInterceptor`), `mfa_enrol.go` (`declaredPaths` of `enrolmentInterceptor`), `oidc_options.go` (`declaredPaths` of `oidcInterceptor`), `base_path.go` and `options.go` (moving the repeat check), `passkey.go` (if Task 22's filter must follow), a new test file `base_path_off_endpoints_test.go` | Opus: ordering of checks in `New`, where a wrong order passes the tests and still skips a served path | Opus |
| — | main | 28 (11.9) | — | the main session runs the gate, then one whole-branch Opus review | — |

- **Why waves 13–15 are sequential.** Task 25 touches every interceptor file, including the passkey file Task 22 changes and the session-management and provider files Tasks 26 and 27 change; Tasks 26 and 27 both edit `oidc_provider.go`. Task 29 (wave 16) reads the `endpointPath` records Task 25 created and runs after wave 15.
- **Wave 12 is four disjoint file sets** in one package; each dispatch gets its own worktree and the main session merges them.

### Task 21: Godoc matches behaviour (11.1)

**Files:** Modify `httpsec/signals.go:148-156`, `httpsec/recovery_options.go` (godoc of `WithRecoveryCompletePath` from line 333, and the four options that refer to it), `httpsec/csrf_exemption.go:252`.

Documentation only (`golang-tdd.md`, "Where this does not apply"); no red step.

- [ ] **Step 1:** `SessionSignals.Path`: replace "must not end with one" with: one trailing slash is accepted and names that exact path (`/session/signals/` is answered, `/session/signals` then passes through); keep the `?`, `#`, `%`, white-space and collision sentences.
- [ ] **Step 2:** Recovery path options: state that two recovery paths are compared only while both operations are served (the start path without issued codes, finish and cancel without a hold are not), as `design.md` D13 says; drop the promise that every pair is refused.
- [ ] **Step 3:** `settleExemptions`: describe the back-channel logout endpoint of the chain's one OIDC login (a second `EnableOIDCLogin` fails `New`, D6).
- [ ] **Step 4:** Run `go doc ./httpsec SessionSignals`, `go doc ./httpsec WithRecoveryCompletePath`, `go vet ./httpsec/`. Expected: the new wording shows; vet prints nothing.

### Task 22: A passwordless prefix is judged by passkeys first (11.2)

**Files:** Modify `httpsec/passkey.go` (the interceptor's declared-path reporting); Test `httpsec/passkey_login_test.go`.

**Interfaces:** Consumes `pathDeclarer.declaredPaths() []declaredPath` (`base_path.go`). Produces nothing new.

- [ ] **Step 1: Write the failing test** `TestPasskeyPasswordlessPrefix_UnderBasePath` (table, `assert` closure):
  - base `/auth`, `WithPasskeyPasswordlessPrefix("/auth/pk")`, no `WithPasskeyPasswordlessLogin`: `errors.Is(err, ErrConfig)`, message contains `WithPasskeyPasswordlessLogin` and `would move no endpoint`, does not contain `/auth/auth/pk`; the same with `WithBasePath` given before and after `EnablePasskeys`;
  - base `/auth`, the same prefix **with** `WithPasskeyPasswordlessLogin`: refused naming `WithPasskeyPasswordlessPrefix` and `/auth/auth/pk` (D5 still applies);
  - base `/auth`, prefix `/pk` with passwordless login: builds; `POST /auth/pk/begin` is answered.
- [ ] **Step 2:** Run `go test -race -count=1 -run 'TestPasskeyPasswordlessPrefix_UnderBasePath' ./httpsec/`. Expected: FAIL on the first rows, the message names `/auth/auth/pk`.
- [ ] **Step 3:** Give `*passkeyInterceptor` its own `declaredPaths() []declaredPath` that omits the `WithPasskeyPasswordlessPrefix` entry while `p.passwordless == nil`. Every option has run before `settleBasePath`, so the result does not depend on option order.
- [ ] **Step 4:** Run `go test -race -count=1 -run 'TestWithBasePath|TestPasskey' ./httpsec/`. Expected: PASS.

### Task 23: `TestClaimsMeet` in the `assert` closure form (11.3)

**Files:** Modify `httpsec/collisions_internal_test.go:147-186`.

- [ ] **Step 1:** Replace the `want bool` field with `assert func(t *testing.T, met bool)`; rows that expected `true` use `assert.True`, rows that expected `false` use `assert.False`, with the row's reason as the message. Keep every row.
- [ ] **Step 2:** Red step: flip one row's closure to the opposite assertion; run `go test -race -count=1 -run 'TestClaimsMeet' ./httpsec/`; Expected: FAIL on that row. Restore it.
- [ ] **Step 3:** Run the same command. Expected: PASS.

### Task 24: Close the verification gaps (11.4)

**Files:** Modify `httpsec/base_path_routes_test.go`, `httpsec/base_path_test.go`, `httpsec/endpoints_guard_test.go`, `httpsec/oidc_redirect_check_test.go`, `notify/smtp_test.go`.

Each step adds assertions to an existing row or one new row, then proves it with a temporary inversion (break the expectation, see FAIL, restore).

- [ ] **Step 1:** `TestBasePathRouteCheck`, row "route written with the base": after the chain builds, put the account in recovery cool-down and send `POST /auth/reauth/password`; assert it is refused as the cool-down refuses (the error the existing cool-down tests assert), and that `POST /auth/sign-in/password` is not.
- [ ] **Step 2:** `base_path_test.go`, row "`/api` with key set path `/api-keys`": assert `GET /api/api-keys` is answered by the key set (200, JSON key set) and `GET /api-keys` passes through to the handler.
- [ ] **Step 3:** `TestChainEndpoints_EveryEntryIsAnswered`: add one chain row built with every built-in the collision test's all-endpoints chain enables (`collisions_test.go:801`; reuse its option builder, moved to a shared helper in `endpoints_guard_test.go` if it is unexported in the other file), probed like every other row.
- [ ] **Step 4:** `oidc_redirect_check_test.go`: with no base path and `WithOIDCCallbackPath("/federation/callback/")`, a provider `corp` with a matching redirect URL builds, and `GET /federation/callback/corp` reaches the callback (the flow-state refusal the existing callback tests assert, not the handler).
- [ ] **Step 5:** `notify/smtp_test.go:544`: the fixture URL uses `/sign-in/magic-link/confirm`.
- [ ] **Step 6:** Run `go test -race -count=1 ./httpsec/ ./notify/`. Expected: PASS.

### Task 25: One record per path (11.5)

**Files:** Modify `httpsec/base_path.go` and each interceptor and option file named in wave 13; Test `httpsec/base_path_internal_test.go`.

**Interfaces:** Produces, in `base_path.go`:
- `type endpointPath struct` holding the declared path, the setting that set it (empty for a default), and the resolved path;
- `func defaultPath(p string) endpointPath` (a default, not consumer-set);
- `func (e *endpointPath) give(setting, p string)` (consumer-set; a later call replaces an earlier one);
- `func (e *endpointPath) resolve(base string)` (resolved = `joinBase(base, declared)`, computed from the declared path every time);
- `func (e endpointPath) at() string` (the resolved path);
- `func (e endpointPath) declaration() (declaredPath, bool)` (the consumer-set path, false for a default).

Replaces the `declared*` string fields, the `pathDeclarations` embedding and `declare` calls. `pathDeclarer` and `pathResolver` stay as interfaces, implemented from the `endpointPath` fields. Task 22's passkey filter is kept.

- [ ] **Step 1: Write the failing tests** in `base_path_internal_test.go`: `TestEndpointPath` (table): a default resolves under `/auth` and reports no declaration; `give` then `resolve` reports the setting and path; `give` twice keeps the last; `resolve` twice under `/auth` gives `/auth/x`, not `/auth/auth/x`. Plus the Review Focus row: `WithLoginRequestPath("/auth/a")` then `WithLoginRequestPath("/b")` under `/auth` builds and answers `POST /auth/b`.
- [ ] **Step 2:** Add the type with method stubs returning zero values, so the test compiles; run `go test -race -count=1 -run 'TestEndpointPath' ./httpsec/`. Expected: FAIL on the assertions, not a compile error.
- [ ] **Step 3:** Implement the methods, then move each interceptor, one file at a time, to `endpointPath` fields; `sessionSignals` takes its default from `defaultPath(DefaultSessionSignalsPath)` in one place, and `settle` no longer fills it.
- [ ] **Step 4:** Red step for the migration: make `give` skip recording the setting; run `go test -race -count=1 -run 'TestWithBasePath|TestBasePath' ./httpsec/`; Expected: the repeat-check rows FAIL. Restore.
- [ ] **Step 5:** Run `go test -race -count=1 ./httpsec/` and `golangci-lint run ./httpsec/`. Expected: PASS, `0 issues`.

### Task 26: One implementation of each match kind (11.6)

**Files:** Modify `httpsec/collisions.go`, `httpsec/base_path_routes.go`, `httpsec/oidc_provider.go:255`, `httpsec/session_management.go:291`, `httpsec/oidc_options.go:287`; Test `httpsec/collisions_internal_test.go`.

**Interfaces:** Produces in `collisions.go`: `func oneSegmentBelow(path, prefix string) (segment string, ok bool)`, with `prefix` given without a trailing slash. Consumes `claimOf(e Endpoint) pathClaim`, `underPrefix(path, prefix string) bool` (`mfa_begin.go:367`).

- [ ] **Step 1: Write the failing test** `TestOneSegmentBelow` (table) with the Review Focus cases for prefix `/sessions`: `/sessions`, `/sessions/`, `/sessions//x`, `/sessions/a/b`, `/sessionsX/a` give `("", false)`; `/sessions/a` gives `("a", true)`.
- [ ] **Step 2:** Run `go test -race -count=1 -run 'TestOneSegmentBelow' ./httpsec/`. Expected: FAIL on the assertions (stub returning `("", false)` first).
- [ ] **Step 3:** Implement it; `isOneSegmentBelow` calls it (or is replaced by it); `consentClient` uses it with `strings.TrimSuffix(op.paths[OIDCConsents], "/")`; `sessionManagement.route` uses it with `m.prefix`; `providerSegment` uses it with its prefix less the trailing slash `oidcPrefix` guarantees.
- [ ] **Step 4:** In `base_path_routes.go`, delete `matchedPrefix`: `movedEndpoint.declared` comes from `claimOf(e).base` on the entry at its pre-base path; `coversNormalised` uses `underPrefix` for subtrees and `oneSegmentBelow` for segments, on lower-cased, trailing-slash-trimmed operands as today.
- [ ] **Step 5:** Red step: make `oneSegmentBelow` accept a deeper path; run `go test -race -count=1 -run 'TestChainEndpoints_EveryEntryIsAnswered|TestChainPathCollisions|TestBasePathRouteCheck' ./httpsec/`; Expected: FAIL in the drift guard (a `DELETE /auth/sessions/a/b` no longer passes through). Restore.
- [ ] **Step 6:** Run `go test -race -count=1 ./httpsec/` and `golangci-lint run ./httpsec/`. Expected: PASS, `0 issues`.

### Task 27: Remove the provider's unreachable backstops (11.7)

**Files:** Modify `httpsec/oidc_provider.go` (fields at lines 60–66, `resolvePaths` at 649, `fillRouters` at 682, `checkPaths` at 713, `checkRoutes` at 725, the `check` list at 803); Test `httpsec/oidc_provider_internal_test.go` (new).

**Interfaces:** `fillRouters() error` keeps its signature; its error no longer wraps `ErrConfig`.

- [ ] **Step 1: Write the failing test** `TestOIDCProviderFillRouters_DuplicateIsInvariant`: build `oidcEndpoints` with two groups whose routes name one path; assert `fillRouters` returns a non-nil error, `errors.Is(err, ErrConfig)` is false, and the message says it is the library's own invariant and names the path.
- [ ] **Step 2:** Run `go test -race -count=1 -run 'TestOIDCProviderFillRouters_DuplicateIsInvariant' ./httpsec/`. Expected: FAIL (the error wraps `ErrConfig`).
- [ ] **Step 3:** Word the duplicate as `checkDeclared` words its invariant error. Delete `resolved`, `checkPaths` and its entry in `check`: `New` always resolves. Keep `routesErr` and the `checkRoutes` call where it is in `options.go`, after `checkCollisions`, so two declared overrides on one path are still refused by the shared check with its message, and only an undeclared duplicate reaches the invariant error (Review Focus). Update both godocs to say it is an invariant, not a configuration error.
- [ ] **Step 4:** Run `go test -race -count=1 ./httpsec/` and `golangci-lint run ./httpsec/`. Expected: PASS, `0 issues`; the two-overrides-on-one-path collision rows still refuse with the shared check's message.

### Task 29: A path reaches the repeat check only while its endpoint is listed (11.8)

**Files:** Modify `httpsec/recovery.go`, `httpsec/mfa_enrol.go`, `httpsec/oidc_options.go` (each built-in's `declaredPaths()`), `httpsec/base_path.go` and `httpsec/options.go` (`New`'s order); Test `httpsec/base_path_off_endpoints_test.go` (new).

**Interfaces:** Consumes `endpointPath.declaration() (declaredPath, bool)` and `declarations(...endpointPath)` (Task 25), and the conditions `endpoints()` already uses: `recoveryInterceptor.startEnabled`, `.holds`, `.codesEnabled`; `enrolmentInterceptor.emailConfirmation`; `oidcInterceptor.redeemer != nil`. Produces nothing new. Same pattern as Task 22: a record is reported exactly when `endpoints()` lists its operation, so the two cannot disagree.

- [ ] **Step 1: Write the failing test** `TestBasePath_OffEndpointPathIsNotJudged` (table, `assert` closure), every row under `WithBasePath("/auth")`:
  - `WithRecoveryStartPath("/auth/x")` without `recovery.ProofIssued`: builds; `POST /auth/auth/x` and `POST /auth/x` pass through to the handler;
  - `WithRecoveryCodesPath("/auth/x")` without `recovery.ProofSaved`: builds;
  - `WithRecoveryFinishPath("/auth/x")` and, as its own row, `WithRecoveryCancelPath("/auth/y")` with no delay and no risk hook: builds;
  - `WithEnrolmentEmailConfirmPrefix("/auth/x")` with `WithoutEnrolmentEmailConfirmation()`: builds;
  - `WithOIDCHandoffPath("/auth/x")` with `WithOIDCCallbackSuccess(...)`: `errors.Is(err, ErrConfig)`, message contains `WithOIDCHandoffPath` and `issues no handoff code`, does not contain `/auth/auth/x`;
  - one row per feature with its endpoint on (`ProofIssued`; `ProofSaved`; a delay; email confirmation on; a handoff redeemer) and the same path: refused naming the option and `/auth/auth/x`.
- [ ] **Step 2:** Run `go test -race -count=1 -run 'TestBasePath_OffEndpointPathIsNotJudged' ./httpsec/`. Expected: FAIL on every off row, the error naming `/auth/auth/x`; the on rows pass.
- [ ] **Step 3:** Split `settleBasePath`: the "moves nothing" check stays before `resolvePaths`; the repeat check runs in two passes (D5 "When it is judged: two passes"): an early pass after `resolvePaths` and before `validate` over every record except the wiring-settled ones (recovery start, finish, cancel, codes; OIDC handoff), and a late pass, `checkBaseRepeats`, in `build` after every `wire*` step and before `collectEndpoints`, over only the wiring-settled records that are served, because `startEnabled`, `holds`, `codesEnabled` and `redeemer` are set by `wireAccountRecovery` and `wireOIDCLogin`. Add rows: base `/auth`, `WithOIDCCallbackPath("/auth/sso/callback/")` with the redirect URL at `/auth/sso/callback/corp` refused naming `WithOIDCCallbackPath`; `WithOIDCProviderPath(OIDCToken, "/auth/token")` with `WithAssertionTokenEndpoint(".../auth/token")` refused naming `WithOIDCProviderPath`. Then, in each built-in's `declaredPaths()`, leave out a record while `endpoints()` does not list its operation, using the conditions named under Interfaces.
- [ ] **Step 3a: Order guard.** Add a row with `recovery.ProofIssued` on and `WithRecoveryStartPath("/auth/x")` given **before** the recovery core option, and one with `WithBasePath` last: both refused naming `/auth/auth/x`. Red step: temporarily run the repeat check before `validate` (or between `validate` and `build`); these on rows must FAIL (the flags are still unset), proving the order matters. Restore.
- [ ] **Step 4:** Run `go test -race -count=1 ./httpsec/` and `golangci-lint run ./httpsec/`. Expected: PASS, `0 issues`.

### Task 28: The gate (11.9)

- [ ] **Step 1:** As Task 20: in every module from `go list -m`, `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...`, `golangci-lint run ./...`; `gofmt -l` over tracked Go files empty; `openspec validate endpoint-inventory-base-path --strict`. Expected: every command exits 0; record output, exit codes included.
- [ ] **Step 2:** One whole-branch review on Opus against every requirement in every delta, then `/opsx:verify`.

---

## Group 12: Verification follow-ups (tasks.md 12.1–12.2)

Two dispatches, run **at the same time**: Task 30 owns only `httpsec/*_test.go` files in package `httpsec` of the root module, and Task 31 owns only `httpsec/ginsec/middleware_test.go` in module `httpsec/ginsec`. Neither touches the other's files, so no worktree is needed. Both are test additions that a stated scenario decides, so both go to **Sonnet**, with a Sonnet reviewer.

Every step adds an assertion to existing behaviour. Its red step is a **temporary inversion**: break the new expectation (or the code path it pins), run the focused test, see it FAIL for the intended reason, then restore it.

### Task 30: Close the partial scenario assertions in `httpsec` (12.1)

**Files:** Modify `httpsec/base_path_test.go`, `httpsec/mfa_verify_test.go`, `httpsec/endpoints_test.go`, `httpsec/collisions_auth_test.go`, `httpsec/passkey_test.go`, `httpsec/base_path_resolve_auth_test.go`.

**Interfaces:** Consumes the existing helpers `refused(name)` (`base_path_test.go`), `collisionRefused(...)` (`collisions_auth_test.go`), `reachedEndpoint` (`passkey_test.go`), `operationIDs` and `endpointsBase` (`endpoints_test.go`), and the exported defaults `DefaultOIDCCallbackPath`, `DefaultMFAVerifyPrefix`. Produces nothing new.

- [ ] **Step 1 — "Nothing to move":** in `TestWithBasePath`, add the row `"a chain with only bearer and authorization is refused"`. It builds bearer authentication (the bearer option the file's other bearer chains use), `EnableAuthorization` with a permitting authorizer, and `WithBasePath("/auth")`, and asserts `refused("WithBasePath")`. Inversion: build the same row without `WithBasePath` and expect it to be refused. It must FAIL, because that chain builds.
- [ ] **Step 2 — "Listing beside the verify endpoints":** in `TestMFAMethodListing`, add the row `"the listing at /mfa/verify/totp answers GET, and verification answers POST"`. The listing is placed at `DefaultMFAVerifyPrefix + "/totp"`, TOTP is configured and `u-1` holds a pending session. Assert that a GET there is answered with the default JSON body listing `totp` and never reaches the handler. Assert that a POST with a valid code there resolves the challenge, so the session is rotated and its second factor satisfied. Inversion: send the GET as a POST and expect the listing body. It must FAIL.
- [ ] **Step 3 — "Operation identifiers are stable", provider:** in `TestChainEndpoints_IdentifiersStableUnderBasePath`, add a provider row. Without the base, the issuer is `https://id.example.com`; under `/auth`, it is `https://id.example.com/auth`, as D8 requires. Give the row its own `assert` closure, not `stable`, because the authorization server metadata does not move by prefix. It asserts:
  - `operationIDs(without) == operationIDs(under)`;
  - for every entry except `scrty.oauth2.authorization-server-metadata`, `under.Path == "/auth" + without.Path`;
  - for that one entry, `without.Path == "/.well-known/oauth-authorization-server"` and `under.Path == "/.well-known/oauth-authorization-server/auth"`.

  Inversion: drop the special case and see the metadata row FAIL.
- [ ] **Step 4 — "Back-channel path shadows the callback":** in the row `"the back-channel prefix at the callback prefix"` (`collisions_auth_test.go`), add `DefaultOIDCCallbackPath` (`"/sso/callback/"`) to the asserted strings, as the handoff row at `:340` asserts its path. Inversion: assert `"/sso/nowhere/"` instead and see it FAIL.
- [ ] **Step 5 — "Passkey registration reachable":** in `reachedEndpoint`, on the begin path, decode the response body as the default registration begin responder writes it (the decode `passkey_register_test.go` already uses for begin). Assert that the challenge field is non-empty. This strengthens both the enrolment-gate row and the recovery-gate row that use the helper. Inversion: assert the challenge is empty and see both rows FAIL.
- [ ] **Step 6 — "Authorization rules keep the consumer's paths":** in `TestBasePath_AuthorizationRulesKeepConsumerPaths`, set the rule's `Require` to a deny, so a request the rule judges is refused. Keep the authorizer permitting for everything else. Assert three things: `GET /projects/42` is refused by the rule and the handler does not run; `GET /auth/projects/42` reaches the handler, because the rule does not match it; and each built-in still answers at its `/auth` path. Inversion: change the rule to match `/auth/projects/` and see the assertions FAIL.
- [ ] **Step 7:** Run `go test -race -count=1 -run 'TestWithBasePath|TestMFAMethodListing|TestChainEndpoints_IdentifiersStableUnderBasePath|TestChainPathCollisions|TestPasskeyGates|TestBasePath_AuthorizationRulesKeepConsumerPaths' ./httpsec/`, then `go test -race -count=1 ./httpsec/` and `golangci-lint run ./httpsec/`. Expected: PASS, and `0 issues`.

### Task 31: A real unknown-provider 404 through gin (12.2)

**Files:** Modify `httpsec/ginsec/middleware_test.go`.

**Interfaces:** Consumes `newChain` and the `served` harness of `middleware_test.go`, and an OIDC login chain built as the module's other OIDC tests build one: provider `corp`, its redirect URL ending in `/sso/callback/corp`. Produces nothing new.

- [ ] **Step 1:** Add the row `"an unknown provider at /sso/login/nope is committed as an empty 404"` beside the stub row. The engine uses `ginsec.Middleware` over a real chain with OIDC login (provider `corp`, bearer mode as the chain requires), and no gin route is registered. Send `GET /sso/login/nope`. Assert three things: status 404, an empty body, and a body that does not contain `404 page not found`.
- [ ] **Step 2:** Inversion: send `GET /sso/login/corp` in the same row and expect 404. It must FAIL, because `corp` is registered and the request is redirected to the provider. Restore the row.
- [ ] **Step 3:** In `httpsec/ginsec`, run `go test -race -count=1 ./...` and `golangci-lint run ./...`. Expected: PASS, and `0 issues`.


## Group 13: Whole-branch review follow-ups (tasks.md 13.1–13.5)

Two dispatches, run **at the same time**:
- **Task 32** (13.1, 13.2) owns the issuer and waiver checks and their tests. It goes to **Opus**, because it writes security-relevant refusal logic for the first time, with an Opus reviewer.
- **Task 33** (13.3, 13.4) owns only `httpsec/endpoints_test.go`. It goes to **Sonnet**, because it adds test assertions only, with a Sonnet reviewer.

Task 32 must not touch `httpsec/endpoints_test.go`, and Task 33 must not touch any other file. Task 34 (13.5) runs in the main session after both are reviewed clean.

**Review Focus for this group:**
- an issuer whose path holds an escape that decodes to an allowed character (`%74`) must still be refused;
- an issuer with a trailing slash or an empty path stays accepted;
- a waiver given before `WithBasePath` must not be refused, since the order of options must not matter;
- an issuer that is not a URL keeps its existing refusal.

### Task 32: Issuer path characters and waivers without a base path (13.1, 13.2)

**Files:**
- Modify: `httpsec/oidc_provider.go` (`checkIssuerBasePath` and its godoc, about `:730-790`).
- Modify: `httpsec/oidc_provider_options.go` (`WithoutOIDCIssuerBasePathCheck` godoc, about `:153-180`, and the issuer setting's godoc).
- Modify: `httpsec/base_path_routes.go` (`WithoutBasePathRouteCheck` godoc `:30-42`, and the check at `:109`).
- Test: `httpsec/oidc_issuer_base_test.go` (`TestOIDCProvider_IssuerBasePath`) and `httpsec/base_path_routes_test.go` (`TestBasePathRouteCheck`).
- Update callers: `httpsec/endpoints_guard_test.go` and `httpsec/base_path_routes_internal_test.go`, wherever they give a waiver without a base path. The same applies to the `test` module, if any scenario does.

**Interfaces:**
- Consumes `checkEndpointPath`'s character set (`httpsec/paths.go:15`), `newConfigError`, `config.basePath`, `config.routeCheckWaived` and `oidcEndpoints.issuerBasePathWaived`.
- Produces no new exported symbol.

- [ ] **Step 1 (13.1 red):** in `TestOIDCProvider_IssuerBasePath`, add three rows:
  - `"a percent-encoded issuer path under the base is refused"`: `WithBasePath("/auth")` with issuer `https://id.example.com/au%74h`. Assert `ErrConfig`, and an error containing the issuer string.
  - `"a percent-encoded issuer path without a base is refused"`: issuer `https://id.example.com/t%65nant`, with the same assertions.
  - `"a plain issuer path without a base is built"`: issuer `https://id.example.com/tenant-1`, with `WithOIDCProviderPrefix("/tenant-1/oauth2")`, since discovery is placed under the issuer only when the token endpoint is. Assert that `GET /tenant-1/.well-known/openid-configuration` is answered with 200.

  Run `go test -race -count=1 -run TestOIDCProvider_IssuerBasePath ./httpsec/`. It must FAIL, because the first two rows build.
- [ ] **Step 2 (13.1 green):** in `checkIssuerBasePath`, before the base-path early return, refuse when the issuer's escaped path (`u.EscapedPath()`) holds any byte outside `[A-Za-z0-9._~/-]`. Use one helper with `checkEndpointPath`, not a second character list. The error names `optionOIDCProvider` and the issuer. Rename the method if it now checks more than the base path, and keep its caller list at `:804`. Update the godoc. Run the tests again: PASS.
- [ ] **Step 3 (13.2 red):**
  - In `TestBasePathRouteCheck`, add `"the waiver without a base path is refused"`: `EnableJWKSEndpoint` with `WithoutBasePathRouteCheck()`. Assert `ErrConfig` naming `WithoutBasePathRouteCheck`.
  - Add `"the waiver given before the base path is built"`, with the waiver first and `WithBasePath("/auth")` last.
  - In `TestOIDCProvider_IssuerBasePath`, add `"the issuer waiver without a base path is refused"`, naming `WithoutOIDCIssuerBasePathCheck`.

  Run both tests. They must FAIL, because the waivers are accepted.
- [ ] **Step 4 (13.2 green):**
  - The route check refuses `routeCheckWaived && basePath == ""`.
  - The issuer check refuses `issuerBasePathWaived && basePath == ""`.

  Both checks run after resolution, so the order of options is irrelevant. Replace "changes nothing" in both godocs with the refusal. Then:
  - fix every existing test that gave a waiver without a base;
  - run `go test -race -count=1 ./httpsec/`;
  - run `golangci-lint run ./httpsec/`;
  - in `test`, run `go test -race ./...`.

  All must PASS with `0 issues`.

### Task 33: Pin the twice-enabled refusals by identifier (13.3, 13.4)

**Files:** Test: `httpsec/endpoints_test.go` only.

**Interfaces:** Consumes the existing builders in that file and `httpsec.ErrConfig`. Produces nothing.

- [ ] **Step 1 (13.4):** in `TestNew_RefusesAKeySetEnabledTwice`, also assert that the error contains `scrty.key-set`. Inversion: expect `scrty.key-sets`, and see it FAIL. Restore it.
- [ ] **Step 2 (13.3):** add `TestNew_RefusesOIDCLoginEnabledTwice`. Call `New` with two `EnableOIDCLogin` on different callback, login and handoff prefixes. Build each the way the file's other OIDC login chains are built. Assert `ErrorIs(err, httpsec.ErrConfig)` and that the error contains `scrty.sso.login`. Inversion: expect no error, and see it FAIL. Restore it.
- [ ] **Step 3:** run `go test -race -count=1 ./httpsec/` and `golangci-lint run ./httpsec/`. Expected: PASS, `0 issues`.

### Task 34: Close-out gate (13.5)

- [ ] **Step 1:** in every module that `go list -m` lists, run `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...` and `golangci-lint run ./...`. Also check that `gofmt -l` is empty over tracked Go files, and run `openspec validate endpoint-inventory-base-path --strict`. Every command must exit 0. Record the output.
