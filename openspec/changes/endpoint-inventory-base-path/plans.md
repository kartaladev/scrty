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
- [ ] **Step 2:** Godoc per tasks.md 8.1; README default-path table, base-path section, migration steps.
- [ ] **Step 3:** Run `go doc ./httpsec WithBasePath`; expected: shows default and exclusions.

### Task 20: The gate (10.1)

- [ ] **Step 1:** In every module from `go list -m`: `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...`, `golangci-lint run ./...`; `gofmt -l` empty; `openspec validate endpoint-inventory-base-path --strict`. Expected: every command exits 0; record output.
