# Browser Session Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an `httpsec` chain authenticate browsers by an `HttpOnly` session cookie, handing out no credential JavaScript can read, under the same session rules as the session-reference bearer.

**Architecture:** The session-bearer pipeline is extracted into one shared session-reference resolver with two transports (header, cookie). `EnableSessionCookie` wires the cookie transport at `OrderBearerToken`, and every issuing endpoint delivers its credential through one delivery step that sets the cookie. Persistence is a library-owned session mark carried through rotations and stored in a new nullable column.

**Tech Stack:** Go 1.27, `net/http`, testify, mockgen (`use-mockgen`), testcontainers PostgreSQL 15/18 (`use-testcontainers`), goose migrations.

**Spec:** `openspec/changes/browser-session/` (`proposal.md`, `design.md`, `specs/browser-session`, `specs/sessions`, `specs/security-state-stores`, `specs/magic-link`, `specs/resource-server`, `tasks.md`). Task numbers below are `tasks.md`'s.

## Global Constraints

- Test-first for every task: failing test, run it, confirm it fails for the intended reason (a compile error is not a red step), then implement (`golang-tdd.md`). Characterization tests are shown to fail once by inverting the code.
- Table tests follow the `table-test` skill: `assert` closures, `t.Context()`.
- Mocks via `use-mockgen`; PostgreSQL via the existing `test` module helpers (`use-testcontainers`).
- Defaults are safe and every default is replaceable or its line is documented; wiring mistakes are `ErrConfig` from `New` (`library-design.md`).
- Every listed failure mode is handled and tested, or accepted in `design.md` (`defensive-coding.md`).
- No legacy citation anywhere in code, comments or commits (`legacy-reference.md`).
- Default cookie: `__Host-scrty-session; Path=/; Secure; HttpOnly; SameSite=Lax`, no `Domain`, no `Max-Age`.
- Default destination field `next`; default magic-link fields `email`, `next`, `token`; default body limit 64 KiB (`64 << 10`).
- Persistent `Max-Age` = seconds to the absolute deadline, rounded up, at least 1.
- Rotations at second-factor verification and re-authentication have no off switch.
- New column: `scrty_sessions.persistent_cookie boolean NULL`, no default, NULL read as unset.

## Review Focus

1. **Duplicate session cookies** (two `__Host-scrty-session` values in one `Cookie` header): expected refusal with `ErrAuthenticationRequired`, never "first wins". Test in Task 5.1.
2. **Encoded or disguised destinations** (`%2F%2Fevil.example`, `/%5Cevil`, `/\evil`, `/\t/evil`, `https:evil`): expected `303` to `/`. Test in Task 8.2.
3. **GET or HEAD to an issuing endpoint** on a cookie chain: expected pass-through, no `Set-Cookie`. Test in Task 6.1.
4. **Logout racing a role switch** on the same sign-in: expected the switch fails with `ErrAuthenticationRequired`, no cookie re-set, nothing stored. Test in Task 11.5, with the no-cookie assertion for the second interleaving made to hold in Task 11.8 (role recorded in the rotation's write).
5. **A persistent sign-in less than a second from its absolute deadline**: expected `Max-Age=1`, never 0 or negative. Test in Task 10.1.

---

## Lanes, dispatches and models

File ownership: lane S owns `session/` and `store/**` and `test/storetest`; lane M owns `httpsec/magiclink*.go`; lane C owns every other `httpsec` file and `test/httpsecconformance`. S2 and C8 run in parallel (C8 touches no `session/` or `store/` file); C9 starts after both, because it consumes S2's option and edits files C8 may touch. S and M run in parallel with C's dispatches 1 and 2. C's dispatch 3 starts only after M is merged, because it edits `magiclink.go`. C's dispatch 5 starts only after S, because it uses `session.WithPersistentCookie`.

| Dispatch | Tasks | Model | Why |
|---|---|---|---|
| S1 | 1.1, 1.2, 2.1, 2.2 | Sonnet | copies the `MFAAtFirstFactor` pattern exactly |
| M1 | 3.1, 3.2 | Sonnet | option plumbing mirroring form login |
| C1 | 4.1, 4.2 | Opus | refactor of shipped security code that must keep behaviour |
| C2 | 5.1, 5.2, 5.3, 5.4 | Opus | security-critical verification and refusal, first time |
| C3 | 6.1, 6.2, 7.1 | Opus | credential delivery across endpoints; a missed path passes tests and leaks |
| C4 | 8.1, 8.2, 9.1 | Opus | redirect validation and federated completion |
| C5 | 10.1, 11.1, 11.2, 11.3 | Opus | rotation ordering |
| C6 | 11.4, 11.5, 12.1, 12.2, 12.3 | Opus | barrier tests, races, a guard exemption on security paths |
| S2 | 11.6, 11.7 | Opus | changes the `Store` port's supersession contract other lanes compile against, atomic inside a transaction on three backends |
| C8 | 12.4, 12.5 | Opus | a refusal rule on the provider's resume, security-critical; runs in parallel with S2 (disjoint files) |
| C8b | 12.6 | Opus | security refusal on the provider's resume and a construction rule; scope-handling change in the chain's run |
| C9 | 11.8 | Sonnet | applies S2's option at one call site, and registers `session.ErrStoreContract` as a dependency failure in `httpsec`'s status table; the test is given (runs in parallel with C8b, disjoint files) |
| C8c | 12.6 (chain-scoped mark), 12.7, C9 godoc nits | Opus | rework of C8b's mark after its review reproduced two defects, plus a security refusal at construction; both in the provider's chain check and the resume |
| C8d | 12.6 and 12.7, C8c review follow-ups | Opus | the per-chain mark is ordering logic on a security path (the resume), and the back-channel check is a refusal rule; the C8c review reproduced the regression |
| C10 | 12.8 | Opus | security verification rules across `resource_server.go` and the provider source; a mistake passes the tests and still trusts the wrong tokens. Starts after C8c: both edit chain construction |
| C7 | 13.1, 13.2 | Sonnet | conformance scenarios and godoc (after C10) |
| — | 14.1 | main session | final gate |

Reviewers: Opus for C1–C6, S2, C8, C8b, C8c, C8d and C10; Sonnet for S1, M1, C9 and C7.

**Scoped verification commands** (`test-scope.md`):
- Lane S: `go test -count=1 ./session/... ./store/... ./internal/... ./httpsec/... ./oidcprovider/... ./policy/... ./recovery/... ./authenticate/...` and, in `test/`, `go test -count=1 ./storetest/... ./sqlstore/... ./pgxstore/... ./gormstore/... ./crossbackend/...` (Docker); plus `go test -count=1 ./...` in `store/pgxstore` and `store/gormstore`; `make generate-check`.
- Lanes M and C: `go test -count=1 -race ./httpsec/... ./oidcprovider/... ./authenticate/oidc/... ./authenticate/passkey/... ./policy/... ./store/sqlstore/...`; in `test/`, `go test -count=1 ./httpsecconformance/... ./` ; `go test -count=1 ./...` in `httpsec/ginsec`, `httpsec/fibersec`, `httpsec/prblmsec`.
- Every dispatch: `go vet` and `gofmt -l` on the touched packages.

---

### Task 1.1: The persistent-cookie mark

**Files:**
- Modify: `session/session.go` (field), `session/sessions_options.go` (create option)
- Test: `session/sessions_test.go`

**Interfaces:**
- Produces: `Session.PersistentCookie bool` (library-owned, godoc like `MFAAtFirstFactor`); `func WithPersistentCookie() CreateOption`.

- [ ] **Step 1: Write the failing tests** `TestSessions_CreatePersistentCookie` (create with the option, load, assert `PersistentCookie` true and one store create write via a counting store) and `TestSessions_PersistentCookieNotFromData` (create with `Data` keys `persistent_cookie`, `PersistentCookie`; assert mark false and `Data` returned unchanged).
- [ ] **Step 2: Run** `go test -count=1 -run 'TestSessions_(CreatePersistentCookie|PersistentCookieNotFromData)' ./session/` — expected FAIL on the assertion (after a stub that compiles).
- [ ] **Step 3: Implement** the field and option, set in the creating write only.
- [ ] **Step 4: Run** the same command — expected PASS.
- [ ] **Step 5: Commit** `feat(session): record whether a sign-in's browser cookie persists`.

### Task 1.2: Rotations carry the mark; Save keeps it

**Files:** Modify `session/sessions.go`, `session/reuse.go`, the memory store in `session/`; Test `session/reuse_test.go`.

**Interfaces:** Consumes 1.1.

- [ ] **Step 1: Write the failing table test** `TestSessions_RotationsCarryPersistentCookie` with one case each for `Rotate`, `RotateIssuing` (mark visible on the successor handed to the issuing step), `RotateWithGrace`, `RotateWithGraceIssuing`; and `TestSessions_SaveKeepsPersistentCookie` (save a copy with the mark flipped both ways; stored value unchanged).
- [ ] **Step 2: Run** `go test -count=1 -run 'TestSessions_(RotationsCarry|SaveKeeps)PersistentCookie' ./session/` — expected FAIL: successor reports false.
- [ ] **Step 3: Implement** carry-over wherever `MFAAtFirstFactor` is carried; memory `Save` keeps the stored mark.
- [ ] **Step 4: Run** — PASS; then lane S's scoped command.
- [ ] **Step 5: Commit** `feat(session): carry the persistent-cookie mark through every rotation`.

### Task 2.1: Migration

**Files:** Create `store/migrate/securitystate/20261128000000_persistent_cookie.sql`; Test `test/migrate_securitystate_test.go`.

- [ ] **Step 1: Write the failing tests**: extend `TestSecurityStateMigrations_Schema` with `scrty_sessions.persistent_cookie` (boolean, nullable, no default), and add `TestSecurityStateMigrations_PersistentCookieUpgrade` (write a session row at the previous version, migrate, load through `sqlstore`, assert mark false).
- [ ] **Step 2: Run** `cd test && go test -count=1 -run 'TestSecurityStateMigrations_(Schema|PersistentCookieUpgrade)' .` — expected FAIL: column missing.
- [ ] **Step 3: Implement** the goose migration in the style of `20261127000000_sign_in_proof.sql`: `SET LOCAL lock_timeout = '5s'; ALTER TABLE scrty_sessions ADD COLUMN persistent_cookie boolean NULL;` with a Down that drops it, and a header comment stating the NULL reading.
- [ ] **Step 4: Run** the same, then `make generate-check` — PASS.
- [ ] **Step 5: Commit** `feat(migrate): add the sessions persistent_cookie column`.

### Task 2.2: Stores

**Files:** Modify `store/sqlstore/session.go`, `store/pgxstore/session.go`, `store/gormstore/session.go`; Test `test/storetest/session_suite.go`.

- [ ] **Step 1: Write the failing suite cases** beside the `MFAAtFirstFactor` ones (lines ~690–745): "persistent cookie round trip", "saved without the mark loads unmarked", "save does not set the mark", "save keeps the stored mark". The existing cross-backend runner covers save-on-one, load-on-another.
- [ ] **Step 2: Run** `cd test && go test -count=1 -run 'Session' ./sqlstore/... ./pgxstore/... ./gormstore/... ./crossbackend/...` — expected FAIL: mark not stored.
- [ ] **Step 3: Implement** the column in create, load and the gorm column lists, excluded from `Save` exactly like `mfa_at_first_factor`; NULL scans as false.
- [ ] **Step 4: Run** lane S's scoped command — PASS.
- [ ] **Step 5: Commit** `feat(store): keep the persistent-cookie mark in every durable store`.

### Task 3.1: Magic-link field names

**Files:** Modify `httpsec/magiclink.go`, `httpsec/magiclink_options.go`; Test `httpsec/magiclink_options_test.go`.

**Interfaces:** Produces `func WithMagicLinkParams(address, next, token string) MagicLinkOption`.

- [ ] **Step 1: Write the failing table test** `TestMagicLink_Params` with cases: default fields (form request reads `email`, `next`); consumer address field `login` (form and JSON); consumer token field `code` redeems, and a POST with only `token` is a failed redemption with the token unspent; empty name → `ErrConfig`; address and token both `value` → `ErrConfig`.
- [ ] **Step 2: Run** `go test -count=1 -run TestMagicLink_Params ./httpsec/` — FAIL.
- [ ] **Step 3: Implement**: store the three names on the interceptor; `readRequest` and `readConsume` use them; JSON decodes into `map[string]json.RawMessage` and reads the configured members.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `feat(httpsec): make magic-link field names replaceable`.

### Task 3.2: Magic-link body limit

**Files:** as 3.1. **Interfaces:** Produces `func WithMagicLinkBodyLimit(limit int64) MagicLinkOption`.

- [ ] **Step 1: Write the failing table test** `TestMagicLink_BodyLimit`: 65 KiB request body with defaults → same status and body as a normal request, no link issued; 65 KiB redemption carrying a valid token → failed redemption, token unspent; limit 4 KiB with a 5 KiB redemption → failed, unspent; limit 0 and -1 → `ErrConfig`.
- [ ] **Step 2: Run** `go test -count=1 -run TestMagicLink_BodyLimit ./httpsec/` — FAIL on the option cases.
- [ ] **Step 3: Implement** the option over the existing `bodyLimit` field; default `64 << 10`.
- [ ] **Step 4: Run** lanes M/C scoped command — PASS.
- [ ] **Step 5: Commit** `feat(httpsec): make the magic-link body limit replaceable`.

### Task 4.1: Characterize the session bearer

**Files:** Test `httpsec/session_bearer_test.go`.

- [ ] **Step 1:** List the checks the spec's "judged by the same rules" requirement names; map each to an existing test in `session_bearer_test.go`. For any without one, add `TestSessionBearer_<Check>` (shape check before lookup, unknown reference counted, reuse revokes family, user reload refuses disabled user, policy deny, outage is a dependency failure, cancelled context is neither).
- [ ] **Step 2:** For each new test, invert the check in a scratch edit, run `go test -count=1 -run 'TestSessionBearer_' ./httpsec/`, see it FAIL, restore.
- [ ] **Step 3: Commit** `test(httpsec): pin the session-bearer pipeline before extracting it`.

### Task 4.2: Extract the shared pipeline

**Files:** Create `httpsec/session_reference.go`; Modify `httpsec/session_bearer.go`.

**Interfaces:**
- Produces (unexported): `type referenceTransport uint8` with `transportHeader`, `transportCookie`; `type sessionReference struct{ … }` holding the shared `sessionResolver`, clock, limiter, guard, sampler and logger; `type referenceCheck func(ex *Exchange) (admit func(*Exchange, *session.Session) (*identity.Details, error), err error)`; `func (r *sessionReference) resolve(ex *Exchange, id string, t referenceTransport, check referenceCheck) error`. Loading, user reload, policy and publishing stay in the existing `sessionResolver.resolve` (`resolve.go`), which the signed bearer shares, so extracting publishing would change shipped behaviour. A transport adds its own steps through `check`: it runs after the shape check and before the load (the header uses it for DPoP), and its returned `admit` runs on the loaded session before publishing (the cookie uses it for `CheckCSRFToken`). The caller records the presented reference after a nil return.

- [ ] **Step 1:** Run the whole session-bearer suite and save the result: `go test -count=1 -run 'SessionBearer|SessionRenewal|Reauth' ./httpsec/ > /tmp/before.txt`.
- [ ] **Step 2: Implement** the extraction; `sessionBearer.Intercept` reads the header and calls `resolve`.
- [ ] **Step 3: Run** the same command and lanes M/C scoped command with `-race` — identical pass set.
- [ ] **Step 4: Commit** `refactor(httpsec): extract the session-reference pipeline`.

### Task 5.1: `EnableSessionCookie`

**Files:** Create `httpsec/session_cookie.go`, `httpsec/session_cookie_test.go`.

**Interfaces:**
- Consumes 4.2's `resolve`.
- Produces: `func EnableSessionCookie(deps SessionBearerDeps, opts ...SessionCookieOption) Option`; `type SessionCookieOption func(*sessionCookie) error`; `const DefaultSessionCookieName = "__Host-scrty-session"`; `func WithSessionCookieLimiter(limiter ratelimit.Limiter) SessionCookieOption`; `(*sessionCookie).AuthenticatesByCookie()`.

- [ ] **Step 1: Write the failing table test** `TestSessionCookie_Authenticates` covering every scenario of the spec's first three requirements, plus Review Focus 1: two `__Host-scrty-session` values in one request → `ErrAuthenticationRequired`, no lookup.
- [ ] **Step 2: Run** `go test -count=1 -run TestSessionCookie_Authenticates ./httpsec/` — FAIL.
- [ ] **Step 3: Implement**: read the cookie, refuse duplicates, `resolve(…, transportCookie)`, `CheckCSRFToken` on unsafe methods, publish as the session bearer does.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `feat(httpsec): authenticate browsers by a session cookie`.

### Task 5.2: Cookie attributes

**Files:** `httpsec/session_cookie.go`, `httpsec/session_cookie_options_test.go`.

**Interfaces:** Produces `WithSessionCookieName(name string)`, `WithSessionCookieSameSite(mode http.SameSite)`, `WithSessionCookieDomain(domain string)`, all `SessionCookieOption`; unexported `(*sessionCookie).cookie(value string, maxAge int) *Cookie` used by every later task.

- [ ] **Step 1: Write the failing table test** `TestSessionCookie_Attributes`: default `Set-Cookie` exact string; `Strict`; `__Secure-scrty-session` + `example.com`; refusals: empty name, name with `;`, `__Host-` + domain, domain without `__Secure-`, `SameSiteNoneMode`, `SameSiteDefaultMode`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `feat(httpsec): session cookie attributes and their construction checks`.

### Task 5.3: Expiring a refused cookie

- [ ] **Step 1: Write the failing table test** `TestSessionCookie_RefusalExpires`: missing, expired, unreadable (cipher failure on decrypt reported as refusal), reused → response has `Max-Age=0` with the set attributes; store outage and cancelled context → no `Set-Cookie`; persistent cookie after its idle deadline → refused and expired.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement** in the cookie interceptor's refusal path. **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `feat(httpsec): expire a refused session cookie, keep it on an outage`.

### Task 5.4: One delivery per chain

- [ ] **Step 1: Write the failing tests** `TestSessionCookie_ExclusiveWithBearers` (with `EnableSessionBearer`, with `EnableBearerToken` → `ErrConfig` naming both) and `ExampleEnableSessionCookie_twoChains` (cookie chain at defaults, token chain with `WithBasePath("/api")`, one `http.ServeMux`).
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement** the check in `New`'s assembly. **Step 4: Run** lanes M/C scoped command — PASS.
- [ ] **Step 5: Commit** `feat(httpsec): a chain delivers cookies or tokens, never both`.

### Task 6.1: Delivery through every issuing endpoint

**Files:** Modify `httpsec/complete.go` (`credentialIssuer`, commit), `login.go`, `magiclink.go`, `passkey_login.go`, `mfa_verify.go`, `reauth_resolve.go`, `recovery.go`, `session_renewal.go`; Test `httpsec/session_cookie_delivery_test.go`.

**Interfaces:** Produces unexported `func (c *config) deliver(ex *Exchange, s *session.Session, credential string) (body string, err error)`; on a cookie chain it sets the cookie and returns `""`.

- [ ] **Step 1: Write the failing table test** `TestSessionCookie_NoCredentialInBody`, one case per issuing endpoint plus a challenged password login: assert `Set-Cookie` names the (rotated) session, and neither the body nor any header other than `Set-Cookie` contains the identifier; `ChallengeError.Token == ""`. Add Review Focus 3: GET and HEAD to each issuing path pass through with no `Set-Cookie`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `feat(httpsec): deliver every credential as the session cookie on a cookie chain`.

### Task 6.2: The delivery port

**Interfaces:** Produces `type SessionDelivery interface { Deliver(ex *Exchange, s *session.Session, credential string) (bodyCredential string, err error) }` and `func WithSessionDelivery(d SessionDelivery) SessionCookieOption` (nil refused).

- [ ] **Step 1: Write the failing table test** `TestSessionCookie_DeliveryPort`: consumer delivery that sets the cookie and records an audit entry; one returning a non-empty body credential on a renewal → issuing failure, nothing written; on a fresh sign-in → same.
- [ ] **Steps 2–5:** run (FAIL), implement, run (PASS), commit `feat(httpsec): a bounded session delivery port`.

### Task 7.1: Both credentials

**Files:** `httpsec/session_cookie_guard.go`, test beside it. **Interfaces:** `const OrderSessionCookieGuard = OrderCSRF + 5`.

- [ ] **Step 1: Write the failing table test** `TestSessionCookie_BothCredentialsRefused`: cookie + `Authorization: Bearer x`, cookie + `Basic`, on a resource-server path → 401, a counting session store saw zero loads, resource server's source saw zero calls; header only on a resource-server path → judged by the resource server.
- [ ] **Steps 2–5:** run (FAIL), implement, run (PASS), commit `feat(httpsec): refuse a request carrying the cookie and an Authorization header`.

### Task 8.1: Negotiated answers

**Files:** Create `httpsec/session_cookie_answer.go`; modify the default responders of the endpoints in 6.1.

**Interfaces:** Produces unexported `func prefersHTML(r Request) bool` (form `Content-Type`, or `Accept` ranking `text/html` above `application/json`) and `func answerSignIn(ex *Exchange, s *session.Session, destination string) error` (`303` + `Cache-Control: no-store`, or `200` `{"idle_expires_at": RFC 3339}`).

- [ ] **Step 1: Write the failing table test** `TestSessionCookie_Answers` over each issuing endpoint × {form post, `Accept: text/html`, JSON} plus a consumer `WithLoginResponder` answering 204.
- [ ] **Steps 2–5:** run (FAIL), implement, run (PASS), commit `feat(httpsec): browser sign-ins answer by what the request prefers`.

### Task 8.2: The destination

**Interfaces:** Produces `const DefaultSessionCookieNextParam = "next"`, `WithSessionCookieNextParam(name string)`, `WithSessionCookieRedirects(targets ...string)` (each must be absolute `https` without fragment, else `ErrConfig`); unexported `func (c *sessionCookie) destination(requested string) string`.

- [ ] **Step 1: Write the failing table test** `TestSessionCookie_Destination`: `/orders` kept; `https://evil.example/`, `//evil.example/`, `/\evil`, `%2F%2Fevil.example`, `/%5Cevil`, `/\t/evil`, `https:evil`, empty → `/` (Review Focus 2); allowlisted `https://app.example.com/home` kept; non-https allowlist entry → `ErrConfig`.
- [ ] **Steps 2–5:** run (FAIL), implement (decode once, reject `\` and control characters, require exactly one leading `/`), run (PASS), commit `feat(httpsec): keep browser sign-in destinations on the same origin`.

### Task 9.1: Federated callback on a cookie chain

**Files:** Modify `httpsec/oidc_login.go`, `httpsec/oidc_options.go`; Test `httpsec/oidc_cookie_test.go`.

- [ ] **Step 1: Write the failing tests** `TestOIDCLogin_CookieChainCallback` (cookie set; `303` to the allowlisted destination; no `code=`/handoff parameter in `Location`; session has `oidc` first factor and federated fields from the creating write) and `TestOIDCLogin_CookieChainRefusesHandoff` (handoff manager given → `ErrConfig`); consumer `WithOIDCCallbackSuccess` still writes the response.
- [ ] **Steps 2–5:** run (FAIL), implement, run (PASS), commit `feat(httpsec): complete federated sign-in in the callback on a cookie chain`.

### Task 10.1: Persistence

**Interfaces:** Consumes 1.1 (`session.WithPersistentCookie`); produces `func WithSessionCookiePersistence(decide func(*Exchange) bool) SessionCookieOption` (nil refused).

- [ ] **Step 1: Write the failing table test** `TestSessionCookie_Persistence`: decide true with a 12 h absolute lifetime → `Max-Age=43200`; persistence survives MFA verification (rotated cookie has `Max-Age` from its deadline); no option → no `Max-Age`; deadline 0.4 s away → `Max-Age=1` (Review Focus 5).
- [ ] **Steps 2–5:** run (FAIL), implement, run (PASS), commit `feat(httpsec): let a sign-in choose a persistent session cookie`.

### Task 11.1: Re-set at second factor and re-authentication

- [ ] **Step 1:** Write `TestSessionCookie_ExistingRotationsReset` asserting the rotated identifier in `Set-Cookie` after MFA verify and after re-authentication; remove the re-set in a scratch edit, see it FAIL, restore.
- [ ] **Step 2: Commit** `test(httpsec): pin cookie re-set at second factor and re-authentication`.

### Task 11.2: Rotation at the role switch

**Files:** Modify `httpsec/role_switch.go` (role source carries the exchange's writer).

- [ ] **Step 1: Write the failing test** `TestSessionCookie_RoleSwitchRotates`: new identifier in `Set-Cookie`, CSRF token still accepted on the next POST, the old identifier after its window → reuse and family revoked.
- [ ] **Steps 2–5:** run (FAIL), implement with `RotateWithGrace` (design 10, settled), run (PASS), commit `feat(httpsec): rotate the cookie session at a role switch`.

### Task 11.3: Rotation at the password change

**Files:** Modify `httpsec/resolve.go`, `httpsec/password_change.go`.

- [ ] **Step 1: Write the failing test** `TestSessionCookie_PasswordChangeRotates` at the gate's resolve endpoint.
- [ ] **Steps 2–5:** run (FAIL), implement, run (PASS), commit `feat(httpsec): rotate the cookie session at a password change`.

### Task 11.4: Opt-outs

**Interfaces:** Produces `type RotationPoint uint8`, `const RotateOnRoleSwitch RotationPoint = iota + 1`, `RotateOnPasswordChange`, and `func WithoutSessionRotation(points ...RotationPoint) SessionCookieOption` (empty or unknown point → `ErrConfig`); godoc states it reopens session fixation for those points.

- [ ] **Step 1: Write the failing table test** `TestSessionCookie_WithoutRotation`: role switch off keeps the identifier and sets no cookie; password change off likewise; unknown point → `ErrConfig`; MFA still rotates with both off.
- [ ] **Steps 2–5:** run (FAIL), implement, run (PASS), commit `feat(httpsec): named opt-outs for the added rotations`.

### Task 11.5: Races

- [ ] **Step 1: Write the failing tests** under `-race`: `TestSessionCookie_ConcurrentRoleSwitch` (two switches released by a barrier: one wins, the loser's identifier works through the window); `TestSessionCookie_RotationCancelled` (context cancelled inside the issuing step: nothing stored, no `Set-Cookie`, old identifier valid); `TestSessionCookie_LogoutRacesRoleSwitch` (Review Focus 4).
- [ ] **Steps 2–5:** run (FAIL where behaviour is missing; characterization otherwise, inverted once), implement, run with `-race` (PASS), commit `test(httpsec): cookie rotation under concurrency`.

### Task 11.6: The successor's role in the rotation's write

**Files:** Modify `session/store.go` (`Supersession` field, `Store.Supersede` godoc), `session/sessions_options.go` or the rotate-option file (option), `session/reuse.go` (grace rotations), `session/store_memory.go`, `session/store_encrypted.go` (pass the field through); Test `session/reuse_test.go`.

**Interfaces:**
- Produces: `Supersession.SuccessorRole *string` (nil = carry the old record's stored role, as today; non-nil = insert the successor with `*SuccessorRole`, `""` clearing it; written back to `op.Successor.SelectedRole` on success); `func WithSuccessorRole(role string) RotateOption`, taken by `RotateWithGrace` and `RotateWithGraceIssuing`, refused with `ErrConfig` by `Rotate` and `RotateIssuing` with nothing stored; `var ErrStoreContract` or a wrapped error identifying a store that wrote back another role (name it in godoc; it must not match `ErrReused`, `ErrNotFound` or `ErrRenewalConflict`).

- [ ] **Step 1: Write the failing table test** `TestSessions_SuccessorRole` (table-test form): stored role `admin`, rotate with `WithSuccessorRole("audit")` through each grace rotation → successor loads `audit`, old record still `admin`, a counting store saw one `Supersede` and zero `SelectRole`; `WithSuccessorRole("")` → successor role empty; no option → successor `admin`; session deleted between load and write → error, no successor stored; a store wrapper that rewrites `op.Successor.SelectedRole` to `admin` after supersede → error matching the store-contract error, returned successor nil; `Rotate`/`RotateIssuing` with the option → `ErrConfig`, nothing stored.
- [ ] **Step 2: Run** `go test -count=1 -run TestSessions_SuccessorRole ./session/` — FAIL on the assertions (after a compiling stub of the option).
- [ ] **Step 3: Implement**: the option sets a field on `rotation`; the grace rotations copy it into `Supersession.SuccessorRole`; the memory store uses it in place of the old record's role inside its lock; `Sessions` compares the written-back role and fails on a mismatch. The encrypted store passes the field unchanged.
- [ ] **Step 4: Run** lane S's scoped command — PASS.
- [ ] **Step 5: Commit** `feat(session): record a successor's role in the rotation's own write`.

### Task 11.7: Durable stores honour the named role

**Files:** Modify `store/sqlstore/session.go`, `store/pgxstore/session.go`, `store/gormstore/session.go`; Test `test/storetest/session_suite.go` (beside `sessionSelectedRoleCases`).

**Interfaces:** Consumes 11.6's `Supersession.SuccessorRole`. The provider's refresh-token lineage statements share the session statements; the named role applies to the sessions table only, and the lineage path passes nil.

- [ ] **Step 1: Write the failing suite cases** `supersede names the successor role` (old `admin`, named `audit` → successor `audit`, old `admin`, `op.Successor.SelectedRole == "audit"`), `supersede names an empty role`, `supersede without a named role carries the stored one`; the cross-backend runner covers write-on-one, load-on-another.
- [ ] **Step 2: Run** `cd test && go test -count=1 -run 'Session' ./sqlstore/... ./pgxstore/... ./gormstore/... ./crossbackend/...` — FAIL: successor takes `admin`.
- [ ] **Step 3: Implement**: in each store's supersession transaction, use the named role instead of the value read from the locked old row when `SuccessorRole` is non-nil; write it back.
- [ ] **Step 4: Run** lane S's scoped command and `make generate-check` — PASS.
- [ ] **Step 5: Commit** `feat(store): honour a successor role named at supersession`.

### Task 11.8: The role switch rotates with its role

**Files:** Modify `httpsec/role_switch.go` (`rotateForSwitch` and the switch path that calls `SelectRole` after it); Test `httpsec/session_cookie_race_test.go`, `httpsec/session_cookie_rotation_test.go`.

**Interfaces:** Consumes `session.WithSuccessorRole` (11.6).

- [ ] **Step 1: Tighten the tests**: in `TestSessionCookie_LogoutRacesRoleSwitch`, the interleaving where logout lands after the rotation's issuing step and before its write asserts the switch fails with `ErrAuthenticationRequired`, no `Set-Cookie`, and no session of the family stored; add `TestSessionCookie_RoleSwitchStoreIgnoresRole` (a store wrapper rewriting the written-back role → switch fails, no `Set-Cookie`, role unchanged); assert a counting store saw no `SelectRole` on a rotating switch.
- [ ] **Step 2: Run** `go test -count=1 -race -run 'TestSessionCookie_(LogoutRacesRoleSwitch|RoleSwitch)' ./httpsec/` — FAIL: a cookie is set on the failed switch.
- [ ] **Step 3: Implement**: pass `session.WithSuccessorRole(role)` to the rotation and drop the separate `SelectRole` on the rotating path; a non-rotating switch (bearer, or rotation turned off) keeps `SelectRole`.
- [ ] **Step 4: Run** lanes M/C scoped command with `-race` — PASS.
- [ ] **Step 5: Commit** `fix(httpsec): record the switched role in the rotation's write`.

### Task 12.1: Logout

- [ ] **Step 1: Write the failing table test** `TestSessionCookie_LogoutExpires`: success → exact expiring `Set-Cookie` with the configured name, domain and same-site; provider store failure on a provider chain → dependency failure, session present, no `Set-Cookie`.
- [ ] **Steps 2–5:** run (FAIL), implement, run (PASS), commit `feat(httpsec): logout expires the session cookie`.

### Task 12.2: The provider on a cookie chain, and its guard exemption

**Files:** Modify `httpsec/oidc_provider.go` (`(*oidcEndpoints).checkBearer`), `httpsec/session_cookie_guard.go`; Test `httpsec/session_cookie_provider_test.go`.

**Interfaces:**
- Consumes: `sessionCookieGuard` and `OrderSessionCookieGuard` (7.1); the `OIDCEndpoint` constants and the provider's resolved paths.
- Produces: `checkBearer` accepting `*sessionCookie` as a bearer mode, and folding its manager into the one-shared-manager check; the guard holding the set of outer provider paths, resolved at construction from the chain's prefix and path overrides (not matched by string prefix at request time).

- [ ] **Step 1: Write the failing table test** `TestSessionCookie_ProviderOnCookieChain`:
  - `New` with `EnableSessionCookie` + the provider → no error (today `ErrConfig` "needs a bearer mode");
  - the cookie session given a manager other than the provider's → `ErrConfig` naming both;
  - cookie + `Authorization: Bearer <access token>` to `OIDCUserInfo` → the provider judges the token (200 with claims), no session loaded;
  - cookie + `Authorization` to `OIDCToken`, `OIDCRevoke`, `OIDCIntrospect` → reach the provider (not the guard's 401);
  - cookie + `Authorization` to `OIDCResume`, `OIDCConsents`, `OIDCLogoutConfirm` → 401 from the guard, zero session loads;
  - with `WithOIDCProviderPath(OIDCUserInfo, "/me")`: `/me` exempt, the default `/userinfo` path not.
  - `WithOIDCProviderCompletion` on a cookie chain: today `checkCompletion` requires a handoff manager, which a cookie chain refuses; settle it so the provider's completion runs without one (the completion already discards its credential and sets no cookie, design 4), with a case proving the chain builds and a completed provider login sets no session cookie.
- [ ] **Step 2:** run, FAIL on the `ErrConfig`.
- [ ] **Step 3:** implement. Outer set: `OIDCAuthorize`, `OIDCToken`, `OIDCUserInfo`, `OIDCRevoke`, `OIDCIntrospect`, `OIDCEndSession`, `OIDCDeviceAuthorization`, and the discovery and JWKS documents. Every other provider route stays guarded. Match the exact cleaned path.
- [ ] **Step 4:** run, PASS; run the scoped C-lane commands.
- [ ] **Step 5: Commit** `feat(httpsec): run the provider on a cookie chain, its outer endpoints outside the guard`.

### Task 12.3: Provider browser sessions end with the sign-in

- [ ] **Step 1:** Write `TestSessionCookie_EndsProviderBrowserSessions` on a chain running the provider: after logout, and after reuse detected through the cookie, `BrowserSessionStore.Load` of that sign-in's record returns `ErrNotFound`. Remove the end-observer wiring in a scratch edit, see it FAIL, restore.
- [ ] **Step 2: Commit** `test(httpsec): ending a cookie sign-in ends the provider's browser sessions`.

### Task 12.4: The resume reads the cookie sign-in

**Files:** Modify `httpsec/oidc_resume.go` (`resumeSignIn` and its godoc), `httpsec/session_cookie.go` (set the exchange mark when the cookie session publishes); Test `httpsec/session_cookie_provider_test.go`.

**Interfaces:** Produces an unexported exchange field (for example `ex.cookieSession bool`) set only by `(*sessionCookie).Intercept` when it publishes, never settable through the public `Exchange` API.

- [ ] **Step 1: Write the failing table test** `TestSessionCookie_ProviderResume`: cookie + CSRF token on a pending authorization → resumes (redirect to the client with a code); cookie + `Authorization` → 401 from the guard, zero session loads; cookie without CSRF token → 403, nothing counted; a consumer interceptor publishing a session from its own cookie on a cookie chain → 401; a header-bearer chain's resume unchanged (existing cases pass); end to end: `WithOIDCProviderCompletion` finds a step owed → `303` to the login page with the handle → the step finished → resume succeeds.
- [ ] **Step 2: Run** `go test -count=1 -run TestSessionCookie_ProviderResume ./httpsec/` — FAIL: `expected 200/303 actual 401`.
- [ ] **Step 3: Implement**: in `resumeSignIn`, accept `ex.Session` when the cookie mark is set and no `Authorization` line is present; everything after (`resumableSignIn`) unchanged.
- [ ] **Step 4: Run** lanes M/C scoped command with `-race` — PASS.
- [ ] **Step 5: Commit** `feat(httpsec): resume a provider authorization with the cookie sign-in`.

### Task 12.5: C6 review follow-ups

**Files:** `httpsec/session_cookie_provider_test.go`, `httpsec/password_change*_test.go`, `httpsec/session_cookie_race_test.go`, `httpsec/logout.go`, `httpsec/session_cookie_logout_test.go`.

- [ ] **Step 1: Write the cases**: `TestSessionCookie_ProviderOnCookieChain` row "endpoint not served adds no exemption" (device grant off: cookie + `Authorization` to the device-authorization path → 401, zero session loads); a password-change row (recovery-pending persistent sign-in, `WithoutSessionRotation(RotateOnPasswordChange)`, role switch inside the change → the switch's cookie `Max-Age` follows the restored deadline); rename the manager-mismatch row to "cookie and session bearer refused" and comment the defensive `checkBearer` branch; replace the race test's `tc.name ==` check with an `owesChange bool` field; `TestSessionCookie_LogoutExpires` row "basic-auth logout without the cookie sets no `Set-Cookie`".
- [ ] **Step 2: Run** each new row with its branch removed in a scratch edit (served filter, restored-deadline branch) and see it FAIL; the logout row fails on today's code.
- [ ] **Step 3: Implement** the logout change: expire only when the request carried the session cookie.
- [ ] **Step 4: Run** lanes M/C scoped command with `-race` — PASS.
- [ ] **Step 5: Commit** `test(httpsec): pin the provider exemption filter and the restored deadline`.

### Task 12.6: C8 and C8b review follow-ups

C8b committed nothing: its run-scoped mark was reviewed and two defects reproduced. C8c reworks the uncommitted C8b edits in place. The construction rule, the godoc fixes and the grace-window row from C8b stay.

**Files:** Modify `httpsec/chain.go` (remove the mark clear at run entry, keep the re-entry check), `httpsec/exchange.go` (the mark's chain field; rewrap the 85-column line near `exchange.go:441`), `httpsec/session_cookie.go` (`sessionCookie.chain`, set in `wire`), `httpsec/oidc_resume.go` (`oidcResumeGroup` keeps its chain), `httpsec/oidc_provider.go` (`checkCSRF`), and the C9 review's godoc nits in `httpsec/role_switch.go` and `httpsec/session_delivery.go` (the stale "moves to a new identifier before the selection is recorded" comment; `rotateForSwitch` naming `WithSuccessorRole`; `rotateForSwitch` and `rotateCookie` stating that a rotation failing with `session.ErrStoreContract` has already written); Test `httpsec/session_cookie_nested_resume_test.go`, `httpsec/session_cookie_provider_test.go`.

**Interfaces:** No new exported names. Unexported: `Exchange.cookieSessionChain *Chain`, set with `Exchange.cookieSession` in `(*sessionCookie).Intercept`; `resumeSignIn` accepts `ex.Session` only when `ex.cookieSession == ex.Session` and `ex.cookieSessionChain == g.chain`.

- [ ] **Step 1: Write the failing table test** `TestSessionCookie_ComposedChainResume`, one row per composition:
  - header-bearer provider chain whose interceptor runs the cookie chain inside it (`cookieChain.Assemble(next)(ex)`); resume POST with the cookie, its CSRF token and no `Authorization` → 401, no code (the C8b review's `TestRepro_CookieChainComposedAroundHeaderProviderRun`);
  - cookie chain with the provider whose interceptor runs a plain chain inside it → the resume succeeds (the C8b review's `TestRepro_PlainChainComposedAroundCookieProviderRun`);
  - the existing nested row (cookie chain outside, header-bearer provider chain inside) → 401;
  - a plain chain outside the cookie chain with the provider → the resume succeeds.
  Keep C8b's CSRF opt-out row and grace-window row.
- [ ] **Step 2: Run** `go test -count=1 -run 'TestSessionCookie_(ComposedChainResume|NestedProviderChainResume)' ./httpsec/` — expected FAIL on the first two rows: `expected: 401, actual: 200` and a 401 where a redirect was expected.
- [ ] **Step 3: Implement**: record the chain beside the mark, compare it at the resume, and remove the clear; update the godoc in `chain.go`, `exchange.go` and `oidc_resume.go` to "the mark belongs to the chain that set it".
- [ ] **Step 4: Run** lanes M/C scoped command with `-race` — PASS.
- [ ] **Step 5:** No commit yet; C8d follows (below).

**C8c review follow-ups (dispatch C8d).** C8c's chain-scoped mark refuses a legitimate resume when a cookie chain running the provider wraps the rest of its run in another cookie chain on the same cookie: that chain republishes the session and the single mark now names it (REPRODUCED by the reviewer: `TestReview_CookieProviderChainAroundCookieChainKeepsResume`, in `/private/tmp/claude-501/review-c8c/wt/httpsec/zz_review_c8c_test.go`; it fails with `httpsec: authentication required`). User decision, 2026-11-27: each chain keeps its own mark (design 12, "Each chain keeps its own mark").

**Interfaces:** Unexported only. Replace the single `Exchange.cookieSessionChain` with a per-chain record of the session identifier each chain's cookie session authenticated in this request (for example `Exchange.cookieMarks map[*Chain]string`, allocated on first write, saved and restored with the run state as the mark is today). `Exchange.cookieSession` keeps pointing at the last session a built-in cookie session published. `resumeSignIn` accepts `ex.Session` when `ex.Session == ex.cookieSession` and `ex.cookieMarks[g.chain] == ex.Session.ID`.

- [ ] **Step 6: Write the failing row** in `TestSessionCookie_ComposedChainResume`: a cookie provider chain whose interceptor runs another cookie chain (same cookie name, same session manager) around the rest of its run, at `OrderSessionTouch+1`; resume with the cookie and its CSRF token → resumes with a code. Keep every C8c row; in particular the header-bearer provider chain around or inside a cookie chain still → 401.
- [ ] **Step 7: Run** `go test -count=1 -run TestSessionCookie_ComposedChainResume ./httpsec/` — expected FAIL on the new row: `Received unexpected error: httpsec: authentication required`.
- [ ] **Step 8: Implement** the per-chain record above; update the godoc in `exchange.go`, `session_cookie.go` and `oidc_resume.go` (and rewrap `resumeSignIn`'s over-long godoc line starting "presented: whoever sent either…" to the surrounding width).
- [ ] **Step 9: Run** lanes M/C scoped command with `-race` — PASS.

**C8d review follow-up (dispatch C8e, Sonnet).** A chain with no mark reads `""` from the record, so a store returning a session with an empty identifier passed the check (REPRODUCED: `TestReview_HeaderProviderChainAroundCookieChain_BlankSessionID`, `/private/tmp/claude-501/review-c8d/wt/httpsec/zz_review_blankid_test.go`, `expected: 401 actual: 200`).

- [ ] **Step 10: Write the failing row** in `TestSessionCookie_ComposedChainResume`: a header-bearer provider chain running a cookie chain around the rest of its run, with a session store whose `Load` returns the session with `ID` blanked → 401 `ErrAuthenticationRequired`, the request stays parked. Run it focused: FAIL `expected: 401 actual: 200`.
- [ ] **Step 11: Implement** in `resumeSignIn`: `mark, marked := ex.cookieMarks[g.chain]`, and accept only when `marked && mark == s.ID` (with the existing conditions). Rerun — PASS; then lanes M/C scoped command with `-race`.

### Task 12.7: No CSRF exemption covers the cookie resume

**Files:** Modify `httpsec/oidc_provider.go` (`checkCSRF`), and `httpsec/csrf_exemption.go` only to expose its matcher to the check if it is not already callable; Test `httpsec/session_cookie_provider_test.go`.

**Interfaces:** Consumes the exemption matcher `WithCSRFExemption` builds (method exact; path compared as sent; `*` matches one non-empty segment). No new exported names. The resume path is the provider prefix (`DefaultOIDCProviderPrefix` or its override) plus `/authorize/resume`, under the chain's base path.

- [ ] **Step 1: Write the failing table rows** in `TestSessionCookie_ProviderOnCookieChain`:
  - cookie session + provider + `WithCSRFExemption("POST", "/oauth2/authorize/resume")` → `ErrConfig` naming the resume endpoint;
  - `WithCSRFExemption("POST", "/oauth2/authorize/*")` → `ErrConfig`;
  - `WithCSRFExemption("POST", "/oauth2/authorize/%72esume")` → `ErrConfig` (an escaped spelling the router decodes to the resume);
  - `WithBasePath("/x")` with `WithCSRFExemption("POST", "/x/oauth2/authorize/resume")` → `ErrConfig`;
  - a renamed provider prefix `/idp` with `WithCSRFExemption("POST", "/idp/authorize/resume")` → `ErrConfig`;
  - the exact exemption on a header-bearer provider chain without the cookie session → builds;
  - `WithCSRFExemption("POST", "/webhooks/payments")` on the cookie chain with the provider → builds.
- [ ] **Step 2: Run** `go test -count=1 -run TestSessionCookie_ProviderOnCookieChain ./httpsec/` — expected FAIL on the four refusal rows: `expected ErrConfig, got nil`.
- [ ] **Step 3: Implement**: in the provider's chain check, when the chain has the cookie session, run `POST` plus the resolved resume path through every configured exemption and refuse with `ErrConfig` on a match, naming the method and path. Add a line to `WithCSRFExemption`'s godoc stating the refusal.
- [ ] **Step 4: Run** lanes M/C scoped command with `-race` — PASS.
- [ ] **Step 5:** No commit yet; C8d follows (below).

**C8c review follow-ups (dispatch C8d).** `checkResumeJudged` loops over the consumer's exemptions only, so the back-channel prefix exemption is never judged and `coversRoute`'s prefix branch never runs (the reviewer's nit; today the endpoint collision check refuses the configurations that would place the back-channel path over the resume).

- [ ] **Step 6: Write the pinning rows** in `TestSessionCookie_ProviderOnCookieChain`: cookie chain with the provider and OIDC login, `WithOIDCBackchannelLogoutPath("/bc")` and `WithOIDCProviderPath(OIDCResume, "/bc/resume")` → `ErrConfig`; `WithOIDCBackchannelLogoutPath("/oauth2/authorize")` → `ErrConfig`. They may pass today through the collision check; show each fails once by disabling that check in a scratch edit, then edit it back.
- [ ] **Step 7: Implement**: make the resume check judge the back-channel exemption too (iterate every exemption the CSRF layer applies, not only the consumer's), so `coversRoute`'s prefix branch is live and the guarantee does not rest on the collision check alone.
- [ ] **Step 8: Run** lanes M/C scoped command with `-race` — PASS.
- [ ] **Step 9: Commit** C8c and C8d together: `fix(httpsec): keep the cookie sign-in to its own chain, and keep the cookie resume under CSRF protection`.

### Task 12.8: `FromProvider` trusts a provider another chain serves

**Files:** Modify `httpsec/resource_source_provider.go` (`checkWiring`, `FromProvider` godoc), `httpsec/resource_server.go` (the issuer check near line 193, the size bound near line 465, the remote-issuer refusal near line 801); Test `httpsec/resource_source_provider_test.go`, `httpsec/resource_server_construction_test.go`, new `httpsec/example_resource_server_two_chains_test.go`.

**Interfaces:** No new exported names. `FromProvider(op *oidcprovider.Provider, opts ...SourceOption)` keeps its signature. Unexported: a helper returning every provider the chain's resource servers trust (the chain's own, plus each provider source's `op`), used by the three rules.

- [ ] **Step 1: Write the failing tests**:
  - `TestFromProvider_OtherChain` (table): a token chain under `WithBasePath("/api")` without a provider, `EnableResourceServer("https://api.example.com", FromProvider(op))`, DPoP enabled; a DPoP-bound access token `op` issued for that audience → 200 with the local user's identifier; the grant revoked through `op`, same token again → 401 invalid token; a chain running provider `op1` with `FromProvider(op2)` → `ErrConfig`; `FromProvider(nil)` → `ErrConfig`.
  - `TestResourceServer_TrustedProviderRules` (table, on a chain without a provider and `FromProvider(op)`): a resource identifier equal to `op.Issuer()` → `ErrConfig`; a second source `FromIssuer(op.Issuer())` → `ErrConfig`; a token of `op.MaxAccessTokenSize()` bytes larger than the default bound → not refused for its size; `op`'s refresh token (`rt.` prefix) on a path whose resource server has only `FromIntrospection` → 401, the introspection endpoint receives no request (characterization: routing is by prefix and may already pass; show it fails once by inverting the prefix rule).
  - `ExampleEnableResourceServer_twoChains`: the provider on a cookie chain at `/`, the resource server with `FromProvider(op)` on a token chain at `/api`, one mux.
- [ ] **Step 2: Run** `go test -count=1 -run 'TestFromProvider_OtherChain|TestResourceServer_TrustedProviderRules|ExampleEnableResourceServer_twoChains' ./httpsec/` — expected FAIL: construction `ErrConfig` ("is not the one EnableOIDCProvider serves on this chain") where a build was expected, and the identifier, issuer and size rows passing where they should fail or failing where they should pass.
- [ ] **Step 3: Implement**: in `checkWiring`, refuse a nil `op`, and refuse `op` only when the chain runs a provider that is not `op`; make the three rules iterate the trusted providers. Rewrite `FromProvider`'s godoc: default, the cross-chain case, the one-provider-per-chain line.
- [ ] **Step 4: Run** lanes M/C scoped command with `-race`, and in `test/` `go test -count=1 ./httpsecconformance/... ./` — PASS.
- [ ] **Step 5: Commit** `feat(httpsec): trust a provider another chain serves through FromProvider`.

### Task 13.1: Adapter conformance

**Files:** Create `test/httpsecconformance/session_cookie_scenarios.go`; register in `scenarios.go`.

- [ ] **Step 1: Write the scenarios** (sign-in sets the cookie; refused cookie expired; logout expires) and run `cd test && go test -count=1 -run 'NetHTTP|Gin|Fiber' .` — FAIL until registered. **Step 2:** register; run — PASS on all three. **Step 3: Commit** `test: browser-session scenarios on every adapter`.

### Task 13.2: Documentation

- [ ] **Step 1:** Godoc for every new exported name, naming the default it replaces and its line; a package doc section on the two-chain setup (`httpsec/doc.go`) stating: a chain delivers cookies or tokens, never both; browsers use a cookie chain and native clients a token chain under `WithBasePath`; on a cookie chain a request carrying the session cookie and any `Authorization` header is refused with `ErrAuthenticationRequired` at `OrderSessionCookieGuard` (80), before Basic (400) or a resource server (425) reads it, and only the OIDC Provider's outer endpoints are exempt; so an API that takes access tokens from a same-origin page belongs on the token chain, since the browser attaches the cookie on its own. Add a one-binary subsection: the provider on the cookie chain and `EnableResourceServer(..., FromProvider(op))` on the token chain; and mounting one API handler on both chains (for example `/app/api/` behind the cookie chain with `http.StripPrefix("/app", api)` and `/api/` behind the token chain), with a scope check (`identity.Principal.Scopes`) on the token mount only, because a third-party token carries the user's grant to that client and the cookie carries the user.
- [ ] **Step 2:** Update `README.md`'s chain and resource-server sections to match Step 1: the chain section names the two-chain setup and the cookie/token exclusivity, and the resource-server section carries the cookie-plus-`Authorization` refusal as a gotcha. Do not restate slot numbers the README does not already list.
- [ ] **Step 3: Verify** `go doc ./httpsec EnableSessionCookie`, each `WithSessionCookie*`, `WithSessionDelivery`, `WithoutSessionRotation`, `WithMagicLinkParams`, `WithMagicLinkBodyLimit`, `go doc ./httpsec` (package doc shows the two-chain section), `go doc ./session WithPersistentCookie`, `go doc ./session WithSuccessorRole`, `go doc ./httpsec FromProvider` (names the cross-chain case), `go doc ./httpsec WithCSRFExemption` (names the resume refusal); `go vet ./...`.
- [ ] **Step 3: Commit** `docs: browser session options`.

### Task 14.1: Final gate (main session)

- [ ] Run `make check` and `make spec-check` once after the last code edit; read the output; record it in the change's verification notes.
