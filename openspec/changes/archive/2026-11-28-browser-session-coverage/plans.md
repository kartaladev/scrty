# Browser Session Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the coverage gaps the `browser-session` verification found, and move the
fixed-answer test stubs to generated mocks, without changing production behaviour.

**Architecture:** Tests in `httpsec` only, plus two `//go:generate` directives. Every scenario test
characterizes behaviour the code already has, so its red step is a temporary inversion of the code
it covers. One spec requirement (logout) is corrected in the change's delta, which the main session
owns.

**Tech Stack:** Go, `httpsec`, `oidcprovider`, `session`, testify, `go.uber.org/mock` (mockgen).

**Spec:** `openspec/changes/browser-session-coverage/` (`design.md` decisions 1–5,
`specs/browser-session/spec.md`), and the settled scenarios it completes in
`openspec/specs/browser-session/spec.md` and `openspec/specs/resource-server/spec.md`. Executors read
the design and the scenarios they cover.

## Global Constraints

- **No production behaviour change.** The only non-test edits are the two `//go:generate` lines
  (task 4.1) and comments. If a scenario test fails on the unmodified code, stop and report it as a
  defect claim with the failing output (`defect-claims.md`); do not change production code.
- **Characterization red step** (`golang-tdd.md`): write the test, run it and see it pass, invert the
  covered code (named in each task), run it and see it fail *for the intended reason*, restore the
  code by editing it back, run it and see it pass. Report the failing output of the inverted run.
  Never use `git checkout --`, `restore`, `reset --hard`, `stash` or `clean` to restore.
- Table tests follow the `table-test` skill: `assert` closure field, `t.Context()`. Add rows to the
  existing tables named below rather than new `TestXxx` functions for the same SUT call.
- Mocks follow the `use-mockgen` skill: `-typed`, destination `*_mock_test.go`, package
  `httpsec_test`, directive beside the interface.
- Cookie attributes in new assertions are checked parsed (`http.Response.Cookies()` /
  `http.ParseSetCookie`), not by header string order (design 2).
- No agent edits anything under `openspec/`.

## Review Focus

1. A composition test that obtains its token from a provider the token chain does not trust would
   pass for the wrong reason → task 1.1's inversion swaps the trusted provider and must fail.
2. A revoked-grant test that revokes a different grant than the token's → task 1.2 asserts the first
   call succeeded with the same token and the inversion (no revocation) passes the second call.
3. A zero-grace assertion that also holds for reuse → task 2.2 asserts no `event.AuthnTokenReuse`
   event and the family intact, which reuse would break.
4. A mock conversion that drops an assertion (e.g. that the delivery was called once) → task 4.2
   keeps every assertion and sets `.Times(1)` where the old stub's call was implied.
5. A cross-site row that passes because the request never reached the CSRF check → task 2.5 asserts
   `ErrCrossSiteRequest`, not only 403.

---

## Dispatches

Three lanes own disjoint files and run in parallel. Each is one dispatch (three to five tasks).

| Lane | Tasks | Owns | Model |
|---|---|---|---|
| A — composition | 1.1, 1.2 | new `httpsec/session_cookie_two_chains_test.go` | Sonnet: test assembly from existing helpers |
| B — scenarios | 2.1, 2.2, 2.3, 2.4, 3.1 | `session_cookie_provider_test.go`, `session_cookie_rotation_test.go`, `session_cookie_answer_test.go`, `session_cookie_delivery_test.go`, `session_cookie_logout_test.go` | Sonnet: rows in existing tables |
| C — mocks + CSRF row | 4.1, 4.2, 4.3, 2.5 | `session_delivery.go`, `csrf.go`, `sessiondelivery_mock_test.go`, `csrftokens_mock_test.go`, `oidc_cookie_test.go`, `session_cookie_test.go`, `session_delivery_port_test.go`, `session_cookie_persistence_test.go`, `session_cookie_provider_ends_test.go` | Sonnet: mechanical conversion with stated assertions |

Lane A may *read* helpers in lane B's and C's files but must not edit them; a helper it needs that
does not exist goes in its own file. Reviewers: Sonnet per lane (test additions), then one
whole-branch review before the gate.

**Scoped verification, every lane** (main module; these tasks change no package other lanes or
workspace modules import, since only `_test.go` files and `go:generate` lines change):

```sh
go test -race -count=1 ./httpsec/...
go vet ./httpsec/...
gofmt -l httpsec
```

Lane C also runs `make generate-check`.

---

### Task 1.1: Provider on the cookie chain, API on the token chain

**Files:**
- Create: `httpsec/session_cookie_two_chains_test.go`

**Interfaces:**
- Consumes (existing, read-only): `newCookieOP(t, func(*flowSetup)) (*opFlow, *loadCounter, error)`
  (`session_cookie_provider_test.go:56`), and `accessTokenOf`'s sequence (`:153`) as the model for
  the fixture's own token helper, which adds `resource` and a DPoP proof; `flowSetup.chain` to add options to the cookie
  chain; `psAPI` and the DPoP helpers (`dpopKey`, proof construction) in
  `resource_source_provider_test.go`; `httpsec.EnableResourceServer(psAPI,
  httpsec.WithPathPrefix("/api/"), httpsec.FromProvider(p))` as at `resource_source_provider_test.go:138`.
- Produces: `TestSessionCookie_TwoChainsWithProvider` and its fixture `twoChainWorld` (cookie chain,
  token chain whose resource server answers under `/api/` via `WithPathPrefix("/api/")` — not
  `WithBasePath("/api")`, which `httpsec.New` refuses on a chain with no built-in endpoint —, one
  `http.ServeMux` routing `/api/` to the token chain and `/` to the cookie chain, the provider, and a way to revoke a
  grant), used by task 1.2.

- [ ] **Step 1: Write the test.** Table test `TestSessionCookie_TwoChainsWithProvider`, row
  `"a bound token the cookie chain's provider issued is accepted on the token chain"`: record a sign-in
  in the cookie chain's session store, complete a first-party authorization for `psAPI` with the
  provider's `Resume`, exchange the code at the cookie chain's token endpoint with a DPoP proof (as
  `accessTokenOf` does, plus `resource` and DPoP), call
  `GET /api/orders` on the mux with the token and a fresh DPoP proof. Assert: status 200, the handler
  ran, the published principal's user ID is the signed-in user's, and the request carried no session
  cookie.
- [ ] **Step 2: Run it and see it pass.**
  `go test -run 'TestSessionCookie_TwoChainsWithProvider' -count=1 ./httpsec/` → `ok`.
- [ ] **Step 3: Invert.** Build the token chain with `FromProvider` of a second, separately built
  provider. Run → FAIL with 401 and the handler not run. Restore.
- [ ] **Step 4: Run it and see it pass**, then the lane's scoped verification.

### Task 1.2: Grant revoked, token checked on the other chain

**Files:**
- Modify: `httpsec/session_cookie_two_chains_test.go`

**Interfaces:**
- Consumes: `twoChainWorld` from task 1.1; the provider's grant revocation as the existing
  `TestFromProvider_OtherChain` (`resource_source_provider_test.go:692`) performs it.

- [ ] **Step 1: Add the row** `"a token whose grant is revoked is refused on the token chain"`: one
  accepted call (assert 200), revoke the token's grant through the provider, call again with the
  same token and a new proof before expiry. Assert the second call is 401 with
  `ErrInvalidToken` (or the error the existing other-chain test asserts) and the handler did not run.
- [ ] **Step 2: Run → pass. Invert:** skip the revocation. Run → FAIL on the second call's status.
  Restore. Run → pass.

### Task 2.1: Provider on a cookie chain without CSRF, default browser sessions

**Files:** Modify: `httpsec/session_cookie_provider_test.go` (table in
`TestSessionCookie_ProviderOnCookieChain`, beside the row at `:327`)

- [ ] **Step 1: Add the row** `"the provider without CSRF protection is refused, naming it, with
  browser sessions"`: as the `:327` row but without `oidcprovider.WithoutBrowserSessions()`. Assert
  `errors.Is(err, httpsec.ErrConfig)` and the same message fragments the `:327` row asserts.
- [ ] **Step 2: Run → pass. Invert** the provider-on-cookie-chain CSRF check in
  `httpsec/oidc_provider.go` (`checkCSRF`, around `:1146`/`:1155`) so it does not fire: both
  branches, the cookie-chain one and the browser-sessions one, since with only one disabled the
  other still refuses. Run → FAIL with no
  error. Restore. Run → pass.

### Task 2.2: Zero grace refused as an unknown reference

**Files:** Modify: `httpsec/session_cookie_rotation_test.go` (rows
`"with a zero grace second-factor verification rotates strictly"` near `:842`, and the
re-authentication twin near `:865`)

- [ ] **Step 1: Extend both rows' `assert`:** the late cookie's answer is 401, carries an expiring
  `Set-Cookie` for the session cookie (parsed: `MaxAge < 0` or `Max-Age=0`), the source was charged
  once (as `refusedCharged(true)` in `session_cookie_test.go` measures it — reuse that helper's
  approach, not its file), no `event.AuthnTokenReuse` was emitted (security events on the same chain), and the next request with the new
  cookie is served (already asserted).
- [ ] **Step 2: Run → pass. Invert:** make the zero-grace path rotate with the role switch's grace
  (`privilegeRotationGrace`). Run → FAIL (the old cookie is served). Restore. Run → pass.
  Then a second inversion for the reuse-event assertion: make the late old cookie be judged reused.
  Run → FAIL on that assertion. Restore. Run → pass.

### Task 2.3: Q-value with an empty fraction, end to end

**Files:** Modify: `httpsec/session_cookie_answer_test.go` (table in `TestSessionCookie_Answers`,
`:172`)

- [ ] **Step 1: Add the row** `"an Accept with an empty q-value fraction prefers HTML"`: a JSON-body
  sign-in with `Accept: text/html;q=1., application/json;q=0.5` (a form post is HTML by its content
  type and would never reach `qvalue`). Assert 303 and a `Location` header, as the existing
  HTML-post row does.
- [ ] **Step 2: Run → pass. Invert:** remove the empty-fraction handling in `qvalue`
  (`httpsec/session_cookie_answer.go:162`). Run → FAIL (JSON answer). Restore. Run → pass.

### Task 2.4: Default and strict cookie on a real sign-in

**Files:** Modify: `httpsec/session_cookie_delivery_test.go`

- [ ] **Step 1: Add a table test** `TestSessionCookie_SignInSetsCookieAttributes` with rows
  `"default"` and `"SameSite=Strict"` (`WithSessionCookieSameSite(http.SameSiteStrictMode)`): a form
  sign-in, then parse the response's cookies. Assert one cookie named `__Host-scrty-session` with
  `Path == "/"`, `Secure`, `HttpOnly`, `SameSite` Lax or Strict per row, `Domain == ""`,
  `MaxAge == 0`, `Expires.IsZero()`, non-empty value.
- [ ] **Step 2: Run → pass. Invert:** change the default same-site in `cookie()`
  (`httpsec/session_cookie.go:93`) to Strict. Run → the `default` row FAILS. Restore. Run → pass.

### Task 3.1: Logout scenarios

**Files:** Modify: `httpsec/session_cookie_logout_test.go` (`TestSessionCookie_LogoutExpires`,
`:57`)

- [ ] **Step 1:** Map the delta's three scenarios to rows. Add any missing assertion: the cookie
  logout's expiring cookie (parsed attributes), the Basic logout's success status and no
  `Set-Cookie`, the provider-outage row's dependency failure, session kept, no `Set-Cookie`.
- [ ] **Step 2: Invert** the "request carried the cookie" condition in `httpsec/logout.go`
  (around `:132`). Run → the Basic row FAILS (a `Set-Cookie` appears). Restore. Run → pass.

### Task 2.5: Cross-site request in one row

**Files:** Modify: `httpsec/session_cookie_test.go` (row `"a CSRF failure leaves the cookie"` in
`TestSessionCookie_RefusalExpires`, `:1099`)

- [ ] **Step 1: Extend the row** so it asserts `ErrCrossSiteRequest`, status 403, no `Set-Cookie`,
  and no charge to the source (as `TestSessionCookie_Authenticates`'s `:505` row measures it).
- [ ] **Step 2: Run → pass. Invert:** make a CSRF refusal expire the cookie. Run → FAIL on
  `Set-Cookie`. Restore. Run → pass. Then invert the charge: make a CSRF refusal count as a
  refused reference (charged). Run → FAIL on the no-charge assertion. Restore. Run → pass.

### Task 4.1: Mock directives

**Files:**
- Modify: `httpsec/session_delivery.go` (above `type SessionDelivery interface`, `:591`),
  `httpsec/csrf.go` (above `type CSRFTokens interface`, `:435`)
- Create (generated): `httpsec/sessiondelivery_mock_test.go`, `httpsec/csrftokens_mock_test.go`

- [ ] **Step 1:** Add `//go:generate mockgen -destination=sessiondelivery_mock_test.go
  -package=httpsec_test -typed . SessionDelivery` and the same for `CSRFTokens`, matching the form of
  the existing directives in `httpsec` (e.g. `complete.go:25`). Run `go generate` for those two
  directives only.
- [ ] **Step 2:** `make generate-check` → passes; `go vet ./httpsec/...` → clean.

### Task 4.2: Stubs to mocks

**Files:** Modify: `httpsec/oidc_cookie_test.go` (`failingOIDCDelivery`, `:27`),
`httpsec/session_cookie_test.go` (`authRequiredTokens`, `outageTokens`, `:758`–`:780`; uses at
`:556`, `:577`)

- [ ] **Step 1:** Replace `failingOIDCDelivery{}` with `NewMockSessionDelivery(ctrl)` whose
  `Deliver` returns `"", errOIDCCookieDelivery`; replace `authRequiredTokens{}` and
  `outageTokens{err}` with `NewMockCSRFTokens(ctrl)` returning the same values (`Token` → `"t", nil`;
  `Verify` → `httpsec.ErrAuthenticationRequired` or `errors.Join(httpsec.ErrAuthenticationRequired,
  err)`). Use `.AnyTimes()` for `Token`; set `.Times(n)` on `Verify`/`Deliver` only where the test
  expects a call. Delete the three types.
- [ ] **Step 2:** Run the affected tests → pass. **Invert:** make each mock return success. Run →
  each affected row FAILS. Restore. Run → pass.

### Task 4.3: Reasons on the doubles that stay

**Files:** Modify: `httpsec/session_delivery_port_test.go` (`auditDelivery`, `:38`),
`httpsec/session_cookie_persistence_test.go` (`persistentDelivery`, `:26`),
`httpsec/session_cookie_provider_ends_test.go` (`recordingBrowsers`, `:28`)

- [ ] **Step 1:** Add one sentence to each type's doc comment: the first two are consumer delivery
  implementations whose logic is the test's subject; `recordingBrowsers` decorates the real memory
  store (design 5).
- [ ] **Step 2:** `gofmt -l httpsec` → empty; `go vet ./httpsec/...` → clean.

### Task 5.1: Gate (main session)

- [ ] **Step 1:** Scoped run for `./httpsec` (above), read the output.
- [ ] **Step 2:** Whole-branch review against the delta and the completed scenarios.
- [ ] **Step 3:** `make check` and `make spec-check`, read the output; both pass after the last edit.
- [ ] **Step 4:** Commit per lane with messages naming the guaranteed behaviour, e.g.
  `test(httpsec): a provider on a cookie chain issues tokens a trusting token chain accepts`.
