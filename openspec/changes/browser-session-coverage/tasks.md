# Tasks

Every scenario test here covers behaviour the code already has, so each is a characterization test:
write it, see it pass, then temporarily invert the code it covers and confirm it fails for the
intended reason, then restore (`golang-tdd.md`). If a test fails on the unmodified code, stop: that
is a defect claim (`defect-claims.md`), reported with its failing output and not fixed in this
change (design, Non-Goals). Verification is scoped to `./httpsec` (`test-scope.md`); the commands
are in `plans.md`.

## 1. Composition: provider on a cookie chain, API on a token chain (design 4)

- [x] 1.1 Test "Provider on the cookie chain, API on the token chain": one mux with the provider on a cookie chain (`EnableSessionCookie`, CSRF) and a token chain whose resource server answers under `/api` (`WithPathPrefix("/api/")`, not `WithBasePath`, which a chain with no built-in endpoint refuses) and trusts that provider through `FromProvider`; a DPoP-bound access token obtained through a sign-in in the cookie chain's session store, authorization, `Resume` and the code exchange on the cookie chain, for the API resource, is accepted at `/api/orders` and the handler sees the local user it names; verify the test passes, and fails when the token chain's `FromProvider` is replaced by a source for another provider
- [x] 1.2 Test "Grant revoked, token checked on the other chain" on the same composition: after one accepted call, revoke the grant through the provider and re-send the token before it expires; it is refused as an invalid token; verify it passes, and fails with revocation skipped

## 2. Scenarios completed (design 2, 3)

- [x] 2.1 Row in `TestSessionCookie_ProviderOnCookieChain`: cookie session plus provider with its default browser sessions and CSRF opted out fails construction with a configuration error; verify it passes, and fails with both branches of the provider-on-cookie-chain CSRF check (cookie chain and browser sessions) disabled
- [x] 2.2 Strengthen both zero-grace rows (second-factor verification and re-authentication) in `session_cookie_rotation_test.go`: the late pre-verification cookie is refused as an unknown reference is — 401, charged against the source, cookie expired — with no `event.AuthnTokenReuse` event and the family intact; verify it passes, and fails when zero grace rotates with a grace window
- [x] 2.3 Row in `TestSessionCookie_Answers`: a JSON-body sign-in with `Accept: text/html;q=1., application/json;q=0.5` (a form post is HTML by its content type and never reaches the q-value) is answered `303 See Other`; verify it passes, and fails with the empty-fraction handling in `qvalue` removed
- [x] 2.4 Assert the session cookie on a real sign-in response, parsed: default chain gives `__Host-scrty-session`, `Path=/`, `Secure`, `HttpOnly`, `SameSite=Lax`, no `Domain`, `Max-Age` or `Expires`; a chain with `SameSite=Strict` gives `SameSite=Strict` and the rest unchanged; verify it passes, and fails with the default same-site changed
- [ ] 2.5 One row for "Cross-site request": an unsafe cookie request without a CSRF token is refused 403, not charged to the source, and its response has no `Set-Cookie`; verify it passes, and fails when a CSRF refusal expires the cookie

## 3. Logout spec correction (design 1)

- [x] 3.1 Confirm the existing test `TestSessionCookie_LogoutExpires` covers the delta's three scenarios ("Logout", "Logout by another credential", "Logout fails on a provider store outage"), adding any missing assertion; verify by inverting the "request carried the cookie" check in `logout.go` once and seeing the other-credential row fail

## 4. Test doubles to mockgen (design 5)

- [ ] 4.1 Add `//go:generate mockgen -typed` directives for `SessionDelivery` (`httpsec/session_delivery.go`) and `CSRFTokens` (`httpsec/csrf.go`) per `use-mockgen`, and generate `sessiondelivery_mock_test.go` and `csrftokens_mock_test.go`; verify `make generate-check` passes
- [ ] 4.2 Replace `failingOIDCDelivery` with the `SessionDelivery` mock and `authRequiredTokens` and `outageTokens` with the `CSRFTokens` mock, keeping every assertion of the tests that use them; verify those tests pass, and each still fails when the fault its mock injects is removed
- [ ] 4.3 Add a comment on `auditDelivery`, `persistentDelivery` and `recordingBrowsers` stating why each stays hand-written (design 5); verify `gofmt -l` and `go vet ./httpsec/...` are clean

## 5. Gate

- [ ] 5.1 Run the scoped checks for `./httpsec` (`go test -race`, `go vet`, `gofmt -l`), then the full gate `make check` and `make spec-check`, and read their output; verify both pass after the last edit
