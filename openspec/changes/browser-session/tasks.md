# Tasks

Every task is test-first: write the failing test, run it, and confirm it fails for the intended reason
(not a compile error), then implement. Where existing code already behaves as the spec requires, the
task says so: its test is a characterization test, shown to fail once by temporarily inverting the
code (`golang-tdd.md`). Verification is scoped to the changed packages and their dependents
(`test-scope.md`), using the commands in `plans.md`.

## 1. Session persistence mark

- [x] 1.1 Add the library-owned `session.Session.PersistentCookie` and the `session.WithPersistentCookie()` create option, set in the creating write only (design 9; spec sessions "Created persistent", "Consumer data cannot claim it"); verify with a focused `go test -run` on the new tests in `./session`
- [x] 1.2 Carry the mark through `Rotate`, `RotateIssuing`, `RotateWithGrace` and `RotateWithGraceIssuing`, and make `Save` keep the stored value in the memory store (spec sessions "Renewal keeps the mark", "Save cannot set the mark"); verify table tests over the four rotations and the save case

## 2. Durable stores

- [x] 2.1 Add a security-state migration adding `persistent_cookie boolean NULL` to `scrty_sessions` (no default, NULL read as unset), and a populated-upgrade test showing a row written before the migration loads with the mark unset (design 9; spec security-state-stores "Session stored before the migration"); verify the migration tests and `make generate-check`
- [x] 2.2 Store and load the mark in `store/sqlstore`, `store/pgxstore` and `store/gormstore`, write-once like `MFAAtFirstFactor`, and extend the `test/storetest` session suite with the round trip across backends (spec security-state-stores "Mark round trip across backends"); verify the store suites on every backend (Docker)

## 3. Magic-link parity

- [x] 3.1 Add `WithMagicLinkParams(address, next, token)` for form bodies and the request endpoint's JSON body, with empty and duplicate names refused (design 13; spec magic-link "Magic-link form field names are replaceable", MODIFIED "Only a POST redeems a link"); verify its scenarios
- [x] 3.2 Add `WithMagicLinkBodyLimit(limit)`, default 64 KiB, refusing zero or less, keeping an oversized body read as no values (spec magic-link "Magic-link request bodies are bounded by a replaceable limit"); verify its four scenarios, including that the request endpoint's answer stays uniform

## 4. Shared session-reference pipeline

- [x] 4.1 Characterize the session bearer before the refactor: confirm the existing `httpsec` session-bearer tests cover the shape check, load, reuse revocation, user reload, policy, throttling and the outage split, and add any missing case as a characterization test (design 3); verify by inverting each check once and seeing its test fail
- [x] 4.2 Extract the pipeline out of `sessionBearer.Intercept` so it takes the identifier and its transport, with the bearer behaviour unchanged (design 3); verify the full `httpsec` session-bearer suite passes unchanged before and after, and `go test -race` on `./httpsec`

## 5. The cookie session

- [x] 5.1 Add `EnableSessionCookie(deps, opts...)` at `OrderBearerToken`, reading the identifier from the cookie through the shared pipeline and implementing `CookieAuthenticator`, off by default (design 3; spec browser-session "The cookie session is off until enabled", "A session cookie is judged by the same rules", "The cookie session requires CSRF protection"); verify their scenarios
- [x] 5.2 Add the cookie attribute options and their construction checks: name, same-site, domain (design 8; spec browser-session "The session cookie has safe attributes by default", "Cookie overrides that break a guarantee fail at construction"); verify table tests for every allowed and refused combination
- [x] 5.3 Expire the cookie on a refused cookie (missing, expired, unreadable, reused) and leave it on a store or cipher outage (design 11; spec browser-session "A refused cookie is expired, an unreadable store keeps it", "The server's deadlines stay authoritative over the cookie"); verify their scenarios
- [x] 5.4 Refuse the cookie session together with `EnableSessionBearer` or `EnableBearerToken` (design 4; spec browser-session "A chain delivers either cookies or tokens"); verify both refusals, and an example test with a cookie chain and a token chain under `WithBasePath("/api")` on one mux

## 6. Credential delivery

- [x] 6.1 Route every issuing endpoint through the delivery step on a cookie chain (form login, magic link, passwordless passkey, second-factor verification, re-authentication, recovery completion, renewal), so the cookie is set and no credential is written to a body or header, and a `ChallengeError` carries no token (design 4; spec browser-session "A cookie chain hands out no credential in a response body"); verify one table test over every issuing endpoint asserting `Set-Cookie` present and no credential in body or headers
- [x] 6.2 Add `WithSessionDelivery(SessionDelivery)` with its line: a returned body credential is an issuing failure and nothing is written (design 4; spec browser-session "A credential delivery port cannot hand a token to a cookie request"); verify its two scenarios

## 7. Both credentials

- [x] 7.1 Add the guard at `OrderCSRF + 5` refusing a request with the session cookie and an `Authorization` header before any credential is read (design 5; spec browser-session "A request carrying both the cookie and an Authorization header is refused"); verify both scenarios, and with a counting fake store that no session was loaded

## 8. Browser answers

- [ ] 8.1 Make each issuing endpoint's default responder on a cookie chain negotiate: `303` with `Cache-Control: no-store` for a form or HTML-preferring request, `200` JSON with `idle_expires_at` otherwise, each responder still replaceable (design 7; spec browser-session "A browser sign-in answers by what the request prefers"); verify its three scenarios per endpoint in one table test
- [ ] 8.2 Resolve the destination: `next` (replaceable by `WithSessionCookieNextParam`) as a same-origin relative path only, or an exact target from `WithSessionCookieRedirects`, validated at construction (design 7; spec browser-session "A sign-in destination stays on the same origin unless allowlisted"); verify a table of hostile values (`https://…`, `//…`, `/\…`, empty, encoded variants) resolving to `/`, and the allowlisted target

## 9. Federated sign-in on a cookie chain

- [ ] 9.1 Supply the default callback success on a cookie chain: completion with the federated first factor and fields in the creating write, cookie set, `303` to the allowlisted destination, and a handoff manager refused at construction (design 6; spec browser-session "Federated sign-in completes in the callback on a cookie chain"); verify its two scenarios and that no handoff code appears in the redirect

## 10. Persistence

- [ ] 10.1 Add `WithSessionCookiePersistence(decide)`, asked at every new sign-in, creating the session with the persistent mark, and set `Max-Age` from the absolute deadline on every cookie of that sign-in, rotations included (design 9; spec browser-session "A sign-in can choose a persistent cookie"); verify its three scenarios, including `Max-Age=43200` for a 12-hour session

## 11. Rotation on privilege change

- [ ] 11.1 Re-set the cookie at second-factor verification and re-authentication, which already rotate (design 10); verify by characterization tests that the rotated identifier is in `Set-Cookie`, shown to fail once with the re-set removed
- [ ] 11.2 Rotate at the active-role switch on a cookie chain, re-setting the cookie through the role source, keeping the CSRF token (design 10; spec browser-session "Privilege changes rotate the cookie session", "Role switch", "Old identifier presented late"); verify those scenarios
- [ ] 11.3 Rotate at the password change at the gate's resolve endpoint on a cookie chain (spec browser-session "Password change"); verify the scenario
- [ ] 11.4 Add `WithoutSessionRotation` for the role switch and the password change only, documented as reopening session fixation (design 10; spec browser-session "The added rotations can be turned off by name, and the existing ones cannot"); verify both scenarios
- [ ] 11.5 Test concurrent rotations: two requests switching roles at once, and a context cancelled mid-rotation (design failure modes); verify with a barrier test under `-race` that one rotation wins and nothing is stored on cancellation

## 12. Ending the sign-in

- [ ] 12.1 Expire the cookie on logout with the attributes it was set with, and not on a logout that fails at a provider store (design 11; spec browser-session "Logout expires the cookie"); verify both scenarios
- [ ] 12.2 Let a chain run the OpenID Provider with the cookie session (the provider's chain check accepts it in place of a bearer mode), and exempt exactly the provider's outer endpoints (authorization, token, userinfo, revocation, introspection, end-session, device authorization, and the discovery and key-set documents) from the both-credentials guard, keeping its inner sign-in-dependent routes guarded (design 5, 12; spec browser-session "Provider endpoint"); verify the scenario, and that an inner provider route carrying the cookie and an `Authorization` header is still refused
- [ ] 12.3 Test that logout and reuse detected through the cookie end the provider's browser sessions of the sign-in, on a chain running the provider (design 12; spec browser-session "Ending a cookie sign-in ends the provider's browser sessions of it"); verify both scenarios (characterization: shown to fail once with the end observer removed)

## 13. Framework adapters and documentation

- [ ] 13.1 Add a browser-session scenario set to the shared adapter conformance suite and run it on net/http, gin and fiber: sign-in sets the cookie, a refused cookie is expired, logout expires it (design failure modes); verify the suite on all three adapters
- [ ] 13.2 Write godoc for every new option naming the default it replaces and its line, and package documentation for the two-chain setup; verify `go doc` output for each option and `go vet`

## 14. Final gate

- [ ] 14.1 Run the full suite once after the last code edit: `make check` and `make spec-check`; verify both pass, and record the output in the change's verification notes

## Workflow follow-up

- Run the whole-branch review against every requirement in this change's specs before archive.
- Archive the change, then retire `bff-resource-server` (needs its own confirmation) and propose `api-token-forwarding` with Q2, Q3 and Q5.
- Then propose the sign-in pages change (change 2 of the roadmap).
