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

- [x] 8.1 Make each issuing endpoint's default responder on a cookie chain negotiate: `303` with `Cache-Control: no-store` for a form or HTML-preferring request, `200` JSON with `idle_expires_at` otherwise, each responder still replaceable (design 7; spec browser-session "A browser sign-in answers by what the request prefers"); verify its three scenarios per endpoint in one table test
- [x] 8.2 Resolve the destination: `next` (replaceable by `WithSessionCookieNextParam`) as a same-origin relative path only, or an exact target from `WithSessionCookieRedirects`, validated at construction (design 7; spec browser-session "A sign-in destination stays on the same origin unless allowlisted"); verify a table of hostile values (`https://…`, `//…`, `/\…`, empty, encoded variants) resolving to `/`, and the allowlisted target

## 9. Federated sign-in on a cookie chain

- [x] 9.1 Supply the default callback success on a cookie chain: completion with the federated first factor and fields in the creating write, cookie set, `303` to the allowlisted destination, and a handoff manager refused at construction (design 6; spec browser-session "Federated sign-in completes in the callback on a cookie chain"); verify its two scenarios and that no handoff code appears in the redirect

## 10. Persistence

- [x] 10.1 Add `WithSessionCookiePersistence(decide)`, asked at every new sign-in, creating the session with the persistent mark, and set `Max-Age` from the absolute deadline on every cookie of that sign-in, rotations included (design 9; spec browser-session "A sign-in can choose a persistent cookie"); verify its three scenarios, including `Max-Age=43200` for a 12-hour session

## 11. Rotation on privilege change

- [x] 11.1 Re-set the cookie at second-factor verification and re-authentication, which already rotate (design 10); verify by characterization tests that the rotated identifier is in `Set-Cookie`, shown to fail once with the re-set removed
- [x] 11.2 Rotate at the active-role switch on a cookie chain, re-setting the cookie through the role source, keeping the CSRF token (design 10; spec browser-session "Privilege changes rotate the cookie session", "Role switch", "Old identifier presented late"); verify those scenarios
- [x] 11.3 Rotate at the password change at the gate's resolve endpoint on a cookie chain (spec browser-session "Password change"); verify the scenario
- [x] 11.4 Add `WithoutSessionRotation` for the role switch and the password change only, documented as reopening session fixation (design 10; spec browser-session "The added rotations can be turned off by name, and the existing ones cannot"); verify both scenarios
- [x] 11.5 Test concurrent rotations: two requests switching roles at once, and a context cancelled mid-rotation (design failure modes); verify with a barrier test under `-race` that one rotation wins and nothing is stored on cancellation
- [x] 11.6 Add `session.WithSuccessorRole(role)`, taken by `RotateWithGrace` and `RotateWithGraceIssuing` (refused with `ErrConfig` by the other rotations), setting a new `Supersession.SuccessorRole *string` that the memory store honours inside its supersession, and make `Sessions` fail the rotation when the role written back differs from the one named (design 10; spec sessions "A rotation can record the successor's selected role in its own write"); verify its four scenarios in `./session`
- [x] 11.7 Honour `Supersession.SuccessorRole` in `store/sqlstore`, `store/pgxstore` and `store/gormstore`, inside the supersession's transaction, and add the cases to the `test/storetest` session suite (spec security-state-stores "Durable stores record a successor role named at supersession"); verify the store suites on every backend (Docker)
- [x] 11.8 Make the role switch on a cookie chain rotate with `WithSuccessorRole`, removing its separate `SelectRole` write, so a logout landing before the write fails the switch with no cookie re-set (design 10; spec browser-session "Logout during a role switch"); verify `TestSessionCookie_LogoutRacesRoleSwitch` with both interleavings asserting no `Set-Cookie` when the switch fails, and a store-ignores-role case

## 12. Ending the sign-in

- [x] 12.1 Expire the cookie on logout with the attributes it was set with, and not on a logout that fails at a provider store (design 11; spec browser-session "Logout expires the cookie"); verify both scenarios
- [x] 12.2 Let a chain run the OpenID Provider with the cookie session (the provider's chain check accepts it in place of a bearer mode), and exempt exactly the provider's outer endpoints (authorization, token, userinfo, revocation, introspection, end-session, device authorization, and the discovery and key-set documents) from the both-credentials guard, keeping its inner sign-in-dependent routes guarded (design 5, 12; spec browser-session "Provider endpoint"); verify the scenario, and that an inner provider route carrying the cookie and an `Authorization` header is still refused
- [x] 12.3 Test that logout and reuse detected through the cookie end the provider's browser sessions of the sign-in, on a chain running the provider (design 12; spec browser-session "Ending a cookie sign-in ends the provider's browser sessions of it"); verify both scenarios (characterization: shown to fail once with the end observer removed)
- [x] 12.4 Let the provider's resume endpoint on a cookie chain take the session the built-in cookie session published, recognised by a mark on the exchange, refusing a session another authenticator published and an `Authorization` line beside the cookie (design 12; spec browser-session "The OpenID Provider resumes a cookie sign-in"); verify both scenarios, that a header-bearer chain's resume is unchanged, and end to end that completion's owed-step fallback finishes through this resume
- [x] 12.5 Fold the C6 review: a guard case showing a provider endpoint the provider does not serve (device grant off) adds no exemption; a password-change case pinning the restored deadline on a recovery-pending persistent sign-in with that rotation off and a role switch inside the change; rename the manager-mismatch case to the cookie-plus-bearer refusal it pins; replace the race test's name check with a field; expire the cookie at logout only when the request carried it (design 5, 10, 11); verify each new case fails once with its branch removed
- [x] 12.6 Fold the C8 and C8b reviews: scope the cookie-session mark to the chain that set it (the resume accepts it only on that chain, and nothing clears it), so a header-bearer provider chain composed with a cookie chain, inside it or around it, refuses the cookie sign-in at its resume while a cookie chain composed with another chain, including another cookie chain on the same cookie, keeps its own resume (each chain keeps its own mark), and a chain that set no mark refuses even a session whose identifier is empty; refuse at construction the cookie session with the provider when CSRF protection is opted out, whatever the provider's browser-session setting; correct the resume and logout godoc; add a resume row presenting the superseded identifier inside its grace window (design 12; spec browser-session "Provider on a cookie chain without CSRF protection", "Provider chain run inside a cookie chain", "Cookie chain composed with another chain"); verify the scenarios red then green with one row per composition direction (the C8b review's two reproductions among them), and the grace-window row

- [x] 12.7 Refuse at construction a chain running the cookie session and the provider when a `WithCSRFExemption` route covers the resume endpoint, checked with the exemptions' own matcher (design 12; spec browser-session "The cookie resume stays under CSRF protection"); verify table rows: the exact path, a `*` segment, an escaped spelling, the path under `WithBasePath`, a renamed provider prefix (each refused), the same exemption on a header-bearer provider chain and an unrelated exemption on the cookie chain (each building); the resume check also judges the back-channel logout exemption, and a back-channel path placed over the resume is refused at `New`
- [ ] 12.8 Let `FromProvider(op)` trust a provider the chain does not run, still refusing one other than the chain's own, and apply every rule that named the chain's provider to the trusted provider: the size bound, the identifier and issuer checks, and the routing of its opaque and refresh tokens; refuse one resource server with two provider sources, and a token chain that cannot check the trusted provider's binding, by both of the provider's own-chain rules: built with DPoP without `EnableDPoP`, or a client requiring a binding the chain does not verify (design 14; spec resource-server "A provider source can trust a provider another chain serves", "Rules naming the chain's provider apply to a trusted provider", and the four modified requirements); verify their scenarios, including end to end one binary with the provider on a cookie chain and the resource server on a token chain under `/api`, and a revoked grant refused there on the next request

## 13. Framework adapters and documentation

- [ ] 13.1 Add a browser-session scenario set to the shared adapter conformance suite and run it on net/http, gin and fiber: sign-in sets the cookie, a refused cookie is expired, logout expires it (design failure modes); verify the suite on all three adapters
- [ ] 13.2 Write godoc for every new option naming the default it replaces and its line, and package documentation for the two-chain setup, including that on a cookie chain a request carrying the session cookie and any `Authorization` header is refused before a resource server reads it (only the provider's outer endpoints are exempt), so an API taking access tokens from a same-origin page belongs on the token chain; the one-binary setup with the provider on the cookie chain and `FromProvider(op)` on the token chain; mounting one API handler on both chains for first-party cookie callers and third-party token callers, with a scope check on the token mount; update the README's chain and resource-server sections to match; verify `go doc` output for each option and `go vet`

## 14. Final gate

- [ ] 14.1 Run the full suite once after the last code edit: `make check` and `make spec-check`; verify both pass, and record the output in the change's verification notes

## Workflow follow-up

- Run the whole-branch review against every requirement in this change's specs before archive.
- Archive the change, then retire `bff-resource-server` (needs its own confirmation) and propose `api-token-forwarding` with Q2, Q3 and Q5.
- Then propose the sign-in pages change (change 2 of the roadmap).
