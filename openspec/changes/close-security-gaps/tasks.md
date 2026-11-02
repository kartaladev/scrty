# Tasks

Every implementation task is test-first: write the failing test, run it and confirm it fails for the intended reason (a compile error is not a red step), make it pass with the smallest change, then refactor. "Verify" names the command whose output proves the task done. Run the module's full suite with `-race` at the end of each group.

## 1. Baseline check (before any code)

- [x] 1.1 Once `key-port-context` has merged, recheck D1 against its merged text: the bearer's outage and hang-up rules, `Prepare`/`Commit`, `RotateWithGraceIssuing`, `hangup.ByCaller` and the issuing mark read by `StatusForError`. Record any difference in `design.md` D1. Verify: `openspec validate close-security-gaps` reports no errors, and D1 names the merged commit.
- [x] 1.2 Settle the CSRF token style (synchronizer or signed double-submit), which must survive a sign-in's renewals and not a new sign-in. Verify: `design.md` Open Questions is empty, and the decision carries its sources.

## 2. Request host and scheme, and trusted proxies (D2, D7)

- [ ] 2.1 Add `Host()` and `Secure()` to `httpsec.Request` and the net/http request, test-first: a table test over a TLS and a plain request. Verify: `go test -run 'TestHTTPRequest_HostAndSecure' -count=1 ./httpsec/` passes after failing.
- [ ] 2.2 Implement `Host()` and `Secure()` in `ginsec` and `fibersec` from the transport, never from the frameworks' proxy helpers, test-first, including "gin's proxy settings do not make a request secure" and "fiber's proxy header does not change the host". Verify: `go test -run 'TestRequest_HostAndSecure' ./...` in both adapter modules passes after failing.
- [ ] 2.3 Add `WithHTTPSDeployment()` and its conflict with trusted proxies, test-first. Verify: `go test -run 'TestHTTPSDeployment' -count=1 ./httpsec/` passes after failing.
- [ ] 2.4 Add `EnableTrustedProxies` construction rules (empty or invalid prefixes, IPv4 and IPv6 catch-alls, no family or field, host without allowlist or with a URL as an allowed host, hop limit below one, enabled twice), test-first, one table. Verify: `go test -run 'TestTrustedProxies_Construction' -count=1 ./httpsec/`.
- [ ] 2.5 Implement right-to-left resolution of `X-Forwarded-For` and `Forwarded`, joining repeated headers, honouring `MaxHops`, comparing IPv4-mapped peers as IPv4, and parsing only the entries the walk reaches, test-first. Use the `trusted-proxies` scenarios as the table: forged left-most entry, bypassed proxy, two hops, hop limit reached, every entry trusted, repeated lines, IPv4-mapped peer, bracketed IPv6 with a port, `for=unknown`, garbage left of the client, garbage where the client should be, trusted peer with no header. Verify: `go test -run 'TestTrustedProxies_Resolve' -count=1 ./httpsec/`.
- [ ] 2.6 Take the scheme and host from the client's hop: `Forwarded` element, single-valued or aligned `X-Forwarded-Proto`/`-Host`, mismatched lengths ignored, only `http`/`https`, `X-Forwarded-Port` ignored, test-first. Verify: `go test -run 'TestTrustedProxies_SchemeHost' -count=1 ./httpsec/`.
- [ ] 2.7 Refuse a forwarded host outside the allowlist with `ErrHostNotAllowed`, matching case-insensitively without the port, never echoing the host, before any interceptor, test-first, including the look-alike and untrusted-peer scenarios. Verify: `go test -run 'TestTrustedProxies_HostNotAllowed' -count=1 ./httpsec/`.
- [ ] 2.8 Remove `Forwarded`, every `X-Forwarded-*` and the named certificate header from every request, trusted peer or not, unless `KeepForwardedHeaders()` is given, on all three adapters, test-first. Verify: `go test -run 'TestTrustedProxies_RemovesHeaders' ./...` in the core and both adapter modules.
- [ ] 2.9 Add `ClientFromContext`, return the resolved values from `ClientIP()`, `Host()` and `Secure()`, and make every interceptor (rate limiting included) read them, test-first, including "Rate limiting keys on the resolved client" and "Without trusted proxies". Verify: `go test -run 'TestClientFromContext|TestSourceGuard_UsesResolvedClient' -count=1 ./httpsec/`.
- [ ] 2.10 Remove `ginsec.WithForwardedClientIP` and route gin and fiber through the chain's resolver, with failing tests first for "gin's own trusted proxies do not change the chain" and "Same answer on every adapter". Verify: those tests pass in `test/httpsecconformance` on all three adapters.
- [ ] 2.11 Document `EnableTrustedProxies` (with `ForwardedHost`'s allowlist), `WithHTTPSDeployment` and `ClientFromContext` in godoc, each naming its default, and add the nginx and Traefik section to the README. Verify: `go doc ./httpsec EnableTrustedProxies` shows the defaults, and `go vet ./...` is clean.

## 3. Outer slots and security headers (D3, D4, D17)

- [ ] 3.1 Publish `OrderSecurityHeaders`, `OrderCORS` and `OrderCSRF`, test-first: a slot-order test asserting 25 < 50 < 75 < `OrderJWKS`. Verify: `go test -run 'TestOrder_OuterSlots' -count=1 ./httpsec/`.
- [ ] 3.2 Implement `EnableSecurityHeaders` with the document defaults, setting headers before `next`, test-first, including "A refusal carries the headers", "Host refusal carries the headers" and enabling twice. Verify: `go test -run 'TestSecurityHeaders_Defaults' -count=1 ./httpsec/`.
- [ ] 3.3 Add directive editing: add, replace a default directive without duplicating it, remove a header, and refuse a directive holding `;`, `,` or a line break, test-first. Verify: `go test -run 'TestSecurityHeaders_Directives' -count=1 ./httpsec/`.
- [ ] 3.4 Generate the per-response nonce and expose `CSPNonce`, failing the request on a randomness error, with no nonce on routes not served by the document profile, test-first. Verify: `go test -run 'TestSecurityHeaders_Nonce' -count=1 ./httpsec/`.
- [ ] 3.5 Add route profiles with the path-prefix (whole segments) and function matchers, first match wins, and the API profile, test-first. Verify: `go test -run 'TestSecurityHeaders_Profiles' -count=1 ./httpsec/`.
- [ ] 3.6 Send HSTS only when `Secure()`, including through a trusted proxy and not from an untrusted peer's forged scheme; allow `max-age=0`; refuse a negative age and `preload` below one year or without subdomains at construction, test-first. Verify: `go test -run 'TestSecurityHeaders_HSTS' -count=1 ./httpsec/`.
- [ ] 3.7 Prove the handler's own header wins and that `Flush` and `Hijack` still work, test-first, through `http.NewResponseController`. Verify: `go test -run 'TestSecurityHeaders_HandlerWins|TestSecurityHeaders_Streaming' -count=1 ./httpsec/`.
- [ ] 3.8 Add report-only mode (alone and beside the enforced policy, one nonce), the reporting endpoint (absolute `https` only) and the hash preset (well-formed hashes only, at least one), test-first. Verify: `go test -run 'TestSecurityHeaders_ReportOnly|TestSecurityHeaders_HashPreset' -count=1 ./httpsec/`.
- [ ] 3.9 Add `WithLogoutClearSiteData`, sent only on a secure, successful logout, and refused with no or an unknown directive, test-first. Verify: `go test -run 'TestLogout_ClearSiteData' -count=1 ./httpsec/`.
- [ ] 3.10 Run the security-headers scenarios on net/http, gin and fiber in `test/httpsecconformance`, test-first, including a refusal through each adapter's default error handling. Verify: `go test -run 'TestSecurityHeaders' ./...` in the `test` module.
- [ ] 3.11 Godoc every option with its default, and add a README section with the Vite, Next.js and template nonce examples. Verify: `go doc ./httpsec EnableSecurityHeaders` names each default.

## 4. CORS (D5)

- [ ] 4.1 Implement `EnableCORS` construction: normalisation of case and default port, and refusals of no origins, `null`, another scheme, a path, query, fragment or userinfo, `*` with credentials or beside other origins, implicit or malformed patterns, and enabling twice, test-first, one table. Verify: `go test -run 'TestCORS_Construction' -count=1 ./httpsec/`.
- [ ] 4.2 Implement exact origin matching, one-label patterns, `Vary: Origin` on every response, credentials and exposed headers, test-first, including the look-alike, other scheme or port, no-origin and `*` cases. Verify: `go test -run 'TestCORS_Origins' -count=1 ./httpsec/`.
- [ ] 4.3 Prove a refusal from an authentication interceptor carries the allow-origin and exposed headers for an allowed origin, test-first. Verify: `go test -run 'TestCORS_RefusalReadable' -count=1 ./httpsec/`.
- [ ] 4.4 Answer preflights with 204 in `OrderCORS` before authentication: default methods GET, HEAD and POST, header lists across lines and cases, disallowed method or header, the default and a replaced max age, the preflight `Vary` set, and a plain `OPTIONS` that continues through the chain, test-first. Verify: `go test -run 'TestCORS_Preflight' -count=1 ./httpsec/`.
- [ ] 4.5 Add the DPoP and CSRF header names automatically, with the explicit opt-out, test-first. Verify: `go test -run 'TestCORS_FollowsChain' -count=1 ./httpsec/`.
- [ ] 4.6 Run the CORS scenarios on all three adapters in conformance, test-first, and document the options with their defaults. Verify: `go test -run 'TestCORS' ./...` in the `test` module, and `go doc ./httpsec EnableCORS`.

## 5. CSRF protection (D6)

- [ ] 5.1 Implement the Fetch Metadata and Origin check on unsafe methods, test-first, using Go's `net/http.CrossOriginProtection` as the oracle in a table over `Sec-Fetch-Site` and `Origin` combinations, plus login CSRF, `Origin: null`, a port mismatch, lower-case and unknown methods, and a trusted-proxy request. Verify: `go test -run 'TestCSRF_FetchMetadata' -count=1 ./httpsec/`.
- [ ] 5.2 Trust CORS-listed and pattern-matched origins by default, never `*`, with the added-origins and opt-out options, test-first, including the unlisted same-site sibling. Verify: `go test -run 'TestCSRF_TrustedOrigins' -count=1 ./httpsec/`.
- [ ] 5.3 Implement the token layer as D6 settles it (a token stored on the sign-in by default, behind the replaceable `CSRFTokens` port with `WithCSRFTokens`, read through `CSRFToken(ctx)`), test-first: missing, malformed, another sign-in's token, constant-time comparison, a token surviving renewal, a token refused after a new sign-in, a sign-in holding no token, a bearer-only request, and a consumer's token source replacing the default. Verify: `go test -run 'TestCSRF_Token' -count=1 ./httpsec/`.
- [ ] 5.4 Refuse construction with cookie authentication and no CSRF protection unless `WithoutCSRFProtection()` is given, test-first. Verify: `go test -run 'TestCSRF_RequiredWithCookies' -count=1 ./httpsec/`.
- [ ] 5.5 Add exact method-and-path exemptions and the default, removable back-channel logout exemption, test-first, including the neighbouring paths (trailing slash, case, dot segments), another method on an exempt path, and refusing an exemption without a method or of `/`. Verify: `go test -run 'TestCSRF_Exemptions' -count=1 ./httpsec/`.
- [ ] 5.6 Register `ErrCrossSiteRequest` at 403, and run the CSRF scenarios, including the re-proof and session-management endpoints, on all three adapters, test-first. Verify: `go test -run 'TestStatusForError' ./httpsec/` and `go test -run 'TestCSRF' ./...` in the `test` module.
- [ ] 5.7 Godoc the options with their defaults, and document the token accessor and the exemption rules in the README. Verify: `go doc ./httpsec EnableCSRFProtection` names each default.

## 6. Sessions: listing, metadata and binding (D12)

- [ ] 6.1 Add `ListByUser` to `session.Store` and the in-memory store, one entry per live family, judged by the caller's time, exact user match, never another user's, test-first. Verify: `go test -run 'TestMemoryStore_ListByUser' -count=1 ./session/`.
- [ ] 6.2 Add the manager's listing: one entry per sign-in, the successor's last use within the grace window, pending sign-ins marked, no identifier or digest, a store failure as a dependency failure and a hang-up as the context's error, test-first. Verify: `go test -run 'TestSessions_List' -count=1 ./session/`.
- [ ] 6.3 Add opt-in sign-in metadata (`WithSessionMetadata`) carried through the family, off by default, the user agent truncated to 512 bytes at a UTF-8 boundary and an unattributable address recorded as absent, test-first. Verify: `go test -run 'TestSessions_Metadata' -count=1 ./session/`.
- [ ] 6.4 Add the key binding on the built session, carried through rotation, renewal and re-authentication, already set on the successor handed to the issuing step, refused by `Commit` when changed after `Prepare`, untouched by `Save`, and settable only on an unbound session by re-authentication, test-first. Add the CSRF token the same way: made only when the create option asks, at least 32 random bytes, carried to every successor, untouched by `Save`, refused by `Commit` when changed, and different for a new sign-in. Verify: `go test -run 'TestSessions_KeyBinding|TestSessions_CSRFToken' -count=1 ./session/`.
- [ ] 6.5 Add owner-checked end-by-handle (malformed, unknown and foreign handles not found; the current handle as a logout) and end-all-but-current over `DeleteByUserExcept`, test-first, including the racing renewal. Verify: `go test -run 'TestSessions_EndSignIn' -count=1 ./session/`.
- [ ] 6.6 Write the security-state migration (nullable columns only, the sealed CSRF token among them, no index) with a populated-database and rollback test, test-first. Verify: `go test -run 'TestMigrations' ./...` in the `test` module, against PostgreSQL 15 and 18 through testcontainers.
- [ ] 6.7 Implement listing, metadata, binding and the CSRF token in the sealing decorator, `sqlstore`, `pgxstore` and `gormstore`, driven by new failing cases in the shared session suite (listing, exact match, save keeps binding, metadata and token, supersession inserts them) and the sealing tests (token sealed and bound to its session, resealed for a successor, a copied token unreadable). Verify: `go test ./...` in the `test` module runs the suite against every store and passes.

## 7. Session management endpoints and notices (D12, D14)

- [ ] 7.1 Implement `EnableSessionManagement` (list, end one, end others) behind `reauthentication`'s recency guard for ending only, test-first, covering "Sign out other devices", "Only the current sign-in", "Stale session", "Listing needs no recent authentication", "Another user's handle", "Ending the current sign-in", "Current during the grace window", pending sessions refused, `Cache-Control: no-store`, and construction without a session manager. Verify: `go test -run 'TestSessionManagement' -count=1 ./httpsec/`.
- [ ] 7.2 Register `ErrSessionHandleNotFound` at 404, and answer a listing store outage as 500 with fixed text, test-first. Verify: `go test -run 'TestStatusForError|TestSessionManagement_Outage' -count=1 ./httpsec/`.
- [ ] 7.3 Add the passkey removal notice, on by default, with `WithoutPasskeyRemovalNotification`, no notice on a refused removal, and a send failure that keeps the removal, test-first. Verify: `go test -run 'TestPasskey_RemovalNotice' ./...` in the core module.
- [ ] 7.4 Add the opt-in unseen-device notice: matching live sign-ins by user agent through a replaceable matcher, the optional seen-devices port, no notice on a first sign-in or an unstored one, a send failure that does not affect the sign-in, and its construction rules, test-first. Verify: `go test -run 'TestSignInNotice' -count=1 ./httpsec/`.
- [ ] 7.5 Run session management on all three adapters in conformance, and document the endpoints and notices with their defaults. Verify: `go test -run 'TestSessionManagement' ./...` in the `test` module.

## 8. Token confirmation claim and DPoP (D8)

- [ ] 8.1 Add the `cnf` claim to issuance and verification, test-first: `jkt`, `x5t#S256`, none, both (refused at issue), a malformed thumbprint, and a malformed claim at verification. Verify: `go test -run 'TestGenerator_Confirmation|TestVerifier_Confirmation' -count=1 ./token/...`.
- [ ] 8.2 Add `EnableDPoP` with its construction rules (no bearer mode, enabled twice) and its defaults, test-first, including "Not enabled" passing the `DPoP` scheme through. Verify: `go test -run 'TestDPoP_Construction' -count=1 ./httpsec/`.
- [ ] 8.3 Implement proof verification in the order D8 gives, as a table of valid and broken proofs signed with jwx v4, test-first: size bound, two headers, `typ`, `none` and `HS256`, a private `jwk`, a key type that does not fit, signature, `htm`, `htu` with case, default port and query, a future and a stale `iat`, `ath` present, absent and for another token. Verify: `go test -run 'TestDPoP_Proof' -count=1 ./httpsec/`.
- [ ] 8.4 Add the replay port (atomic insert-if-absent, keyed by `jti` and thumbprint, `jti` at most 256 bytes) with the in-memory default, recording only after every other check, a store failure as a dependency failure and a hang-up as the context's error, test-first, including the concurrent replay. Verify: `go test -run 'TestDPoP_Replay' -count=1 -race ./httpsec/`.
- [ ] 8.5 Accept the `DPoP` scheme in the signed-bearer and session-reference interceptors, refuse bound tokens as `Bearer`, refuse a proof from another key, refuse a `cnf` the chain cannot honour, and add `Require`, test-first. Verify: `go test -run 'TestDPoP_Bearer' -count=1 ./httpsec/`.
- [ ] 8.6 Verify the proof in each issuing endpoint's checks, before anything is spent, and bind the built session, test-first, one row per endpoint (login, MFA verify, passkey, magic link, OIDC handoff, recovery, re-authentication, renewal): bound, unbound, bad proof leaves the link, code, attempts or proofs unspent, bad proof records no lockout failure, required DPoP refuses before any account lookup. Verify: `go test -run 'TestDPoP_Binding|TestDPoP_ProofBeforeSpend' -count=1 ./httpsec/`.
- [ ] 8.7 Keep the binding through rotation: renewal never binds or rebinds, re-authentication binds an unbound session and keeps a bound one, renewal or re-authentication with another key is refused, an ended family is refused, test-first. Verify: `go test -run 'TestDPoP_Rotation' -count=1 ./httpsec/`.
- [ ] 8.8 Tell the responder the token type (`DPoP` or `Bearer`) for every issuing endpoint, test-first. Verify: `go test -run 'TestDPoP_TokenType' -count=1 ./httpsec/`.
- [ ] 8.9 Build `htu` from the resolved scheme and host, or the config's `PublicURL`, test-first, including the trusted-proxy scenario. Verify: `go test -run 'TestDPoP_PublicURL' -count=1 ./httpsec/`.
- [ ] 8.10 Add opt-in stateless server nonces (missing and expired nonce, a nonce verified on another replica's chain with the same key material) and the `WWW-Authenticate: DPoP` responses, including both challenges for a missing token, and register the DPoP refusals at 401, test-first. Verify: `go test -run 'TestDPoP_Nonce|TestDPoP_Challenge|TestStatusForError' -count=1 ./httpsec/`.
- [ ] 8.11 Run DPoP end to end on all three adapters in conformance, and check the doc's browser `dpop.ts` against a test server in a headless-browser test or a recorded proof vector. Verify: `go test -run 'TestDPoP' ./...` in the `test` module.
- [ ] 8.12 Godoc `EnableDPoP` and its defaults, and add the README section with the React, Next.js and htmx samples. Verify: `go doc ./httpsec EnableDPoP`.

## 9. mTLS-bound tokens (D9)

- [ ] 9.1 Bind tokens to a direct TLS client certificate with `EnableCertificateBinding`, test-first, over an `httptest` TLS server with client certificates: same certificate, none, another one. Verify: `go test -run 'TestCertificateBinding_Direct' -count=1 ./httpsec/`.
- [ ] 9.2 Read a forwarded client certificate only from a trusted peer, URL-encoded PEM by default or through the consumer's decoder, with an undecodable value meaning no certificate, test-first. Verify: `go test -run 'TestCertificateBinding_Forwarded' -count=1 ./httpsec/`.
- [ ] 9.3 Bind DPoP only when both a proof and a certificate are offered, refuse a certificate-bound token after the feature is turned off, register the refusal at 401, and run the scenarios on all three adapters, test-first. Verify: `go test -run 'TestCertificateBinding' ./...` in the core and `test` modules.
- [ ] 9.4 Document certificate binding with its default, the decoder, that chain and validity checks belong to TLS or the proxy, and proxy examples verified against each proxy's documentation. Verify: `go doc ./httpsec EnableCertificateBinding`.

## 10. Password policy and rehash (D10, D11)

- [ ] 10.1 Implement `password.NewPolicy` with the length (15 to 128) and common-password defaults, the replace-only-what-you-name options, cheapest-first ordering that skips later rules after a refusal, test-first. Verify: `go test -run 'TestPolicy_Defaults|TestPolicy_Options' -count=1 ./authenticate/password/`.
- [ ] 10.2 Add length in code points (no trim, no normalisation, empty refused), the maximum floor of 64, and bcrypt's 72-byte limit in the check, test-first. Verify: `go test -run 'TestPolicy_Length' -count=1 ./authenticate/password/`.
- [ ] 10.3 Add context words (equality, containment for words of 4 or more characters, a failing word function as a dependency failure), test-first. Verify: `go test -run 'TestPolicy_ContextWords' -count=1 ./authenticate/password/`.
- [ ] 10.4 Add the opt-in breach check over the confined outbound client, with padding (count-zero entries ignored), a required failure mode (timeout, non-success status, malformed body), a hang-up as the context's error, and a replaceable source, test-first against an `httptest` range API that asserts only the prefix leaves. Verify: `go test -run 'TestPolicy_Breached' -count=1 ./authenticate/password/`.
- [ ] 10.5 Move every reuse-guard test to the `NoReuse` rule first (they must fail to compile only for the renamed API, then fail on behaviour once ported), then move the implementation and remove `NewReuseGuard`. Verify: `go test -run 'TestPolicy_NoReuse|TestPolicy_Change' -count=1 ./authenticate/password/` and `go test ./...` in the `test` module (history conformance).
- [ ] 10.6 Add the construction refusals (maximum below 64 or the minimum, an empty replacement list) and prove no refusal's text or log carries the candidate, a hash or a context word, test-first. Verify: `go test -run 'TestPolicy_Construction|TestPolicy_NoSecrets' -count=1 ./authenticate/password/`.
- [ ] 10.7 Register `ErrPasswordRejected` at 422, with `password.ErrReused` also matching it, and the lookup-unavailable error at 500, test-first. Verify: `go test -run 'TestStatusForError' -count=1 ./httpsec/`.
- [ ] 10.8 Add `password.Upgrader` to the three built-in encoders, test-first: weaker, current, stronger, another algorithm, unparseable. Verify: `go test -run 'TestEncoder_NeedsUpgrade' -count=1 ./authenticate/password/`.
- [ ] 10.9 Add `WithLoginRehash` to form login, Basic and the password re-proof, handing the write the replaced and the new hash, test-first, including "No write configured", "Wrong password", "Write fails", "Challenged for a second factor", and a ready-made conditional provisioner write that leaves a concurrent change in place. Verify: `go test -run 'TestLogin_Rehash' -count=1 ./httpsec/`.
- [ ] 10.10 Document the policy, the breach check's failure-mode choice and rehash, each with its default, and update the README's password section. Verify: `go doc ./authenticate/password NewPolicy`.

## 11. Security events (D13)

- [ ] 11.1 Add the `security.Event` type, the sink option and the documented `scrty_` names, test-first: no sink means no events, a sink receives `authn_login_fail`, a panicking sink is recovered, and the sink's context is not cancelled when the request's is. Verify: `go test -run 'TestSecurityEvents_Sink' -count=1 ./...` in the core module.
- [ ] 11.2 Emit events from login, lockout, MFA, passkey, recovery, re-authentication, renewal, logout, session management, CSRF, host, DPoP, certificate-binding, challenge and rate-limit refusals, test-first, one table row per event, asserting the resolved client address and that no secret appears. Verify: `go test -run 'TestSecurityEvents_Emitted' -count=1 ./httpsec/`.
- [ ] 11.3 Emit creation events only for stored sessions and handed-out credentials, and no refusal event for a hang-up or a dependency failure, test-first: lost redemption race, failed commit, store outage at verification. Verify: `go test -run 'TestSecurityEvents_OnlyWhatHappened' -count=1 ./httpsec/`.
- [ ] 11.4 Deliver the lockout and reuse observer reports as events while the observers keep working, test-first. Verify: `go test -run 'TestSecurityEvents_Observers' -count=1 ./...` in the core module.
- [ ] 11.5 Document the event list and the sink's contract, including that a blocking sink is the consumer's responsibility. Verify: `go doc` of the events package lists every name.

## 12. Automation challenge (D15)

- [ ] 12.1 Add the verifier port and its construction rules, and wire it after the source limit and before login, Basic, magic-link request, passwordless begin and recovery start, test-first, asserting that no account is looked up on a refusal. Verify: `go test -run 'TestChallenge_Flows|TestChallenge_Construction' -count=1 ./httpsec/`.
- [ ] 12.2 Answer a verifier error as a dependency failure (500, not charged) and a hang-up as the context's error, test-first. Verify: `go test -run 'TestChallenge_Outage' -count=1 ./httpsec/`.
- [ ] 12.3 Pass source and identifier signals to the verifier (a failing limiter reported as recent failures), count refusals against the source limit but not the lockout, with the opt-out, and register `ErrChallengeRequired` at 403, test-first. Verify: `go test -run 'TestChallenge_Signals|TestChallenge_CountsAgainstSource|TestStatusForError' -count=1 ./httpsec/`.
- [ ] 12.4 Run the challenge scenarios on all three adapters, and document the port with its defaults. Verify: `go test -run 'TestChallenge' ./...` in the `test` module.

## 13. Supply chain (D16)

- [x] 13.1 Pin every workflow action and reusable workflow to a full commit SHA with its tag in a comment, container actions by digest, and add the CI pinning check that exempts local actions, proving the check fails on a tag and on a short SHA first. Verify: the check fails on a branch with `actions/checkout@v5`, and passes on the pinned workflows.
- [x] 13.2 Add the Dependabot configuration for `gomod` in every published module, nested ones included, and for `github-actions`. Verify: GitHub's Dependabot configuration check accepts the file, and it lists every directory with a published `go.mod`.
- [x] 13.3 Add the SBOM generator as a `tool` directive in the `tools` module, and an SBOM step per published module in the release gate that fails when generation fails. Verify: `make release-gate` (or its equivalent target) produces one SBOM per published module.
- [x] 13.4 Make `govulncheck` block the release gate, proving the gate fails on a module pinned to a known-vulnerable dependency in a disposable branch. Verify: the gate fails there and passes on `main`.

## 14. Integration

- [ ] 14.1 Run every module's full suite with the race detector, and the whole conformance suite on net/http, gin and fiber. Verify: `make check` (or the per-module `go test -race ./...`) passes in every module.
- [ ] 14.2 Run `govulncheck`, `gofmt -l` and `go vet` on every module. Verify: all three are clean.
- [ ] 14.3 Review the whole branch against every requirement in this change's specs, with a reviewer that did not write the code. Verify: the review lists each requirement as met, or files a finding.

## Workflow follow-up

- Update `CHANGELOG.md`'s first entry through `release-readiness` with this change's breaking items and security additions.
- Archive `close-security-gaps` after `release-readiness` is updated, then archive or close `trusted-proxy-client-ip` as superseded.
