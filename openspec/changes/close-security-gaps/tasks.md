# Tasks

Every implementation task is test-first: write the failing test, run it and confirm it fails for the intended reason (a compile error is not a red step), make it pass with the smallest change, then refactor. "Verify" names the command whose output proves the task done. Run the module's full suite with `-race` at the end of each group.

## 1. Draft review (before any code)

- [ ] 1.1 Re-read the specs and code `reauthentication` landed, and reconcile this change's artifacts with them: D1's points (error table, recency check, re-proof rotation, guards). Verify: every spec delta validates with `openspec validate close-security-gaps --strict`, and `design.md` D1 records what changed.
- [ ] 1.2 Re-read what `key-port-context` landed for bearer authentication and token issuance, and reconcile D8 and the `token-issuance` delta. Verify: `openspec validate close-security-gaps --strict` passes and the design names the landed key-port signatures.
- [ ] 1.3 Settle the open questions that block a group: the CSRF token style (group 5), and the forwarded client-certificate header per proxy (group 10, from each proxy's documentation). Verify: `design.md` Open Questions lists neither, and the decisions carry their sources.

## 2. Request host and scheme, and trusted proxies (D2, D7)

- [ ] 2.1 Add `Host()` and `Secure()` to `httpsec.Request` and the net/http request, test-first: a table test over a TLS and a plain request. Verify: `go test -run 'TestHTTPRequest_HostAndSecure' -count=1 ./httpsec/` passes after failing.
- [ ] 2.2 Implement `Host()` and `Secure()` in `ginsec` and `fibersec` from the transport, never from the frameworks' proxy helpers, test-first. Verify: `go test -run 'TestRequest_HostAndSecure' ./...` in both adapter modules passes after failing.
- [ ] 2.3 Add `WithHTTPSDeployment()` and its conflict with trusted proxies, test-first. Verify: `go test -run 'TestHTTPSDeployment' -count=1 ./httpsec/` passes after failing.
- [ ] 2.4 Add `EnableTrustedProxies` construction rules (empty list, catch-all prefixes, no family or field, host without allowlist, hop limit below one), test-first, one table. Verify: `go test -run 'TestTrustedProxies_Construction' -count=1 ./httpsec/`.
- [ ] 2.5 Implement right-to-left resolution of `X-Forwarded-*` and `Forwarded`, joining repeated headers, honouring `MaxHops` and the named fields, test-first. Use the scenarios of `trusted-proxies` as the table, including a forged left-most entry and a bypassed proxy. Verify: `go test -run 'TestTrustedProxies_Resolve' -count=1 ./httpsec/`.
- [ ] 2.6 Refuse a forwarded host outside the allowlist with `ErrHostNotAllowed`, and register it in the status table at 400, test-first. Verify: `go test -run 'TestTrustedProxies_HostNotAllowed|TestStatusForError' -count=1 ./httpsec/`.
- [ ] 2.7 Remove both header families after resolution unless `KeepForwardedHeaders()` is given, on all three adapters, test-first. Verify: `go test -run 'TestTrustedProxies_RemovesHeaders' ./...` in the core and both adapter modules.
- [ ] 2.8 Add `ClientFromContext` and make every interceptor (rate limiting included) read the resolved values, test-first. Verify: `go test -run 'TestClientFromContext|TestSourceGuard_UsesResolvedClient' -count=1 ./httpsec/`.
- [ ] 2.9 Remove `ginsec.WithForwardedClientIP` and route gin and fiber through the chain's resolver, with failing tests first for "gin's own trusted proxies do not change the chain" and "Same answer on every adapter". Verify: those tests pass in `test/httpsecconformance` on all three adapters.
- [ ] 2.10 Document `EnableTrustedProxies` (with `ForwardedHost`'s allowlist), `WithHTTPSDeployment` and `ClientFromContext` in godoc, each naming its default, and add the nginx and Traefik section to the README. Verify: `go doc ./httpsec EnableTrustedProxies` shows the defaults, and `go vet ./...` is clean.

## 3. Outer slots and security headers (D3, D4, D17)

- [ ] 3.1 Publish `OrderSecurityHeaders`, `OrderCORS` and `OrderCSRF`, test-first: a slot-order test asserting 25 < 50 < 75 < `OrderJWKS`. Verify: `go test -run 'TestOrder_OuterSlots' -count=1 ./httpsec/`.
- [ ] 3.2 Implement `EnableSecurityHeaders` with the document defaults, setting headers before `next`, test-first, including "A refusal carries the headers". Verify: `go test -run 'TestSecurityHeaders_Defaults' -count=1 ./httpsec/`.
- [ ] 3.3 Generate the per-response nonce and expose `CSPNonce`, failing closed on a randomness error, test-first. Verify: `go test -run 'TestSecurityHeaders_Nonce' -count=1 ./httpsec/`.
- [ ] 3.4 Add route profiles with the path-prefix and function matchers, and the API profile, test-first. Verify: `go test -run 'TestSecurityHeaders_Profiles' -count=1 ./httpsec/`.
- [ ] 3.5 Send HSTS only when `Secure()`, and refuse `preload` below one year or without subdomains at construction, test-first. Verify: `go test -run 'TestSecurityHeaders_HSTS' -count=1 ./httpsec/`.
- [ ] 3.6 Prove the handler's own header wins and that `Flush` and `Hijack` still work, test-first, through `http.NewResponseController`. Verify: `go test -run 'TestSecurityHeaders_HandlerWins|TestSecurityHeaders_Streaming' -count=1 ./httpsec/`.
- [ ] 3.7 Add report-only mode, the reporting endpoint and the hash preset, test-first. Verify: `go test -run 'TestSecurityHeaders_ReportOnly|TestSecurityHeaders_HashPreset' -count=1 ./httpsec/`.
- [ ] 3.8 Add `WithLogoutClearSiteData`, sent only when secure, test-first. Verify: `go test -run 'TestLogout_ClearSiteData' -count=1 ./httpsec/`.
- [ ] 3.9 Run the security-headers scenarios on net/http, gin and fiber in `test/httpsecconformance`, test-first. Verify: `go test -run 'TestSecurityHeaders' ./...` in the `test` module.
- [ ] 3.10 Godoc every option with its default, and add a README section with the Vite, Next.js and template nonce examples. Verify: `go doc ./httpsec EnableSecurityHeaders` names each default.

## 4. CORS (D5)

- [ ] 4.1 Implement `EnableCORS` construction refusals (no origins, `null`, malformed origins, `*` with credentials, implicit patterns), test-first, one table. Verify: `go test -run 'TestCORS_Construction' -count=1 ./httpsec/`.
- [ ] 4.2 Implement exact origin matching, `Vary: Origin` and the actual-response headers, test-first, including the look-alike origin. Verify: `go test -run 'TestCORS_Origins' -count=1 ./httpsec/`.
- [ ] 4.3 Answer preflights with 204 in `OrderCORS` before authentication, with the default and a replaced max age, test-first. Verify: `go test -run 'TestCORS_Preflight' -count=1 ./httpsec/`.
- [ ] 4.4 Add the DPoP and CSRF header names automatically, with the explicit opt-out, test-first. Verify: `go test -run 'TestCORS_FollowsChain' -count=1 ./httpsec/`.
- [ ] 4.5 Run the CORS scenarios on all three adapters in conformance, test-first, and document the options with their defaults. Verify: `go test -run 'TestCORS' ./...` in the `test` module, and `go doc ./httpsec EnableCORS`.

## 5. CSRF protection (D6)

- [ ] 5.1 Implement the Fetch Metadata and Origin check on unsafe methods, test-first, using Go's `net/http.CrossOriginProtection` as the oracle in a table over `Sec-Fetch-Site` and `Origin` combinations. Verify: `go test -run 'TestCSRF_FetchMetadata' -count=1 ./httpsec/`.
- [ ] 5.2 Trust CORS-allowed origins by default, with the added-origins and opt-out options, test-first. Verify: `go test -run 'TestCSRF_TrustedOrigins' -count=1 ./httpsec/`.
- [ ] 5.3 Implement the session-bound token layer in the style settled in 1.3, test-first: missing, malformed, another session's token, and a bearer-only request. Verify: `go test -run 'TestCSRF_Token' -count=1 ./httpsec/`.
- [ ] 5.4 Refuse construction with cookie authentication and no CSRF protection unless `WithoutCSRFProtection()` is given, test-first. Verify: `go test -run 'TestCSRF_RequiredWithCookies' -count=1 ./httpsec/`.
- [ ] 5.5 Add method-and-path exemptions and the default back-channel logout exemption, test-first. Verify: `go test -run 'TestCSRF_Exemptions' -count=1 ./httpsec/`.
- [ ] 5.6 Register `ErrCrossSiteRequest` at 403, and run the CSRF scenarios, including the re-proof endpoint, on all three adapters, test-first. Verify: `go test -run 'TestStatusForError' ./httpsec/` and `go test -run 'TestCSRF' ./...` in the `test` module.
- [ ] 5.7 Godoc the options with their defaults, and document the token accessor and the exemption rules in the README. Verify: `go doc ./httpsec EnableCSRFProtection` names each default.

## 6. Sessions: listing, metadata and binding (D12)

- [ ] 6.1 Add `ListByUser` to `session.Store` and the in-memory store, one entry per live family, test-first. Verify: `go test -run 'TestMemoryStore_ListByUser' -count=1 ./session/`.
- [ ] 6.2 Add opt-in sign-in metadata (`WithSessionMetadata`) carried through the family, test-first, off by default. Verify: `go test -run 'TestSessions_Metadata' -count=1 ./session/`.
- [ ] 6.3 Add the key binding on the session, carried through rotation, renewal and re-authentication and untouched by `Save`, test-first. Verify: `go test -run 'TestSessions_KeyBinding' -count=1 ./session/`.
- [ ] 6.4 Add owner-checked end-by-handle and end-all-but-one on the manager, test-first. Verify: `go test -run 'TestSessions_EndSignIn' -count=1 ./session/`.
- [ ] 6.5 Write the security-state migration (nullable columns and listing index) with a populated-database and rollback test, test-first. Verify: `go test -run 'TestMigrations' ./...` in the `test` module, against PostgreSQL 15 and 18 through testcontainers.
- [ ] 6.6 Implement listing, metadata and binding in the sealing decorator, `sqlstore`, `pgxstore` and `gormstore`, driven by new failing cases in the shared session suite. Verify: `go test ./...` in the `test` module runs the suite against every store and passes.

## 7. Session management endpoints and notices (D12, D14)

- [ ] 7.1 Implement `EnableSessionManagement` (list, end one, end others) behind `reauthentication`'s recency check, test-first, covering "Sign out other devices", "Stale session" and "Another user's handle". Verify: `go test -run 'TestSessionManagement' -count=1 ./httpsec/`.
- [ ] 7.2 Register the session-handle-not-found refusal at 404, test-first. Verify: `go test -run 'TestStatusForError' -count=1 ./httpsec/`.
- [ ] 7.3 Add the passkey removal notice, on by default, with `WithoutPasskeyRemovalNotification`, test-first. Verify: `go test -run 'TestPasskey_RemovalNotice' ./...` in the core module.
- [ ] 7.4 Add the opt-in unseen-device sign-in notice and its construction rule, test-first. Verify: `go test -run 'TestSignInNotice' -count=1 ./httpsec/`.
- [ ] 7.5 Run session management on all three adapters in conformance, and document the endpoints and notices with their defaults. Verify: `go test -run 'TestSessionManagement' ./...` in the `test` module.

## 8. Token confirmation claim and DPoP (D8)

- [ ] 8.1 Add the `cnf` claim to issuance and verification, test-first: `jkt`, `x5t#S256`, none, and malformed. Verify: `go test -run 'TestGenerator_Confirmation|TestVerifier_Confirmation' -count=1 ./token/...`.
- [ ] 8.2 Implement DPoP proof verification (every check in the `sender-constrained-tokens` requirement) as a table of valid and broken proofs signed with jwx v4, test-first. Verify: `go test -run 'TestDPoP_Proof' -count=1 ./httpsec/`.
- [ ] 8.3 Add the replay port with the in-memory default, and the fail-closed store error, test-first. Verify: `go test -run 'TestDPoP_Replay' -count=1 -race ./httpsec/`.
- [ ] 8.4 Accept the `DPoP` scheme in the signed-bearer and session-reference interceptors, refuse bound tokens as `Bearer`, and add `Require`, test-first. Verify: `go test -run 'TestDPoP_Bearer' -count=1 ./httpsec/`.
- [ ] 8.5 Bind tokens at every issuing endpoint (login, MFA verify, passkey, magic link, OIDC handoff, recovery, re-authentication, renewal), test-first, one case per endpoint. Verify: `go test -run 'TestDPoP_Binding' -count=1 ./httpsec/`.
- [ ] 8.6 Build `htu` from the resolved scheme and host, or the DPoP config's `PublicURL`, test-first, including the trusted-proxy scenario. Verify: `go test -run 'TestDPoP_PublicURL' -count=1 ./httpsec/`.
- [ ] 8.7 Add opt-in server nonces (the DPoP config's `Nonce` field) and the `WWW-Authenticate: DPoP` responses, and register the DPoP refusals at 401, test-first. Verify: `go test -run 'TestDPoP_Nonce|TestDPoP_Challenge|TestStatusForError' -count=1 ./httpsec/`.
- [ ] 8.8 Run DPoP end to end on all three adapters in conformance, and check the doc's browser `dpop.ts` against a test server in a headless-browser test or a recorded proof vector. Verify: `go test -run 'TestDPoP' ./...` in the `test` module.
- [ ] 8.9 Godoc `WithDPoP` and its defaults, and add the README section with the React, Next.js and htmx samples. Verify: `go doc ./httpsec WithDPoP`.

## 9. mTLS-bound tokens (D9)

- [ ] 9.1 Bind tokens to a direct TLS client certificate with `EnableCertificateBinding`, test-first, over an `httptest` TLS server with client certificates. Verify: `go test -run 'TestCertificateBinding_Direct' -count=1 ./httpsec/`.
- [ ] 9.2 Read a forwarded client certificate only from a trusted peer, in the header and encoding settled in 1.3, test-first. Verify: `go test -run 'TestCertificateBinding_Forwarded' -count=1 ./httpsec/`.
- [ ] 9.3 Refuse a bound token without its certificate, register the refusal at 401, and run the scenarios on all three adapters, test-first. Verify: `go test -run 'TestCertificateBinding' ./...` in the core and `test` modules.
- [ ] 9.4 Document certificate binding with its default and the proxy configuration it needs. Verify: `go doc ./httpsec EnableCertificateBinding`.

## 10. Password policy and rehash (D10, D11)

- [ ] 10.1 Implement `password.NewPolicy` with the length and common-password defaults and the replace-only-what-you-name options, test-first. Verify: `go test -run 'TestPolicy_Defaults|TestPolicy_Options' -count=1 ./authenticate/password/`.
- [ ] 10.2 Add context words, length in code points, and the 64-character floor, test-first. Verify: `go test -run 'TestPolicy_Length|TestPolicy_ContextWords' -count=1 ./authenticate/password/`.
- [ ] 10.3 Add the opt-in breach check over the confined outbound client, with padding, a required failure mode and a replaceable source, test-first against an `httptest` range API. Verify: `go test -run 'TestPolicy_Breached' -count=1 ./authenticate/password/`.
- [ ] 10.4 Move every reuse-guard test to the `NoReuse` rule first (they must fail to compile only for the renamed API, then fail on behaviour once ported), then move the implementation and remove `NewReuseGuard`. Verify: `go test -run 'TestPolicy_NoReuse|TestPolicy_Change' -count=1 ./authenticate/password/` and `go test ./...` in the `test` module (history conformance).
- [ ] 10.5 Register `ErrPasswordRejected` at 422, with `ErrPasswordReused` also matching it, test-first. Verify: `go test -run 'TestStatusForError' -count=1 ./httpsec/`.
- [ ] 10.6 Add `password.Upgrader` to the three built-in encoders, test-first. Verify: `go test -run 'TestEncoder_NeedsUpgrade' -count=1 ./authenticate/password/`.
- [ ] 10.7 Add `WithLoginRehash` to form and Basic login, test-first, including "No write configured" and a failing write that does not fail the login. Verify: `go test -run 'TestLogin_Rehash' -count=1 ./httpsec/`.
- [ ] 10.8 Document the policy, the breach check's failure-mode choice and rehash, each with its default, and update the README's password section. Verify: `go doc ./authenticate/password NewPolicy`.

## 11. Security events (D13)

- [ ] 11.1 Add the `security.Event` type, the sink option and the documented `scrty_` names, test-first: no sink means no events, and a sink receives `authn_login_fail`. Verify: `go test -run 'TestSecurityEvents_Sink' -count=1 ./...` in the core module.
- [ ] 11.2 Emit events from login, lockout, MFA, passkey, recovery, re-authentication, renewal, logout, CSRF, DPoP, challenge and rate-limit refusals, test-first, one table row per event, asserting that no secret appears. Verify: `go test -run 'TestSecurityEvents_Emitted' -count=1 ./httpsec/`.
- [ ] 11.3 Deliver the lockout and reuse observer reports as events while the observers keep working, test-first. Verify: `go test -run 'TestSecurityEvents_Observers' -count=1 ./...` in the core module.
- [ ] 11.4 Document the event list and the sink's contract. Verify: `go doc` of the events package lists every name.

## 12. Automation challenge (D15)

- [ ] 12.1 Add the verifier port and wire it before login, Basic, magic-link request, passwordless begin and recovery start, test-first, asserting that no account is looked up on a refusal. Verify: `go test -run 'TestChallenge_Flows' -count=1 ./httpsec/`.
- [ ] 12.2 Pass limiter signals to the verifier, count refusals against the source limit, and register `ErrChallengeRequired` at 403, test-first. Verify: `go test -run 'TestChallenge_Signals|TestChallenge_CountsAgainstSource|TestStatusForError' -count=1 ./httpsec/`.
- [ ] 12.3 Run the challenge scenarios on all three adapters, and document the port with its defaults. Verify: `go test -run 'TestChallenge' ./...` in the `test` module.

## 13. Supply chain (D16)

- [ ] 13.1 Pin every workflow action to a commit SHA with its tag in a comment, and add the CI pinning check, proving the check fails on a tag reference first. Verify: the check fails on a branch with `actions/checkout@v5`, and passes on the pinned workflows.
- [ ] 13.2 Add the Dependabot configuration for `gomod` in every published module and for `github-actions`. Verify: GitHub's Dependabot configuration check accepts the file.
- [ ] 13.3 Add the SBOM generator as a `tool` directive in the `tools` module, and an SBOM step per published module in the release gate that fails when generation fails. Verify: `make release-gate` (or its equivalent target) produces one SBOM per published module.
- [ ] 13.4 Make `govulncheck` block the release gate, proving the gate fails on a module pinned to a known-vulnerable dependency in a disposable branch. Verify: the gate fails there and passes on `main`.

## 14. Integration

- [ ] 14.1 Run every module's full suite with the race detector, and the whole conformance suite on net/http, gin and fiber. Verify: `make check` (or the per-module `go test -race ./...`) passes in every module.
- [ ] 14.2 Run `govulncheck`, `gofmt -l` and `go vet` on every module. Verify: all three are clean.
- [ ] 14.3 Review the whole branch against every requirement in this change's specs, with a reviewer that did not write the code. Verify: the review lists each requirement as met, or files a finding.

## Workflow follow-up

- Update `CHANGELOG.md`'s first entry through `release-readiness` with this change's breaking items and security additions.
- Archive `close-security-gaps` after `release-readiness` is updated, then archive or close `trusted-proxy-client-ip` as superseded.
