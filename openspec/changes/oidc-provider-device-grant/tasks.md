# Tasks

Every task is test-first: write the failing test, run it with `go test -run '<Name>' -count=1 <pkg>` and confirm it fails for the intended reason (a compile error is not a red step), then implement, then refactor. Each task is complete when its named tests pass and `go vet` and `gofmt -l` are clean for the packages it touched.

## 0. Gate

- [ ] 0.1 Confirm `harden-chain-boundary` and `split-ci-jobs` are archived (`openspec list --json` shows neither) before any code task starts.

## 1. Client registration and the provider option (D1, D8, D9)

- [x] 1.1 Add `GrantDeviceCode` and `WithDeviceAuthorization(entryURL, ...DeviceOption)`. Verify with table tests that the grant is off by default, and that an entry URL on another origin, with a fragment, or relative fails construction naming the option.
- [x] 1.2 Validate `GrantDeviceCode` in `validateGrantTypes`. Verify that a configured client with the grant on a provider without the option fails construction, that a registry client in that state is unknown and logged with the setting, and that a device-only client needs no redirect URI.
- [x] 1.3 Add `Client.DeviceCompleteURI`. Verify it is off by default, and that it fails construction without the device grant (registry client: unknown).
- [x] 1.4 Add `Client.DeviceGrantsOutliveSignIn`. Verify it fails construction alongside `EndGrantsWithSignIn`, on a public web client under its default without `KeepPublicWebGrantsPastSignIn`, and on a client without the grant, each naming both settings. Verify it is accepted on a public native client.

## 2. Codes (D4, D5)

- [x] 2.1 Device-code minting: 32 bytes from the provider's random source, stored as a digest. Verify the length and digest-only storage, and that a failing random source fails the request with nothing stored.
- [x] 2.2 User-code generator with the default base-20, 8-character, dashed format, using rejection sampling. Verify the format regex, and verify uniformity with a deterministic random source covering the rejection branch.
- [x] 2.3 `WithUserCodeFormat`. Verify that a 9-digit format is accepted and shown in groups of three, and that a 6-digit format, a repeated character and a non-printable character each fail construction naming the option.
- [x] 2.4 Keyed user-code digest and `WithUserCodeKey`. Verify a random key by default, a refusal for keys under 32 bytes, a refusal for a durable store without a key (test with a stub durable marker), and that two providers sharing a key compute the same digest.
- [x] 2.5 Normalisation. Verify with table tests: lower case, spaces and dashes are accepted; a character outside the alphabet and a wrong length are refused without a lookup; a lower-case alphabet is not upper-cased.

## 3. Device authorization store (D3)

- [x] 3.1 Define `DeviceAuthorization`, the `DeviceAuthorizationStore` port and its godoc contract: digests only, no store clock, no digest in errors. Generate its mock per the `use-mockgen` skill. Verify `go vet` and the mock compiling in a test that uses it.
- [x] 3.2 Write the exported conformance suite in `test/storetest`: create, lookups (including an expired record with the same user-code digest not blocking a new one), and every transition's compare-and-set refusing from a wrong state. Run it against an empty stub to see it fail.
- [x] 3.3 Add the race cases to the suite: one winner for a claim, decide (approve against deny), record-poll and spend. Add a case that fails a store judging expiry by its own clock, naming the case.
- [x] 3.4 Implement `MemoryDeviceAuthorizationStore` until 3.2 and 3.3 pass with `-race`, and wire it as the default behind `WithDeviceAuthorizationStore`. Verify a consumer store replaces it.
- [x] 3.5 Implement `DeleteExpired`, keeping spent records until one minute past expiry. Verify with the suite's sweep cases.

## 4. Device authorization request (spec: device authorization endpoint)

- [x] 4.1 `Provider.AuthorizeDevice(ctx, credentials, form)`: client authentication as at the token endpoint, and a public client by `client_id`. Verify `invalid_client` for a wrong secret with nothing stored, `invalid_request` for a credential in the query, and `unauthorized_client` for a client without the grant.
- [x] 4.2 Parameter rules: repeated and empty parameters, NUL or invalid UTF-8, bounds, and scope and resource checks reused from the authorization endpoint. Verify each refusal with nothing stored and no value echoed.
- [x] 4.3 The response body: `device_code`, `user_code`, `verification_uri`, `expires_in`, `interval`, and `verification_uri_complete` only when the client opts in, with lifetime and interval options bounded. Verify the defaults (600 and 5), a 15-minute override, and that out-of-bound values fail construction.
- [x] 4.4 User-code collisions. Verify with a scripted random source that a first collision regenerates, and that 5 collisions fail as a server error with nothing stored.

## 5. User-code entry (D2, D5, D6)

- [x] 5.1 `Provider.EnterUserCode` with a `ratelimit.SourceGuard`, by default 5 failures per source in 10 minutes. Verify that the sixth entry is refused as throttled before any lookup (assert on a store mock that no call was made), that a limiter error fails closed, and that `WithUserCodeEntryLimiter` replaces the default.
- [x] 5.2 The single refusal. Verify with a table test that unknown, expired, claimed by another browser, approved, denied and spent codes all return `ErrInvalidUserCode`, charge the throttle, and leave the record unchanged.
- [x] 5.3 Claim and park. Verify that a valid code is claimed by one write and a pending request is parked bound to the flow secret (minted when absent). Verify a 303 to login with the handle, or to consent when a browser session answers. Verify that the claiming browser's re-entry goes to the stage reached.
- [x] 5.4 The pending view's `Device` part: user code as entered and normalised, request time, client. Verify that the view holds no device code, handle or flow secret.
- [x] 5.5 A redaction test for the new input and result types. Verify that `fmt` and `slog` output holds no code, secret or digest.
- [x] 5.6 Claim succeeds but parking fails (pending store mock). Verify the entry fails as a dependency error, the claiming browser's re-entry parks again and reaches login, and another browser is still refused.

## 6. Consent and resume for device requests (D3, D7)

- [ ] 6.1 Make `consentNeeded` always ask for a device-origin request. Verify with table tests for first-party, offline pre-authorized, and remembered-consent clients.
- [ ] 6.2 Approval in `resumeConsent`: decide the device record first, then spend the stage, then remember consent. Verify partial scopes recorded, `redirect_to` to the entry page with `result=approved`, and consent remembered.
- [ ] 6.3 Denial. Verify the record is denied, `redirect_to` carries `result=denied`, and no consent is remembered.
- [ ] 6.4 Expiry during sign-in and at consent. Verify that an answer after `ExpiresAt` approves nothing and redirects with `result=expired`, including the exact-boundary case.
- [ ] 6.5 Half-applied failure. Make the stage spend fail after the device decision (store mock). Verify the device decision stands, a re-entry of the code is refused, and nothing is issued twice.

## 7. Token endpoint: polling and exchange (D10, D11)

- [ ] 7.1 Add the device-code case to `Token`'s dispatch. Verify `unsupported_grant_type` when the provider has not enabled it, and `unauthorized_client` for a client without the grant.
- [ ] 7.2 Answers by state. Verify `authorization_pending`, `access_denied` and `expired_token` (including at exactly `ExpiresAt`), and `invalid_grant` for an unknown code or another client's code, with the record unchanged.
- [ ] 7.3 `slow_down`. Verify that a poll inside the interval grows it by 5 s permanently, that a lost compare-and-set is answered `slow_down` (barrier test with two goroutines), and that an approved, denied or expired record is answered without the pace check.
- [ ] 7.4 The exchange: user check, approving-sign-in check under the default, `RequireBinding` before the spend, one spend, then `newGrant` with `Origin` set to device. Verify tokens, an ID token without `nonce` carrying the sign-in's `auth_time`, a refresh token only for a refresh-registered client, and `invalid_grant` with nothing recorded for a disabled user and for an ended sign-in.
- [ ] 7.5 Concurrent exchange. Verify with a barrier test that exactly one of N polls of an approved code gets tokens.
- [ ] 7.6 Replay. Verify that a spent code from its client revokes the grant (refresh and opaque access tokens stop working) within expiry plus one minute, that another client's presentation revokes nothing, and that a bound grant needs the key proof.
- [ ] 7.7 DPoP. Verify that a public client's proof binds the grant, and that a refresh without the key is refused.
- [ ] 7.8 Dependency failure. Verify that a store error during a poll answers a dependency failure, never `authorization_pending`, and logs without the code.
- [ ] 7.9 Spend succeeds but grant creation fails. Verify the poll fails as a dependency error and no token is issued.

## 8. Sign-in end and grant survival (D8)

- [ ] 8.1 Record `SignInFamily` from the approving sign-in, plus `SurvivesSignInEnd` from the client setting. Verify that under the default a device grant without `offline_access` is revoked by `EndSignIn` and one with it survives, and that under `DeviceGrantsOutliveSignIn` the former survives.
- [ ] 8.2 Verify that `EndGrantsWithSignIn` still revokes a device grant holding `offline_access`, and that consent revocation and `RevokeUserGrants` revoke device grants.
- [ ] 8.3 Verify the grant's absolute lifetime cap: the sign-in deadline under the default, and the grant's own lifetime when it survives.
- [ ] 8.4 Reach an unexchanged approval. Verify that `EndSignIn` (under the default, without `offline_access`), `RevokeConsent` and `RevokeUserGrants` between approval and poll make the poll answer `invalid_grant` with no token, through the device store's `UnspentCodes` joined to the grant store. Verify a second provider sharing both stores joins without error.

## 9. Events and expiry tasks (D13)

- [ ] 9.1 Add the device event names to `event`, and emit them from the provider. Verify one event per outcome (issued, claimed, approved, denied, exchanged, replayed, throttled), each naming the client and user when known and carrying no code.
- [ ] 9.2 Add the `oidc-provider.device-authorizations` task to `ExpiryTasks`. Verify it deletes expired records and keeps spent ones inside the replay window.

## 10. Durable stores and migration

- [ ] 10.1 Write a migration test first: apply to a database populated with grants and pending requests (per `use-testcontainers`), and check the new table, the grant and pending-request columns' defaults and a full rollback. See it fail. Then add the security-state migration after `20261103000000_oidc_provider.sql`.
- [ ] 10.2 `sqlstore` device authorization store and grant columns. Verify that the exported suite (3.2, 3.3) and the existing grant suites pass under `-race` on PostgreSQL 15 and 18.
- [ ] 10.3 `pgxstore`, verified the same way.
- [ ] 10.4 `gormstore`, verified the same way.

## 11. Chain wiring (D6, D12)

- [ ] 11.1 Add `OIDCDeviceAuthorization` and `OIDCDeviceEntry`, operation IDs and default paths, registered only when the grant is enabled. Verify the endpoint inventory, base-path, moved-path and collision tests list them only then.
- [ ] 11.2 The device authorization endpoint handler: POST form only, TLS rule, and the token endpoint's error body with `no-store`. Verify a GET is refused, plain HTTP is refused, and a 200 has the JSON shape.
- [ ] 11.3 The client-authentication throttle under `oidc-device-authorization` (10 per 15 minutes). Verify that the eleventh request is refused as `invalid_client`, and that the token endpoint's budget is separate.
- [ ] 11.4 The code-entry endpoint: GET with `user_code`, POST, a 303 conversion of a cookieless POST, the flow cookie, and the trusted-proxy source handed to `EnterUserCode`. Verify each, including two proxied addresses throttled separately.
- [ ] 11.5 Pass the chain's limiter factory to the provider under `oidc-device-entry` when configured. Verify the factory's limiter is the one asked.
- [ ] 11.6 CSRF. Verify that the device authorization endpoint is exempt (a POST with no `Origin` passes), and that a cross-site POST to code entry is refused with nothing claimed.
- [ ] 11.7 CORS. Verify that neither device endpoint carries CORS headers for an allowed origin.
- [ ] 11.8 Metadata. Derive `grant_types_supported`, and add `device_authorization_endpoint` when enabled. Verify both documents, enabled and not, and with a moved path.
- [ ] 11.9 Map `ErrInvalidUserCode` to 400 and throttling to 429 in the error-propagation helper. Verify the status-only answers with nothing rendered.

## 12. Documentation

- [ ] 12.1 Godoc for every new exported identifier, naming the default each option replaces. Add an `Example` showing `WithDeviceAuthorization` with a native client. Verify `go test -run Example` passes and `go doc` shows the defaults.
- [ ] 12.2 README "CLI clients": loopback with PKCE first, then the device grant with a `golang.org/x/oauth2` sketch; the entry-page contract (`result` values, no auto-submit); the phishing guidance; the HMAC key for durable stores; the distributed-guessing limit. Verify the snippet compiles as an example test.
- [ ] 12.3 CHANGELOG entry under the next minor version: the option, client fields, store port, migration and events. Verify `make spec-check` passes.

## 13. Integration

- [ ] 13.1 An end-to-end test in the `test` module: a `golang.org/x/oauth2` client runs `DeviceAuth` and `DeviceAccessToken` against a chain with the provider, a scripted browser enters the code, signs in and approves, and the client receives tokens and refreshes. Verify it passes on the in-memory and one durable store.
- [ ] 13.2 Run `make check`, `make spec-check` and `openspec validate oidc-provider-device-grant --strict`. Verify all three pass, and keep their output.
- [ ] 13.3 A whole-branch review against every requirement in this change's specs. Verify every finding is resolved or recorded.

## Workflow follow-up

- Archive the change after the whole-branch review is clean and the user approves.
