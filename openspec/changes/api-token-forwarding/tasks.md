# Tasks

Every task is test-first. For each one:

1. Write the failing test.
2. Run it with a focused `go test -run '<Name>' -count=1`.
3. Confirm that it fails for the intended reason. A compile error is not a red step.
4. Implement.
5. Re-run the test.

Each task states how completion is verified. Scoped verification follows `test-scope.md`, covering
the changed packages and their transitive dependents. The full suite runs once, in group 8.

## 1. Session contract for provider tokens (`session`)

- [ ] 1.1 Add the library-owned provider access token, refresh token and access-token expiry to
  `session.Session`. They are recorded in the creating write and empty by default. Verify with a
  test that creates a session with them on `MemoryStore` and loads them back (sessions: "A session
  can carry a provider's tokens for forwarding", scenario "Recorded at creation").
- [ ] 1.2 Make `Save` and consumer data unable to change the provider tokens. Verify with tests for
  the scenarios "Save cannot change them" and "Consumer data cannot set them".
- [ ] 1.3 Carry the provider tokens to every successor made by rotation, renewal or
  re-authentication, already set on the successor handed to the issuing step. Verify with the
  scenario "Privilege change rotates the session", run for each rotation kind.
- [ ] 1.4 Define the conditional provider-token replace/clear port, modelled on `RoleSelector`. It
  writes only to a stored, non-superseded session holding the named refresh token, reporting
  `ErrNotFound`, `ErrSuperseded` or not-applied, and is implemented on `MemoryStore`. Verify with a
  table test of the five scenarios of "Provider tokens are replaced only by a conditional write on
  the newest session", plus a race test (`-race`) where two replacers name the same refresh token
  and exactly one wins.
- [ ] 1.5 Seal the provider access and refresh tokens in the sealing store
  (`session/store_encrypted.go`) under the ID token's rules, including the conditional replace.
  Verify with the scenarios "Sealed round trip", "Copied to another session" and "Conditional
  replace through the sealing store", and an outage case that fails as a store failure and not as
  session-unreadable.
- [ ] 1.6 Redact the provider tokens when a session is printed. Verify with a test that formats a
  session holding `AT-SENTINEL` and `RT-SENTINEL` with `%v`, `%+v`, `%#v`, as a slog attribute and
  as a field of a consumer struct, and finds neither sentinel.
- [ ] 1.7 Document the new fields and the port in godoc, naming the default (empty, not kept) and
  the sealing requirement. Verify with `go doc ./session` showing them, and `go vet ./session`.

## 2. Durable session stores (`store/migrate`, `internal/pgschema`, `internal/storekit`, `store/sqlstore`, `store/pgxstore`, `store/gormstore`, `test/storetest`)

- [ ] 2.1 Add conformance cases to `test/storetest`:
  - provider tokens reloaded;
  - provider tokens surviving supersession;
  - a copied sealed token that does not open;
  - pre-migration rows loading with no tokens;
  - the conditional replace: success, lost write, superseded, deleted, and racing replacements.

  Verify by running them against `MemoryStore` (green) and against each durable store before 2.2
  (red for the intended reason: missing columns or port).
- [ ] 2.2 Add one nullable security-state migration for the provider-token columns, and its schema
  helpers in `internal/pgschema`. Verify with the `store/migrate` tests and a migration up/down
  test on PostgreSQL through testcontainers.
- [ ] 2.3 Implement storage and the single-statement conditional replace in `store/sqlstore` and
  `store/pgxstore`, through `internal/storekit`. Verify with the 2.1 conformance cases passing on
  both, against PostgreSQL 15 and 18 via testcontainers.
- [ ] 2.4 Implement the same in `store/gormstore`. Verify with the 2.1 conformance cases passing.
- [ ] 2.5 Add the `secrets-at-rest` column test: the stored columns, read directly and decoded,
  contain neither sentinel, and loading returns both. Verify it fails before sealing is wired
  through the durable path and passes after.

## 3. Keeping a forwarding provider's tokens (`authenticate/oidc`)

- [ ] 3.1 Add the per-provider "keep tokens for forwarding" option, off by default. Verify that the
  existing test "Access token outlives no callback" still passes for a provider without the option.
- [ ] 3.2 For a forwarding provider, record the access token, the optional refresh token and the
  expiry on the session in its creating write, and never in the flow or handoff records or the
  callback result. Verify with the scenarios "Consumer configures forwarding", "No refresh token
  issued" and "Token response without an access token".
- [ ] 3.3 Fail the login as a provider failure when a kept token exceeds 16 KiB, storing no session.
  Verify with the scenario "Oversized access token".
- [ ] 3.4 Add a provider refresh-token call on the relying party: through the confined client, with
  the code exchange's client authentication, returning a typed outcome of refreshed, rejected
  (`invalid_grant`) or dependency failure. Provider error descriptions are bounded in logs and
  never returned. Verify with a table test against an `httptest` provider covering:
  - a rotated refresh token;
  - an absent refresh token;
  - an absent `expires_in`, with both the default and a consumer fallback;
  - `invalid_grant` with `DESC-SENTINEL`;
  - a 503, a timeout and a malformed body.
- [ ] 3.5 Document the option and the `offline_access` scope requirement in godoc. Verify with
  `go doc ./authenticate/oidc`.

## 4. Outbound tokens: wiring, access and minting (`httpsec`, `token`)

- [ ] 4.1 Write the red test for the session-identifier hazard first (design F3). Mint a token, then:
  - present its `jti` as the session cookie;
  - present the token as a signed bearer token on a chain sharing the keys;
  - assert that neither authenticates, and that `jti` is not and does not contain the session
    identifier.

  Record the red output.
- [ ] 4.2 Add the enabling option with the per-API configuration (resource identifier, base URLs,
  exactly one source), off by default. Verify with the scenarios "Default chain" and "Consumer
  enables outbound tokens".
- [ ] 4.3 Add the construction checks of "Outbound-token wiring mistakes fail at construction" and
  "Provider tokens are kept only for a provider an API uses". Verify with a table test with one case
  per D6 condition, each asserting a configuration error that names the setting.
- [ ] 4.4 Add the accessor and its errors: no-outbound-token, provider-token-unavailable, and a
  dependency error. It returns a token only for a cookie-authenticated request owing no challenge.
  Verify with the three scenarios of "Only a cookie-authenticated request gets an outbound token".
- [ ] 4.5 Mint the token: `typ` `at+jwt`, the RFC 9068 claims, a fresh random `jti`, `client_id`
  defaulting to the issuer, a lifetime of at most 5 minutes, and `exp` capped by the session's
  absolute deadline. Verify with:
  - the scenarios "Default claims", "Consumer sets the client identifier", "Session ends sooner",
    "Consumer shortens the lifetime" and "Two tokens for one session";
  - 4.1 turning green;
  - the scenario "Verified by a resource server", through `EnableResourceServer` with binding
    opted out.
- [ ] 4.6 Add per-request reuse while more than one minute remains, with nothing persisted. Verify
  with the scenarios "Same request asks twice", "Under one minute left" and "Nothing persisted".
- [ ] 4.7 Map minting failures. Verify that a key-source failure gives a dependency error with the
  cause reachable and the session unchanged, and that a cancelled context gives an error matching
  the context.
- [ ] 4.8 Support the consumer token source. Verify with the scenarios "Consumer source" and
  "Consumer source fails", where an empty token is treated as an error.
- [ ] 4.9 Never write a token to a response, and redact tokens in logs and errors. Verify with the
  scenario "Handler obtains a token" and with the formatting tests of "Outbound tokens never reach
  logs or errors".

## 5. Provider tokens on the outbound path (`httpsec`, using groups 1 and 3)

- [ ] 5.1 Serve a provider API from the session's kept token. Verify with the scenarios "Federated
  session", "Local sign-in" and "Another provider".
- [ ] 5.2 Refresh when less than one minute remains, and save through the conditional replace.
  Verify with the scenarios "Refresh near expiry", "Provider rotates the refresh token", "Provider
  keeps the refresh token" and both expiry-fallback scenarios.
- [ ] 5.3 Coalesce refreshes per session within a process, so that one caller's cancellation does
  not cancel the others. Verify with a barrier test (`-race`) where ten concurrent requests send one
  refresh and all receive the same token, and with "One waiter's request is cancelled".
- [ ] 5.4 Handle a lost write across replicas. Verify with:
  - "Another replica refreshed first": reload and use the winner's token;
  - "Session rotated during the refresh": save to the newest successor under the same condition;
  - "Session deleted during the refresh": no-outbound-token, nothing re-created.
- [ ] 5.5 Never refresh from a superseded identifier. Verify with "Superseded identifier near
  expiry", where no refresh request is sent.
- [ ] 5.6 Handle failures. Verify with:
  - "Refresh token revoked at the provider": tokens cleared conditionally, the session still
    signed in on the next request;
  - "No refresh token kept";
  - "Token endpoint answers 503": a dependency error, tokens kept.
- [ ] 5.7 Run the provider path end to end against a durable store, PostgreSQL via testcontainers,
  in `test/`. Verify that sign-in through a forwarding provider, a refresh and an API call succeed,
  and that the stored columns are sealed.

## 6. Outbound transport (`httpsec`, `outbound`)

- [ ] 6.1 Refuse destinations outside the configured APIs, with segment-bounded prefixes, before
  any connection, returning `outbound.ErrDestinationNotAllowed`. Verify with the scenarios
  "Unconfigured destination" and "Prefix is not a segment boundary", using a dialer that records
  connections, and assert the error matches `outbound.ErrDestinationNotAllowed` and not
  `ErrNoOutboundToken`.
- [ ] 6.2 Attach the API's token, replace any existing `Authorization` header, remove every
  `Cookie` header, and refuse with the accessor's error when there is no token. Verify with the
  scenarios "Cookie and stale authorization present" and "No token for this request".
- [ ] 6.3 Apply the confined client's rules. Verify with:
  - "Cross-origin redirect": no request carrying the token reaches the other origin;
  - "Plain HTTP by default" as a construction error;
  - "Consumer allows plain HTTP";
  - a time and size bound test.
- [ ] 6.4 Add an `Example` test that wires a cookie chain, one minted API and one provider API, and
  calls both through the transport. Verify that `go test -run Example ./httpsec` passes and the
  example renders in `go doc`.

## 7. Consumer documentation

- [ ] 7.1 Write the consumer guide for the outbound hop. It covers:
  - the obligations the transport cannot enforce: `Cache-Control: private, no-store` on per-user
    responses, pass-through routes, and TLS on the app-to-API hop;
  - how a downstream API verifies minted tokens with `EnableResourceServer` and opts its source out
    of binding, naming the app's key set with `WithJWKSURL`, because `FromIssuer` discovers keys
    from issuer metadata by default and an app that only serves a key set publishes none;
  - the 5-minute revocation window, and introspection for APIs that need it;
  - `offline_access` for provider refresh;
  - the accepted failures F4, F20, F21 and F22.

  Verify that every code snippet in the guide compiles as an `Example` test, or is cross-checked
  against one.

## 8. Final gate and review

- [ ] 8.1 Run `make check` and `make spec-check` once, after the last code edit, and read the
  output. Verify that both are green, with the output recorded.
- [ ] 8.2 Run a whole-branch review against every requirement in the five spec deltas and every
  failure mode in `design.md`. Verify that each finding is fixed (followed by a rerun of 8.1), or
  recorded as accepted in `design.md`.

## Workflow follow-up

- Archive the change after the project's review requirements are satisfied.
- Verify the archived specs: `token-forwarding` is created, and `oidc-login`, `sessions`,
  `secrets-at-rest` and `security-state-stores` are updated.
