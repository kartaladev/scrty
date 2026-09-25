# Tasks

Every task follows the project's test-first rule: write the failing test, run it, confirm it fails
for the intended reason (a compile error is not a red step), then implement. "Verify" in a task
names the focused run that must first fail and then pass. Table tests follow the `table-test`
skill, test doubles the `use-mockgen` skill, and the Keycloak test the `use-testcontainers` skill.

`design.md` was revised against the code before these tasks were written, so its names are the
code's names. Where a task says "as magic-link does", the reference is `httpsec/magiclink.go` and
`magiclink/`, whose pattern this change reuses rather than copies.

Tests in the core module never import the `test` module. `oidc` package tests serve a provider
from an in-package `httptest` TLS helper in a `_test.go` file; the store conformance suites, the
in-process test identity provider and the Keycloak test live in the `test` module.

## 1. Prerequisites in archived capabilities

- [x] 1.1 Give `outbound.(*Client).PostForm` a header argument, `PostForm(ctx, rawURL string,
  form url.Values, header http.Header)`, sent exactly as given, nil meaning none; update its two
  callers in `outbound/client_test.go`. Verify a table test that an `Authorization` header reaches
  the server with the form, that a nil header sends only the content type, and that a `307` to
  another origin sends nothing, header included (spec `outbound-http-confinement`, "A form POST
  carries the caller's headers"). The existing `TestOutboundPostForm` becomes this table's first
  row: `go test -run 'TestOutboundPostForm|TestOutboundNoBodyReplay' -count=1 ./outbound/`.
- [x] 1.2 Let the login tail accept session create options: `completeLogin` (and `loginTailDeps` or
  its call signature) takes `...session.CreateOption` appended after `WithFirstFactor`, so the
  options land in the creating write. Form login, magic-link and every other caller pass none and
  behave as before. Verify a test that a caller passing `session.WithExternalSession(...)` gets a
  session whose `External*` fields load from the store without a later save, and that the existing
  form-login and magic-link tail tests still pass (spec `http-security-chain`, "Redemption flows
  plug into named seams"): `go test -run 'TestCompleteLogin|TestFormLogin|TestMagicLink' -count=1
  ./httpsec/`.
- [x] 1.3 Add the optional end-session step to logout: `httpsec.EndSessionBuilder` and
  `LogoutDeps.EndSession`. After deleting a session that records a provider, call it with the
  deleted session and the `state` form value; a non-empty URL answers 200 with
  `{"end_session_url": ...}` and `Cache-Control: no-store`, otherwise 200 with an empty body; a
  builder error is logged and the logout still answers 200. Verify a table over a federated session
  with a URL, a password session (builder not called), a builder error, and no builder configured
  (response unchanged from today), asserting the delete happened before the builder ran (spec
  `http-security-chain`, "Logout ends the session"): `go test -run TestLogoutEndSession -count=1
  ./httpsec/`.
- [x] 1.4 Add the load-by-reference cases to the identity conformance suite in `test/identity`: an
  existing reference loads details carrying exactly that reference (including a trailing space), an
  unknown reference and a case-folded reference are "user not found". Verify the new cases fail
  against a non-conforming fixture that case-folds references, added beside the existing broken
  fixtures in `conformance_guard_test.go`, then that the suite passes against the in-memory store
  (spec `identity-model`, "User loader contract"): `cd test && go test -run
  'TestInMemoryStoreConformance|TestBrokenStoreConformance|TestConformanceSuiteIsLoadBearing'
  -count=1 ./identity/`.
- [x] 1.5 Add `golang.org/x/sync` to the core `go.mod`. Verify `layout_guard_test.go` still passes
  with it present and `go mod tidy` leaves no diff: `go test -run
  'TestModuleLayout|TestConsumerModuleGraph' -count=1 . && go mod tidy && git diff --exit-code
  go.mod go.sum`.
- [x] 1.6 Add `outbound.(*Client).AllowsScheme(scheme string) bool`, answering exactly as the
  client's own request-time scheme check does, case-insensitively. Verify a table that a default
  client allows `https` and not `http`, and a client built with `WithAllowedSchemes("http")` allows
  `HTTP` (spec `outbound-http-confinement`, "A client reports the schemes it allows"): `go test -run
  TestOutboundAllowsScheme -count=1 ./outbound/`.

## 2. oidc: errors, provider registry and construction

- [x] 2.1 Create the `oidc` package with its sentinels: `ErrConfig`, `ErrInvalidState`,
  `ErrInvalidIDToken`, `ErrNoLinkedAccount`, `ErrProvisioningRefused`, `ErrInvalidHandoff`,
  `ErrInvalidLogoutToken`, `ErrUnknownProvider`, `ErrExchangeFailed`, `ErrDiscoveryFailed`,
  `ErrLinkNotFound`, `ErrLinkExists`, `ErrHandoffNotFound`, `ErrRetainSinceRequired` (a zero purge
  cutoff), `ErrFlowUnspent`. The five
  authentication failures wrap `authenticate.ErrAuthenticationFailed`; the others wrap no refusal.
  Verify a table asserting each authentication failure `errors.Is` both itself and
  `authenticate.ErrAuthenticationFailed`, and that the rest do not: `go test -run TestOIDCSentinels
  -count=1 ./oidc/`.
- [x] 2.2 Implement `Provider`, `ClientAuthMethod` and `NewRegistry` with every construction refusal
  in spec `oidc-login`, "Provider configuration is validated at construction": duplicate or empty
  or multi-segment names; missing issuer, client id or redirect URL; an issuer, redirect,
  end-session or pinned endpoint that is not an absolute URL with a host name; an issuer with a query
  or fragment, or a redirect URL with a fragment; configured scopes without `openid`; a partial pin
  of the three endpoints; `none` in the algorithm list; a symmetric algorithm not explicitly listed,
  or listed with an empty client secret. The scheme is not checked here (task 2.3 checks it against
  the outbound client). `EndSessionEndpoint` stays outside the pin rule. Loopback and private hosts
  are accepted. Verify a table test with one row per refusal and the accepted
  `https://localhost:8443/realms/dev` and `http://localhost:8080/realms/dev` cases: `go test -run
  TestNewRegistry -count=1 ./oidc/`.
- [x] 2.3 Declare the shared ports and records (`FlowStore`, `LinkStore`, `HandoffStore`,
  `IdentityBroker`, `Flow`, `Link`, `HandoffRecord`, `ExternalIdentity`, `CallbackResult`), and add
  `NewManager(registry, broker, opts...)` with `WithOutboundClient` (default `outbound.New()`),
  `WithRandom` (default `crypto/rand.Reader`), `WithClock` (default `time.Now`) and `WithLogger`,
  refusing nil values, typed nils included (`internal/nilcheck`), and a nil broker
  (`identity.MissingPort`) with `ErrConfig`. Refuse, naming the provider, any issuer, redirect,
  end-session or pinned endpoint whose scheme the outbound client does not allow
  (`AllowsScheme`, task 1.6), so an `http` issuer fails with the default client and is accepted
  with a client allowing `http` (spec "Provider configuration is validated at construction"). Add the accessors
  the chain needs (`Providers`, `Links`, `RoleSyncProviders`) and refuse a broker whose options name
  a provider the registry lacks (spec "OIDC wiring mistakes fail at construction"). Per-provider
  signing algorithms are `Provider.SigningAlgs`, validated in 2.2. Verify the defaults are used when
  nothing is supplied, each refusal, and the unregistered-provider refusal naming `corpp`: `go test
  -run TestNewManagerOptions -count=1 ./oidc/`.

## 3. oidc: discovery and the key-set cache

- [x] 3.1 Fetch and validate the discovery document through `outbound.Get`: exact issuer match,
  every named endpoint of a scheme the outbound client allows and `origin.Same` as the issuer; a fully pinned provider is never
  sent a discovery request; a document failure is `ErrDiscoveryFailed`. Verify a table over the
  issuer-mismatch, other-origin key set, pinned-provider and happy cases, asserting request counts
  on the in-package provider (spec "Discovery is lazy by default and confined to the issuer"): `go
  test -run TestDiscovery -count=1 ./oidc/`.
- [x] 3.2 Build the cache: one map keyed `meta:<provider>` and `keys:<provider>`, entries holding the
  parsed value and fetch time, served with no network call while younger than the TTL (default
  15 minutes, `WithDiscoveryTTL`), refetched on demand when older, key sets parsed with
  `jwk.Parse`. Verify with `testing/synctest` and the injected clock that a fresh entry makes no
  request, an expired one makes exactly one, and a consumer TTL of 1 hour serves a 30-minute-old
  entry (specs "Provider metadata is cached, coalesced and backed off" and "Provider metadata is
  fetched on demand"): `go test -run TestKeyCacheTTL -count=1 ./oidc/`.
- [x] 3.3 Coalesce concurrent misses with `singleflight.DoChan` on `context.WithoutCancel`, each
  caller selecting on its own context. Verify 8 concurrent misses send exactly one fetch and all
  receive it, that a cancelling leader does not fail a waiting caller, and that no goroutine remains
  after every caller has returned (goroutine-leak check): `go test -run TestKeyCacheCoalesces
  -race -count=1 ./oidc/`.
- [x] 3.4 Add failure backoff (default 1 s doubling to 30 s, `WithDiscoveryFailureBackoff`, reset on
  success, not-attempted refusals never opening or widening a window, each transition logged once,
  directly, since the backoff bounds the volume). Verify with synctest that 20 requests within a second after a
  failure send no fetch and each fail as `ErrDiscoveryFailed`, that the window doubles and caps,
  and that a cooldown refusal leaves the window untouched; then run the design's mutation "not-
  attempted refusals fed to the backoff" by hand and see the last case fail: `go test -run
  TestKeyCacheBackoff -count=1 ./oidc/`.
- [x] 3.5 Add the unknown-`kid` refetch: one refetch per cooldown per provider (default 30 s,
  `WithJWKSRefetchCooldown`), the claim taken inside the flight, a refusal inside the cooldown
  reported as an unknown signing key that verification maps to `ErrInvalidIDToken`. Verify key
  rotation is picked up, 100 random `kid`s cost at most one fetch, the cooldown is per provider, and
  a zero cooldown fails construction; then run "the cooldown claimed outside the flight" by hand and
  see the concurrency case fail: `go test -run TestKeyCacheUnknownKid -race -count=1 ./oidc/`.
- [x] 3.6 Add the stale window (default off, `WithDiscoveryStaleWhileError`, negative refused): an
  expired entry within `TTL + window` is served after a failed refetch with a warning per use,
  never for a `kid` it lacks and never in place of a failed unknown-`kid` refetch. Verify the
  default refuses an expired set during an outage, the consumer window serves one with a warning,
  and a stale set lacking the `kid` fails as a provider failure; run "the stale window serving a
  fresh entry" by hand: `go test -run TestKeyCacheStaleWindow -count=1 ./oidc/`.
- [x] 3.7 Add `Manager.Prefetch(ctx)`: fetches every provider's document (when unpinned) and key set
  and returns an error naming the first that failed; construction itself makes no request. Verify a
  registry of unreachable providers constructs with zero requests, and `Prefetch` returns an error
  naming the unreachable one: `go test -run TestManagerPrefetch -count=1 ./oidc/`.

## 4. oidc: authorization and the flow store

- [x] 4.1 Define `Flow` and the `FlowStore` port, and implement the in-memory default: `Begin`,
  `Complete(handle, provider, state)` deciding existence, bindings, single completion and expiry
  under one mutex with a constant-time state compare, inline pruning, `WithMaxFlows` (default
  100,000) refusing rather than evicting, and `DeleteExpired` refusing a zero cutoff. Verify a table
  over unknown handle, wrong provider, wrong and empty state, expired, completed and zero cutoff,
  each followed by the correct call still succeeding: `go test -run TestMemoryFlowStore -count=1
  ./oidc/`.
- [x] 4.2 Verify single completion under concurrency: 8 goroutines completing one flow behind a
  barrier yield exactly one success and seven `ErrInvalidState`. `go test -run
  TestMemoryFlowStoreRacingComplete -race -count=1 ./oidc/`.
- [x] 4.3 Write `RunFlowStoreSuite` in a new `test/oidc` package, covering spec "A flow is completed
  only by a caller who knows its provider and state" and the zero-cutoff scenario, with every
  refusal paired with a following success and the racing case behind a barrier. Verify it fails
  against a deliberately read-then-write fixture defined in the suite's own test, then passes
  against `oidc`'s in-memory store: `cd test && go test -run TestFlowStoreSuite -race -count=1
  ./oidc/`.
- [x] 4.4 Implement `Manager.Authorize(ctx, provider, next)`: state, nonce and verifier of 32 bytes
  each from the random source, an `S256` challenge, the configured scopes (default `openid profile
  email`), the flow stored for `WithFlowTTL` (default 10 minutes), and `ErrUnknownProvider` for an
  unregistered name without storing a flow. Verify the redirect parameters, fresh values per
  attempt, consumer scopes, and the unknown-provider case (spec "Authorization always uses PKCE,
  state and nonce"): `go test -run TestManagerAuthorize -count=1 ./oidc/`.

## 5. oidc: callback, exchange and ID token verification

- [x] 5.1 Implement the code exchange through `outbound.PostForm`: `grant_type`, `code`,
  `redirect_uri`, `code_verifier`; `client_secret_post` by default, `client_secret_basic` sending an
  `Authorization` header and no `client_secret` field; an error, malformed or ID-token-less response
  is `ErrExchangeFailed` with the body logged truncated and never returned; provider access and
  refresh tokens discarded. Verify a table over both client authentication methods, `invalid_grant`
  and a missing ID token (spec "The code exchange authenticates the client and hides provider
  detail"): `go test -run TestExchange -count=1 ./oidc/`.
- [x] 5.2 Implement ID token verification with jwx v4 and the shared `parseProviderJWT`: the
  algorithm allowlist (default `RS256`), required `kid`, exact issuer, audience with `azp` when
  several, `exp` present, `iat`/`nbf` within the leeway (default 60 s, `WithClockSkew`), constant-time
  `nonce`, non-empty `sub`; every failure `ErrInvalidIDToken`, a key-set failure
  `ErrDiscoveryFailed`. Verify a table with one row per malformed token (wrong `iss`, wrong `aud`,
  expired, missing `exp`, future `iat`, bad signature, unknown `kid`, `alg: none`, `HS256` with the
  client secret, wrong `nonce`, missing `sub`, several audiences without `azp`, consumer `ES256`
  only) and the valid case (spec "ID tokens are verified strictly"): `go test -run
  TestVerifyIDToken -count=1 ./oidc/`.
- [x] 5.3 Implement `Manager.Callback(ctx, provider, code, state, handle)` and `AbortFlow`: complete
  the flow, exchange, verify, broker; return `CallbackResult`; join `ErrFlowUnspent` exactly on the
  returns at or before `Complete`; the error branch ends the flow only when the echoed state
  completes it and logs the provider's error text only then. Verify the forged callback and forged
  error link leave the victim's flow completable, the genuine denial ends the flow, and a store
  fault propagates as itself (specs "A flow is completed only by…" and "A provider error redirect
  cannot cancel someone else's login"): `go test -run TestManagerCallback -count=1 ./oidc/`.

## 6. oidc: broker, links, provisioning, mirroring and roles

- [x] 6.1 Define `Link` and the `LinkStore` port, and implement the in-memory default: find by
  provider, issuer and subject; insert refusing any existing key, identical re-inserts included;
  delete by user returning the count; errors carrying no subject, email, username or reference.
  Verify a table over conflicting insert, identical re-insert, delete count and byte-for-byte
  round-trip (spec "Link store contract"): `go test -run TestMemoryLinkStore -count=1 ./oidc/`.
- [x] 6.2 Write `RunLinkStoreSuite` in `test/oidc`, including concurrent inserts of one key behind a
  barrier. Verify it fails against a read-then-write fixture and passes against the in-memory
  store: `cd test && go test -run TestLinkStoreSuite -race -count=1 ./oidc/`.
- [x] 6.3 Implement `NewBroker` and linked resolution by user reference: `LoadByUserID(Link.UserID)`,
  refusing a miss, nil details, a `Details.ID` mismatch and an inactive user with
  `ErrNoLinkedAccount`, a loader outage returned wrapped and not an authentication failure; a nil
  link store or loader refused with `identity.MissingPort`. Use a mockgen `UserLoader`. Verify a
  table over dangling link, recycled username (asserting `LoadByUsername` is never called),
  non-conforming loader returning another user, disabled user, outage and missing ports; then run
  "`LoadByUsername` substituted for `LoadByUserID`" and "the `Details.ID` equality check dropped" by
  hand (spec "A linked identity resolves only to the user it was created for"): `go test -run
  TestBrokerLinkedResolution -count=1 ./oidc/`.
- [x] 6.4 Implement just-in-time provisioning: `WithJIT`, `WithJITAllowUnverifiedEmail`,
  `WithJITEmailDomains` (comma-ok "configured" versus "configured empty"), `WithNameClaim`,
  `WithProvisioner` (missing refused with `identity.MissingPort("user provisioner")`); create-only
  `Provision` with `ErrUserExists` becoming `ErrProvisioningRefused`; the link bound to the returned
  `det.ID` and `det.Username`; a failed link insert logged naming the provider. Verify a table over
  every scenario of specs "Just-in-time provisioning is off by default", "Provisioning requires a
  verified email and an allowed domain" and "Provisioning creates a user and never adopts one":
  `go test -run TestBrokerProvisioning -count=1 ./oidc/`.
- [x] 6.5 Implement password-hash mapping: `WithPasswordClaim`, `WithPasswordEncoder` (probe must
  produce bcrypt), `WithPasswordClaimCostRange` (default 10–15 within 4–31); the anchored bcrypt
  pattern and `bcrypt.Cost` band check; ignored values logged without the value, WARN once per
  (provider, reason) then DEBUG; redaction of bcrypt-shaped text in provisioner and loader errors;
  every construction refusal. Verify a table over every scenario of spec "A password hash can be
  mapped from a claim only in a verifiable, bounded form": `go test -run TestBrokerPasswordClaim
  -count=1 ./oidc/`.
- [x] 6.6 Implement claim mirroring (`WithClaimMirror`): options resolved once through
  `mappedUserOptions`, named fields read with `identity.ApplyUserOptions(...).IsSet`, compared
  through `mirroredFields` keyed by `identity.Field`, `Update` naming only those fields, failures
  and nil results logged at ERROR and ignored, copy-back of mirrored fields only. Verify a table
  over every scenario of spec "Claim mirroring refreshes mapped fields on later logins through an
  update", including the partial-result case that must keep role `editor`: `go test -run
  TestBrokerClaimMirroring -count=1 ./oidc/`.
- [x] 6.7 Implement roles from claims: `WithDefaultRole`, `WithRoleClaim` (dotted path, string or
  string array, configured-empty yielding none), `WithRoleMapping`, `WithAllowedRoles` (also applied
  to the default role), `WithRoleSync` (requires a claim path; synced roles carry only name and
  primary flag and are never persisted); `RoleSyncProviders()`; one resolution function for
  provisioning and sync. Verify a table over every scenario of specs "Roles can be derived from a
  claim path at provisioning" and "Role sync applies claim-derived roles to each login without
  persisting them" that the broker alone decides: `go test -run TestBrokerRoles -count=1 ./oidc/`.
- [x] 6.8 Verify a consumer `IdentityBroker` passed to `NewManager` replaces linking, provisioning and mirroring and receives every claim
  unchanged, with the link store and provisioner mocks asserting no call (spec "The library does not
  interpret claims it was not told to read"): `go test -run TestConsumerBroker -count=1 ./oidc/`.

## 7. oidc: the handoff code

- [x] 7.1 Define `HandoffRecord` (with `UserID`) and the `HandoffStore` port, and implement the
  in-memory default: insert, find by token id, conditional `Consume` of an unconsumed record,
  `DeleteExpired` refusing a zero cutoff. Verify a table over each operation and the zero cutoff,
  each refusal followed by a succeeding call: `go test -run TestMemoryHandoffStore -count=1
  ./oidc/`.
- [x] 7.2 Write `RunHandoffStoreSuite` in `test/oidc`, with 8 concurrent consumes of one record
  behind a barrier yielding exactly one success. Verify it fails against a read-then-write fixture
  and passes against the in-memory store: `cd test && go test -run TestHandoffStoreSuite -race
  -count=1 ./oidc/`.
- [x] 7.3 Implement issuance: `<tokenID>.<secret>` from the random source (16 and 32 bytes,
  base64url), `SHA-256(secret)` at rest, a fixed 60-second expiry, the record carrying the user
  reference, provider, issuer, `sid` and ID token, and `WithHandoffIDGenerator` for the record id. Verify
  the stored record holds no secret and a code redeemed exactly at 60 seconds is refused (spec "The
  callback conveys the login by a short-lived single-use code"): `go test -run TestHandoffIssue
  -count=1 ./oidc/`.
- [x] 7.4 Implement `HandoffManager.Redeem(ctx, code, checks...)` in the design's order: parse, find,
  constant-time compare, expiry, the consumed fast path, `LoadByUserID` with the reference, active
  and nil checks, the checks in order with the first error unwrapped, `Consume` last. Every failure
  except a check's own error is `ErrInvalidHandoff`, logged at DEBUG or, for an outage, ERROR.
  Verify a table over every scenario of specs "Handoff redemption is check-then-consume" and
  "Handoff redemption failures reveal nothing about the cause" at the manager level (disabled user
  and wrong secret alike, loader outage then success, reference mismatch leaves the code, consume
  failure), and 8 racing redemptions yielding one success; then run "`Consume` moved before the
  checks" and "the fast path dropped" by hand: `go test -run TestHandoffRedeem -race -count=1
  ./oidc/`.

## 8. oidc: logout tokens and the end-session URL

- [x] 8.1 Implement `VerifyLogoutToken` beside the ID-token verifier on `parseProviderJWT`: the same
  signature, issuer and audience checks; `iat` required, not older than `WithLogoutTokenMaxAge`
  (default 2 minutes) plus leeway and not in the future beyond it; `exp` optional but enforced; `jti`
  required; `events` holding the back-channel member as an object; no `nonce`; `sub`, `sid` or both.
  Every failure is `ErrInvalidLogoutToken`. Verify a table over every scenario of spec "Logout
  tokens are verified strictly", and run "the `iat` presence check dropped" by hand: `go test -run
  TestVerifyLogoutToken -count=1 ./oidc/`.
- [x] 8.2 Implement `Manager.EndSessionURL` and the `httpsec.EndSessionBuilder` adapter over a
  session: the provider's end-session endpoint (pinned or discovered), `client_id`,
  `id_token_hint`, `post_logout_redirect_uri` from `WithPostLogoutRedirect` (validated as absolute
  `https` without user information) and `state`, empty values omitted; no endpoint or no provider
  yields `""` and no error. Verify a table over every scenario of spec "RP-initiated logout offers
  the provider's end-session URL" that the URL builder alone decides: `go test -run
  TestEndSessionURL -count=1 ./oidc/`.

## 9. httpsec: the OIDC interceptors

- [x] 9.1 Add the two status rows, `oidc.ErrUnknownProvider` → 404 and `oidc.ErrInvalidLogoutToken`
  → 400, and add `oidc` to the sentinel registry in `TestStatusForErrorCoversEverySentinel`. Verify
  the registry test fails when `oidc` is added before the rows, then passes, and that an
  `oidc.ErrInvalidHandoff` maps to 401 with no row (spec `http-error-propagation`, "One public table
  maps refusals to a status"): `go test -run 'TestStatusFor' -count=1 ./httpsec/`.
- [x] 9.2 Add `EnableOIDCLogin(m *oidc.Manager, h *oidc.HandoffManager, opts ...OIDCOption)`
  registering at `OrderOIDC`, with the required `WithOIDCTokens` and `WithOIDCSessions`, the
  paths, `WithOIDCAllowedRedirects` and `WithOIDCAllowedOrigins` built with
  `origin.NewAllowlist`, `WithCallbackSuccess`, and every construction refusal of design decision
  14 and specs "OIDC wiring mistakes fail at construction" and "Logout wiring mistakes fail at
  construction", including role sync without `WithCallbackSuccess`. Update the `OrderOIDC` comment.
  Verify a table test with one row per refusal: `go test -run TestEnableOIDCLoginConstruction
  -count=1 ./httpsec/`.
- [x] 9.3 Implement the authorize interceptor: GET on `/oauth2/authorization/{provider}`, one
  non-empty segment, `ErrUnknownProvider` for an unregistered name, the flow cookie (`HttpOnly;
  Secure; SameSite=Lax; Path=<callback base>`, `Max-Age` from the flow expiry clamped to at least
  1, name via `WithFlowCookieName`), the redirect with `Referrer-Policy: no-referrer`, off-route
  requests passed through. Verify the redirect, the cookie attributes and the unknown-provider 404:
  `go test -run TestOIDCAuthorize -count=1 ./httpsec/`.
- [x] 9.4 Implement the callback interceptor: GET on `/login/oauth2/callback/{provider}`, clearing
  the flow cookie only when `ErrFlowUnspent` is absent, issuing the handoff and redirecting to the
  allowlist-resolved destination with `handoff` set by `url.Values.Set`, `Referrer-Policy:
  no-referrer` and `Cache-Control: no-store`; or calling `WithCallbackSuccess` and issuing nothing.
  Refusals logged through the chain sampler under `oidc.callback`. Verify a table over the forged
  error link (no clearing header), genuine denial, successful callback (no session yet), unlisted
  destination falling back to `/`, and the consumer conveyance storing no handoff: `go test -run
  TestOIDCCallback -count=1 ./httpsec/`.
- [x] 9.5 Implement the redemption interceptor as magic-link does: POST on `/login/oauth2/handoff`
  reading the code from the body only; `sourceThrottled` first, a throttled or unattributable source
  refused with `ErrInvalidHandoff`; the policy check through `policyOutcome` with `factor.OIDC`;
  `guardRedemption` after `Redeem`; `recordSourceFailure` for every failure, with
  `WithHandoffCountRefusals(false)` exempting exactly policy denies and check refusals; the limiter
  from `resolveSourceGuard` (default 10 in 5 minutes, `WithHandoffRateLimit`, `WithHandoffLimiter`,
  nil refused); `WithHandoffRedeemer`. Verify a table over every scenario of specs "Policy
  decisions at redemption cannot be lost" and "Refused redemptions count against the per-source
  limit by default", the query-string code, and the throttled response; then run the mutations
  "`!evaluated` dropped", "`|| Outcome == Deny` dropped", "deny returned without the
  `policy.ErrPolicyDenied` fallback" and "refusals not recorded against the source guard" by hand:
  `go test -run TestOIDCRedeem -count=1 ./httpsec/`.
- [x] 9.6 Finish redemption through `completeLogin` with `session.WithExternalSession(...)` from task
  1.2, and answer with `oidcHandoffDocument` embedding `loginDocument` plus `next` re-resolved
  through the allowlist, written by `writeSuccessDocument` with `Cache-Control: no-store` and
  `Referrer-Policy: no-referrer`. Verify the created session carries the OIDC first factor and the
  federated fields from its first write, the body carries `access_token`, `valid_until` and `next`,
  a challenge consumes the code and returns the challenge error with a pending session, and the
  default exemption creates a session without a challenge (specs "A successful redemption
  establishes a federated session" and "OIDC logins are exempt from local MFA by default"): `go test
  -run TestOIDCRedeemSession -count=1 ./httpsec/`.
- [x] 9.7 Verify removing the exemption with `policy.WithMFAExemption` on both MFA policies, with
  `EnableMFA` wired, refuses a required-but-unenrolled user with the enrolment-required reason and
  keeps the code; and that the same classification without `EnableMFA` fails chain assembly: `go
  test -run TestOIDCRedeemMFAExemptionRemoved -count=1 ./httpsec/`.
- [x] 9.8 Implement the back-channel interceptor: POST on `/logout/oauth2/backchannel/{provider}`
  with a `logout_token` form parameter and no credential; `sid` dispatching to
  `DeleteByExternalSession(issuer, sid)`, subject-only to `FindByExternal` then
  `DeleteByUserAndExternalIssuer`, or `DeleteByUser` under `WithBackchannelLogoutScope(AllSessions)`;
  an unlinked subject a success; 200 with an empty body and `no-store` for a verified token;
  `ErrInvalidLogoutToken` with `no-store` otherwise; store, link-store and key-set failures
  returned as themselves; counts to the chain sampler under `oidc.backchannel`. Verify a table over
  every scenario of specs "The back-channel endpoint ends sessions named by a verified token", "A
  subject-only logout is scoped to its issuer by default", "Back-channel responses reveal nothing
  about sessions or users" and "Logout-token replay is bounded by issued-at"; then run "`AllSessions`
  as the default" and "`sub` checked before `sid`" by hand: `go test -run TestOIDCBackchannel
  -count=1 ./httpsec/`.
- [x] 9.9 Wire RP-initiated logout: `EnableOIDCLogin` supplies its manager as the logout's
  end-session builder when `LogoutDeps.EndSession` is nil, `WithOIDCRPInitiatedLogout(false)`
  turns that off, and an explicit `LogoutDeps.EndSession` wins. Verify a table over the default on,
  the consumer turning it off, and a consumer builder taking precedence: `go test -run
  TestOIDCRPInitiatedLogout -count=1 ./httpsec/`.

## 10. The test module: identity provider, adapters and a real provider

- [x] 10.1 Build the in-process test identity provider in `test/oidc`: discovery, key set and token
  endpoints over TLS, rotatable keys, call counters, both client authentication methods, and a
  token builder that emits every malformed token of design decision 15 plus logout tokens. Verify
  its own test drives one full authorize → callback → redeem through a `net/http` chain against it
  and asserts the session: `cd test && go test -run TestTestIdentityProvider -count=1 ./oidc/`.
- [x] 10.2 Add OIDC scenarios to `test/httpsecconformance` (authorize, callback, redemption,
  back-channel, logout with an end-session URL) and run them through the `net/http`, gin and fiber
  adapters. Verify the new rows fail before the scenarios are registered with the adapters' OIDC
  wiring, then pass on all three (spec "Endpoints fail in a way that separates bad input from
  outages", "Every adapter answers alike"): `cd test && go test -run 'TestConformance(NetHTTP|Gin|Fiber)'
  -count=1 .`.
- [x] 10.3 Add a `RunTestKeycloak` helper to `test/testutils.go` following the `use-testcontainers`
  skill, and one test covering discovery, the authorize redirect, the code exchange with both client
  authentication methods, ID token verification and a back-channel logout. Verify it passes with
  Docker available; without Docker, report it as not run: `cd test && go test -run TestKeycloak
  -count=1 .`.
- [x] 10.4 Make ginsec commit a refusal mapped to 404, with an empty body, when gin matched no route
  for the request (`gin.Context.FullPath() == ""`), in the middleware and the guards; every other
  refusal stays set-but-uncommitted. Verify a ginsec table that an unrouted 404 refusal answers an
  empty body, that a 404 on a matched route and an unrouted 401 stay uncommitted (consumer error
  middleware still renders them), and that the gin conformance row "OIDC authorize for an unknown
  provider is 404" passes (spec `framework-adapters`, "gin refusals reach the error channel and fail
  closed"): `cd ginsec && go test -run 'TestRefusal' -count=1 ./... && cd ../test && go test -run
  'TestConformance(NetHTTP|Gin|Fiber)' -count=1 .`.

## 11. Documentation, records and the gate

- [x] 11.1 Write the `oidc` package godoc and the new `httpsec` godoc, naming for every option the
  default it replaces and for every port what the library uses when the consumer supplies none.
  State the limits the design commits to documenting: trusted provider configuration and the client
  secret; per-process caches, flow store and rate limiter; the first request after expiry waiting a
  fetch; the handoff code in a URL and its fixed 60-second window; a refused code staying live;
  logout-token replay within the maximum age; the total MFA exemption; role sync removing roles on a
  provider misconfiguration; the mapped hash as a standby credential and mirroring's limits; the
  crash between provisioning and linking; and not rendering `err.Error()`. Add the OIDC section to
  `README.md`, including removing the `handoff` parameter with `history.replaceState`. Verify `go doc
  ./oidc` and `go doc ./httpsec EnableOIDCLogin` show each.
- [x] 11.2 Report to `durable-persistence` what this change needs from it, and record the flag in
  `design.md`'s Risks: link, flow and handoff tables matching `oidc.Link`, `oidc.Flow` and
  `oidc.HandoffRecord` (the handoff subject column holds the user reference); the store-conformance
  suites `RunLinkStoreSuite`, `RunFlowStoreSuite` and `RunHandoffStoreSuite`, including the
  zero-cutoff refusal; and a `session.Cipher` for the existing sealing store.
- [x] 11.3 Record in `design.md` any place where implementation had to depart from the revised
  design, as a decision naming the default and the override.
- [x] 11.4 Run the full gate across every module and confirm it is green: `make check`.
