# Changelog

All notable changes to scrty are recorded here, for every published module. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

All published modules are released in lockstep: one version number names the same release of each.

While the major version is 0, **no compatibility is promised**: any minor release may break a
published API, and each break is stated in its entry under *Changed*. Security fixes go to the latest
minor release only, as [SECURITY.md](SECURITY.md) states.

## [Unreleased]

### Added

- The browser session cookie: `httpsec.EnableSessionCookie` and its options. A host-only cookie name must carry the `__Host-` prefix.
- `session.WithSuccessorFromCaller`, which builds a rotation's successor from the caller's copy and refuses one whose stored record changed since it was loaded.

### Changed

- **BREAKING (behaviour): a strict `session.Sessions.Rotate` never extends a session, never moves it to another user, and keeps the stored first factor.** A copy naming another user is refused with `session.ErrConfig`.
- **BREAKING (behaviour): MFA verification and re-authentication answer 409 when the session's stored security state changed since the request loaded it**, on every chain.
- A cookie chain never binds sessions to a sender key (DPoP proof or client certificate); the OpenID Provider's tokens still bind.
- MFA verification and re-authentication rotate with a grace window on a cookie chain.

### Fixed

- A cookie name padded with Unicode whitespace was read as the session cookie.
- A password change on a cookie chain shortened the session's idle deadline.
- `Accept` q-values `1.` and `0.` were read as malformed.
- A sign-in over mTLS or with a DPoP proof on a cookie chain created a session its own cookie was refused with.

## [0.6.0] - 2026-11-25

### Added

- **A resource server: the chain accepts OAuth access tokens on an API's routes.**
  `httpsec.EnableResourceServer(resourceID, opts...)` (`ResourceServerOption`, ordered at
  `httpsec.OrderResourceServer`) takes tokens from one or more sources. `httpsec.FromProvider(op)`
  trusts the chain's own provider and checks the grant on every request, `httpsec.FromIssuer(issuer)`
  verifies a remote issuer's JWT access tokens against its key set, and
  `httpsec.FromIntrospection(issuer, endpoint, clientID)` asks an RFC 7662 endpoint on every request.
  A chain may enable several, each confined by `httpsec.WithPathPrefix` and naming its API by
  `httpsec.WithResourceAliases`.
  - **Defaults, each replaceable per source.** The audience must name the resource identifier
    (`WithSourceAudience` adds another spelling). The token must be bound to a DPoP key or a
    certificate (`WithUnboundTokens` opts one source out, never on a chain that requires DPoP, nor
    on `FromProvider`), and typed `at+jwt` (`WithUntypedTokens` accepts untyped JWTs beside a claim
    that tells them from ID tokens). Key sets are found from the issuer's metadata (`WithJWKSURL`),
    fetched through `outbound.New()` (`WithOutboundClient`), signed with `RS256` or `ES256`
    (`WithAlgorithms`), judged without clock skew (`WithClockSkew`). A verified JWT is valid until it
    expires (`WithJWTIntrospection` with `httpsec.IntrospectionConfig` introspects each one), and an
    introspection answer is not cached (`WithIntrospectionCache`). `WithOpaquePrefix`,
    `WithIntrospectionSecret` and `WithIntrospectionKey` (`httpsec.IntrospectionKey`) complete an
    introspection source.
  - **Four caller strategies, one per source.** `WithClaimsOnly` (the default for external sources: the
    caller is named `<issuer>#<subject>`, carries the token's scopes and no role), `WithClaimsMapper`
    (the consumer derives the caller; `httpsec.MappedCaller`), `WithLocalUsers` (the default for
    `FromProvider`: the subject's user, reloaded on every request) and `WithLinkedUsers` (the user
    found through the identity links by issuer and subject). An external subject is never taken as a
    local user identifier.
  - **Refusals are throttled** per client address and source, through `WithRefusalLimiter` or the
    chain's rate-limiter factory, before any key set is fetched or endpoint called.
  - **What a handler sees.** `identity.PrincipalFromContext` carries the token's scopes
    (`Principal.Scopes`, now also set on a user principal), and `httpsec.AccessTokenFromContext`
    returns the accepted token (`httpsec.AccessToken`). Two first-factor kinds, `factor.AccessToken`
    and `factor.ExternalAccessToken`, are added; neither is exempt from an MFA requirement; `policy.Input.AccessTokenAssurance`
    carries what the resource server established, and only the library mints it.
  - **Challenges.** `httpsec.ErrInvalidToken` is answered 401 with `error="invalid_token"`;
    `httpsec.ErrInsufficientScope` and `authorize.MissingScopesError` are answered 403 with
    `error="insufficient_scope"` and the scopes needed; `httpsec.ErrInsufficientUserAuthentication`
    and `httpsec.InsufficientUserAuthenticationError` are answered 401 with
    `error="insufficient_user_authentication"` and `max_age` (RFC 9470). The problem-details
    integration gains the types `invalid-token`, `insufficient-scope`,
    `insufficient-user-authentication` and `account-inactive`, and the member `scope`.
  - **Session-only endpoints refuse an access-token caller** on a covered path: password change,
    passkeys, second factors, saved codes, re-authentication, session renewal and management, the
    provider's resume and consent, the active-role switch and logout.
  - **Supporting API.** `oidcprovider.Provider.UserLoader` and `Provider.MaxAccessTokenSize`;
    `oidcprovider.AccessToken` gains `AuthTime`, `ACR` and `AMR`, and the introspection answer carries
    them; a grant records whether a second factor was verified at its sign-in and the federated
    evidence it rested on. The remote key-set cache is now shared between `authenticate/oidc` and the
    resource server.
- **Password rules you own.** `password.WithRule(name, check)` (`password.RuleFunc`) adds a rule that
  runs after the built-in lists and before the breach lookup, and refuses with a
  `password.RejectedError` naming the rule. A rule that returns an error fails closed as
  `password.ErrRuleFailed`.
- **An opt-in disclosure of inactive accounts.** `authenticate.ErrAccountInactive` identifies a correct
  password for an inactive account, and `httpsec.WithInactiveDisclosure()` answers it 403 in place of
  the uniform 401.

### Changed

- **BREAKING: `token.TypeFirstParty` is renamed `token.TypeSessionToken`.** Its value, `scrty+jwt`,
  is unchanged, so every token already issued still verifies. "First-party" now means only an
  OAuth client the provider trusts (`oidcprovider.Client.FirstParty`). Replace
  `token.TypeFirstParty` with `token.TypeSessionToken`. An `Issuer` asked for that type now says
  it "does not issue session tokens". Three scenario titles in the `token-issuance` spec keep the
  old wording; their text says "session token".
- **BREAKING: each migration set is now one baseline, and earlier databases must be recreated.**
  `migrate.SecurityState()` is the single migration `20261126000000_security_state` and
  `migrate.Identity()` is the single migration `20261126000000_identity`. Each creates only
  `scrty_` relations directly, with the schema v0.5.0 ended with, and records its version in a new
  default table: `migrate.SecurityStateVersionTable` is now `scrty_state_migrate` and
  `migrate.IdentityVersionTable` is now `scrty_identity_migrate`. A consumer's own `users` or
  `sessions` table no longer blocks an install. Pass `goose.WithTableName` to keep another version
  table name, as before.
  - **There is no upgrade path.** The baselines do not detect an earlier history. Against a database
    that holds `scrty_` relations (v0.3.0 to v0.5.0) the first `CREATE TABLE` fails on the existing
    relation and nothing is applied. Against a database that holds only unprefixed scrty tables
    (v0.2.x and earlier) they create new, empty `scrty_` tables beside them. Stop every instance and
    recreate the database, or drop scrty's relations and version tables, then start this release.
    Run the statements for the sets you use, in a schema you own (`CASCADE` makes the order
    irrelevant). Drop the version tables you have; those that do not exist are skipped:

    ```sql
    DROP TABLE IF EXISTS scrty_account_recoveries CASCADE;
    DROP TABLE IF EXISTS scrty_api_keys CASCADE;
    DROP TABLE IF EXISTS scrty_assigned_roles CASCADE;
    DROP TABLE IF EXISTS scrty_groups CASCADE;
    DROP TABLE IF EXISTS scrty_login_attempts CASCADE;
    DROP TABLE IF EXISTS scrty_login_failure_streaks CASCADE;
    DROP TABLE IF EXISTS scrty_mfa_enrolments CASCADE;
    DROP TABLE IF EXISTS scrty_oidc_flows CASCADE;
    DROP TABLE IF EXISTS scrty_oidc_handoffs CASCADE;
    DROP TABLE IF EXISTS scrty_oidc_links CASCADE;
    DROP TABLE IF EXISTS scrty_one_time_tokens CASCADE;
    DROP TABLE IF EXISTS scrty_op_access_tokens CASCADE;
    DROP TABLE IF EXISTS scrty_op_authorization_codes CASCADE;
    DROP TABLE IF EXISTS scrty_op_browser_sessions CASCADE;
    DROP TABLE IF EXISTS scrty_op_client_assertions CASCADE;
    DROP TABLE IF EXISTS scrty_op_clients CASCADE;
    DROP TABLE IF EXISTS scrty_op_consents CASCADE;
    DROP TABLE IF EXISTS scrty_op_device_authorizations CASCADE;
    DROP TABLE IF EXISTS scrty_op_grants CASCADE;
    DROP TABLE IF EXISTS scrty_op_pending_requests CASCADE;
    DROP TABLE IF EXISTS scrty_op_refresh_tokens CASCADE;
    DROP TABLE IF EXISTS scrty_organizations CASCADE;
    DROP TABLE IF EXISTS scrty_passkey_credentials CASCADE;
    DROP TABLE IF EXISTS scrty_passkey_user_handles CASCADE;
    DROP TABLE IF EXISTS scrty_password_history CASCADE;
    DROP TABLE IF EXISTS scrty_rate_limit_buckets CASCADE;
    DROP TABLE IF EXISTS scrty_recovery_codes CASCADE;
    DROP TABLE IF EXISTS scrty_resource_privileges CASCADE;
    DROP TABLE IF EXISTS scrty_roles CASCADE;
    DROP TABLE IF EXISTS scrty_sessions CASCADE;
    DROP TABLE IF EXISTS scrty_signing_keys CASCADE;
    DROP TABLE IF EXISTS scrty_user_attributes CASCADE;
    DROP TABLE IF EXISTS scrty_users CASCADE;
    DROP TABLE IF EXISTS goose_security_state;
    DROP TABLE IF EXISTS goose_identity;
    DROP TABLE IF EXISTS scrty_state_migrate;
    DROP TABLE IF EXISTS scrty_identity_migrate;
    ```

    The statements drop every table of both sets, security state and identity, and their data.
    The unprefixed names of v0.2.x and earlier (`sessions`, `users`, ...) are not in the list; drop
    those only if they are scrty's own.
  - **Going back to v0.5.0 is not supported.** Its migrations fail partway on a database this release
    migrated, on a relation that already exists. Recreate the database for an older release.
  - **One `goose down` drops a whole set and its data**, bounded by a 5 second `lock_timeout`.
  - **Applying a set from two replicas at once** fails the second on an existing relation, with
    nothing applied, and succeeds on retry. Pass `goose.WithSessionLocker` to serialise them.
- **BREAKING: the SSO callback answers `server_error` for an unclassified failure after a spent
  flow.** For a login parked by the provider under `WithOIDCProviderCompletion`, a failure that is
  neither a refusal nor an outage (a failed sign-in hook or `Apply`, a store failure) was a plain
  500. It is now a 303 to `<LoginURL>?req=<handle>&error=server_error`, with the request still
  parked, or to the client's redirect URI with `error=server_error`, `state` and `iss` under
  `WithOIDCFailToClient`, which ends the request. These keep their plain answer: an unspent flow, an
  invalid state, a caller that hung up, `ErrOIDCReauthenticate`, `oidc.ErrUnknownProvider`, a login
  that is not parked, and a login that fails the parked-request checks. A `server_error` answer
  writes one error-level log record, built by `diag.Failure`, that names the cause's Go type and
  never holds the error text, the handle, the state or the redirect target; alerting that watches
  5xx answers should also watch for it. No `AuthnLoginFail` event is emitted. There is no option to
  restore the plain 500.
- **BREAKING (behaviour): a recency guard judges an access-token caller by its token's authentication
  time.** Every guard that requires recent authentication (`RequireRecentAuthentication`,
  `RequireAuthenticationWithin`, and the gin and fiber guards) refused every access-token caller,
  because it has no session. A token whose sign-in is within the window now passes. A stale token, or
  one that states no authentication time, is refused with
  `*httpsec.InsufficientUserAuthenticationError`: 401 with `error="insufficient_user_authentication"`
  and `max_age`, not 403. It also matches `httpsec.ErrReauthenticationRequired`, so an `errors.Is`
  check keeps matching, but a handler reading the window through `*httpsec.ReauthenticationRequiredError`
  no longer finds it for an access-token caller. A session caller keeps the session's time and the
  403.
- **BREAKING (behaviour): logout refuses an access-token caller on a path a resource server covers.**
  It answered 200 and deleted nothing, so a client was told it had signed out while its grant lived on.
  It now refuses with `httpsec.ErrAuthenticationRequired`. A client holding only an access token signs
  out through the provider's revocation (RFC 7009) and end-session endpoints. A chain that enables no
  resource server is unchanged.
- **BREAKING (behaviour): `authenticate.ErrAccountInactive` is now reachable beneath the uniform
  failure.** A correct password for an inactive account was refused as `ErrAuthenticationFailed` alone.
  The password provider now joins `ErrAccountInactive` beneath it, only after the password verifies, so
  `errors.Is(err, authenticate.ErrAccountInactive)` holds in a consumer's own error handler. The
  status, headers and problem type are unchanged by default (a wrong password and a concealed inactive
  account still look alike), and `httpsec.WithInactiveDisclosure()` discloses it. A consumer that
  treated every `ErrAuthenticationFailed` identically but matched exact error values needs `errors.Is`.
- **Grants, authorization codes and browser sessions from before the upgrade carry no second-factor
  marker.** `migrate.SecurityState()` now ends with `20261127000000_sign_in_proof`, which adds
  `second_factor_verified`, `external_provider`, `external_amr` and `external_acr` to
  `scrty_op_grants`, `scrty_op_authorization_codes` and `scrty_op_browser_sessions`, all nullable. Run
  it before starting this release. An MFA-required user whose grant predates it signs in again once,
  and a resource server judges such a grant as having verified no second factor.
- **A consumer's per-request policy may now receive a request with no session.** An access-token
  caller has none, and a policy of the `policy.PerRequest` phase is evaluated for it. A policy that
  dereferenced the session must check for its absence.

## [0.5.0] - 2026-11-24

A minor release with behaviour changes, each stated under *Changed* with its opt-out where one
exists. Nothing in the API is removed, and no migration is needed.

### Added

- **A cancel endpoint for the login page.** `POST /authorize/cancel` under the provider prefix
  (`httpsec.OIDCCancel`, operation `httpsec.OperationOAuth2AuthorizeCancel`) ends a parked request
  with `access_denied`. It needs no signed-in session, and follows the resume endpoint's TLS, origin,
  flow-cookie and throttle rules. `oidcprovider.Provider.EndPending` (with `EndPendingInput`) is the
  call underneath.
- `oidcprovider.CodeTemporarilyUnavailable`, `CodeServerError` and `CodeUnsupportedTokenType`, and the
  revocation cause `CauseUnanswered`, for a code written but never handed out.
- `oidc.RelyingParty.AbortFlowNext` and `oidc.AbortedFlow`, which end a flow and report where the
  request was parked.
- `httpsec.WithOIDCLoginErrorParam` and `httpsec.DefaultOIDCLoginErrorParam` (`error`), the query
  parameter that carries the code back to the login page.
- **Opt-in hardening, all off by default:**
  - `oidcprovider.WithPendingRequestLimit(limit)` caps live parked requests and answers
    `temporarily_unavailable` at the cap. The store must implement
    `oidcprovider.PendingRequestCounter`, which the memory store and the SQL stores do.
  - `httpsec.WithOIDCThrottle429()` answers a throttled source at the token, revocation,
    introspection and device-authorization endpoints with 429 and `Retry-After`, in place of
    `invalid_client`.
  - `oidcprovider.WithStrictRevocation()` answers the revocation of a valid JWT access token with
    `unsupported_token_type`, in place of success with nothing revoked.
  - `httpsec.WithOIDCEntryRedirects()` sends a refused device user code back to the code-entry page
    with `result=invalid` or `result=throttled`, in place of a 400 or 429.
- A README note, "Scheduled jobs (later work)", listing every expiry task a deployment on durable
  stores must run. Durable stores are swept only when you run them.

### Changed

- **BREAKING (behaviour): a failed brokered login for a parked request returns to the login page.**
  With `WithOIDCProviderCompletion`, a failure at the SSO start or callback used to answer a problem
  body. It now answers 303 to `<LoginURL>?req=<handle>&error=<code>`, with `access_denied`,
  `temporarily_unavailable` or `server_error`, none naming an account. The request stays parked.
  `httpsec.WithOIDCFailToClient()` sends the error to the client's redirect URI instead, ending the
  request (a device request still returns to the login page). Nothing restores the problem body.
- **BREAKING (behaviour): resume failures that can be answered are answered at the redirect URI.** A
  store failure answers `server_error`, a client that lost the code grant `unauthorized_client`, and a
  client with no usable scope `invalid_scope`. A removed client or an unregistered redirect URI is
  still refused with no redirect. There is no opt-out.
- **BREAKING (behaviour): an expired request is answered within a grace window.** A request that
  expired, and is still bound to this browser, answers the client `access_denied` for 10 minutes past
  its expiry, where it was an unknown handle. Opt out with `oidcprovider.WithPendingRequestGrace(0)`;
  the window can be set from 0 to 30 minutes.
- **BREAKING (events): a refusal beside an outage emits the login-failure event.** A callback whose
  error is both a refusal and an outage emitted nothing, and now emits the event, for every login.
  There is no opt-out.
- **BREAKING (headers): bearer 401s carry a challenge.** On a chain with a built-in bearer, every 401
  the chain answers carries `WWW-Authenticate: Bearer`, with `error="invalid_token"` when a bearer
  token was presented and refused. Opt out with `httpsec.WithoutBearerChallenge()`.
- **A sign-in hook's `ErrUserInfoFailed` passes through as that outcome.** `oidc.ErrUserInfoFailed`
  returned by a hook now reaches the caller as the bare sentinel, a provider outage, in place of a
  broker failure, so a UserInfo outage inside a hook is answered as an outage.
- **`oidc.RelyingParty.Callback` returns `CallbackResult{Next}` when it fails after the flow is
  spent.** Only `Next` is set, read from the stored flow. A flow the store completes with a state
  other than the one presented is refused as `ErrInvalidState`, spent, with no `Next`.
- **A `MemoryPendingRequestStore` you build keeps expired records for 30 minutes past expiry**, the
  longest a grace window can be, so a store you construct never deletes a request a provider might
  still answer.
- **The pending-request sweep keeps the grace window.** The `oidc-provider.pending-requests` expiry
  task deletes a request only after its expiry plus the grace window, so expired rows stay up to twice
  as long by default. They are unusable. `WithPendingRequestGrace(0)` restores the earlier retention.

## [0.4.0] - 2026-11-24

Every addition below is opt-in: a provider with no sign-in hook, a chain without server-side
completion and a link store that implements neither new interface behave as before. Nothing breaks,
and no migration is needed.

### Added

- **Upstream access for a sign-in.** `oidc.Upstream` carries the access token of the token response
  that carried the verified ID token, bound to its subject, and prints redacted. `Upstream.UserInfo`
  makes one GET to the provider's UserInfo endpoint, checks that `sub` matches, and returns the members
  unchanged. A broker that wants it implements `oidc.UpstreamBroker` and names the providers it
  wants it for with `AcceptsUpstream`; every other provider's login calls `Broker` as before. The
  library's `oidc.Broker` accepts it only for its hooked providers, so a wrapper that embeds it by pointer under
  another name (a type alias such as `type libraryBroker = oidc.Broker`, embedded as `*libraryBroker`)
  and overrides `Broker` keeps that override on unhooked providers (and overrides `BrokerUpstream` too to
  intercept hooked sign-ins).
  - `oidc.Provider.UserInfoEndpoint` pins the endpoint, replacing the one in the discovery document
    (default: discovered, and dropped with a warning if off the issuer's origin).
  - Every UserInfo failure wraps `oidc.ErrUserInfoFailed`, except a cancelled or expired context, which
    returns the context's own error. The text never holds the token or the answer.
- **The sign-in hook.** `oidc.WithBrokerSignInHook(provider, hook)` lets a consumer decide, per login
  through one provider, which user an identity belongs to. The hook returns an `oidc.SignInDecision`:
  keep the linked user, adopt an existing one, or `Provision` a new one. Its writes go in the
  decision's `Apply`, which runs only after the broker accepts the decision.
  - A provisioning `Apply` on a first sign-in must create only, with fresh random references.
  - The broker keeps one link per user for each provider and issuer, on new and existing links.
    `oidc.WithBrokerSignInHookAllowManyLinks(provider)` lifts the rule.
  - A hooked provider brokered without upstream access fails with `oidc.ErrUpstreamRequired`.
    A hook on a provider that also sets `WithBrokerJIT`, `WithBrokerClaimMirror` or
    `WithBrokerRoleSync` is a configuration error from `oidc.NewBroker`.
- `oidc.LinkLister` (`ListByUser`) and `oidc.LinkRemover` (`DeleteLink`, one link), optional beside
  `oidc.LinkStore`. The memory store and `sqlstore`, `pgxstore` and `gormstore` implement both, with
  no migration. A hook over a store without them needs `WithBrokerSignInHookAllowManyLinks`.
- **Server-side completion of a federated sign-in.** `httpsec.WithOIDCProviderCompletion()` completes
  a parked provider sign-in on the server, so a login page needs no script and no session
  credential reaches the browser (only the provider's browser-session cookie is set). It needs the
  new `httpsec.OIDCDeps.Users` loader, and falls back to the handoff when a
  step is owed. It is off by default.
  - `oidcprovider.Provider.LoginURL()` reads the login page's address.
  - `oidcprovider.ResumeResult.Outcome`, a `oidcprovider.ResumeOutcome`, names what `RedirectTo`
    carries (such as consent, code or client error). Completion decides from it, so a client's redirect URI may
    carry any query parameter.

## [0.3.0] - 2026-11-23

A minor release: security administration (the `admin` package), scoped grants and a resource
catalogue, a per-request privilege memo, login by verified email, an opt-in active-role switch, the
OAuth device authorization grant, and the `scrty_` prefix on every table. It carries breaking changes,
listed under *Changed*, and new migrations in both sets (three security-state, two identity); read
*Changed* before upgrading.
Upgrade every scrty module to `v0.3.0`.

### Added

- **The device authorization grant (RFC 8628).** It is off by default, and a provider turns it on
  with `oidcprovider.WithDeviceAuthorization(entryURL, ...DeviceOption)`, which names the
  application's own code-entry page. A client then lists `oidcprovider.GrantDeviceCode`.
  - The chain serves the device authorization and code-entry endpoints when the grant is enabled.
  - The device options are `WithDeviceLifetime` (default 10 minutes), `WithDevicePollInterval`
    (default 5 seconds), `WithUserCodeFormat`, `WithUserCodeKey`, `WithUserCodeEntryLimiter`,
    `WithUserCodeEntryKeyer` (how code-entry sources are keyed, IPv6 by /64 by default) and
    `WithDeviceAuthorizationStore`. `WithUserCodeKey` is required with a durable store, and must be
    the same on every replica.
  - `Client.DeviceCompleteURI` (default off) lets a client receive `verification_uri_complete`.
    `Client.DeviceGrantsOutliveSignIn` (default off) keeps a device client's grants past the end of
    the sign-in that approved them. Without it a device grant follows Back-Channel Logout: one without
    `offline_access` ends with its sign-in.
  - Consent is always asked for a device request, and the consent page reads a `Device` view of it.
- `oidcprovider.DeviceAuthorizationStore`, the port that keeps device authorizations, and
  `MemoryDeviceAuthorizationStore`, the default. `sqlstore.NewDeviceAuthorizationStore`,
  `pgxstore.NewDeviceAuthorizationStore` and `gormstore.NewDeviceAuthorizationStore` keep them in
  PostgreSQL, across replicas.
- `Provider.UseUserCodeEntryLimiter`, which hands the provider the chain's rate-limiter factory and
  source keying, and `Provider.DeviceEntryURL`, the consumer's code-entry page. The chain calls the first
  as it is built, so its `WithRateLimiterFactory` and `WithIPv6SourcePrefix` reach code entry, and two
  chains over one provider with the same factory count entries together. A different factory,
  namespace or prefix fails `New` with `ErrConfig`.
- The chain's device endpoints, served only when the grant is on: `OIDCDeviceAuthorization`
  (`/oauth2/device-authorization`) and `OIDCDeviceEntry` (`/oauth2/device`), with the operations
  `OperationOAuth2DeviceAuthorization` and `OperationOAuth2DeviceEntry`, and the options
  `WithOIDCDeviceAuthorizationLimiter`, `WithOIDCDeviceAuthorizationBodyLimit` and
  `WithOIDCDeviceEntryBodyLimit`. A throttled code entry answers `ErrOIDCThrottled` (429).
- A GET gate at code entry: a GET carrying `user_code` claims it only when `Sec-Fetch-Site` is
  `same-origin`, or absent. Any other (`none`, `same-site`, `cross-site`) claims nothing and is sent
  with 303 to the consumer's entry page with the code prefilled. A POST to code entry is refused with
  403 unless `Sec-Fetch-Site` is `same-origin`, `none` or absent, with CSRF protection on or off. A
  code-entry page that would make that redirect loop fails `New`.
- The authorization server metadata lists `device_authorization_endpoint` and the device grant in
  `grant_types_supported` when the grant is on. The device endpoints carry no CORS headers.
- `Provider.AuthorizeDevice` and `Provider.EnterUserCode`, for an application that serves the
  endpoints itself. The throttle on code entry lives inside `EnterUserCode`.
- The security-state migration `20261122000000_oidc_provider_device`, for the device authorization
  table and the new grant columns. Apply it before using a durable store.
- Seven events: `DeviceAuthorizationIssued`, `DeviceAuthorizationClaimed`,
  `DeviceAuthorizationApproved`, `DeviceAuthorizationDenied`, `DeviceCodeExchanged`,
  `DeviceCodeReplayed` and `UserCodeEntryThrottled`. None carries a code.
- `Grant.Origin` and `Grant.SurvivesSignInEnd`, new fields every grant store keeps. A stored grant
  reads as a code grant that ends with its sign-in by the rule it always had.
- The `oidc-provider.device-authorizations` expiry task, which sweeps expired device authorizations.
- The README's "CLI clients" section.

- **Security administration: the `admin` package.** Services over ports, with scrty's identity stores
  (`sqlstore`, `pgxstore`, `gormstore`) as the default implementation, and ports a consumer's own store
  implements. **The services do not authorize:** they record who acted, but any caller reaching them
  can change any user or role, so guard every route that reaches them (`Guards.Require`). They are:
  - `admin.Users` (`NewUsers`): `List` with search, filters and an opaque cursor (`WithPageSize`,
    default 50), `Get`, `Create`, `Update`, `Deactivate`, `Reactivate`, soft `Delete` and
    `SetPassword` through the password policy and history (`WithPasswordPolicy`,
    `WithPasswordEncoder`, `WithIDGenerator`). Email is a user field, unique among live users ignoring
    case, with a verification time; a changed email is unverified unless the change names a time.
    Profile attributes are stored, returned and searchable by exact match (`WithAttributeLimits`).
  - `admin.Roles` (`NewRoles`): create, update, list by label, get, and delete, refused with
    `ErrStillAssigned` while assigned unless forced. The role name is an immutable key; a role carries
    a display name, a description and labels.
  - `admin.Grants` (`NewGrants`): read a role's grants and replace them per resource in one
    transaction, refusing a privilege or scope the catalogue does not list (`ErrUnknownPrivilege`).
  - `admin.Assignments` (`NewAssignments`): add, remove, list and mark primary, with optional start
    and end dates.
  - `admin.Importer` (`NewImporter`): import users with given values (identifier, password hash,
    active flag, times) by identifier only, idempotently, reporting an `ImportOutcome`.
  - Writes to one role's grants or one user's roles are serialised, and a stale `version` is refused
    with `ErrStaleUpdate`. The actor comes from the context (`ActorFrom`, `WithSystemActor`); a write
    with none is `ErrNoActor`.
  - One sentinel per reason: `ErrConfig`, `ErrNotFound`, `ErrAlreadyExists` (an `AlreadyExistsError`
    naming the field), `ErrStillAssigned`, `ErrStaleUpdate`, `ErrUnknownPrivilege`, `ErrInvalidInput`,
    `ErrNoActor`. Error text never carries a username, email, attribute value or password hash.
  - Common options `WithEventSink`, `WithAudit` (an `AuditSink` receiving before and after values,
    never a password hash), `WithClock` and `WithLogger`.
  - The identity stores implement the ports: `CreateUser`, `UpdateUser`, `SetActive`, `DeleteUser`,
    `SetPassword`, `CurrentPasswordHash`, `GetUser`, `ListUsers`, `ImportUser`, `CreateRole`,
    `UpdateRole`, `DeleteRole`, `GetRole`, `ListRoles`, `GetGrants`, `ReplaceGrants`,
    `AddAssignment`, `RemoveAssignment`, `ListAssignments`, `SetPrimary` and `LoadByEmail`, on
    `sqlstore`, `pgxstore` and `gormstore`.
- **Scoped grants and a resource catalogue.** `identity.Privilege.Scope` (`identity.Scope`,
  `ScopeAll`, `ScopeOwn`, and `EffectiveScope`, which reads a grant stored without one as `all`). A
  privilege granted only with `own` does not satisfy a plain check: `authorize.HasPrivilegeAnyScope`
  and `CheckAnyScope` ask for any scope and report it, and `HasPrivilegeFor` checks one record with an
  ownership check (`PrivilegeAttributes.Accept`). `authorize.NewCatalogue` declares resources and
  privileges in code (`Catalogue`, `CatalogueResource`, `CataloguePrivilege`).
- **Authorization at runtime.**
  - A per-request privilege memo: a role's privileges load at most once per request. The chain
    installs it by default; `httpsec.WithoutPrivilegeMemo` turns it off, and `authorize.WithRequestMemo`
    installs it outside the chain.
  - `authorize.AllOf`, beside `AnyOf`, and `Guards.Require` in `httpsec`, `ginsec` and `fibersec`,
    which guards a route with any `authorize.Requirement`.
  - A bulk check, `authorize.HeldPrivileges`, answering which of several privileges the caller holds
    on one resource and with which scope (`Holdings`, `Holding`), through the optional
    `PrivilegeInspector` port (`InspectPrivileges` on `PrivilegeAuthorizer` and `FirstOf`;
    `ErrInspectionUnsupported` otherwise).
  - One sentinel per denial reason, each still matching `authorize.ErrAccessDenied`:
    `ErrNotGranted`, `ErrWrongScope`, `ErrNotOwner`, `ErrNoSubject`, `ErrNoActiveRole`.
- **Login by email**, off by default: `authenticate.WithEmailLogin()` on the password provider, with a
  user loader that also implements `identity.EmailLoader`. Only a verified email of a live user logs
  in. The chain's login and Basic endpoints resolve the identifier first
  (`authenticate.IdentifierResolver`, `ResolvedIdentifier`, `ResolverOf`, `WithResolved`,
  `ResolveIdentifier` and `EmailLogin` on the provider and on `FirstOf`), so the username and the
  email share one lockout budget. A failure is also recorded under the email as typed, for the automation
  challenge, through the new optional port `policy.UnreportedAttemptRecorder`, which the lockout
  view implements, so a lock, hold or clear is reported and evented once, under the account. `identity.Details` gains `Email`, `EmailVerifiedAt` and
  `EmailVerified`.
- **Switching the active role**, off by default: `httpsec.WithSwitchableRoles()` and
  `Chain.SwitchActiveRole`, refusing with `ErrRoleNotHeld` or `ErrRoleSwitchingDisabled`. The choice
  is recorded as `session.Session.SelectedRole` through the optional `session.RoleSelector`
  (`Sessions.SelectRole`, `Sessions.SelectsRoles`, `MemoryStore.SelectRole`; every shipped store
  implements it) and re-checked on every request.
- `identity.PrincipalFromDetailsAt` and `AssignedRole.ValidAt`, which apply a grant's start and end
  dates.
- Administration events: `event.Event` gains `Actor`, `Target` and `Changed`, and the types
  `UserCreated`, `UserUpdated`, `UserArchived`, `UserDeleted`, `UserReactivated`, `UserImported`,
  `PrivilegePermissionsChanged`, `AuthzChange`, `AuthzAdmin`, `IdentifierConflict`
  (`scrty_identifier_conflict`) and `ActiveRoleSwitched` (`scrty_active_role_switched`).
- The identity migration `20261125000000_scrty_administration` (email, its verification time and a
  unique index on live users' lower-cased emails, soft deletion, versions, role display names,
  descriptions and labels, grant scopes and profile attributes) and the
  security-state migration `20261125000000_scrty_selected_role` (the session's selected role).
- In the `test` module: `test/admin` (the administration conformance suites `RunConformanceSuite`,
  `RunUserSuite`, `RunRoleSuite`, `RunImportSuite`), `identity.RunEmailLoaderSuite` and
  `storetest.RunSessionRoleUnstorable`.
- The README's "Administration", "Resources, privileges and scopes", "The per-request privilege
  memo", "Login by email" and "Switching the active role" sections.

### Changed

- **BREAKING: every table, index and sequence scrty's migrations create is now named `scrty_<name>`.**
  The prefix is fixed. Migration `20261124000000_scrty_prefix`, in each set, renames the relations in
  place, so rows, indexes and constraints are kept. The stores, the rate limiter and the gorm models use
  the new names. The version tables `goose_security_state` and `goose_identity` are unchanged.
  - Security-state set: `account_recoveries`, `api_keys`, `login_attempts`, `login_failure_streaks`,
    `mfa_enrolments`, `oidc_flows`, `oidc_handoffs`, `oidc_links`, `one_time_tokens`,
    `op_access_tokens`, `op_authorization_codes`, `op_browser_sessions`, `op_client_assertions`,
    `op_clients`, `op_consents`, `op_device_authorizations`, `op_grants`, `op_pending_requests`,
    `op_refresh_tokens`, `passkey_credentials`, `passkey_user_handles`, `rate_limit_buckets`,
    `recovery_codes`, `sessions` and `signing_keys` become `scrty_` plus the same name.
  - Identity set: `assigned_roles`, `groups`, `organizations`, `password_history`,
    `resource_privileges`, `roles` and `users` become `scrty_` plus the same name, and the sequence
    `password_history_seq_seq` becomes `scrty_password_history_seq_seq`.
  - To upgrade, stop every replica running v0.2.x or earlier, apply the security-state set, apply the
    identity set if you use it, then start the new release. To roll back, stop the new release, roll back
    the identity rename (if you use the identity set), roll back the security-state rename (one version
    down per set), then start the previous release.
  - The rename migration waits for each table lock at most 5 seconds (`lock_timeout` bounds each wait,
    not the whole migration). With old replicas still running it could wait that long once per table,
    which is why they must be stopped first. A run that hits the bound fails with nothing renamed, and
    you can retry it.
  - A new binary against a database that was not renamed is refused when the limiter factory's `Verify`
    runs: the error wraps `ratelimit.ErrConfig` and names `scrty_rate_limit_buckets`.
  - Consumer SQL, reporting queries, function bodies and `pg_dump -t` / `--table` filters that name
    scrty's tables must be updated. Grants, row-level security policies and views reference tables by
    OID, so they follow the rename and need nothing.
  - To keep scrty's tables apart from your own, use a PostgreSQL schema and a `search_path`.
- The grant store keeps a revocation 31 minutes, where it kept it 11, so that a revocation outlives the
  longest device authorization.
- **BREAKING (behaviour): a soft-deleted user is not found.** scrty's identity stores load a user that
  `admin.Users.Delete` marked deleted as `identity.ErrUserNotFound`, by username and by identifier, so
  it cannot log in or be resolved by a session.
- **BREAKING (behaviour): a role assignment's start and end dates are enforced.** The chain builds the
  principal with `identity.PrincipalFromDetailsAt` at its clock, so an assignment before its start or
  after its end no longer reaches the principal and no longer authorizes. Before, the dates were
  carried and never checked.
- **BREAKING (behaviour): provisioning refuses a username that is another live user's email**,
  ignoring case, with `identity.ErrUserExists`. A federated first login whose username is a local
  user's email now fails instead of creating a second user the email would also name. The identity
  ports still discard an email given to `Provision` or `Update`; only the administration services and
  import set it.
- **BREAKING: two migrations.** Apply both before starting the release:
  - identity set, `20261125000000_scrty_administration`: `scrty_users` gains `email`,
    `email_verified_at`, `deleted_at` and `version`, with a unique index on `lower(email)` among live
    users; `scrty_roles` gains `display_name`, `description`, `labels` and `version`;
    `scrty_resource_privileges` gains `scope` (default `all`); profile attributes get the new table
    `scrty_user_attributes`. **If you added an `email` column to `scrty_users` yourself, rename or drop it
    first:** otherwise the migration fails, atomically, and changes nothing.
  - security-state set, `20261125000000_scrty_selected_role`: `scrty_sessions` and
    `scrty_op_refresh_tokens` gain `selected_role`.
  - Rolling back the identity migration drops emails, attributes, scopes, versions, labels and
    deletion marks.
- **BREAKING (behaviour): the password provider refuses an account with an empty username.** A user loader that returns
  one, by username or by email, with email login on or off, is answered as for an unknown user:
  `authenticate.ErrAuthenticationFailed` after the same decoy password work, with a warning whose
  reason is `user-without-username`. Before, such an account logged in under a blank username.
  `identity.UserLoader` now states that a user it returns carries its username. scrty's identity
  stores always do; **a consumer's own loader that leaves `Details.Username` empty must fill it**, or
  every login through it fails.
- `policy.AttemptStore` states that identifiers match exactly: a store must not fold case. A store
  that does counts a failure twice when a login's typed identifier and its account differ only in
  case, and so locks sooner than configured.
- **BREAKING (API): `event.Event` is no longer comparable**, because its new `Changed` field is a
  slice. Code that compares events with `==` or uses them as map keys must compare fields instead.
- **BREAKING (API), `test` module: `test/identity.Fixture` gains `SeedEmail` and `SoftDelete`.** A
  consumer's own fixture for the identity conformance suite implements both.

### Security

- An authorization-code replay no longer revokes a grant bound to a client certificate unless the
  replay presents the certificate. Before, a replay was judged by the DPoP key alone, so anyone holding
  a used code could end a certificate-bound grant.
- User-code entry charges its throttle before it looks the code up, and refunds what was not a wrong
  code, so a concurrent burst from one source is looked up no more often than the limit allows.

## [0.2.1] - 2026-11-22

A patch release that raises two dependency floors. No scrty API or behaviour changes. Upgrade every
scrty module to `v0.2.1`.

### Changed

- `github.com/kartaladev/scrty/httpsec/fibersec` and `github.com/kartaladev/scrty/test` require
  `github.com/valyala/fasthttp` `v1.79.0` (was `v1.78.0`).
  - The fasthttp release notes list request-parsing, connection-reuse, redirect and compression
    hardening under "Security fixes and hardening". A fiber application's server runs this code.
  - Neither fasthttp nor scrty has published an advisory for `v1.78.0`, so this entry records a
    hardening upgrade, not a fixed vulnerability.
  - An application that already requires `v1.79.0` or later is unaffected.
- `github.com/kartaladev/scrty/expiry/sweep` requires `github.com/go-co-op/gocron/v2` `v2.23.2` (was
  `v2.23.1`).

## [0.2.0] - 2026-11-22

A minor release with breaking changes, each stated under *Changed*. It adds the `httpsec/prblmsec`
module, which ships for the first time. Upgrade every scrty module to `v0.2.0`.

### Added

- **`github.com/kartaladev/scrty/httpsec/prblmsec`.** A new module that renders the chain's refusals
  as RFC 9457 problem details through `github.com/kartaladev/prblm`. It is opt-in: nothing changes
  for an application that does not mount it.
- `httpsec.LookupStatus`, which reports the HTTP status the chain maps an error to and whether it
  maps one at all.
- `httpsec.ChallengeError.TokenType`, the token type a challenge names.
- `ginsec.WithRefusalsRendered`, an option that leaves a chain's refusals to the application's error
  middleware, including a 404 for an unrouted path.

### Changed

- **BREAKING** `ginsec.Middleware` takes options after the chain (`...Option`). Every call compiles
  unchanged, but code that stores it as a `func(*httpsec.Chain) gin.HandlerFunc` value no longer
  compiles.
- `httpsec` sets `Cache-Control: no-store` on any response refused with a `*ChallengeError` that
  carries a `Token`. It replaces any cache policy that an outer middleware or an earlier interceptor
  set, so a credential handed out with a challenge is never cacheable. A challenge without a token
  leaves `Cache-Control` as it was. An error handler that sets `Cache-Control` again after the
  refusal overrides this.
- A challenge offered through an `As` method behind a typed-nil `*ChallengeError` is now found, and
  an error chain of more than 1,000 links is unrecognised by `httpsec.LookupStatus` and
  `httpsec.StatusForError` (status 500, not recognised).
- **BREAKING (records).** Where a component writes its records is now decided when each record is
  written. In order: the component's own logger option, else the logger of the `httpsec` chain
  handling the request (`httpsec.WithLogger`), else `slog.Default()` as it is at that moment.
  - A component without a logger option, used inside a chain, now writes to the chain's logger and
    is filtered by its level. A chain logger at Warn drops the Info and Debug records that used to
    reach the default.
  - `slog.SetDefault` called after wiring is honoured. Before, each component kept the default it
    saw at construction.
  - The same component writes to the chain's logger inside a chain and to `slog.Default()` outside
    one. A chain answers its logger to components only when `httpsec.WithLogger` was given.
  - To keep the old destination, pass `slog.Default()` to the component's logger option.
  - The chain-built source guards' suppressed-records summary now reads `ratelimit: refusal records
    suppressed` with a `flow` attribute (it read `httpsec: refusal logs suppressed`). A consumer
    `WithRefusalLogReporter` still receives it.
  - A sampler's suppressed-count summary goes where that key's own records went, so a summary that
    names a user never reaches another chain's log. Before, it went to the last logger the component
    had resolved.
- **BREAKING (configuration).** A nil logger option now fails construction with the component's
  `ErrConfig`, naming the option. These options ignored nil before, which meant "use the default" or
  "do not log": `authenticate.WithPasswordLogger`, `apikey.WithLogger`, `session.WithLogger`,
  `lockout.WithLogger`, `policy.WithMFALogger`, `policy.WithMFARequirementLogger`,
  `magiclink.WithLogger`, `passkey.WithLogger`, `recovery.WithLogger`, `recovery.WithCodesLogger`,
  `onetime.WithLogger`, `notify.WithSMTPLogger` and `notify.WithQueueLogger`. The OpenID Provider's
  `WithLogger` now refuses a typed nil as well. To get the default, leave the option out. The other
  logger options already refused nil, as `redisstore.WithLogger` does.
- **BREAKING (consumer errors).** An error returned by a consumer-supplied port (a store, limiter,
  loader, sender, authenticator, hook, refusal check, write function, key source, signer or the
  `http.Client` behind the outbound calls) is read once where it enters the library. A walkable
  error passes unchanged. An error that cannot be walked (a cycle, a fan-out, a panicking `Unwrap`)
  is replaced by a fixed error, one Error record is written, and the site answers as it does when
  that dependency is down. A store or user loader that answers neither a record nor an error is now
  a dependency failure, never a missing record or user. Before, a hostile error could make a flow
  treat a fault as "not found", "refused" or "unsupported".
- **BREAKING (identifier generators).** An `id.Generator` that answers the nil identifier with no
  error is now a failing dependency at every place the library asks it for an identifier, the
  `sqlstore`, `pgxstore` and `gormstore` backends included. The caller sees that site's own failure
  (the OpenID Provider's `server_error`, a store's failure error, a refused issuance), and nothing
  is stored under the nil identifier. The session family keeps its configuration error.
- A panic in consumer code that the library runs on a goroutine of its own is recovered, with one
  Error record, instead of ending the process. The site then answers its outage and carries on: the
  WebAuthn metadata refresh (`passkey/webauthn`; registration is refused), the OIDC relying party's
  discovery and key-set fetches (`ErrDiscoveryFailed`), the `signingkey` rotation loops, the memory
  `session` store's housekeeping, and the `expiry/sweep` scheduled jobs (locker, observer, clock).
- The `prblmsec` module requires `github.com/kartaladev/prblm` v0.3.0, and the test module requires
  its `ginprblm` and `fiberprblm` adapters at v0.3.0. prblm now bounds its own walks. Its hooks
  receive a note wrapping `prblm.ErrUnwalkableError` instead of `*PanicError` reports, a `WithStatus`
  hint joined beside a sentinel is decided in `errors.Is` order, and typed-nil pointers in a chain
  are skipped.
- Dependencies are updated across the workspace modules: `gofiber/fiber/v3` 3.7.0 (its static
  middleware now confines symlinks by default), `valyala/fasthttp` 1.78.0,
  `klauspost/compress` 1.20.4, `golang.org/x/crypto` 0.59.0, `golang.org/x/sync` 0.25.0,
  `golang.org/x/mod` 0.43.0 (tools), `pressly/goose/v3` 3.30.1, `jackc/pgx/v5` 5.13.0 and
  `go-co-op/gocron/v2` 2.23.1.

### Fixed

- `httpsec.LookupStatus` and `httpsec.StatusForError` no longer hang, crash or panic on a cyclic,
  fanned-out or panicking error chain, or on a typed-nil `*ChallengeError` or
  `*password.RejectedError` in it. They read the chain once, within 1,000 entries, and recover a
  panicking `Unwrap`, `Is` or `As`. An unreadable chain is unrecognised (500) and writes one
  redacted Error record. The `prblmsec` mapper and `fibersec` classify through the same bounded walk.
  Consumer code that calls stdlib `errors.Is` or `errors.As` on the same error is not protected.
- Refusal-path reads of an error (request cancellation causes, a consumer `httpsec.Request`'s body
  read, the outbound client's transport and body errors) use the same bounded walk, so a hostile
  error no longer hangs or crashes the request.
- Hostile consumer-port errors no longer change a security outcome. Each of these used to read a
  cycle or fan-out that claimed "not found", "refused" or "unsupported" as that answer:
  - the authenticator chain `authenticate.FirstOf` skipped a delegate and authenticated through the
    next one, and an `authorize.FirstOf` chain skipped a consumer authorizer, so the next one could grant
    access;
  - the OIDC provider's code exchange issued tokens, a code replay revoked nothing, a refresh revoked
    the grant on a user-loader fault, and revocation and introspection answered as if the token store
    had worked;
  - the OIDC broker provisioned a duplicate user, back-channel logout ended nothing, and a consent
    store fault parked the request at the consent page;
  - passkey sign-in and the passkey second factor answered a credential-store fault as an unknown
    credential, passwordless login answered a user-loader fault as an unknown user, and recovery and
    magic-link flows no longer log or refuse a store fault as an unknown user;
  - step-up verification charged nothing for a refusal, and the sealed MFA store read
    `ErrAlreadyEnrolled` where it had not been returned;
  - magic-link redemption charged the client's source for a hostile consumer check, and MFA
    enrolment answered 500 and charged its limiter twice where a plain outage answers 401.
- The expiry sweeper no longer crashes the process when a consumer error's `Is` method panics on a
  scheduler goroutine, and a lock answered as nil no longer panics `gocron`. A scheduler timer that
  never fires no longer hangs shutdown, and the memory `session` store's housekeeping no longer
  stops silently on a nil timer channel.
- The OpenID Provider no longer stores an authorization code under the nil grant family when the
  identifier generator answers the nil identifier, so one family can no longer span users' grants.
  The code exchange and a replay refuse a stored code that names the nil family, and a store that
  answers neither a pending request nor a browser session no longer causes a nil dereference.
- The store backends no longer write a row under the nil identifier. Before, a nil identifier could
  overwrite an existing signing key or replace a recovery-code set.
- Hostile errors no longer hang their caller where the library handed them back raw: the password
  policy's write and context-words errors, the password authenticator's event-id generator, the
  signing-key manager's store errors, the token generator's key-source and signer errors, and the
  sealed MFA store's cipher errors. A random-source error is no longer rendered eagerly by
  `fmt.Errorf` before it is checked.
- A consumer `slog.Handler` that panics no longer ends the process from the queued notifier's
  workers or the sign-in notice goroutine, and a consumer clock that panics no longer ends it from
  the OpenID Provider's client-key-set fetch, which now answers a dependency failure and no longer
  calls the clock while holding its lock. A panicking handler loses only that record.
- A dependency's error text no longer reaches the returned error of TOTP enrolment, the MFA
  emailed-code draw, one-time token issue, the `session` manager's identifiers and CSRF token, or
  the SMTP sender's connection deadline. Each carries fixed library text, and `errors.Is` still
  finds the cause.
- `notify.NewSMTPSender` refuses a default sender (`WithSMTPFrom`) that contains a carriage return
  or line feed, wrapping `ErrUnsafeHeaderValue`. Such a value was written unchecked into the `From`
  header of every message that named no sender of its own.

## [0.1.1] - 2026-11-11

A patch release that fixes three security defects in `v0.1.0`, and retracts `v0.1.0`. Upgrade every
scrty module to `v0.1.1`.

### Security

All three affect the `httpsec` chain in `github.com/kartaladev/scrty` `v0.1.0`.

- **A fiber application could serve a path its authorization rules never approved.** Fiber removes
  `.` and `..` segments before routing, while the chain's rules read the path as sent. So a
  `/public` rule permitted `GET /public/../admin/users`, and fiber served it from the `/admin/users`
  handler. Encoded spellings (`%2e%2e`, and segments joined by `%2F` when `UnescapePath` is set)
  did the same. The chain now refuses such paths on every adapter (see *Changed*).
- **The recovery cool-down could be bypassed the same way.** On fiber, `/x/../account/delete`
  reached a route the cool-down marks while the cool-down was in force.
- **A consumer authenticator placed after the gates skipped them.** An authenticator registered past
  the recovery, enrolment, second-factor and password-change gates could publish a session those
  gates never judged. A session still owing a second factor, an enrolment or a password change then
  reached the handler with 200. A second chain run inside the first chain's gates, mounted through
  any adapter, could do the same with its own authenticator. `Exchange.PublishSession` now refuses a
  session while a request is inside the chain's gates, or inside another chain's gates that enclose
  this run, unless the publishing chain enables every gate the enclosing chain enables, so that its
  own gates judge what it publishes. The reverse nesting is closed too: a chain with gates mounted
  inside a chain without them never judged the session the outer chain had published, so its
  handler could serve a session still owing a second factor. Its gates and authorization stage now
  judge that session. As defence in depth, the authorization stage refuses a session that
  still owes the challenge of a gate the chain enables, with that gate's own error.

### Changed

- **BREAKING (request handling).** The chain answers `400` (`httpsec.ErrMalformedRequest`) to a
  request whose path holds a `.` or `..` segment, sent as is or percent-encoded, or whose
  percent-encoding does not decode. The check runs after client resolution, whose own refusal wins
  when both apply, and before any interceptor, on every adapter. It has no opt-out, and the 400
  carries the same security headers as any other refusal. Browsers never send such paths.
- **BREAKING (configuration).** `WithLogger`, `WithClock`, `WithPolicyEngine`,
  `WithRateLimiterFactory` and `WithErrorHandler` given more than once now fail `httpsec.New`, where
  the last value used to win silently. `EnableAuthorization` keeps its last-wins authorizer, and now
  refuses a nil authorizer in any of its calls.
- **BREAKING (configuration).** `Exchange.PublishSession` returns an `httpsec.ErrConfig` error, and
  publishes nothing, when a session is published after the chain's gates have begun, or by a chain
  run inside another chain's gates that lacks one of that chain's gates. A handler's in-process
  forward through the same chain, or through a chain with the same gates, still publishes. Register a consumer authenticator at `OrderBearerToken`, no
  later: the recovery cool-down, just after it, judges a request by the session it carries when it
  runs. Mount a second chain outside the first chain's gates, or authenticate in the outer chain.
- One chain mounted twice on a request, such as on a gin engine or fiber application and again on a
  group, now runs once. The second mount lets the request through as the first one judged it, so a
  middleware between the two mounts that changes what a rule reads is not judged again. Two
  different chains still both run.
- An interceptor that keeps `next` and calls it after its run has returned, or a terminal that calls
  `next` of its own run, now gets an `httpsec.ErrConfig` error instead of running the terminal again.
- After the chain's step returns, an exchange's context, `Session` and `Authentication`, and the
  rest of its per-run state, are what they were before the run, including after a recovered
  panic. Code that read them after the step returned used to see the run's state, and an exchange
  run many times grew its context on every run. Read a run's state inside the terminal. An exchange
  refused once and run again now reports its second refusal too.
- The chain builds its interceptor fold once, when it is constructed, instead of on every request.
  With eight interceptors a request now allocates as much as with none.
- Token verification (`token.Verifier`) and the OIDC provider's ID token hint check refuse a token
  whose header names no `alg`. `token.Verifier` accepted one on `v0.1.0`, against its documentation;
  the hint check began accepting one with jwx 4.6.0. The signature was always checked under the
  algorithm recorded on the key, so neither let a token through without the issuer's key.
- Store and service calls that must finish even if the client hangs up now have a deadline where
  they had none: 5 seconds for a write, and 10 seconds for revoking a session, a session family or a
  credential. They still outlive the client's cancellation. When the deadline passes, the call
  fails as a store error from that call already did, and the failure is logged as an outage, not
  as the client leaving. Calls that already had a bound keep it. Rate-limiter calls, session end
  observers, the event sink and notification senders are not bounded by the library: the limiter
  and the sender bound themselves, and an observer or sink bounds its own work. A lockout observer
  shares the 5-second bound of the chain's failed-attempt record or reset that runs it. A consumer-supplied WebAuthn metadata fetch now receives a
  context with a deadline of `outbound.DefaultTimeout` (10 seconds). A fetch that runs past it
  refuses the registration, as any metadata failure does.
- `notify.SMTPSender.Send` returns an error that matches the context's error (`context.Canceled`
  or `context.DeadlineExceeded`) when the caller's context ended during the send. Such a send is
  logged at debug level, as a hang-up, not as a failed delivery. A timeout of the sender's own still
  returns the network error.
- Exported signatures use descriptive parameter names (no API change).
- Dependencies: `github.com/lestrrat-go/jwx/v4` 4.6.0; `github.com/testcontainers/testcontainers-go`
  and its postgres, redis and mailpit modules 0.45.0 (the `test` module only). With jwx 4.6.0 a
  token's negative `nbf` or `iat` parses as a date before 1970 instead of being refused, and a
  malformed string date is refused when the token is parsed.

## [0.1.0] - 2026-11-09

The first release. Nothing was tagged before it, so the items under *Changed* describe what differs
from the earlier, untagged tree that this release replaces. Items marked **BREAKING** change a public
signature, a default, or how stored data behaves.

### Added

**`github.com/kartaladev/scrty` (root module).** Production builds carry no web framework, database driver, scheduler or test tooling; those live in the nested modules.

- Authentication (`authenticate`): a first-of-many authenticator; password sign-in with scrypt,
  bcrypt and Argon2id encoders (`authenticate/password`); API keys (`authenticate/apikey`); magic
  links (`authenticate/magiclink`); passkeys, over a verifier port (`authenticate/passkey`); a
  second factor after the first (`authenticate/mfa`); and sign-in through external OpenID Connect
  providers (`authenticate/oidc`).
- Authorization (`authorize`) and the identity ports a consumer implements to supply users, roles and
  links (`identity`).
- Sessions with rotation, renewal and reuse detection (`session`), and signed tokens
  (`token`), with signing-key management (`token/signingkey`) and single-use credentials
  (`token/onetime`).
- Rules a deployment applies around authentication (`policy`), account lockout (`policy/lockout`),
  and a failure rate-limit port with an in-memory limiter (`ratelimit`).
- Account recovery with two independent proofs (`recovery`), and required second-factor enrolment.
- The security chain in front of any HTTP handler (`httpsec`), with:
  - login, logout, magic-link, passkey, MFA, recovery, session-management and OIDC endpoints;
  - per-route guards, including a recent-authentication guard (`Guards.RequireRecentAuthentication`,
    `RequireAuthenticationWithin`);
  - opt-in security response headers (`EnableSecurityHeaders`), CORS (`EnableCORS`), CSRF protection,
    trusted proxies and API gateways (`EnableTrustedProxies`), DPoP (`EnableDPoP`) and mTLS-bound
    tokens, and an automation-challenge seam before login, magic-link requests and recovery start;
  - opt-in re-authentication endpoints for a signed-in session (`EnableReauthentication`), under
    `/reauth` by default: the user re-proves with an enrolled second factor, or with the password
    when they hold none;
  - an opt-in session-signal stream of server-sent events about the signed-in user's own session
    (`EnableSessionSignals`), with a closed set of library signals, the consumer's own namespaced
    signals, and an in-process signal bus replaceable through a port;
  - `WithBasePath`, which puts every built-in endpoint under one prefix, and `(*Chain).Endpoints()`,
    a read-only inventory of every operation of every enabled endpoint.
- User-facing session management: list a user's live sessions, revoke one or all others, and opt-in
  sign-in metadata with an opt-in notice for a sign-in from an unseen device.
- `password.Policy`: minimum length, a common-password list, context words, an opt-in breach check
  and a no-reuse rule. A stored hash is upgraded on login when its algorithm or parameters are
  outdated.
- `password.Recognizer`, an optional encoder interface. A user whose stored hash is empty or
  unrecognised costs the same work as an unknown user.
- An OpenID Provider a consumer can run for their own applications (`oidcprovider`), built on
  scrty's own primitives with no OpenID Provider library underneath:
  - authorization code flow with PKCE, `prompt`, `max_age` and `iss` in responses; a browser session
    for single sign-on and `prompt=none`; remembered consent; refresh-token rotation with reuse
    detection; ID tokens and JWT access tokens, with DPoP and mTLS binding;
  - client authentication by `client_secret_basic`, `client_secret_post`, `private_key_jwt` and
    `none`; UserInfo, revocation and introspection; OpenID Provider and OAuth authorization server
    metadata;
  - RP-initiated logout and back-channel logout; a static client registry with in-memory and durable
    stores;
  - the OpenID Foundation conformance suite runs in CI against the Basic OP, Config OP,
    RP-initiated logout and back-channel RP-initiated logout plans (`make conformance`), with one
    recorded expected failure, `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`, and one
    recorded expected warning, `oidcc-claims-essential` (the optional `claims` request parameter is
    not supported). Official
    certification has not been sought.
- A security-event port that emits OWASP Logging Vocabulary events (`event`), which the lockout and
  reuse observers feed. Removing a passkey notifies the user by default.
- Package `store`, holding the errors every durable store backend shares, and `store/seal`, which
  encrypts long-lived secrets at rest; `store/sqlstore` and `store/migrate` for PostgreSQL through
  `database/sql`.
- Time (`pkg/clock`), identifiers (`pkg/id`), log sampling (`pkg/logsample`), confined outbound HTTP
  (`outbound`), email (`notify`) and expiry (`expiry`).
- Supply chain: CI actions pinned to commit SHAs, automated dependency updates, a vulnerability
  check over every published module, and a CycloneDX SBOM per published module.

**`github.com/kartaladev/scrty/httpsec/fibersec`.** Runs the security chain in front of fiber
handlers, with the same guards, including the recent-authentication guard, and the stream support the
session signals need.

**`github.com/kartaladev/scrty/httpsec/ginsec`.** Runs the security chain in front of gin handlers,
with the same guards, including the recent-authentication guard, and the stream support the session
signals need.

**`github.com/kartaladev/scrty/store/gormstore`.** The security-state stores, and an optional
identity store, over gorm with its PostgreSQL driver.

**`github.com/kartaladev/scrty/authenticate/passkey/webauthn`.** The passkey package's verifier port
over a WebAuthn library, in a module of its own so the core carries no WebAuthn, CBOR or TPM
dependency, and `webauthntest`, a software WebAuthn authenticator for tests.

**`github.com/kartaladev/scrty/store/pgxstore`.** The security-state stores over native pgx v5.

**`github.com/kartaladev/scrty/ratelimit/redisstore`.** A `ratelimit.Limiter` over Redis or Valkey, so
one limit holds across every replica.

**`github.com/kartaladev/scrty/expiry/sweep`.** Runs the tasks of an `expiry.Runner` on a gocron
schedule.

**`github.com/kartaladev/scrty/test`.** Shared test helpers and conformance suites for scrty's ports:
security-state stores, rate limiters, identity ports, the `oidc` package, and the behaviours
every framework integration of the chain must produce identically. It also holds the conformance
OpenID Provider the suite tests. No other scrty module imports it.

### Changed

Items below are stated relative to the earlier, untagged tree.

**Package layout and names** (`restructure-layout`). **BREAKING** for every import path and many
exported identifiers; the moves and renames change no behaviour.

- **BREAKING** The root directories are regrouped by concept. Under `authenticate/`: `factor`,
  `password`, `apikey`, `magiclink`, `oidc`, `passkey` and `mfa`. Under `token/`: `signingkey` and
  `onetime`. The account-lockout group of `policy` becomes `policy/lockout`. `storeerr` becomes the
  parent package `store`, with `sqlstore`, `migrate` and `seal` under it. `identity`, `authorize`,
  `session`, `recovery`, `ratelimit`, `outbound`, `notify`, `pkg/` and `internal/` keep their places.
- **BREAKING** Nested module paths move: `passkey/webauthn` to `authenticate/passkey/webauthn`, `pgx`
  to `store/pgxstore`, `gorm` to `store/gormstore`, `redis` to `ratelimit/redisstore` (package
  `redisstore`, was `scrtyredis`), `sweep` to `expiry/sweep`, `ginsec` to `httpsec/ginsec` and
  `fibersec` to `httpsec/fibersec`.
- **BREAKING** `Manager` leaves every type name: `oidc.Manager` is `RelyingParty`,
  `oidc.HandoffManager` is `Handoff`, `authenticate.Manager` and `authorize.Manager` are `FirstOf`,
  `session.Manager` is `Sessions`, `passkey.Manager` is `Passkeys`, `signingkey.KeyManager` is
  `Keys`, `apikey.Manager` is `Keys`, `onetime.Manager` is `Tokens` and `magiclink.Manager` is
  `Links`. Constructors and option types follow.
- **BREAKING** Sentinel errors drop the package noun (`session.ErrNotFound`, `password.ErrTooLong`,
  `token.ErrInvalid`, `policy.ErrDenied`); policy types drop the `Policy` suffix (`policy.IdleTimeout`,
  `policy.ConcurrentSessions`, `policy.PasswordAge`, `lockout.Policy`); initialisms, getter prefixes
  and spellings are corrected (`JWT…`, `Signer`, `ErrMFAEnrolmentRequired`, `NormalizeName`).
- **BREAKING** Options say what they bound, with one vocabulary: Limit for a count per subject,
  `Max<Entity>` for a container's size, Timeout, Lifetime and TTL by meaning. The lockout family is
  `WithFailureStreakLimit`, `WithFailureStreakRetention`, `WithWaitThreshold`,
  `WithWindowFailureLimit`, `WithFailureWindow` and `WithAttemptStoreMaxIdentifiers`, and about
  twenty more names gained the noun they lacked.
- **BREAKING** `token.NewVerifier` requires an issuer and an audience, or an explicit waiver of each
  (`WithoutVerifyIssuer`, `WithoutVerifyAudience`), so a token minted for one service no longer
  verifies at another that shares its keys.
- **BREAKING** A user-store outage during a password login is its own outcome,
  `authenticate.ErrUnavailable`, answered as a wrong password is. Form login, Basic authentication
  and a recovery's password proof charge it to the source, never to the username, so an outage no
  longer holds real accounts.
- **BREAKING** The `ratelimit` limiter port gains an atomic charge and refund, which every shipped
  limiter implements. Saved recovery codes charge
  before the lookup and refund on success, so the limit holds under concurrent presentations.
- API key authentication can be given a user loader (`httpsec.WithAPIKeyOwners`) and then refuses a
  key whose user is inactive or gone. Without one it looks nothing up, as before.
- The SQL backends build columns only through the shared store helpers, so no caller can put text
  into a SQL statement.

**API shape** (`idiomatic-api-shape`). **BREAKING** in signatures and lifecycle behaviour.

- **BREAKING** Twelve constructors return concrete types, not interfaces: `*UsernamePasswordAuthenticator`
  and `*JWTAuthenticator` (`authenticate`), `*MFA` and `*MFARequirement` (`policy`), `*BcryptEncoder`,
  `*ScryptEncoder` and `*Argon2idEncoder` (`password`), `*JWTGenerator` and `*JWTVerifier` (`token`),
  `*StaticKeyring` and `*AEADCipher` (`seal`), and `*MemoryKeyStore` (`signingkey`). The ports keep
  their names.
- **BREAKING** `logsample.Flusher` replaces `authenticate.RefusalLogFlusher`,
  `policy.RefusalLogFlusher` and `oidc`'s anonymous interface. `policy.Engine.FlushRefusalLogs` and
  `httpsec.Chain.FlushRefusalLogs` return an `error` joining what they flush, and
  `authenticate.FirstOf` forwards the flush to its delegates.
- **BREAKING** The in-memory stores that take options (`onetime`, `session`, `lockout`) return
  `(T, error)`, and refuse a nil clock, a housekeeping interval of zero or less and a capacity of zero
  or less with their package's `ErrConfig`.
- **BREAKING** One lifecycle for `signingkey.Keys`, `session.MemoryStore`, `sweep.Sweeper` and
  `notify.QueuedSender`: `Start(ctx)` takes the context's values but not its cancellation; a second
  `Start` returns `ErrAlreadyStarted` and a `Start` after shutdown `ErrAlreadyShutdown`; `Shutdown(ctx)`
  is bounded by its context, terminal and idempotent. It replaces `Stop()` and `Close(ctx)`.
- **BREAKING** `NewGuards` in `httpsec`, `httpsec/ginsec` and `httpsec/fibersec` returns
  `(*Guards, error)` and refuses a nil authorizer unless the consumer opts in to the chain's
  authorizer explicitly. The `fibersec` guards take `GuardOption`.
- **BREAKING** `httpsec.NewExchange` and `Exchange.SetContext` panic on a nil context instead of
  substituting or ignoring it; the lifecycle methods return their package's configuration error.
- **BREAKING** `EnableOIDCLogin` takes `OIDCDeps`: one required dependency is a positional argument,
  two or more go in a `Deps` struct.
- **BREAKING** `oidc.DefaultScopes()` is a function that returns a fresh copy, not an exported
  mutable global.

**Context on the key and cipher ports** (`key-port-context`). **BREAKING** in five ports.

- **BREAKING** `ctx` is the first parameter of every method of `seal.Keyring` (`Active`, `ByID`),
  `seal.Cipher` (`Seal`, `Open`, `ActiveKeyID`), `session.Cipher` (`Seal`, `Open`),
  `signingkey.KeySource` (`Signer`, `VerificationKeys`) and `httpsec.KeySetProvider` (`JWKS`).
- **BREAKING** `KeySource.Signer` returns an error instead of a boolean:
  `Signer(ctx, alg) (kid, signer, err)`. A source holding no key for the algorithm returns an error
  matching the new `signingkey.ErrNoKey`; any other error is an outage.
- An outage is answered as one. A cipher, session-store or user-store failure that is not a refusal,
  and a key set that cannot be obtained, fail the request as a dependency failure (500 by default),
  are not logged as an undecryptable session and are not charged to the source's throttle. New
  `seal.ErrUnavailable` and `session.ErrCipherUnavailable` carry a remote cipher's retryable failure.
- A credential is issued before anything is stored or spent, so a credential that cannot be issued
  stores, spends, removes and revokes nothing.
- A request whose own context ended is not refused: it fails with the context's error.

**Re-authentication** (`reauthentication`).

- **BREAKING** The MFA begin and verify endpoints refuse a session that owes no second-factor
  challenge, with `ErrNoMFAChallengePending`. Re-proof has its own endpoints.
- **BREAKING** A chain that has the MFA slot and passkeys must enable re-authentication; construction
  fails and names the option. A chain that gave MFA a shared challenge store must give
  re-authentication one too.
- **BREAKING** The sessions table gains one column. A strict rotation that lost a race keeps the old
  session, marked, for its 30-second in-flight window instead of deleting it, so a losing rotation or
  renewal answers 409 on every replica that shares the store, not 401.
- Recovery-code regeneration, passkey registration and removal, and the recency guard judge one
  shared "authentication time", which a re-proof refreshes as a second factor does.
- The default re-proof policy is "strongest factor held"; `RequireSecondFactorForReauthentication()`
  makes it second factor only. Re-proof paths are checked against every endpoint the chain answers.

**Security gaps** (`close-security-gaps`).

- **BREAKING** `httpsec.Request` gains `Host()` and `Secure()`, and every adapter implements them. A
  consumer's own `Request` implementation must add them.
- **BREAKING** `NewReuseGuard` is removed; `password.Policy`'s `NoReuse` rule replaces it.
- **BREAKING** A consumer's own `session.Store` implements the new session-listing and revocation
  methods.

**Pre-release fixes** (`pre-release-api-fixes`).

- **BREAKING** The token subject is the user's identifier by default; an option on the generator, on
  the JWT authenticator and on the chain's bearer keeps the username. Issuing with an empty subject
  fails. The chain reloads a signed bearer's user by the session's user reference and refuses a token
  whose subject is not that reference. This breaks any reader of `sub`, a reader of
  `Principal.Username` behind the standalone `JWTAuthenticator` (empty by default), a consumer's own
  `token.Generator` (it gains a method reporting its subject mode), a `JWTAuthenticator` given a
  generator of the other mode as its verifier, and an authentication provider that returns no user
  identifier. A chain whose generators disagree with its bearer fails to build.
- **BREAKING** A signing key retires when its tokens can have expired, and the key manager deletes it
  from the store one grace later, one key lifetime by default, with options to change the grace or
  keep retired keys. `signingkey.KeyStore` gains a delete method, which a consumer's own key store
  must implement.
- **BREAKING** `passkey.CredentialStore` loses `DeleteAwaitingSavedCodes`, which the library no longer
  calls.
- **BREAKING** `EnrolmentStore.Confirm` refuses an enrolment whose device is proven, decided by its
  one write; a consumer's own store that implements `DeviceProofStore` must do the same.
- `ErrConfig` in `notify` names the SMTP send with no sender address, which it already wrapped.

**Session signals** (`session-signals`).

- **BREAKING** `httpsec.ResponseWriter` gains a required `Stream` method, implemented by the net/http,
  gin and fiber adapters. An adapter of the consumer's own must add it, or report that it cannot
  stream.

**OpenID Provider** (`oidc-provider`).

- **BREAKING** `token` gains a typed issuer, with the claims an access token and an ID token need,
  and enforces `typ`.
- Provider endpoints render the error bodies the protocols require, a departure from the chain's
  bare-status default.
- The provider's tables arrive in a security-state migration, and new conformance suites cover its
  stores.

**Endpoint paths** (`endpoint-inventory-base-path`). **BREAKING** for `httpsec`.

- **BREAKING** The default endpoint paths are regrouped by what each endpoint does:
  `/sign-in/{password,magic-link,passkey}`, `/sign-out`,
  `/sso/{login,callback,handoff,backchannel-logout}/...` for signing in at other providers,
  `/oauth2/*` only for scrty as a provider, `/passkeys`, `/mfa/challenge/{m}` and
  `/reauth/challenge/{m}`. The magic-link confirm page default moves to `/sign-in/magic-link/confirm`.
  Option names do not change.
- **BREAKING** Every path setting must be absolute, not the root, clean, and free of characters that
  need escaping; with `WithBasePath` set, every path setting is relative to it, and a base path that is
  malformed, moves nothing or is repeated in a per-feature path is refused at construction.
- **BREAKING** One collision check covers the whole chain, within and across features. Paths may be
  shared only by declaration, and a collision names both settings, both paths and what it would break.
- **BREAKING** New construction-time refusals, each with a waiver: an OIDC provider's redirect URL path
  must end with the resolved callback path and the provider's name
  (`WithoutOIDCRedirectPathCheck`); under a base path the provider's issuer must cover it
  (`WithoutOIDCIssuerBasePathCheck`); under a base path a consumer route left at an endpoint's
  pre-base path is refused (`WithoutBasePathRouteCheck`).

**Hardening** (`pre-release-hardening`).

- **BREAKING** `onetime.Store` gains `InsertWithin(ctx, tok, since, limit) (bool, error)`, and
  `onetime.Tokens` gains `IssueWithin`, which reports the new `onetime.ErrIssueLimitReached`
  (answered 429). Every consumer-written one-time store must implement it.
- **BREAKING** `passkey.CredentialStore` gains `InsertWithin(ctx, cred, limit) (bool, error)`.
- **BREAKING** The MFA enrolment store's `Confirm` and `AcceptStep` take the enrolment generation and
  write only on it.
- **BREAKING** `apikey.Store.Revoke` returns `(bool, error)`: whether this call revoked the key.
  `apikey.Keys.Rotate` refuses a revoked or expired key with the new `apikey.ErrRotationRefused`
  (answered 409).
- **BREAKING** `seal.MFASecretAAD` takes `(gen id.ID, user identity.UserID)` and binds the enrolment
  generation. TOTP secrets sealed before this release no longer open: affected users enrol their
  authenticator again.
- **BREAKING** Stored password hashes are bounded: scrypt `p ≤ 16`, `(N + p)·128·r ≤ 1 GiB` and a
  power-of-two `N ≥ 2`; bcrypt cost `≤ 16`; Argon2id memory `≤ 1 GiB`, iterations and threads `≤ 16`,
  salt and key `≤ 64` bytes. A hash above them no longer matches, and encoders refuse such parameters
  at construction. bcrypt refuses a password containing NUL. Affected users reset their password. The
  OIDC password-claim cost band tops out at 16.
- **BREAKING** Account recovery refuses an issued code paired with an email-channel MFA proof, and
  the way-back check no longer counts that pairing.
- **BREAKING** The recovery cool-down matches its marked routes ignoring ASCII case and trailing
  slashes, with `HEAD` as `GET`, so on net/http and gin it also holds a differently cased route.
- A refused magic-link redemption answers 401; it answered 500. `apikey.ErrKeyNotFound` answers 404.
- A TOTP period and a token lifetime must be whole seconds, at least one; OIDC clock-skew leeway is
  bounded at 5 minutes and logout-token max age at 1 hour; OIDC redirect allowlist entries and a
  requested `next` are bounded at 2048 bytes; a rate-limit flow name may not contain `:`; magic-link
  and passkey-ceremony cookie TTLs must be whole seconds; the passkey relying-party ID must be a
  lowercase DNS name. Each is refused at construction.
- Ownership and resource guards in `httpsec`, `fibersec` and `ginsec` panic at wiring on a nil
  checker, extractor or `Guards`.
- `fibersec` keeps a route's own error and status, and runs the chain on a context cancelled when the
  request's handling ends (fiber gives no disconnect signal).
- Security-state stores pin READ COMMITTED for every transaction they open; recovery-code replace,
  the streak add and the bounded inserts refuse a caller's stronger transaction with the new
  `store.ErrIsolationTooStrong`. User-wide session deletes stop after 64 passes with
  `session.ErrDeleteDidNotSettle`.
- The default lockout attempt store, the outage hold and the log sampler are bounded and fail closed
  when full (`lockout.WithAttemptStoreMaxIdentifiers`, `logsample.WithMaxKeys`).
- Signing keys: construction, reload and housekeeping share one publishing rule; a future-dated key
  never signs.
- Policies deny a zero `Input.Now` (idle timeout, password age, enrolment path) and
  `Engine.EvaluatePhase` denies a nil input; they allowed before.
- A nested `authenticate.FirstOf` whose delegates skip lets the outer one try its next delegate.
- Default login, magic-link, MFA begin and verify, and passkey login responses carry
  `Cache-Control: no-store`.
- A WebAuthn backed-up state without backup eligibility is refused at registration and assertion.
- SMTP bodies normalise bare CR and bare LF to CRLF.
- New sentinels: `password.ErrContainsNUL`, `lockout.ErrAttemptStoreFull`,
  `onetime.ErrIssueLimitReached`, `apikey.ErrRotationRefused`, `session.ErrDeleteDidNotSettle`,
  `store.ErrIsolationTooStrong`, `signingkey.ErrNoKey`, `seal.ErrUnavailable`,
  `session.ErrCipherUnavailable` and `authenticate.ErrUnavailable`.

### Fixed

- A queued sender whose wrapped sender ends its goroutine (`runtime.Goexit`, as `t.FailNow` does) lost
  that worker, and once every worker was gone it accepted messages it never delivered. The worker is
  now replaced.
- A device proof landing inside the single-call confirm of an MFA enrolment left the enrolment
  confirmed without the emailed code.
- A bearer whose resolution ended in a per-request policy's throttle now records its credential, so
  the session-signal stream's cross-site check judges that request as a bearer, as it judges the same
  request unthrottled.

### Security

- A signed bearer no longer authenticates whoever now holds the session owner's former username; a
  disabled user's sessions are refused.
- One stored scrypt or bcrypt record can no longer exhaust memory or CPU.
- The recovery cool-down can no longer be bypassed on fiber by changing a path's case or adding
  trailing slashes.
- Issuance and passkey limits hold under concurrent requests.
- A token minted for one service no longer verifies at another that shares its keys, because a
  verifier now enforces an issuer and an audience unless each is waived.
- API keys can be refused when their owner is inactive or gone (`httpsec.WithAPIKeyOwners`).
- A user-store outage during a password login no longer places a hold on a real account.
- The limit on saved recovery codes holds when the codes are presented concurrently.

[Unreleased]: https://github.com/kartaladev/scrty/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/kartaladev/scrty/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/kartaladev/scrty/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/kartaladev/scrty/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kartaladev/scrty/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/kartaladev/scrty/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/kartaladev/scrty/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/kartaladev/scrty/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/kartaladev/scrty/releases/tag/v0.1.0
