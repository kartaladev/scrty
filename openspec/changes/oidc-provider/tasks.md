# Tasks

Every implementation task is test-first: write the failing test, run it and confirm it fails for the intended reason (a compile error is not a red step), make it pass with the smallest change, then refactor. "Verify" names the command whose output proves the task done. Run the touched module's full suite with `-race` at the end of each group.

The risks the design labels `UNREPRODUCED` (H2, H3, H4, token-type confusion) are each the red step of the task that names them. If such a test passes before the fix, the claim was wrong: say so, and record it in `design.md` (`defect-claims`).

## 1. Baseline check (before any code)

- [x] 1.1 `pre-release-api-fixes` and `close-security-gaps` have merged, so rebase this branch onto `main`. Recheck the design's "What exists", P6, T4 and R6 against the merged code, and record every difference in `design.md`:
  - DPoP: the proof-verification entry point a non-bearer endpoint can call, the `jti` and nonce stores, and the internal set of features that verify bound credentials (D8 as amended);
  - certificate binding: the thumbprint accessor (D9);
  - CSRF: the exemption API (D6);
  - CORS: how routes are matched (D5);
  - security events: the sink and the event shape (D13);
  - session listing: `EndSignIn` and the end-others endpoint (D12);
  - `sub`: that it is the user identifier by default, and `token.Generator`'s final shape;
  - signing keys: the retire rule, the lifetime cap, and whether `VerificationKeys` still publishes what R6 assumes;
  - `split-ci-jobs`: the `make` and `ci-ok` shape R5 follows.

  Verify: `openspec validate oidc-provider --strict` passes, and `design.md` names the merged commits.
- [x] 1.2 Run the OpenID Foundation conformance suite locally once, pinned, and check P9's facts by running it, since they were read from its source: the plan and module lists, that a self-signed `https` OP is accepted by both the server side and HtmlUnit, and the headless runner's options. Correct anything that differs in `design.md`. Verify: P9 states which facts were confirmed by a run, and `openspec validate oidc-provider --strict` passes.
- [x] 1.3 Align `session-signals` with R16 through `/opsx:update`: one repeatable `WithEndObserver` over an `EndObserver` interface and func adapter, `EndReport` carrying the upstream issuer and session, `DeleteByExternalSession` reported, and its chain option no longer refusing a manager with an observer. Update its `plans.md` through `/superpowers:writing-plans`. Verify: `openspec validate session-signals --strict`.

## 2. Token types and claims (`token`, `token-issuance`)

- [x] 2.1 Issue every first-party token with header `typ` `scrty+jwt`, replaceable by an option. Refuse at construction a replacement equal to `at+jwt`, `JWT` or `logout+jwt`, test-first. Verify: `go test -run 'TestGenerator_TokenType' -count=1 ./token/`.
- [x] 2.2 Enforce `typ` at verification: a verifier accepts only its declared type (the first-party type by default), compared case-insensitively with an `application/` prefix ignored. A missing or other type is refused as `ErrInvalid`, and no option accepts any type. Test-first, including the red test for the token-type confusion risk: an `at+jwt` token signed by the same keys, with the same issuer and audience, refused by a default verifier. Verify: `go test -run 'TestVerifier_TokenType' -count=1 ./token/`.
- [x] 2.3 Add `token.Issuer`, built from a key source, an algorithm and an issuer identifier, leaving `Generator` unchanged (R6). It issues a token of a declared type for a named subject, with further claims (`client_id`, `scope`, `nonce`, `auth_time`, `acr`, `amr`, `azp`, `sid`, `gid`, `events`, `cnf`) and a per-token audience of one or more values, test-first. A further claim naming `iss`, `sub`, `iat`, `exp` or `jti` fails as a configuration error and issues nothing, an empty subject matches `ErrNoSubject`, and a lifetime past the key cap is refused. Extend the jwx allow-list test only for calls this task adds. Verify: `go test -run 'TestIssuer|TestNewIssuer|TestProductionSourceGuards|TestJOSEAllowListIsHonest' -count=1 ./token/`.
- [x] 2.4 Prove at the chain that an ID token and an access token presented to `EnableBearerToken` are refused as unauthenticated, test-first. Godoc the type option and the typed issue with their defaults. Verify: `go test -run 'TestBearer_RefusesOtherTokenTypes' -count=1 ./httpsec/`, and `go doc ./token` names the default type.

## 3. Session end observers (`session`, `sessions`, design T4)

- [x] 3.1 Add the `EndObserver` interface with an `EndObserverFunc` adapter, and the repeatable `WithEndObserver` option (R16), refuse a nil observer at construction, and add `(*Sessions).ReportsEndsTo`, comparing observers by identity, with an incomparable value such as a func answering no rather than panicking, test-first. If `session-signals` landed first, extend what it added. Verify: `go test -run 'TestSessions_EndObserverConstruction|TestSessions_ReportsEndsTo' -count=1 ./session/`.
- [x] 3.2 Report each explicit end after its store write, test-first, one table over every ending path: reuse revocation, `RevokeFamily`, `Delete`, `DeleteByUser`, `DeleteByUserExcept` (with the kept family), `DeleteByExternalSession`, `DeleteByUserAndExternalIssuer`, `EndSignIn` and `EndOtherSignIns`. Assert each report's cause, user, family and upstream session, that no report holds a session identifier, that observers run in order, that a cancelled caller's context reaches the observer uncancelled, that a panicking observer does not stop the next, and that nothing is reported on a failed write or by `DeleteExpired`. Verify: `go test -run 'TestSessions_EndObserver' -count=1 ./session/`.
- [x] 3.3 Godoc the option, the report and `ReportsEndsTo`, stating that expiry is never reported. Verify: `go doc ./session WithEndObserver` describes what is and is not reported.

## 4. Provider construction and clients (`oidcprovider`, `oidc-provider-clients`, design T1)

- [x] 4.1 Create the `oidcprovider` package with `New`, test-first, one construction table:
  - issuer `https` with no query or fragment, and the loopback-only `http` option;
  - the key source required (`Deps.Keys`, R6), and a JWKS provider that is the same manager checked where it can be seen;
  - login and consent URLs required, absolute and on the issuer's origin (R9);
  - `WithoutBrowserSessions`, and `WithLogoutConfirmation`, recorded with their defaults (R2, R3);
  - the pending-request lifetime positive and at most 30 minutes;
  - the code lifetime at most 10 minutes;
  - the assertion lifetime bound at most 1 hour;
  - the logged-out page and the logout page required when logout is enabled, on the issuer's origin.

  Verify: `go test -run 'TestNew_Construction' -count=1 ./oidcprovider/`.
- [x] 4.2 Validate client registration at construction, test-first, one table, each failure naming the client and setting:
  - client type: confidential or public; application type web (default) or native;
  - authentication method: one per client, `client_secret_basic` by default, `client_secret_jwt` refused, a secret method on a public client refused, `none` on a confidential client refused;
  - redirect URIs: required when the client uses the authorization endpoint; absolute, without fragment, wildcard or user information; `https` for web; `https`, a private-use scheme containing a period, or loopback `http` for native; `javascript`, `data`, `vbscript` and `file` refused. Post-logout URIs follow the same rules, and a back-channel logout URI must be `https`;
  - PKCE: `PKCEOrNonce` only for a confidential client (R1);
  - lifetimes: ID and access token lifetimes within the key cap (R6);
  - uniqueness and keys: duplicate identifiers refused; an ID token algorithm the keys cannot produce refused;
  - offline access: pre-authorization only for a first-party native client;
  - refresh: rotation off only for a confidential client required to use sender-constrained tokens; grace at most 5 minutes; idle timeout at most the absolute lifetime;
  - defaults: first-party off, grant types `authorization_code`, a public web client tied to its sign-in (R13).

  Verify: `go test -run 'TestClient_Validation' -count=1 ./oidcprovider/`.
- [x] 4.3 Match redirect URIs by exact string, except that a native client's loopback IP redirect URI may differ in port only, test-first, with the four `oidc-provider-clients` scenarios as the table. Verify: `go test -run 'TestClient_MatchRedirectURI' -count=1 ./oidcprovider/`.
- [x] 4.4 Add the client registry port and its in-memory default built from configuration, test-first, covering:
  - a consumer registry replacing the default;
  - generated secrets: 256 bits, returned once, stored as a digest;
  - supplied secrets: at least 32 bytes;
  - constant-time comparison;
  - a second live secret, and a secret's expiry (R13);
  - a consumer registry's client validated as it is read, an invalid one treated as unknown and logged with the setting (R13);
  - no secret or digest in an error's text.

  Verify: `go test -run 'TestMemoryRegistry|TestRegistry_Secrets' -count=1 ./oidcprovider/`.
- [x] 4.5 Authenticate clients by `client_secret_basic` (Base64, then URL-decode), `client_secret_post` and `none`, test-first: the wrong method and an undecodable header are `invalid_client`; two methods at once and two different identifiers are `invalid_request`; a credential in the query is `invalid_request`. Verify: `go test -run 'TestAuthenticateClient' -count=1 ./oidcprovider/`.
- [x] 4.6 Verify `private_key_jwt` assertions, test-first. Cover:
  - an asymmetric algorithm only;
  - `iss` and `sub` equal to `client_id`;
  - `aud` the issuer alone by default, with the `AudienceIssuerOrTokenEndpoint` option;
  - `exp` present, in the future, and within the bound (5 minutes by default);
  - `jti` recorded through the assertion-identifier store until `exp`, with a replay refused;
  - `typ` absent, `client-authentication+jwt` or `JWT`, and any other refused (R13);
  - keys from the registered set or `jwks_uri`, fetched through the outbound client and cached, an unknown `kid` refetching at most once per 30-second cooldown;
  - a fetch failure reported as a dependency failure, not as `invalid_client`.

  Verify: `go test -run 'TestAuthenticateClient_PrivateKeyJWT' -count=1 ./oidcprovider/`.
- [x] 4.7 Godoc the package, `New`, `Client` and every option, each naming its default and limit. Verify: `go doc ./oidcprovider` lists them, and `go vet ./oidcprovider/` is clean.

## 5. Provider stores, in-memory defaults and conformance suites (`security-state-stores`, `store-conformance`, design T2, T3, T6, T7)

- [x] 5.1 Add the pending-request store port and its in-memory default, test-first. Records hold the handle's and the flow secret's digests. The stage advances login → consent → done by one conditional write, and expiry is judged at the caller's time. Add its exported suite to `test/storetest`. Verify: `go test -run 'TestMemory/PendingRequests' ./storetest/` in the `test` module.
- [x] 5.2 Add the code-record store port and its in-memory default, keyed by the `token/onetime` identifier and holding every binding of T2, including the grant family `F`, the sign-in's upstream issuer and session, and whether it holds `offline_access` (R7), test-first, with its suite. Verify: `go test -run 'TestMemory/CodeRecords' ./storetest/` in the `test` module.
- [x] 5.3 Add the consent store port and its in-memory default, test-first, with its suite:
  - scopes accumulate per user and client;
  - offline consent is recorded only when given explicitly;
  - the time consent was last given is kept;
  - consent can be revoked, and listed by user only.

  Verify: `go test -run 'TestMemory/Consents' ./storetest/` in the `test` module.
- [x] 5.4 Add the grant store port and its in-memory default, test-first, with its suite:
  - create keeps a revocation recorded first (the H2 tombstone);
  - load by family;
  - revoke, which inserts a tombstone when no row exists;
  - revoke by user, and by user and client;
  - end sign-ins by each T3 selector, returning only newly marked grants, and recording a revocation carrying the mark for each matching unspent code without `offline_access` or of a client tied to its sign-in (R7);
  - revoke by user, and by user and client, recording one for each such code, `offline_access` included (R7);
  - a grant recorded to hold no lineage (R10);
  - grants record the sign-in's family and upstream session unchanged;
  - expired grants are deleted, and revoked ones are kept until the codes that could name them expire.

  Verify: `go test -run 'TestMemory/Grants' ./storetest/` in the `test` module.
- [x] 5.5 Add `RefreshTokenStore` as a type with only an unexported field, built through a scrty `internal` package (T7), with a private in-memory default, test-first. A test outside scrty's import path cannot build one from a `session.Store`, shown by an example that fails to compile and is kept out of the build. Verify: `go test -run 'TestRefreshTokenStore' -count=1 ./oidcprovider/`.
- [x] 5.6 Add the opaque access-token store (digests; revoke one; delete expired) and the assertion-identifier store (insert-if-absent per client until `exp`) with their in-memory defaults and suites, test-first. Verify: `go test -run 'TestMemory/(AccessTokens|AssertionIDs)' ./storetest/` in the `test` module.
- [x] 5.7 Extend the exported race suite, test-first, so each case fails against a deliberately broken store:
  - single spend of a code, a handle stage and an assertion identifier under concurrency;
  - a tombstone surviving a concurrent create, including one recorded by a sign-in's end racing its code's exchange (R7);
  - an end reported twice returning nothing the second time.

  Run it against every in-memory default. Verify: `go test -race -run 'TestMemory|TestRace|TestBroken' ./storetest/` in the `test` module.

- [x] 5.8 Add the browser-session store port and its in-memory default, test-first, with its suite (R2): digest only; load by digest judged at the caller's time; touch extending the idle deadline, never past the absolute one; replace; delete by T3's selectors. Verify: `go test -run 'TestMemory/BrowserSessions' ./storetest/` in the `test` module.

## 6. Authorization and consent (`oidcprovider`, `oidc-provider-authorization`, `oidc-provider-consent`)

- [x] 6.1 Validate an authorization request, test-first, one table over `oidc-provider-authorization`'s scenarios:
  - client and redirect URI first, as an unredirectable error;
  - a repeated `client_id` or `redirect_uri` as an unredirectable error too; a redirect URI's own query kept;
  - then `response_type=code` and `response_mode=query` only, a missing `response_type` refused, and a repeated parameter refused; a parameter with no value treated as omitted;
  - the string bounds (R11);
  - PKCE `S256` with a 43 to 128 character unreserved challenge, and `PKCEOrNonce` (R1);
  - `offline_access` dropped for a client not registered for refresh;
  - allowed scopes, with `openid` detection; allowed `resource` values (`invalid_target`);
  - `request` and `request_uri` unsupported, and no fetch made;
  - `prompt`, with `none` alone, and unknown values ignored; `max_age`, malformed refused; `display` ignored;
  - `id_token_hint` verified by type, signature and issuer with expiry ignored, and one signed by an unpublished key counted as none, or `login_required` with `prompt=none` (R6);
  - `dpop_jkt`, refused while DPoP is off (R12); `login_hint`, `ui_locales`, `claims_locales` and `acr_values` kept.

  Every redirect error carries `state` and `iss`, and no `error_description`. Verify: `go test -run 'TestValidateAuthorizationRequest' -count=1 ./oidcprovider/`.
- [x] 6.2 Park a valid request, test-first: an `rh.<id>.<secret>` handle of at least 128 bits, a separate 256-bit flow secret (T5) reused from a valid cookie so that two tabs both resume (R9), a 10-minute lifetime by default with `WithPendingRequestLifetime`, and expiry refused as an unknown handle. Verify: `go test -run 'TestProvider_Park' -count=1 ./oidcprovider/`.
- [x] 6.3 Expose `PendingRequest` for the consumer's pages, test-first:
  - it requires the flow secret, or the handle is unknown;
  - it holds the client's identifier and name, the requested and already granted scopes, `prompt`, `max_age`, `login_hint`, `ui_locales`, `claims_locales`, `acr_values` and the stage;
  - it never holds the challenge, the nonce, the state or the redirect URI.

  Verify: `go test -run 'TestProvider_PendingRequest' -count=1 ./oidcprovider/`.
- [x] 6.4 Decide whether consent is needed, test-first, one table over `oidc-provider-consent`:
  - required by default; skipped when remembered consent covers the scopes;
  - always shown for `prompt=consent`;
  - skipped by a first-party client for ordinary scopes;
  - `offline_access` asked unless explicitly consented before or the native client is pre-authorized, and honoured only when a code results.

  Verify: `go test -run 'TestConsentNeeded' -count=1 ./oidcprovider/`.
- [x] 6.5 Resume the login stage from sign-in facts, test-first:
  - the handle and flow secret must be valid, and the stage spent once;
  - `prompt=login` needs authentication after parking, and `max_age` (with 0 as `login`) is measured against `AuthenticatedAt`, never the renewal time. A failure leaves the handle unspent;
  - a hint naming another subject answers `login_required`;
  - a principal with no identifier fails matching `token.ErrNoSubject`, and no code is issued (R6);
  - the answer is the consent URL with the handle, or the code redirect, and a browser session is recorded (R2).

  Verify: `go test -run 'TestProvider_ResumeLogin' -count=1 ./oidcprovider/`.
- [x] 6.6 Resume the consent stage, test-first:
  - the same user as the login stage, or the browser session of that user (R2);
  - granted scopes a subset that keeps `openid`, otherwise malformed with the handle unspent;
  - a denial answers `access_denied` and records nothing;
  - a grant adds to the remembered consent and binds the code to the granted scopes.

  Verify: `go test -run 'TestProvider_ResumeConsent' -count=1 ./oidcprovider/`.
- [x] 6.7 Issue codes through `token/onetime` with a code record (T2), test-first: every binding including `F`, a 60-second default with `WithCodeLifetime` up to 10 minutes, and a success redirect carrying `code`, `state` and `iss`. Godoc the authorization and consent API. Verify: `go test -run 'TestProvider_IssueCode' -count=1 ./oidcprovider/`, and `go doc ./oidcprovider PendingRequest`.

- [x] 6.8 Answer from the browser session, test-first, one table (R2), with these red tests first: a second authorization with `prompt=none` after a first login must issue a code carrying the same `auth_time`; and one after the sign-in ended must not:
  - a valid session skips the login stage, and touches its idle deadline;
  - `prompt=login`, or an unmet `max_age`, shows the login page;
  - `prompt=none`: no session or an unmet `max_age` is `login_required`, consent needed is `consent_required`;
  - a matching `id_token_hint` proceeds, another subject's is `login_required`;
  - a missing or disabled user counts as no session;
  - `WithoutBrowserSessions` always answers `login_required`.

  Verify: `go test -run 'TestProvider_BrowserSession' -count=1 ./oidcprovider/`.

## 7. Grants and tokens (`oidcprovider`, `oidc-provider-tokens`, `oidc-provider-userinfo`)

- [x] 7.1 Exchange a code in T2's order, test-first:
  - another client's code is consumed, then refused;
  - a wrong redirect URI, verifier or `dpop_jkt` is refused with the code left unspent; so is a verifier of bad syntax, and a verifier sent for a code with no challenge (R1);
  - a missing or disabled user is refused (R7);
  - the grant row, then the lineage, are written in T9's order, keeping a prior tombstone;
  - a client with no refresh grant gets a row holding no lineage, expiring at the sign-in's deadline (R10);
  - the online grant is capped at the sign-in's absolute deadline.

  The red tests for H3 and H5 come first: a grant created at 10:04 from a sign-in at 10:00 must carry 10:00; and a code outstanding when its sign-in ends, or when its user's grants are revoked, must be refused (R7). Verify: `go test -run 'TestProvider_ExchangeCode' -count=1 ./oidcprovider/`.
- [x] 7.2 Make code replay revoke what the code issued, test-first. The red tests for H2 come first: a replay after the exchange, and a replay that lands between the first exchange's consume and its commit, driven by a barrier. Both must end with the grant revoked and its refresh token refused. Also cover two concurrent exchanges, of which exactly one succeeds. Only a valid replay revokes: a wrong or missing verifier, or another client, revokes nothing (R17). Detection lasts until at least a minute past the code's expiry, through the default stores' sweeps, and a valid replay after that revokes nothing. A dependency failure during the spend, or a caller hanging up, is answered as such and not as a bad code. Verify: `go test -race -run 'TestProvider_CodeReplay' -count=1 ./oidcprovider/`.
- [x] 7.3 Mint ID tokens, test-first:
  - header `typ` `JWT`;
  - claims `iss`, `sub`, `aud` and `azp`, `iat`;
  - `sub` the user identifier, on a chain reading usernames too (R6);
  - `exp` 5 minutes later by default, set per client;
  - `auth_time`, `nonce`, `amr`, `acr` and `sid` (stable across renewals);
  - RS256 by default, ES256 per client.

  Verify: `go test -run 'TestProvider_IDToken' -count=1 ./oidcprovider/`.
- [x] 7.4 Mint access tokens, test-first:
  - a JWT with `typ` `at+jwt`, 5 minutes by default, set per client;
  - audience from `resource` within the allowlist and the grant (R15); with none named, the one granted resource alone, or `invalid_target` with the code unspent when several were granted (R15); with none granted, the client's default, plus the issuer for an `openid` token (R4), else the issuer; with `invalid_target` outside;
  - `gid` naming the grant (R4);
  - `cnf` when bound;
  - opaque `at.<id>.<secret>` tokens per client.

  Verify: `go test -run 'TestProvider_AccessToken' -count=1 ./oidcprovider/`.
- [x] 7.5 Refresh through the provider-private lineage manager, test-first. Cover:
  - a malformed token refused with no lookup;
  - a real family with a secret never issued refused, with nothing written (R8; red first);
  - the grant row checked before any write: missing, revoked, another client, or expired;
  - the binding checked before rotation;
  - a missing or disabled user refused, and the grant revoked;
  - narrowed scope allowed, omitted scope the grant's own, wider scope answered `invalid_scope`, and scopes the client has lost left out and reported (R13);
  - a client removed from the registry refused as `invalid_client`;
  - rotation with a 30-second grace by default, at most 5 minutes; `WithUnusedSuccessorRecovery` refused;
  - a token re-presented within 10 seconds of its rotation answering the same successor with no write, `WithRefreshSuccessorKey` defaulting to a per-process key, and `WithRefreshSuccessorWindow` (R20);
  - reuse revoking the whole grant through the reuse observer;
  - rotation off returning the same token;
  - refreshed tokens keeping the grant's authentication facts, and an ID token without `nonce`;
  - idle timeout 30 days and absolute lifetime 90 days by default, set per client.

  The red test for H4 comes first: a lineage missing while the grant row is live reads as revoked. Verify: `go test -race -run 'TestProvider_Refresh' -count=1 ./oidcprovider/`.
- [x] 7.6 Revoke and introspect, test-first:
  - revoking a refresh token ends its grant; an opaque token ends itself;
  - a public client may revoke by naming its `client_id` (R13);
  - a JWT, an unknown or an expired token answers success with nothing revoked; so does a real family with a forged secret (R8);
  - a superseded secret at revocation or introspection is not a reuse (R8);
  - another client's token is refused with `invalid_grant`;
  - introspection follows the visibility rule, refuses a public client, reports a JWT of a revoked grant inactive (R4), and an active answer carries the full field list.

  Verify: `go test -run 'TestProvider_Revoke|TestProvider_Introspect' -count=1 ./oidcprovider/`.
- [x] 7.7 Answer UserInfo, test-first. Cover:
  - only this provider's access tokens with `openid`, whose audience includes the issuer and whose grant is not revoked (R4);
  - claims released by scope, and absent claims omitted;
  - a replaceable claim source, defaulting to the identity store (`name`, `preferred_username`, and for the `email` scope a username that is exactly an email address as `email`, with `email_verified` false), with consumer values returned unchanged;
  - a missing or disabled user answered `invalid_token`.

  Verify: `go test -run 'TestProvider_UserInfo' -count=1 ./oidcprovider/`.
- [x] 7.8 End grants, test-first:
  - `EndSignIn` by T3's selectors, returning the clients to notify;
  - the provider as a session end observer, whose failure is logged and reported and never returned;
  - `RevokeUserGrants` with a cause, satisfying T8's ports;
  - a client tied to its sign-in losing its `offline_access` grants too;
  - consent revocation revoking that user's and client's grants.

  Verify: `go test -run 'TestProvider_EndSignIn|TestProvider_RevokeUserGrants' -count=1 ./oidcprovider/`.
- [x] 7.9 Build and deliver back-channel logout tokens, test-first:
  - the token: `typ` `logout+jwt`, `iss`, `aud`, `iat`, `exp` at most 2 minutes later, `jti`, `events`, `sub` and `sid`, no `nonce`, and the client's ID token algorithm;
  - `events` exactly the logout event with an empty object, and `sid` equal to the ID tokens';
  - delivery: asynchronous, through the outbound client with a timeout and no redirect followed, 200 and 204 as success, at most once per client per ended sign-in, one attempt;
  - a bounded pool and queue, a replaced worker, `Shutdown`, a drop reported as failed, and an uncancelled context (R14);
  - a failure logged and reported, never undoing the logout;
  - a replaceable delivery.

  Verify: `go test -race -run 'TestProvider_LogoutToken|TestProvider_BackChannelDelivery' -count=1 ./oidcprovider/`.
- [x] 7.10 Emit the provider's security events through D13's sink, test-first:
  - grant created;
  - consent given, denied or revoked;
  - client authentication refused;
  - code replayed;
  - refresh reused;
  - grant revoked with its cause;
  - delivery failed.

  Prove that no event, log line or error text carries a code, handle, token, assertion or secret, and that with no sink the behaviour is unchanged. Verify: `go test -run 'TestProvider_Events|TestProvider_NoSecretsInLogs' -count=1 ./oidcprovider/`.

## 8. Chain wiring, authorization and resume endpoints (`httpsec`, `http-security-chain`, `http-error-propagation`)

- [x] 8.1 Add `EnableOIDCProvider` with its construction rules, test-first, one table:
  - a bearer mode is required, and so is the JWKS endpoint;
  - an assertion token endpoint differing from the chain's real token path is refused (P7);
  - a JWKS endpoint serving a different signing-key manager from the provider's key source is refused, while a wrapped provider, which cannot be compared, builds (R6);
  - enabling it twice is refused, and so are path collisions;
  - every session manager on the chain must report to the provider (T4), judged after the chain's own wiring has run, because a manager can gain an observer at construction;
  - a client requiring DPoP while DPoP is not enabled is refused, and the provider's `WithDPoP` must agree with `EnableDPoP`;
  - CSRF protection required while browser sessions are on, and security headers required unless the consumer states its pages carry `frame-ancestors` (R2, R11);
  - the provider joins the internal set of features that verify bound credentials, so a provider-only chain can enable DPoP.

  Verify: `go test -run 'TestOIDCProvider_Construction' -count=1 ./httpsec/`.
- [x] 8.2 Route the provider's paths, test-first: the `/oauth2` defaults, a consumer prefix and per-path options, and other paths passing through. Verify: `go test -run 'TestOIDCProvider_Routes' -count=1 ./httpsec/`.
- [x] 8.3 Add the provider's public refusal errors to the status table, test-first:
  - 400 for an invalid client or redirect URI, an unknown handle and a malformed consent answer;
  - 401 for re-authentication needed;
  - 404 for another user's consents;
  - 500 for a dependency failure, with no text.

  Verify: `go test -run 'TestStatusForError' -count=1 ./httpsec/`.
- [x] 8.4 Serve the authorization endpoint, test-first, by GET and form POST:
  - an unredirectable error goes to the chain's error handling with no `Location` header;
  - other errors are 303 redirects with `state` and `iss`;
  - a parked request answers 303 to the login URL with the handle and `Cache-Control: no-store`, and sets or keeps the `__Host-` flow cookie (`HttpOnly`, `Secure`, `SameSite=Lax`), without the prefix or `Secure` under the loopback issuer;
  - a valid browser-session cookie is read and answered through 6.8;
  - a request not over TLS is refused (R11);
  - the endpoint is throttled per source.

  Verify: `go test -run 'TestOIDCAuthorize' -count=1 ./httpsec/`.
- [x] 8.5 Serve the resume endpoint, test-first:
  - the sign-in comes from the `Authorization` header, through the chain's bearer modes, and never from the query; at the consent stage alone, the browser session may stand in (R2);
  - an API key, Basic credentials, a session only a late renewal may recover, and a bound sign-in without its proof are refused (R6, R12);
  - a successful login stage sets the browser-session cookie (R2);
  - the policy phase refuses a session owing a step with its usual refusal, leaving the handle unspent;
  - the freshness refusal applies;
  - the answer is 200 with `{"redirect_to"}` and `Cache-Control: no-store`, never a redirect;
  - an unknown handle is charged to the source;
  - the consent stage accepts a grant or a denial.

  Verify: `go test -run 'TestOIDCResume' -count=1 ./httpsec/`.
- [x] 8.6 Let the consumer's pages read a pending request from an `httpsec.Request`, taking the flow cookie from it, test-first. Verify: `go test -run 'TestOIDCPendingRequest' -count=1 ./httpsec/`.
- [x] 8.7 Document `EnableOIDCProvider` in godoc, naming each default. Add the README section covering:
  - wiring, and the login and consent page contract;
  - pages served from the issuer's origin;
  - `frame-ancestors` for pages served outside the chain;
  - a login finished in another browser needing a restart (R9);
  - the browser session, what it does not see, and what `WithoutBrowserSessions` gives up (R2).

  Verify: `go doc ./httpsec EnableOIDCProvider` names the defaults, and `go vet ./...` is clean.

## 9. Token, revocation, introspection and UserInfo endpoints (`httpsec`)

- [x] 9.1 Serve the token endpoint, test-first:
  - form POST only, over TLS, with a repeated parameter refused and an empty one omitted; a credential in the query refused (R11);
  - client authentication before the grant, and failures charged to the source;
  - a JSON success with `Cache-Control: no-store`;
  - `{"error"}` errors with 400, or 401 with `WWW-Authenticate` for `invalid_client`, and no `error_description`.

  Verify: `go test -run 'TestOIDCToken' -count=1 ./httpsec/`.
- [x] 9.2 Bind tokens at the token endpoint, test-first:
  - the DPoP proof (without `ath`) is verified before a code is spent or a refresh token rotated;
  - access tokens carry `cnf.jkt` with `token_type` `DPoP`;
  - a public client's grant is bound to the key, a confidential client's is not;
  - clients that require binding are enforced;
  - `dpop_jkt` codes are honoured;
  - a client certificate binds through `cnf.x5t#S256`, and with a proof too only `cnf.jkt` is set;
  - `use_dpop_nonce` answered 400 with `DPoP-Nonce`, the code unspent and the token unrotated (R12);
  - a confidential client refreshing with no proof gets `Bearer` unless required; a required one is refused; a `DPoP` header while DPoP is off is ignored.

  Verify: `go test -run 'TestOIDCToken_SenderConstrained' -count=1 ./httpsec/`.
- [x] 9.3 Serve the revocation and introspection endpoints, with client authentication and `Cache-Control: no-store`, test-first. Verify: `go test -run 'TestOIDCRevoke|TestOIDCIntrospect' -count=1 ./httpsec/`.
- [x] 9.4 Serve UserInfo, test-first:
  - GET and POST, with the token from the header or a POST body and never the query;
  - over TLS (R11);
  - challenges: 401 `invalid_token`, 401 with no code when no token was sent, 403 `insufficient_scope`, and the `DPoP` scheme for a bound token, verified through D8, with `use_dpop_nonce` in its 401 form;
  - `Cache-Control: no-store`;
  - a claim-source outage answered 500 with no text.

  Verify: `go test -run 'TestOIDCUserInfo' -count=1 ./httpsec/`.
- [x] 9.5 Prove that a refresh token is never a sign-in, test-first: one presented as a session-reference bearer or to session renewal is refused as an unknown credential. Verify: `go test -run 'TestRefreshToken_NotASignIn' -count=1 ./httpsec/`.
- [x] 9.6 Apply CORS to the provider, test-first: the token, UserInfo, revocation, introspection and metadata endpoints follow the allowlist, allow `DPoP` and `Authorization`, expose `DPoP-Nonce` and `WWW-Authenticate`, and allow no credentials; the authorization, resume, end-session and confirmation endpoints never carry CORS headers. Verify: `go test -run 'TestCORS_OIDCProvider' -count=1 ./httpsec/`.

## 10. Metadata (`httpsec`, `oidc-provider-metadata`)

- [x] 10.1 Build both metadata documents from the configuration, test-first:
  - both well-known paths, including for an issuer with a path;
  - the required and supported members, endpoints following the paths in use, `end_session_endpoint` when logout is on;
  - the revocation and introspection authentication methods, the latter without `none`, and the assertion algorithms without `none` once `private_key_jwt` is listed (R11);
  - the refused features as `false`, and `authorization_response_iss_parameter_supported` and back-channel logout as `true`;
  - the DPoP and certificate members only when enabled;
  - consumer members added, and an override of a provider member refused at construction.

  Verify: `go test -run 'TestOIDCMetadata' -count=1 ./httpsec/`.
- [x] 10.2 Serve the documents publicly with `Cache-Control` of 1 hour by default, replaceable, test-first, and prove that the JWKS endpoint keeps publishing the previous key after a rotation. Verify: `go test -run 'TestOIDCMetadata_Serving' -count=1 ./httpsec/`.

## 11. Logout, consents and grant revocation across the chain

- [x] 11.1 Serve the end-session endpoint, test-first (R3):
  - GET and form POST, with `logout_hint` accepted and not acted on;
  - `id_token_hint` verified by type, signature and issuer with expiry ignored, and its audience matched to `client_id`;
  - a valid hint naming the browser session's sign-in ends it as a logout does, without asking; `WithLogoutConfirmation` asks anyway;
  - a hint failing under a published key is a chain 400, with no redirect and nothing ended;
  - no hint, a retired key's hint, or a hint for another sign-in parks the request and sends the browser to the logout page with a handle, nothing ended;
  - an exactly registered `post_logout_redirect_uri` with a valid hint gets `state`, and every other case the logged-out page, including `client_id` with no hint.

  Verify: `go test -run 'TestOIDCEndSession' -count=1 ./httpsec/`.
- [x] 11.8 Serve the logout confirmation, test-first (R3): a POST with the handle and flow cookie, answering 200 with `redirect_to` and `Cache-Control: no-store`; it ends the browser session's sign-in and never the one a hint names, unless browser sessions are off; a browser with no session ends nothing, and is no error; a declined answer ends nothing; CSRF protection stays on. Verify: `go test -run 'TestOIDCLogoutConfirm' -count=1 ./httpsec/`.
- [x] 11.2 Make the chain's logout end the sign-in through the provider before deleting its sessions, test-first. A grant-store failure answers 500 and leaves the session loadable, a retry succeeds, and a failed notification does not fail the logout. Verify: `go test -run 'TestLogout_EndsProviderGrants' -count=1 ./httpsec/`.
- [x] 11.3 Prove that the other ends reach the provider through the session end observer, test-first:
  - reuse revocation, `EndSignIn`, ending other sessions (D12), passkey removal ending other sessions, and `DeleteByUser`;
  - each also ending the sign-in's browser sessions (R2);
  - their failures logged and reported, never undoing the end;
  - a sign-in that expires sending nothing.

  Verify: `go test -run 'TestOIDCProvider_SignInEnds' -count=1 ./httpsec/`.
- [x] 11.4 Make an upstream back-channel logout end the provider grants of the sessions it ends, with its response unchanged, test-first. Verify: `go test -run 'TestOIDCBackchannel_EndsProviderGrants' -count=1 ./httpsec/`.
- [x] 11.5 Serve `/consents`, test-first:
  - the signed-in user lists their own consents, with names, scopes, offline access and when consent was last given;
  - revoking one's own consent revokes that user's and client's grants;
  - another user's consent is a 404 refusal;
  - CSRF protection stays on.

  Verify: `go test -run 'TestOIDCConsents' -count=1 ./httpsec/`.
- [x] 11.6 Revoke grants through T8's ports, test-first:
  - recovery completion, with a failure returned;
  - an MFA reset, with a failure returned after the removals;
  - passkey clone suspension;
  - the password-change option, revoking before the new password is written;
  - D12's "revoke application access" choice.

  Each event has an option to keep grants, with no change when the provider is not in use. Verify: `go test -run 'TestRecoverer_RevokesGrants|TestResetEnrolment_RevokesGrants' -count=1 ./recovery/ ./authenticate/mfa/`, and `go test -run 'TestPasskey_CloneRevokesGrants|TestPasswordChange_RevokesGrants|TestSessionManagement_RevokeApplicationAccess' -count=1 ./httpsec/`.
- [x] 11.7 Exempt the authorization, token, revocation, introspection and end-session endpoints from the cross-site check, while resume, the logout confirmation and `/consents` stay protected, test-first, with a cross-site consent answer and a cross-site confirmation as the red cases. Document logout, consents and the event options in godoc and the README. Verify: `go test -run 'TestCSRF_OIDCProviderExemptions' -count=1 ./httpsec/`, and `go doc ./httpsec` names the new options' defaults.

## 12. Durable stores, migration and sweeping (`schema-migrations`, `security-state-stores`, `expiry-sweeping`)

- [x] 12.1 Write the security-state migration that creates the provider's nine tables and every lookup index (grants by user, by user and client, by sign-in, by upstream session; held codes and browser sessions by user, by sign-in and by upstream session), test-first, with a populated-database test and a rollback test. Verify: `go test -run 'TestMigrations' ./...` in the `test` module, against PostgreSQL 15 and 18.
- [x] 12.2 Implement every provider store in `sqlstore`, and `NewRefreshTokenStore` over the fixed `op_refresh_tokens` table (T7), test-first, driven by the suites. Include the "lineage identifier not found through the session store" case and the "no credential in any column" case. Verify: `go test -race -run 'TestSQLStore' ./sqlstore/...` in the `test` module.
- [x] 12.3 Implement the same in `pgxstore`, test-first. Verify: `go test -race -run 'TestPgxStore' ./pgxstore/...` in the `test` module.
- [x] 12.4 Implement the same in `gormstore`, test-first. Verify: `go test -race -run 'TestGormStore' ./gormstore/...` in the `test` module.
- [x] 12.5 Add the expiry tasks, test-first:
  - code records swept only a minute past their expiry, so an exchange in flight keeps the record an end needs (R7);
  - pending requests, browser sessions, codes (the onetime purge), opaque tokens and assertion identifiers;
  - grants, keeping revoked ones until the codes that name them expire;
  - lineages under a renamed task;
  - no orphan pass (R19): remove `GrantStore.DeleteOrphans`, its memory and adapter implementations, its statements and suite rows, and prove that a grant whose lineage went idle stays stored and its client is told when the sign-in ends.

  Verify: `go test -run 'TestExpiryTasks_OIDCProvider' ./...` in the `test` module.
- [x] 12.6 Prove on each backend that an authorization, an exchange, a refresh after a restart, and a revocation succeed, test-first. Verify: `go test -run 'TestOIDCProvider_Durable' ./...` in the `test` module.

## 13. Framework adapters (`framework-adapters`)

- [x] 13.1 Run the provider scenarios on net/http, gin and fiber in `test/httpsecconformance`, test-first:
  - authorize redirect and flow cookie, and the browser-session cookie's attributes;
  - resume JSON;
  - token JSON with `no-store`;
  - UserInfo challenge;
  - metadata;
  - end-session redirect, and the logout confirmation.

  Verify: `go test -run 'TestConformance(NetHTTP|Gin|Fiber)/oidcprovider' ./...` in the `test` module.

## 14. OpenID conformance in CI (P9)

- [x] 14.1 Add a conformance OP command to the `test` module (R5): the provider's defaults served over `https` on a self-signed certificate; `client` and `client2` with secrets, registered as `PKCEOrNonce` and for the refresh grant; server-rendered plain-form login, consent and logout pages that resume through the provider's Go API; and users holding profile, email, phone and address claims. Verify: it starts locally, and the suite's discovery test reaches it.
- [x] 14.2 Add `make conformance` and a CI job `conformance` in `split-ci-jobs`' shape: the job calls the target, the target is outside `make check`, `ci-ok` requires the job, the suite is pinned to a full commit hash because it is built from source, and the images the job names are pinned by digest for `pincheck`. It starts the suite and the OP with Docker Compose, and runs `scripts/run-test-plan.py` over the Basic OP, Config OP, RP-initiated logout and back-channel logout plans, with one expected failure, `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`. It fails on any unexpected `FAILED`, `WARNING` or `INTERRUPTED` result, and on an expected one that stops occurring, and keeps the logs as an artifact. Verify: the job runs on a pull request and reports all four plans.
- [x] 14.3 Triage every failing test:
  - a provider defect gets a failing unit test in its owning package, then the fix;
  - a job misconfiguration is fixed in the job;
  - nothing is added to the expected-failures file without a decision recorded in `design.md`.

  Verify: all four plans pass in CI.

## 15. Integration and release gate

- [x] 15.1 Amend `release-readiness`: its gate names the `conformance` job, its first changelog entry summarises this change, and its README task drops the `prompt=none` limitation in favour of R2's and R9's. Update its `plans.md` through `/superpowers:writing-plans` (`tasks-plans`). Verify: `openspec validate release-readiness --strict`.
- [x] 15.2 Run one whole-branch review against every requirement this change's specs add or modify (`subagent-delegation`), and fold its findings in. Verify: the review reports nothing open.
- [x] 15.3 Run the final gate. Verify:
  - `make check` passes in the core module;
  - the `test` module's full suite passes with `-race` against PostgreSQL 15 and 18;
  - the `conformance` job is green.

## 16. The code review of #72 (R27)

The defects here are `UNREPRODUCED`. Each task's first step is the failing test. If it passes before the fix, the claim was wrong: stop, say so, and remove that part of R27.

- [ ] 16.1 A recovery revokes the user's grants after its proofs pass every check and before any is spent, and a failure there is a dependency failure with nothing spent, so the same proofs succeed when retried. It revokes again after the sessions end, where a failure no longer aborts: the session is stored, saved codes are reissued, the notice is sent, `Result` says the grants were not revoked, and `scrty_grant_revoke_failed` is reported through the recoverer's sink. A held recovery revokes nothing at its start and takes the same two steps at its finish, where a first failure leaves the finish able to be retried. Update `event.GrantRevokeFailed`'s godoc and `WithGrantRevoker`'s, and carry the result through `httpsec`'s recovery. Verify: `go test -race -run 'Recover' ./recovery/ ./httpsec/`, with each failure position covered and `WithoutRecoveryGrantRevocation` still revoking nothing.
- [ ] 16.2 A form POST with no flow cookie to the authorization or end-session endpoint answers 303 to the same endpoint with its parameters in the query, with `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, no `Set-Cookie`, nothing parked and nothing charged, and repeated parameters preserved. One holding the cookie is answered directly. Verify: `go test -race -run 'OIDC' ./httpsec/`; the `test` module's `TestConformance(NetHTTP|Gin|Fiber)` scenarios; the conformance suite's POST modules, including `oidcc-ensure-post-request-succeeds`, through `make conformance`; and a real browser confirming that a cross-site POST's redirected GET carries the Lax cookie. Record both results in R27. If either fails, stop and reopen the decision.
- [ ] 16.3 With an end observer, `Delete` and `DeleteByUserExcept` return a read failure other than gone or expired before any write, and report nothing. With no observer they do not read. `RevokeFamily` still reads nothing, and `Delete`'s godoc points a logout at it. Verify: `go test -race -run 'EndObserver|Delete|RevokeFamily' ./session/`; a provider-level test that a failed read leaves the sign-in's grants and the kept sign-in's grants as they were; and an `httpsec` test that the chain's logout and end-session complete while session reads fail.
- [ ] 16.4 `oidcprovider.New` refuses `WithRefreshTokenStore` with no `WithRefreshSuccessorKey` and the window on, naming both ways out, in either option order. Give the durable tests and the README's wiring a key. Update `WithRefreshSuccessorKey`'s and `WithRefreshTokenStore`'s godoc, saying the key serves this purpose alone. Verify: `go test -race -run 'Provider|Successor' ./oidcprovider/`, and the `test` module's durable suites on PostgreSQL 15 and 18.
- [ ] 16.5 A key-source failure judging `id_token_hint` at the authorization endpoint, with the client and redirect URI valid, redirects with `server_error` and the request's `state` and parks nothing, including with `prompt=none`, and logs only the error's type. A request whose client or redirect URI is invalid still gets no redirect. At the end-session endpoint a key outage stays an error at the OP, with no post-logout redirection. Verify: `go test -race -run 'Hint|EndSession' ./oidcprovider/`.
- [ ] 16.6 Run one whole-branch review against the requirements 16.1 to 16.5 add or change, and against whatever a change in `session` or the recovery order reaches, and fold its findings in. Verify: the review reports nothing open.
- [ ] 16.7 Run the final gate again, as in 15.3, and confirm CodeQL reports no new alert on #72. Tell the `session-signals` session about the `sessions` requirement this adds, as its rebase carries that spec. Verify: `make check`, the `test` module with `-race` on PostgreSQL 15 and 18, and the `conformance` job are green.

## Workflow follow-up

- Archive the change after the pull request merges and the review requirements are met, then verify the archived specs with `openspec validate --specs --strict`.
