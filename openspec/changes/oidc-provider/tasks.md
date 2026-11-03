# Tasks

Every implementation task is test-first: write the failing test, run it and confirm it fails for the intended reason (a compile error is not a red step), make it pass with the smallest change, then refactor. "Verify" names the command whose output proves the task done. Run the touched module's full suite with `-race` at the end of each group.

The risks the design labels `UNREPRODUCED` (H2, H3, H4, token-type confusion) are each the red step of the task that names them. If such a test passes before the fix, the claim was wrong: say so, and record it in `design.md` (`defect-claims`).

## 1. Baseline check (before any code)

- [ ] 1.1 Once `close-security-gaps` and `pre-release-api-fixes` have merged, rebase this branch onto `main`. Recheck the design's "What exists", P6 and T4 against the merged code, and record every difference in `design.md`:
  - DPoP: the proof-verification entry point a non-bearer endpoint can call, the `jti` and nonce stores, and the internal set of features that verify bound credentials (D8 as amended);
  - certificate binding: the thumbprint accessor (D9);
  - CSRF: the exemption API (D6);
  - CORS: how routes are matched (D5);
  - security events: the sink and the event shape (D13);
  - session listing: the end-by-handle method and the end-others endpoint (D12);
  - `sub`: that it is the user identifier by default.

  Verify: `openspec validate oidc-provider --strict` passes, and `design.md` names the merged commits.
- [ ] 1.2 Run the OpenID Foundation conformance suite locally once, and record P9's three unverified facts in `design.md`: the exact Basic OP and Config OP plan names and test lists, whether an `http://` loopback issuer is accepted or TLS with a trusted certificate is needed, and where the headless runner lives. Verify: P9's "Unverified" list is replaced by the facts with their sources, and `openspec validate oidc-provider --strict` passes.

## 2. Token types and claims (`token`, `token-issuance`)

- [ ] 2.1 Issue every first-party token with header `typ` `scrty+jwt`, replaceable by an option. Refuse at construction a replacement equal to `at+jwt`, `JWT` or `logout+jwt`, test-first. Verify: `go test -run 'TestGenerator_TokenType' -count=1 ./token/`.
- [ ] 2.2 Enforce `typ` at verification: a verifier accepts only its declared type (the first-party type by default), compared case-insensitively with an `application/` prefix ignored. A missing or other type is refused as `ErrInvalid`, and no option accepts any type. Test-first, including the red test for the token-type confusion risk: an `at+jwt` token signed by the same keys, with the same issuer and audience, refused by a default verifier. Verify: `go test -run 'TestVerifier_TokenType' -count=1 ./token/`.
- [ ] 2.3 Issue a token of a declared type with further claims (`client_id`, `scope`, `nonce`, `auth_time`, `acr`, `amr`, `azp`, `sid`, `events`, `cnf`) and a per-token audience of one or more values. A further claim naming `iss`, `iat`, `exp` or `jti` fails as a configuration error and issues nothing, test-first. Extend the jwx allow-list test only for calls this task adds. Verify: `go test -run 'TestGenerator_IssueTyped|TestJWXAllowList' -count=1 ./token/`.
- [ ] 2.4 Prove at the chain that an ID token and an access token presented to `EnableBearerToken` are refused as unauthenticated, test-first. Godoc the type option and the typed issue with their defaults. Verify: `go test -run 'TestBearer_RefusesOtherTokenTypes' -count=1 ./httpsec/`, and `go doc ./token` names the default type.

## 3. Session end observers (`session`, `sessions`, design T4)

- [ ] 3.1 Add the repeatable `WithEndObserver` option, refuse a nil observer at construction, and add `(*Sessions).ReportsEndsTo`, comparing observers by identity, test-first. Verify: `go test -run 'TestSessions_EndObserverConstruction|TestSessions_ReportsEndsTo' -count=1 ./session/`.
- [ ] 3.2 Report each explicit end after its store write, test-first, one table over every ending path: reuse revocation, `RevokeFamily`, `Delete`, `DeleteByUser`, `DeleteByUserExcept` (with the kept family), `DeleteByExternalSession`, `DeleteByUserAndExternalIssuer`, and D12's end-by-handle. Assert each report's cause, user, family and upstream session, that no report holds a session identifier, that observers run in order, and that nothing is reported on a failed write or by `DeleteExpired`. Verify: `go test -run 'TestSessions_EndObserver' -count=1 ./session/`.
- [ ] 3.3 Godoc the option, the report and `ReportsEndsTo`, stating that expiry is never reported. Verify: `go doc ./session WithEndObserver` describes what is and is not reported.

## 4. Provider construction and clients (`oidcprovider`, `oidc-provider-clients`, design T1)

- [ ] 4.1 Create the `oidcprovider` package with `New`, test-first, one construction table:
  - issuer `https` with no query or fragment, and the loopback-only `http` option;
  - login and consent URLs required, absolute and on the issuer's site;
  - the pending-request lifetime positive and at most 30 minutes;
  - the code lifetime at most 10 minutes;
  - the assertion lifetime bound at most 1 hour;
  - the logged-out page required when logout is enabled.

  Verify: `go test -run 'TestNew_Construction' -count=1 ./oidcprovider/`.
- [ ] 4.2 Validate client registration at construction, test-first, one table, each failure naming the client and setting:
  - client type: confidential or public; application type web (default) or native;
  - authentication method: one per client, `client_secret_basic` by default, `client_secret_jwt` refused, a secret method on a public client refused, `none` on a confidential client refused;
  - redirect URIs: required when the client uses the authorization endpoint; absolute, without fragment or wildcard; `https` for web; `https`, a private-use scheme or loopback `http` for native. Post-logout URIs follow the same rules, and a back-channel logout URI must be `https`;
  - uniqueness and keys: duplicate identifiers refused; an ID token algorithm the keys cannot produce refused;
  - offline access: pre-authorization only for a first-party native client;
  - refresh: rotation off only for a confidential client required to use sender-constrained tokens; grace at most 5 minutes; idle timeout at most the absolute lifetime;
  - defaults: first-party off, grant types `authorization_code`.

  Verify: `go test -run 'TestClient_Validation' -count=1 ./oidcprovider/`.
- [ ] 4.3 Match redirect URIs by exact string, except that a native client's loopback IP redirect URI may differ in port only, test-first, with the four `oidc-provider-clients` scenarios as the table. Verify: `go test -run 'TestClient_MatchRedirectURI' -count=1 ./oidcprovider/`.
- [ ] 4.4 Add the client registry port and its in-memory default built from configuration, test-first, covering:
  - a consumer registry replacing the default;
  - generated secrets: 256 bits, returned once, stored as a digest;
  - supplied secrets: at least 32 bytes;
  - constant-time comparison;
  - no secret or digest in an error's text.

  Verify: `go test -run 'TestMemoryRegistry|TestRegistry_Secrets' -count=1 ./oidcprovider/`.
- [ ] 4.5 Authenticate clients by `client_secret_basic` (Base64, then URL-decode), `client_secret_post` and `none`, test-first: the wrong method, two methods at once and an undecodable header are `invalid_client`. Verify: `go test -run 'TestAuthenticateClient' -count=1 ./oidcprovider/`.
- [ ] 4.6 Verify `private_key_jwt` assertions, test-first. Cover:
  - an asymmetric algorithm only;
  - `iss` and `sub` equal to `client_id`;
  - `aud` the issuer alone by default, with the `AudienceIssuerOrTokenEndpoint` option;
  - `exp` present, in the future, and within the bound (5 minutes by default);
  - `jti` recorded through the assertion-identifier store until `exp`, with a replay refused;
  - keys from the registered set or `jwks_uri`, fetched through the outbound client and cached;
  - a fetch failure reported as a dependency failure, not as `invalid_client`.

  Verify: `go test -run 'TestAuthenticateClient_PrivateKeyJWT' -count=1 ./oidcprovider/`.
- [ ] 4.7 Godoc the package, `New`, `Client` and every option, each naming its default and limit. Verify: `go doc ./oidcprovider` lists them, and `go vet ./oidcprovider/` is clean.

## 5. Provider stores, in-memory defaults and conformance suites (`security-state-stores`, `store-conformance`, design T2, T3, T6, T7)

- [ ] 5.1 Add the pending-request store port and its in-memory default, test-first. Records hold the handle's and the flow secret's digests. The stage advances login → consent → done by one conditional write, and expiry is judged at the caller's time. Add its exported suite to `test/storetest`. Verify: `go test -run 'TestMemory/PendingRequests' ./storetest/` in the `test` module.
- [ ] 5.2 Add the code-record store port and its in-memory default, keyed by the `token/onetime` identifier and holding every binding of T2, including the grant family `F`, test-first, with its suite. Verify: `go test -run 'TestMemory/CodeRecords' ./storetest/` in the `test` module.
- [ ] 5.3 Add the consent store port and its in-memory default, test-first, with its suite:
  - scopes accumulate per user and client;
  - offline consent is recorded only when given explicitly;
  - the time consent was last given is kept;
  - consent can be revoked, and listed by user only.

  Verify: `go test -run 'TestMemory/Consents' ./storetest/` in the `test` module.
- [ ] 5.4 Add the grant store port and its in-memory default, test-first, with its suite:
  - create keeps a revocation recorded first (the H2 tombstone);
  - load by family;
  - revoke, which inserts a tombstone when no row exists;
  - revoke by user, and by user and client;
  - end sign-ins by each T3 selector, returning only newly marked grants;
  - grants record the sign-in's family and upstream session unchanged;
  - expired grants are deleted, and revoked ones are kept until the codes that could name them expire.

  Verify: `go test -run 'TestMemory/Grants' ./storetest/` in the `test` module.
- [ ] 5.5 Add `RefreshTokenStore` as a type with only an unexported field, built through a scrty `internal` package (T7), with a private in-memory default, test-first. A test outside scrty's import path cannot build one from a `session.Store`, shown by an example that fails to compile and is kept out of the build. Verify: `go test -run 'TestRefreshTokenStore' -count=1 ./oidcprovider/`.
- [ ] 5.6 Add the opaque access-token store (digests; revoke one; delete expired) and the assertion-identifier store (insert-if-absent per client until `exp`) with their in-memory defaults and suites, test-first. Verify: `go test -run 'TestMemory/(AccessTokens|AssertionIDs)' ./storetest/` in the `test` module.
- [ ] 5.7 Extend the exported race suite, test-first, so each case fails against a deliberately broken store:
  - single spend of a code, a handle stage and an assertion identifier under concurrency;
  - a tombstone surviving a concurrent create;
  - an end reported twice returning nothing the second time.

  Run it against every in-memory default. Verify: `go test -race -run 'TestMemory|TestRace|TestBroken' ./storetest/` in the `test` module.

## 6. Authorization and consent (`oidcprovider`, `oidc-provider-authorization`, `oidc-provider-consent`)

- [ ] 6.1 Validate an authorization request, test-first, one table over `oidc-provider-authorization`'s scenarios:
  - client and redirect URI first, as an unredirectable error;
  - then `response_type=code` and `response_mode=query` only, and a repeated parameter refused;
  - PKCE `S256` with a 43 to 128 character unreserved challenge;
  - allowed scopes, with `openid` detection; allowed `resource` values (`invalid_target`);
  - `request` and `request_uri` unsupported, and no fetch made;
  - `prompt`, with `none` alone; `max_age`;
  - `id_token_hint` verified by signature and issuer with expiry ignored;
  - `dpop_jkt`; `login_hint` and `ui_locales` kept.

  Every redirect error carries `state` and `iss`, and no `error_description`. Verify: `go test -run 'TestValidateAuthorizationRequest' -count=1 ./oidcprovider/`.
- [ ] 6.2 Park a valid request, test-first: an `rh.<id>.<secret>` handle of at least 128 bits, a separate 256-bit flow secret (T5), a 10-minute lifetime by default with `WithPendingRequestLifetime`, and expiry refused as an unknown handle. Verify: `go test -run 'TestProvider_Park' -count=1 ./oidcprovider/`.
- [ ] 6.3 Expose `PendingRequest` for the consumer's pages, test-first:
  - it requires the flow secret, or the handle is unknown;
  - it holds the client's identifier and name, the requested and already granted scopes, `prompt`, `max_age`, `login_hint`, `ui_locales` and the stage;
  - it never holds the challenge, the nonce, the state or the redirect URI.

  Verify: `go test -run 'TestProvider_PendingRequest' -count=1 ./oidcprovider/`.
- [ ] 6.4 Decide whether consent is needed, test-first, one table over `oidc-provider-consent`:
  - required by default; skipped when remembered consent covers the scopes;
  - always shown for `prompt=consent`;
  - skipped by a first-party client for ordinary scopes;
  - `offline_access` asked unless explicitly consented before or the native client is pre-authorized, and honoured only when a code results.

  Verify: `go test -run 'TestConsentNeeded' -count=1 ./oidcprovider/`.
- [ ] 6.5 Resume the login stage from sign-in facts, test-first:
  - the handle and flow secret must be valid, and the stage spent once;
  - `prompt=login` needs authentication after parking, and `max_age` (with 0 as `login`) is measured against `AuthenticatedAt`, never the renewal time. A failure leaves the handle unspent;
  - a hint naming another subject answers `login_required`;
  - `prompt=none` answers `login_required`;
  - the answer is the consent URL with the handle, or the code redirect.

  Verify: `go test -run 'TestProvider_ResumeLogin' -count=1 ./oidcprovider/`.
- [ ] 6.6 Resume the consent stage, test-first:
  - the same user as the login stage;
  - granted scopes a subset that keeps `openid`, otherwise malformed with the handle unspent;
  - a denial answers `access_denied` and records nothing;
  - a grant adds to the remembered consent and binds the code to the granted scopes.

  Verify: `go test -run 'TestProvider_ResumeConsent' -count=1 ./oidcprovider/`.
- [ ] 6.7 Issue codes through `token/onetime` with a code record (T2), test-first: every binding including `F`, a 60-second default with `WithCodeLifetime` up to 10 minutes, and a success redirect carrying `code`, `state` and `iss`. Godoc the authorization and consent API. Verify: `go test -run 'TestProvider_IssueCode' -count=1 ./oidcprovider/`, and `go doc ./oidcprovider PendingRequest`.

## 7. Grants and tokens (`oidcprovider`, `oidc-provider-tokens`, `oidc-provider-userinfo`)

- [ ] 7.1 Exchange a code in T2's order, test-first:
  - another client's code is consumed, then refused;
  - a wrong redirect URI, verifier or `dpop_jkt` is refused with the code left unspent;
  - the lineage and the grant row are written in one transaction that keeps a prior tombstone;
  - the online grant is capped at the sign-in's absolute deadline.

  The red test for H3 comes first: a grant created at 10:04 from a sign-in at 10:00 must carry 10:00. Verify: `go test -run 'TestProvider_ExchangeCode' -count=1 ./oidcprovider/`.
- [ ] 7.2 Make code replay revoke what the code issued, test-first. The red tests for H2 come first: a replay after the exchange, and a replay that lands between the first exchange's consume and its commit, driven by a barrier. Both must end with the grant revoked and its refresh token refused. Also cover two concurrent exchanges, of which exactly one succeeds. Verify: `go test -race -run 'TestProvider_CodeReplay' -count=1 ./oidcprovider/`.
- [ ] 7.3 Mint ID tokens, test-first:
  - header `typ` `JWT`;
  - claims `iss`, `sub`, `aud` and `azp`, `iat`;
  - `exp` 5 minutes later by default, set per client;
  - `auth_time`, `nonce`, `amr`, `acr` and `sid` (stable across renewals);
  - RS256 by default, ES256 per client.

  Verify: `go test -run 'TestProvider_IDToken' -count=1 ./oidcprovider/`.
- [ ] 7.4 Mint access tokens, test-first:
  - a JWT with `typ` `at+jwt`, 5 minutes by default, set per client;
  - audience from `resource` within the allowlist, else the client's default, else the issuer, with `invalid_target` outside the allowlist;
  - `cnf` when bound;
  - opaque `at.<id>.<secret>` tokens per client.

  Verify: `go test -run 'TestProvider_AccessToken' -count=1 ./oidcprovider/`.
- [ ] 7.5 Refresh through the provider-private lineage manager, test-first. Cover:
  - a malformed token refused with no lookup;
  - the grant row checked before any write: missing, revoked, another client, or expired;
  - the binding checked before rotation;
  - a missing or disabled user refused, and the grant revoked;
  - narrowed scope allowed, wider scope answered `invalid_scope`;
  - rotation with a 30-second grace by default, at most 5 minutes; `WithUnusedSuccessorRecovery` refused;
  - reuse revoking the whole grant through the reuse observer;
  - rotation off returning the same token;
  - refreshed tokens keeping the grant's authentication facts, and an ID token without `nonce`;
  - idle timeout 30 days and absolute lifetime 90 days by default, set per client.

  The red test for H4 comes first: a lineage missing while the grant row is live reads as revoked. Verify: `go test -race -run 'TestProvider_Refresh' -count=1 ./oidcprovider/`.
- [ ] 7.6 Revoke and introspect, test-first:
  - revoking a refresh token ends its grant; an opaque token ends itself;
  - a JWT, an unknown or an expired token answers success with nothing revoked;
  - another client's token is refused with `invalid_grant`;
  - introspection follows the visibility rule, and an active answer carries the full field list.

  Verify: `go test -run 'TestProvider_Revoke|TestProvider_Introspect' -count=1 ./oidcprovider/`.
- [ ] 7.7 Answer UserInfo, test-first. Cover:
  - only this provider's access tokens with `openid`, of any audience;
  - claims released by scope, and absent claims omitted;
  - a replaceable claim source, defaulting to the identity store (`preferred_username`, `email`, `email_verified`), with consumer values returned unchanged;
  - a missing or disabled user answered `invalid_token`.

  Verify: `go test -run 'TestProvider_UserInfo' -count=1 ./oidcprovider/`.
- [ ] 7.8 End grants, test-first:
  - `EndSignIn` by T3's selectors, returning the clients to notify;
  - the provider as a session end observer, whose failure is logged and reported and never returned;
  - `RevokeUserGrants` with a cause, satisfying T8's ports;
  - a client tied to its sign-in losing its `offline_access` grants too;
  - consent revocation revoking that user's and client's grants.

  Verify: `go test -run 'TestProvider_EndSignIn|TestProvider_RevokeUserGrants' -count=1 ./oidcprovider/`.
- [ ] 7.9 Build and deliver back-channel logout tokens, test-first:
  - the token: `typ` `logout+jwt`, `iss`, `aud`, `iat`, `exp` at most 2 minutes later, `jti`, `events`, `sub` and `sid`, no `nonce`, and the client's ID token algorithm;
  - delivery: asynchronous, through the outbound client with a timeout, at most once per client per ended sign-in, one attempt;
  - a failure logged and reported, never undoing the logout;
  - a replaceable delivery.

  Verify: `go test -race -run 'TestProvider_LogoutToken|TestProvider_BackChannelDelivery' -count=1 ./oidcprovider/`.
- [ ] 7.10 Emit the provider's security events through D13's sink, test-first:
  - grant created;
  - consent given, denied or revoked;
  - client authentication refused;
  - code replayed;
  - refresh reused;
  - grant revoked with its cause;
  - delivery failed.

  Prove that no event, log line or error text carries a code, handle, token, assertion or secret, and that with no sink the behaviour is unchanged. Verify: `go test -run 'TestProvider_Events|TestProvider_NoSecretsInLogs' -count=1 ./oidcprovider/`.

## 8. Chain wiring, authorization and resume endpoints (`httpsec`, `http-security-chain`, `http-error-propagation`)

- [ ] 8.1 Add `EnableOIDCProvider` with its construction rules, test-first, one table:
  - a bearer mode is required, and so is the JWKS endpoint;
  - enabling it twice is refused, and so are path collisions;
  - every session manager on the chain must report to the provider (T4);
  - a client requiring DPoP while DPoP is not enabled is refused;
  - the provider joins the internal set of features that verify bound credentials, so a provider-only chain can enable DPoP.

  Verify: `go test -run 'TestOIDCProvider_Construction' -count=1 ./httpsec/`.
- [ ] 8.2 Route the provider's paths, test-first: the `/oauth2` defaults, a consumer prefix and per-path options, and other paths passing through. Verify: `go test -run 'TestOIDCProvider_Routes' -count=1 ./httpsec/`.
- [ ] 8.3 Add the provider's public refusal errors to the status table, test-first:
  - 400 for an invalid client or redirect URI, an unknown handle and a malformed consent answer;
  - 401 for re-authentication needed;
  - 404 for another user's consents;
  - 500 for a dependency failure, with no text.

  Verify: `go test -run 'TestStatusForError' -count=1 ./httpsec/`.
- [ ] 8.4 Serve the authorization endpoint, test-first, by GET and form POST:
  - an unredirectable error goes to the chain's error handling with no `Location` header;
  - other errors are 303 redirects with `state` and `iss`;
  - a parked request answers 303 to the login URL with the handle, and sets the `__Host-` flow cookie (`HttpOnly`, `Secure`, `SameSite=Lax`);
  - the endpoint is throttled per source.

  Verify: `go test -run 'TestOIDCAuthorize' -count=1 ./httpsec/`.
- [ ] 8.5 Serve the resume endpoint, test-first:
  - the sign-in comes from the `Authorization` header only, through the chain's bearer modes, and is never read from a cookie or the query;
  - the policy phase refuses a session owing a step with its usual refusal, leaving the handle unspent;
  - the freshness refusal applies;
  - the answer is 200 with `{"redirect_to"}` and `Cache-Control: no-store`, never a redirect;
  - an unknown handle is charged to the source;
  - the consent stage accepts a grant or a denial.

  Verify: `go test -run 'TestOIDCResume' -count=1 ./httpsec/`.
- [ ] 8.6 Let the consumer's pages read a pending request from an `httpsec.Request`, taking the flow cookie from it, test-first. Verify: `go test -run 'TestOIDCPendingRequest' -count=1 ./httpsec/`.
- [ ] 8.7 Document `EnableOIDCProvider` in godoc, naming each default. Add the README section covering:
  - wiring, and the login and consent page contract;
  - pages served from the provider's site;
  - `frame-ancestors` for pages served outside the chain;
  - the known `prompt=none` limitation.

  Verify: `go doc ./httpsec EnableOIDCProvider` names the defaults, and `go vet ./...` is clean.

## 9. Token, revocation, introspection and UserInfo endpoints (`httpsec`)

- [ ] 9.1 Serve the token endpoint, test-first:
  - form POST only, with a repeated parameter refused;
  - client authentication before the grant, and failures charged to the source;
  - a JSON success with `Cache-Control: no-store`;
  - `{"error"}` errors with 400, or 401 with `WWW-Authenticate` for `invalid_client`, and no `error_description`.

  Verify: `go test -run 'TestOIDCToken' -count=1 ./httpsec/`.
- [ ] 9.2 Bind tokens at the token endpoint, test-first:
  - the DPoP proof (without `ath`) is verified before a code is spent or a refresh token rotated;
  - access tokens carry `cnf.jkt` with `token_type` `DPoP`;
  - a public client's grant is bound to the key, a confidential client's is not;
  - clients that require binding are enforced;
  - `dpop_jkt` codes are honoured;
  - a client certificate binds through `cnf.x5t#S256`.

  Verify: `go test -run 'TestOIDCToken_SenderConstrained' -count=1 ./httpsec/`.
- [ ] 9.3 Serve the revocation and introspection endpoints, with client authentication and `Cache-Control: no-store`, test-first. Verify: `go test -run 'TestOIDCRevoke|TestOIDCIntrospect' -count=1 ./httpsec/`.
- [ ] 9.4 Serve UserInfo, test-first:
  - GET and POST, with the token from the header or a POST body and never the query;
  - challenges: 401 `invalid_token`, 401 with no code when no token was sent, 403 `insufficient_scope`, and the `DPoP` scheme for a bound token, verified through D8;
  - `Cache-Control: no-store`;
  - a claim-source outage answered 500 with no text.

  Verify: `go test -run 'TestOIDCUserInfo' -count=1 ./httpsec/`.
- [ ] 9.5 Prove that a refresh token is never a sign-in, test-first: one presented as a session-reference bearer or to session renewal is refused as an unknown credential. Verify: `go test -run 'TestRefreshToken_NotASignIn' -count=1 ./httpsec/`.
- [ ] 9.6 Apply CORS to the provider, test-first: the token, UserInfo, revocation, introspection and metadata endpoints follow the allowlist, and the authorization and end-session endpoints never carry CORS headers. Verify: `go test -run 'TestCORS_OIDCProvider' -count=1 ./httpsec/`.

## 10. Metadata (`httpsec`, `oidc-provider-metadata`)

- [ ] 10.1 Build both metadata documents from the configuration, test-first:
  - both well-known paths, including for an issuer with a path;
  - the required and supported members, endpoints following the paths in use;
  - the refused features as `false`, and `authorization_response_iss_parameter_supported` and back-channel logout as `true`;
  - the DPoP and certificate members only when enabled;
  - consumer members added, and an override of a provider member refused at construction.

  Verify: `go test -run 'TestOIDCMetadata' -count=1 ./httpsec/`.
- [ ] 10.2 Serve the documents publicly with `Cache-Control` of 1 hour by default, replaceable, test-first, and prove that the JWKS endpoint keeps publishing the previous key after a rotation. Verify: `go test -run 'TestOIDCMetadata_Serving' -count=1 ./httpsec/`.

## 11. Logout, consents and grant revocation across the chain

- [ ] 11.1 Serve the end-session endpoint, test-first:
  - GET and form POST;
  - `id_token_hint` verified by signature and issuer with expiry ignored, and its audience matched to `client_id`;
  - a valid hint ends the sign-in as a logout does;
  - an invalid hint is a chain 400, with no redirect and nothing ended;
  - with no hint, nothing ends and the browser goes to the logged-out page;
  - an exactly registered `post_logout_redirect_uri` gets `state`, and any other URI the logged-out page.

  Verify: `go test -run 'TestOIDCEndSession' -count=1 ./httpsec/`.
- [ ] 11.2 Make the chain's logout end the sign-in through the provider before deleting its sessions, test-first. A grant-store failure answers 500 and leaves the session loadable, a retry succeeds, and a failed notification does not fail the logout. Verify: `go test -run 'TestLogout_EndsProviderGrants' -count=1 ./httpsec/`.
- [ ] 11.3 Prove that the other ends reach the provider through the session end observer, test-first:
  - reuse revocation, ending other sessions (D12), passkey removal ending other sessions, and `DeleteByUser`;
  - their failures logged and reported, never undoing the end;
  - a sign-in that expires sending nothing.

  Verify: `go test -run 'TestOIDCProvider_SignInEnds' -count=1 ./httpsec/`.
- [ ] 11.4 Make an upstream back-channel logout end the provider grants of the sessions it ends, with its response unchanged, test-first. Verify: `go test -run 'TestOIDCBackchannel_EndsProviderGrants' -count=1 ./httpsec/`.
- [ ] 11.5 Serve `/consents`, test-first:
  - the signed-in user lists their own consents, with names, scopes, offline access and when consent was last given;
  - revoking one's own consent revokes that user's and client's grants;
  - another user's consent is a 404 refusal;
  - CSRF protection stays on.

  Verify: `go test -run 'TestOIDCConsents' -count=1 ./httpsec/`.
- [ ] 11.6 Revoke grants through T8's ports, test-first:
  - recovery completion, with a failure returned;
  - an MFA reset, with a failure returned after the removals;
  - passkey clone suspension;
  - the password-change option, revoking before the new password is written;
  - D12's "revoke application access" choice.

  Each event has an option to keep grants, with no change when the provider is not in use. Verify: `go test -run 'TestRecoverer_RevokesGrants|TestResetEnrolment_RevokesGrants' -count=1 ./recovery/ ./authenticate/mfa/`, and `go test -run 'TestPasskey_CloneRevokesGrants|TestPasswordChange_RevokesGrants|TestSessionManagement_RevokeApplicationAccess' -count=1 ./httpsec/`.
- [ ] 11.7 Exempt the authorization, token, revocation, introspection and end-session endpoints from the cross-site check, while resume and `/consents` stay protected, test-first. Document logout, consents and the event options in godoc and the README. Verify: `go test -run 'TestCSRF_OIDCProviderExemptions' -count=1 ./httpsec/`, and `go doc ./httpsec` names the new options' defaults.

## 12. Durable stores, migration and sweeping (`schema-migrations`, `security-state-stores`, `expiry-sweeping`)

- [ ] 12.1 Write the security-state migration that creates the provider's eight tables and every lookup index (grants by user, by user and client, by sign-in, by upstream session), test-first, with a populated-database test and a rollback test. Verify: `go test -run 'TestMigrations' ./...` in the `test` module, against PostgreSQL 15 and 18.
- [ ] 12.2 Implement every provider store in `sqlstore`, and `NewRefreshTokenStore` over the fixed `op_refresh_tokens` table (T7), test-first, driven by the suites. Include the "lineage identifier not found through the session store" case and the "no credential in any column" case. Verify: `go test -race -run 'TestSQLStore' ./sqlstore/...` in the `test` module.
- [ ] 12.3 Implement the same in `pgxstore`, test-first. Verify: `go test -race -run 'TestPgxStore' ./pgxstore/...` in the `test` module.
- [ ] 12.4 Implement the same in `gormstore`, test-first. Verify: `go test -race -run 'TestGormStore' ./gormstore/...` in the `test` module.
- [ ] 12.5 Add the expiry tasks, test-first:
  - pending requests, codes (the onetime purge), opaque tokens and assertion identifiers;
  - grants, keeping revoked ones until the codes that name them expire;
  - lineages under a renamed task;
  - the orphaned-grant sweep.

  Verify: `go test -run 'TestExpiryTasks_OIDCProvider' ./...` in the `test` module.
- [ ] 12.6 Prove on each backend that an authorization, an exchange, a refresh after a restart, and a revocation succeed, test-first. Verify: `go test -run 'TestOIDCProvider_Durable' ./...` in the `test` module.

## 13. Framework adapters (`framework-adapters`)

- [ ] 13.1 Run the provider scenarios on net/http, gin and fiber in `test/httpsecconformance`, test-first:
  - authorize redirect and flow cookie;
  - resume JSON;
  - token JSON with `no-store`;
  - UserInfo challenge;
  - metadata;
  - end-session redirect.

  Verify: `go test -run 'TestConformance(NetHTTP|Gin|Fiber)/oidcprovider' ./...` in the `test` module.

## 14. OpenID conformance in CI (P9)

- [ ] 14.1 Add a conformance OP command to the `test` module: the provider's defaults plus the suite's test clients, with the issuer and TLS as 1.2 recorded. Verify: it starts locally, and the suite's discovery test reaches it.
- [ ] 14.2 Add the CI job `conformance`. It starts the suite and the OP with Docker Compose and runs the Basic OP and Config OP plans. It fails on any `FAILED` or `INTERRUPTED` result and keeps the logs as an artifact. Verify: the job runs on a pull request and reports both plans.
- [ ] 14.3 Triage every failing test:
  - a provider defect gets a failing unit test in its owning package, then the fix;
  - a job misconfiguration is fixed in the job.

  Verify: both plans pass in CI.

## 15. Integration and release gate

- [ ] 15.1 Amend `release-readiness`: its gate names the `conformance` job, and its first changelog entry summarises this change. Update its `plans.md` through `/superpowers:writing-plans` (`tasks-plans`). Verify: `openspec validate release-readiness --strict`.
- [ ] 15.2 Run one whole-branch review against every requirement this change's specs add or modify (`subagent-delegation`), and fold its findings in. Verify: the review reports nothing open.
- [ ] 15.3 Run the final gate. Verify:
  - `make check` passes in the core module;
  - the `test` module's full suite passes with `-race` against PostgreSQL 15 and 18;
  - the `conformance` job is green.

## Workflow follow-up

- Archive the change after the pull request merges and the review requirements are met, then verify the archived specs with `openspec validate --specs --strict`.
