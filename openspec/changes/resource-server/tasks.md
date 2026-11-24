# Tasks

Every task is test-first: write the failing test, run it, and confirm it fails for the intended reason
(not a compile error), then implement. Where existing code already behaves as the spec requires, the
task says so: its test is a characterization test, shown to fail once by temporarily inverting the
code (`golang-tdd.md`). Verification is scoped to the changed packages and their dependents
(`test-scope.md`), using the command in `plans.md`.

## 1. Kinds, scope refusals, principal scopes

- [ ] 1.1 Add `factor.AccessToken` (no channel, not exempt) and `factor.ExternalAccessToken` (`federated`, not exempt) (design 9; spec identity-model); verify the kind table cases
- [ ] 1.2 Document `identity.Principal.Scopes` as carrying an access token's scopes on a user principal (design 17); verify `go doc ./identity Principal` shows it (the identity-model "User authenticated by a session" scenario is tested in 8.2)
- [ ] 1.3 Add `authorize.MissingScopesError{Scopes, All}` from `HasAnyScope`/`HasAllScopes`, matching `ErrAccessDenied` and `ErrNotGranted`, and make `AnyOf` wrap its members' refusals so it is found beneath both composites (design 14; spec authorization); verify its five scenarios pass

## 2. Consumer password rules

- [ ] 2.1 Add `password.WithRule(name, RuleFunc) PolicyOption`, run after the lists and before the breach lookup (design 18; spec password-policy ADDED); verify the "letters and digits", "weak and reused stay distinct", "rule failure" and "no rule by default" scenarios pass
- [ ] 2.2 Add the construction refusals, including the rule-name syntax, and the "consumer rule runs before the breach lookup" ordering (design 18; spec password-policy MODIFIED); verify the table tests pass

## 3. Inactive accounts

- [ ] 3.1 Add `authenticate.ErrAccountInactive`, joined beneath the uniform failure only after the password verifies, with equal work (design 19; spec authentication); verify the "inactive account" scenario, and that a wrong password on an inactive account carries no inactive error
- [ ] 3.2 Add `httpsec.WithInactiveDisclosure()` for form login and Basic, 403 alone, Basic without a challenge, the status-table row, and the prblmsec `account-inactive` type with concealment (design 20; spec http-error-propagation inactive requirement and status table; spec problem-details-rendering); verify their scenarios

## 4. Provider support

- [ ] 4.1 Give `oidcprovider.AccessToken` `AuthTime`, `ACR` and `AMR`, from the JWT's claims or from the grant (design 13); verify table tests for a JWT and an opaque token
- [ ] 4.2 Add `(*oidcprovider.Provider).UserLoader()` (design 8); verify a test asserts it returns the loader given
- [ ] 4.3 Add `auth_time`, `acr` and `amr` to the provider's introspection answer (design 12; spec oidc-provider-tokens); verify the "sign-in members" scenario
- [ ] 4.4 Give `oidcprovider.SignIn` the library's second-factor marker and the federated evidence, set in `oidcSignInOf` from the session only, and copy them through `newGrant`, `newDeviceGrant` and the refresh rebuild into the grant and `AccessToken`; the first red test is `TestGrantAMR_MFAWithoutLibraryVerifiedSecondFactor` (design 9; spec oidc-provider-tokens "A sign-in records how it was proved, and its grants keep it"); verify its four scenarios against the memory stores
- [ ] 4.5 After PR #149 merges, add a security-state migration after its folded baseline with the new columns on grants, codes and browser sessions and the new fields in the pending-request and device-authorization sign-in documents, store and load them in `store/sqlstore`, `store/pgxstore` and `store/gormstore`, extend the `test/storetest` suites, and add a populated-upgrade test (design 9; spec security-state-stores, schema-migrations); verify the suites on every store (Docker), `make generate-check` and the schema inventory tests

## 5. Shared remote key set

- [ ] 5.1 Copy `authenticate/oidc`'s key-set cache behaviour into `internal/keyset`, keyed by an opaque source name, and make `authenticate/oidc` use it, with its own suite unchanged (design 11); verify `go test -count=1 ./authenticate/oidc/...` passes byte-identical before and after, and `internal/keyset`'s copied tests cover TTL, backoff, unknown-`kid` cooldown and singleflight
- [ ] 5.2 Add RFC 8414 fallback on 404, the issuer-equality check, origin confinement of discovered URLs, a pinned URL, and a replaceable outbound client (design 11; spec "A remote issuer's key set is found only where the issuer says"); verify its three scenarios and the 404-only fallback

## 6. Introspection client

- [ ] 6.1 Add `internal/introspect`: `client_secret_basic` and `private_key_jwt`, https only, acceptance rules for `active`, `token_type`, `iss`, `aud`, `sub` and `exp`, and `auth_time`/`acr`/`amr`/`cnf` read (design 12; spec introspection requirements); verify table tests for active, inactive, a refresh token reported active, another issuer, no audience, endpoint 503, a malformed body, and that no log or error carries the token or secret
- [ ] 6.2 Add the per-source cache: bounded by age, entries and `exp`, keyed by digest, no caching without `exp`, singleflight per token (spec "Introspection answers are cached only within bounds"); verify its two scenarios with a fake clock

## 7. Mode core

- [ ] 7.1 Add `EnableResourceServer`, `OrderResourceServer = 425`, `ResourceServerOption`, `WithPathPrefix`, `WithResourceAliases`, prefix rules and the mode-level construction checks (design 1–3; spec identity, prefix, segment and wiring requirements); verify those scenarios as table cases
- [ ] 7.2 Refactor UserInfo's binding check into one that returns typed results and writes nothing, with UserInfo mapping them to its settled answers, and share the header reader (design 7); verify `go test -count=1 -run 'UserInfo' ./httpsec/` is unchanged and green, and the "one replay store" scenario passes
- [ ] 7.3 Add the size bound derived from the provider's, path-first routing, recognition, the session-token exclusion and its construction check, with a fuzz test of the routing read (design 2, 5; spec routing, bound, "not handed on" and off-prefix requirements); verify those scenarios, a provider token at the provider's maximum size accepted, and a 30 s clean fuzz run
- [ ] 7.4 Add `ErrInvalidToken`, extend `bearerChallenge` so the resource server counts as a built-in bearer, add the status-table row, the stable-contract entry and the prblmsec `invalid-token` type (design 14; spec http-error-propagation invalid-token, contract, table and challenge requirements; spec problem-details-rendering); verify their scenarios and exactly one `WWW-Authenticate` per refusal with DPoP off, optional and required
- [ ] 7.5 Map binding failures to the settled refusals, including nonces, certificates and an unbound token under the `DPoP` scheme; count the resource server as a verifier of bound credentials; refuse an opt-out on a DPoP-required chain (design 7; spec binding requirements, sender-constrained-tokens); verify those scenarios

## 8. Provider source and publication

- [ ] 8.1 Add `FromProvider(op)` with the grant checked per request, the audience and type checks, and the local-user default (design 3, 6, 8; spec provider, audience, type and caller requirements); verify those scenarios, including opaque tokens and the grant-revoked scenario
- [ ] 8.2 Publish the caller (kinds, token scopes), `AccessToken` and `AccessTokenFromContext` with copy on read, and run the per-request policy phase (design 13; spec publication and scope requirements); verify those scenarios
- [ ] 8.3 Map dependency failures (provider store, user loader) and cancellation, and pin the shared replay store's race (design F12, F14, F34); verify the three scenarios of "Failures of a source's dependencies are not refusals" and a concurrent-proof test

## 9. External sources

- [ ] 9.1 Add `FromIssuer(issuer, opts...)` with the issuer-syntax check (also applied by 9.3), the unknown-confirmation refusal, the 60-second `iat`/`nbf` leeway, `WithSourceAudience`, `WithJWKSURL`, `WithOutboundClient`, `WithAlgorithms`, `WithClockSkew`, `WithUnboundTokens`, `WithUntypedTokens`, the required claims, and the no-`kid` rule (design 6, 7, 11; spec remote-issuer requirements); verify their scenarios, including the override scenarios, against a local TLS test issuer
- [ ] 9.2 Add `WithJWTIntrospection(cfg)` on `FromIssuer` (design 10); verify its two scenarios
- [ ] 9.3 Add `FromIntrospection(issuer, endpoint, clientID, opts...)` with `WithIntrospectionSecret`, `WithIntrospectionKey`, `WithIntrospectionCache` and `WithOpaquePrefix`, the prefix check against every other `Bearer`-scheme mode, and the rule that the provider's own token formats are never routed to it (design 5, 12); verify the introspection, "provider's own tokens" and "other credentials" scenarios
- [ ] 9.4 Add `WithClaimsOnly` (issuer-qualified identifier), `WithClaimsMapper(provider, fn)` returning `MappedCaller{Principal, External}` (zero value = a local user), `WithLinkedUsers`, every caller refusal as `ErrInvalidToken`, and the strategy construction checks (design 8; spec caller-strategy, qualified-identifier, external-subject and source-wiring requirements); verify their scenarios, including the subject-collision scenario
- [ ] 9.5 Add per-address, per-source throttling of verification refusals only, through the chain's limiter factory (namespace `resource-server`, IPv6 aggregate), refusing with `ErrInvalidToken` before any fetch or call, with `WithRefusalLimiter(ratelimit.Limiter)` (design 12; spec "Refused access tokens are throttled per source"); verify its three scenarios and the unattributable-request refusal
- [ ] 9.6 Add `policy.Input.AccessTokenAssurance` (library-minted, fail-closed zero value), and judge access-token callers in the MFA requirement policy: provider tokens by the grant marker or re-matched federated evidence, external and mapper-local callers by federated assurance, callers naming no local user not judged; refuse the access-token kinds on the enrolment allowlist at construction (design 9; spec security-policy); verify its scenarios, including the zero value and the allowlist refusal
- [ ] 9.7 Refuse every per-request challenge for an access-token caller with `ErrInsufficientUserAuthentication`, map an assurance-source or requirement-lookup failure to a dependency failure, and fail construction when linked or mapped sources exist, the policy judges external tokens, and it has no federated-assurance source (design 9; spec security-policy, resource-server dependency requirement); verify their scenarios, including "assurance source down" and "exempt mode needs no source"
- [ ] 9.8 Emit the access-token refusal event and `excess_rate_limit_exceeded` for the throttle, with user references only for local users (design 13; spec security-events); verify its three scenarios

## 10. Guards and session-only endpoints

- [ ] 10.1 Add characterization tests showing every session-only endpoint refuses an access-token caller and changes nothing, and that the session-signal stream keeps its settled answer, each shown to fail once by temporarily publishing a fake session; give `SwitchActiveRole` the same check (design 15; spec http-security-chain session-only requirement); verify the table passes
- [ ] 10.2 Make logout refuse an access-token caller (real red: today it answers 200), with its godoc naming revocation and end-session (spec http-security-chain logout MODIFIED); verify the "access-token caller" scenario and the settled logout scenarios
- [ ] 10.3 Answer scope refusals of access-token callers with 403 `insufficient_scope`, through `bearerChallenge` for chain rules and `internal/guardauth` for guards, with the prblmsec `insufficient-scope` type and `scope` member (design 14; spec http-error-propagation, problem-details-rendering); verify the "chain rule", "guard" and "API key caller" scenarios
- [ ] 10.4 Make the recency rule in `internal/guardauth` use an access-token caller's `AuthTime` and choose the error, refusing with `ErrInsufficientUserAuthentication` answered 401 with `max_age`, and make the gin and fiber guards take both from `guardauth` (design 14, 16; spec reauthentication, http-error-propagation recency requirements, framework-adapters); verify their scenarios on all three adapters, with sessions unchanged
- [ ] 10.5 Add adapter tests in `httpsec/fibersec` and `httpsec/ginsec` for scope challenges (spec framework-adapters); verify both modules' tests pass

## 11. Conformance, docs and integration

- [ ] 11.1 Add conformance scenarios in `test/httpsecconformance` for a provider-and-API chain, an API-only chain with a remote issuer, and two resource servers by prefix trusting one issuer; verify they pass on net/http, fiber and gin
- [ ] 11.2 Document every option with the default it replaces (godoc), and add README sections for the resource server (a provider-and-API example and an API-only example), `password.WithRule` and `WithInactiveDisclosure`; verify an example test compiles the README examples
- [ ] 11.3 Record the change in `CHANGELOG.md` under *Unreleased*: *Added* for the new API, *Changed* for every entry of design's Migration Plan (recency, logout, inactive accounts, pre-upgrade grants, per-request policies without a session), merged by hand with the other v0.6.0 changes' entries; verify the three **BREAKING (behaviour)** entries
- [ ] 11.4 Run `gofmt -l`, `go vet` and the scoped tests across every workspace module, then the full gate `make check` and `make spec-check` after the last edit; verify all pass

## Workflow follow-up

- When `bff-resource-server` is next revised (it needs spec deltas to validate), record there that its resource-server mode moved to `resource-server`.

- Close PR #117 (`provider-resource-server`) with a link to PR #151.
- Message crm-coordinator the settled API: `EnableResourceServer` with `FromProvider`, the client's `DefaultAudience`, DPoP enabled, handlers reading `identity.PrincipalFromContext` and `httpsec.AccessTokenFromContext`, and sign-out through revocation and end-session.
- Whole-branch review against every spec requirement this change covers, then archive.
