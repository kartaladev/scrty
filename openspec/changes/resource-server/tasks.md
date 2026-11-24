# Tasks

Every task is test-first: write the failing test, run it, confirm it fails for the intended reason
(not a compile error), then implement. Verification is scoped to the changed packages and their
dependents (`test-scope.md`).

## 1. Identity, authorization and the access-token kind

- [ ] 1.1 Add `factor.AccessToken` (`"access-token"`): no channel, exempt from an MFA requirement (design 16); verify the kind table test in `authenticate/factor` covers it and passes
- [ ] 1.2 Document `identity.Principal.Scopes` as carrying an access token's scopes on a user principal (design 16); verify `go doc ./identity Principal` shows it
- [ ] 1.3 Add `authorize.ScopeError{Scopes, All}` returned by `HasAnyScope`/`HasAllScopes` refusals, matching `ErrAccessDenied` and `ErrNotGranted`; anonymous refusal unchanged (spec authorization "A scope refusal names the scopes it needed"); verify the three scenarios as table cases pass

## 2. Consumer password rules

- [ ] 2.1 Add `password.WithRule(name, RuleFunc)` run after the lists and before the breach lookup, refusal `RejectedError{Rule: name}` (design 17; spec password-policy ADDED requirement); verify the "letters and digits", "weak and reused stay distinct", "rule failure" and "no rule by default" scenarios pass
- [ ] 2.2 Add construction refusals for a nil, typed-nil, unnamed, built-in-named or duplicate rule, and the ordering scenario "a consumer rule runs before the breach lookup" (spec password-policy MODIFIED requirements); verify the table tests pass

## 3. Inactive-account disclosure

- [ ] 3.1 Add `authenticate.ErrAccountInactive` and join it beneath the uniform failure in the password provider only after the password verifies (design 18; spec authentication); verify the "inactive account" scenario and that a wrong password on an inactive account carries no inactive error
- [ ] 3.2 Add `httpsec.WithInactiveDisclosure()` answering the refusal alone as 403, default concealed (spec http-error-propagation "An inactive-account refusal…"); verify the three scenarios through form login pass

## 4. Provider support

- [ ] 4.1 Give `oidcprovider.AccessToken` `AuthTime`, `ACR` and `AMR`, from the JWT's claims or from the grant for an opaque token (design 12); verify table tests for a JWT and an opaque token
- [ ] 4.2 Add `(*oidcprovider.Provider).UserLoader()` returning the loader the provider was built with (design 8); verify a test asserts it is the one given

## 5. Shared remote key set

- [ ] 5.1 Move `authenticate/oidc`'s discovery and key-set cache into an internal package without changing behaviour (design 10); verify `go test ./authenticate/oidc/...` passes unchanged before and after, and the new package's own tests cover TTL, backoff, unknown-`kid` cooldown and singleflight
- [ ] 5.2 Add RFC 8414 metadata as the fallback when OpenID discovery is absent, and a direct key-set URL that skips discovery; verify table tests for both and for a `jwks_uri` on another origin being refused

## 6. Introspection client

- [ ] 6.1 Add an internal RFC 7662 client posting through `outbound`: `client_secret_basic` and `private_key_jwt`, `active` parsing, `iss`/`aud`/`cnf`/`exp` read, https only (design 11); verify table tests for active, inactive, endpoint 503, malformed body, and that no log or error carries the token or secret
- [ ] 6.2 Add the optional answer cache bounded by its maximum and the token's expiry (design 9); verify the "cache bounded by expiry" scenario with a fake clock

## 7. The resource-server mode and the provider source

- [ ] 7.1 Add `EnableResourceServer`, `OrderResourceServer = 490`, `ResourceServerOption`, `WithPathPrefix`, `WithResourceAliases`, and the construction checks for identifier, aliases, prefixes and overlap (design 1–3; spec resource-server identity, prefix and wiring requirements); verify the construction scenarios as table cases
- [ ] 7.2 Extract UserInfo's binding check (`holdToKey`) into a check shared with the resource server, one replay store (design 7); verify `go test ./httpsec/ -run 'UserInfo'` passes unchanged, and the "one replay store" scenario passes
- [ ] 7.3 Add recognition and routing (design 5) with the bounded header peek, and a fuzz test of the peek; verify the routing scenarios ("session token beside a resource server", "refused provider token not retried", "unknown issuer", "token outside every prefix", "the provider's own endpoints") pass and the fuzz target runs 30 s clean
- [ ] 7.4 Add `FromProvider(op)`: provider verification with the grant checked every request, audience check, type check, default binding, local-user caller with the provider's loader (design 3, 6–8; spec resource-server provider, audience, type and binding requirements); verify those scenarios pass, including opaque tokens and the grant-revoked scenario
- [ ] 7.5 Publish the caller (`WithCaller`, `factor.AccessToken`, scopes), `AccessToken` and `AccessTokenFromContext` with copy on read, and run the stateless policy phase (design 12); verify the "handler reads the token" and "copy on read" scenarios
- [ ] 7.6 Add `ErrInvalidToken` and the `invalid_token` challenge with the scheme rule and the no-DPoP fallback interceptor, one challenge per response (design 13; spec http-error-propagation first two requirements); verify the three scenarios and a test asserting exactly one `WWW-Authenticate` per refusal kind
- [ ] 7.7 Count the resource server as a verifier of bound credentials and refuse default binding without DPoP or certificate binding; keep sign-in proof-free (spec sender-constrained-tokens); verify its scenarios pass
- [ ] 7.8 Map dependency failures and cancellation as design F12 and F28 state; verify table cases for a provider store outage and a cancelled request

## 8. External sources

- [ ] 8.1 Add `FromIssuer(issuer, opts...)` with `WithSourceAudience`, `WithJWKSURL`, `WithClockSkew`, `WithUnboundTokens`, `WithUntypedTokens` over the shared key set (design 3, 6, 7, 10); verify the remote-issuer scenarios ("keys rotated", "unknown key flood", "unsigned token", "an issuer's own spelling", "untyped token by default", "opted in with a telling claim") against a local test issuer
- [ ] 8.2 Add `WithJWTIntrospection(cfg)` on `FromIssuer` (design 9); verify the "default" and "consumer opts in to introspection" scenarios
- [ ] 8.3 Add `FromIntrospection(endpoint, clientID, opts...)` with `WithIntrospectionSecret`, `WithIntrospectionKey`, `WithIntrospectionCache`, `WithOpaquePrefix`, and the session-reference construction check (design 11); verify the introspection and "session references are never sent" scenarios
- [ ] 8.4 Add the caller strategies `WithClaimsOnly`, `WithClaimsMapper`, `WithLocalUsers` with one-per-source check (design 8); verify the four caller scenarios and the mapper-error and nil-principal cases
- [ ] 8.5 Complete the remaining construction checks of design F25 (two sources for one issuer, issuer equal to the provider's, non-positive cache bound, skew above the bound, http endpoint); verify each as a table case

## 9. Guards, scopes and session-only endpoints

- [ ] 9.1 Make session-only endpoints refuse an access-token caller before any work (design 14; spec http-security-chain "Session-only endpoints refuse…"); verify a table test over every listed endpoint, including logout ending nothing
- [ ] 9.2 Answer a scope refusal of an access-token caller with 403 `insufficient_scope` at chain rules (design 13); verify the "chain rule" and "API key caller" scenarios
- [ ] 9.3 Make the net/http guards judge access-token callers and answer `insufficient_scope` (spec http-security-chain "Per-endpoint guards judge…", http-error-propagation "guard" scenario); verify those scenarios
- [ ] 9.4 Make the recency guard read an access-token caller's `AuthTime` and answer 401 `insufficient_user_authentication` with `max_age` (design 15; spec reauthentication MODIFIED, http-error-propagation recency requirement); verify all their scenarios, sessions unchanged
- [ ] 9.5 Bring `fibersec` and `ginsec` guards to the same behaviour as 9.3 and 9.4 (spec framework-adapters "Adapter recency guards match the core recency guard"); verify adapter tests for scope and recency challenges in both modules

## 10. Conformance, docs and integration

- [ ] 10.1 Add conformance scenarios in `test/httpsecconformance` for a provider-and-API chain, an API-only chain with a remote issuer, and two resource servers by prefix; verify they pass on net/http, fiber and gin
- [ ] 10.2 Document the mode in godoc (every option names its default) and in `README.md` (a provider-and-API example and an API-only example); verify `go doc ./httpsec EnableResourceServer` and the README examples compile in an example test
- [ ] 10.3 Record the change in `CHANGELOG.md` under *Unreleased*: *Added* for the new API, *Changed* for the recency and inactive-account behaviour; verify both **BREAKING (behaviour)** entries are present
- [x] 10.4 Mark `bff-resource-server`'s resource-server mode as moved to this change, as its CSRF item was; verify its proposal names `resource-server`
- [ ] 10.5 Run `gofmt -l`, `go vet` and the scoped tests across every workspace module, then the full gate `make check` and `make spec-check` after the last edit; verify all pass

## Workflow follow-up

- Close PR #117 (`provider-resource-server`) with a link to this change's PR.
- Message crm-coordinator the settled API: `EnableResourceServer` with `FromProvider`, the client's `DefaultAudience`, and that handlers read `identity.PrincipalFromContext` and `httpsec.AccessTokenFromContext`.
- Whole-branch review against every spec requirement this change covers, then archive.
