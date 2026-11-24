# Resource server: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A generic OAuth resource-server mode for the httpsec chain, comprising:
- `EnableResourceServer` with provider, remote-issuer and introspection sources;
- guard, challenge and assurance support;
- session-endpoint refusals;
- consumer password rules;
- inactive-account disclosure.

**Architecture:**
- **Wave 1:** the leaf packages (`authenticate/factor`, `authorize`, `authenticate/password`,
  `authenticate`, `oidcprovider`), plus the two new internal packages (`internal/keyset`,
  `internal/introspect`).
- **Then the `httpsec` lane,** in sequential dispatches, each of six tasks or fewer: core, provider
  source, external sources, guards and endpoints.
- **Then adapter tests, conformance and docs.**

**Tech Stack:** Go workspace, `lestrrat-go/jwx/v4`, `outbound`, `golang.org/x/sync/singleflight`,
mockgen, testcontainers (conformance only).

**Spec:** `openspec/changes/resource-server/`: `proposal.md`, `design.md` (decisions 1–20,
F1–F50), `specs/` and `tasks.md`.

## Global Constraints

- **Binding rules** (every dispatch prompt states them): test-first (`golang-tdd.md`),
  `library-design.md`, `defensive-coding.md`, `defect-claims.md`, the `table-test`, `use-mockgen` and
  `use-testcontainers` skills, and the read-only legacy reference.
- **Exact values:**
  - `OrderResourceServer = 425`;
  - kinds `"access-token"` and `"external-access-token"`;
  - a token bound of the larger of 8 KiB and the chain provider's own verifier bound;
  - a 60-second `iat`/`nbf` leeway;
  - clock skew defaulting to 0, at most 5 minutes;
  - default algorithms `RS256` and `ES256`;
  - introspection posts `token_type_hint=access_token`;
  - the challenge codes `invalid_token`, `insufficient_scope` and `insufficient_user_authentication`,
    with `max_age` in whole seconds.
- **Settled errors kept:**
  - binding failures use `ErrInvalidDPoPProof`, the nonce-required refusal and
    `ErrCertificateBinding`;
  - `ErrInsufficientUserAuthentication` wraps `ErrReauthenticationRequired`;
  - `ErrInvalidToken` wraps `authenticate.ErrAuthenticationFailed`.
- **No secrets anywhere:** no token, secret, key or introspection body in any log, error or event.
- **Files no dispatch touches:** `store/migrate/**`, the `test/` migration tests, and
  `httpsec/oidc_login.go`'s `callbackCode`. Those belong to PR #149.
- **Git:**
  - never `checkout --`, `restore`, `reset --hard`, `stash` or `clean`;
  - the main session commits;
  - wave-1 dispatches run in their own git worktrees (`isolation: worktree`), and the main session
    integrates them. That way no dispatch's verification compiles another's half-done packages.

## Review Focus

1. A session token or session reference reaching a source, or being sent to an introspection
   endpoint. Expected: never.
2. An external `sub` loaded as a local user. Expected: only through identity links.
3. A dependency outage answered as 401. Expected: 500, and the outage is not counted as a refused
   credential.
4. Two `WWW-Authenticate` headers on one refusal. Expected: exactly one, written by `bearerChallenge`.
5. Recency for session callers changed. Expected: still 403 with no body, on every adapter.

---

## Scoped test command

Run it from each workspace module's directory, with `P` set to each changed package. It lists the
package itself and every package that depends on it, under real import paths:

```sh
go list -test -f '{{if .ForTest}}{{.ForTest}}{{else}}{{.ImportPath}}{{end}}{{range .Deps}} {{.}}{{end}}' ./... \
  | awk -v P="$P" '{ if ($1==P) {print $1; next} for (i=2;i<=NF;i++) if ($i==P) {print $1; break} }' \
  | grep -v '\.test$' | sort -u | xargs go test -count=1
```

Modules that may import a changed package: the root module, `authenticate/passkey/webauthn`,
`httpsec/fibersec`, `httpsec/ginsec`, `httpsec/prblmsec`, `store/gormstore`, `store/pgxstore` and
`test`.

The `httpsec` lane (C1 → C2 → C3 → C4 → D1) is one lane run in order, never concurrently, so a later
dispatch may extend a file an earlier one changed (`errors.go`, `bearer.go`, `prblmsec`). Ownership
below names what each dispatch may change; no two dispatches run on one file at the same time.

## Lanes and dispatches

| Dispatch | Tasks | Owns | Model | Reason | Runs |
|---|---|---|---|---|---|
| A1 | 1.1–1.3 | `authenticate/factor/factor.go`, `identity/principal.go` (godoc), `authorize/requirements.go`, `authorize/authorize.go`, their tests | Sonnet | Known patterns; signatures given | Wave 1 |
| A2 | 2.1–2.2 | `authenticate/password/policy.go` and its tests | Sonnet | Fully specified | Wave 1 |
| A3 | 3.1 | `authenticate/authenticate.go`, `authenticate/password.go`, tests | Opus | Security-critical refusal and timing | Wave 1 |
| A4 | 4.1–4.4 | `oidcprovider/accesstoken.go`, `provider.go`, `revoke.go`, `store.go` (`Grant`), `store_memory.go`, `resume.go`, tests | Opus | Library-only grant facts set at resume: a security-critical source of truth | Wave 1 |
| G1 | 4.5 | a new migration in `store/migrate`, `internal/pgschema/oidcprovider_*`, `store/sqlstore/oidcprovider_grants.go`, `store/pgxstore` and `store/gormstore` grant code, `test/storetest/oidcprovider_grant_suite.go` | Opus | Schema change across three stores | After A4 **and after PR #149 merges** |
| B1 | 5.1–5.2 | new `internal/keyset/`; `authenticate/oidc/remote.go` and its callers | Opus | A behaviour-preserving extraction with concurrency | Wave 1 |
| B2 | 6.1–6.2 | new `internal/introspect/` | Opus | A new security-critical client and a bounded cache | Wave 1 |
| C1 | 3.2, 7.1–7.3 | `httpsec`: new `resource_server*.go`, `chain.go` (slot), the shared binding and reader files moved out of `oidc_userinfo.go`, `login.go`/`basic.go` (disclosure), `errors.go`; `httpsec/prblmsec` (disclosure concealment) | Opus | Security-critical routing; an API later dispatches compile against | After wave 1 |
| C2 | 7.4–7.5, 8.1 | `httpsec`: `bearer.go` (`bearerChallenge`), `errors.go`, `dpop*.go`/`certbinding.go` (counting), new `resource_source_provider.go`; `httpsec/prblmsec` (`invalid-token`) | Opus | Challenge and binding semantics against settled specs | After C1 |
| C3 | 8.2–8.3, 9.1–9.2 | `httpsec`: new `access_token.go`, `resource_source_issuer.go`; `httpsec/prblmsec` (new refusal types) | Opus | Verification and publication | After C2, B1 |
| C4 | 9.3–9.6 | `httpsec`: new `resource_source_introspect.go`, `resource_strategy.go`, `resource_throttle.go`, `resource_assurance.go`, `errors.go` (`ErrInsufficientUserAuthentication` and its row); `policy` (the MFA requirement policy, `AccessTokenAssurance`, `mfa_requirement_enrolment.go` allowlist); `httpsec/prblmsec` (`insufficient-user-authentication`) | Opus | Identity resolution, throttling, assurance | After C3, B2, G1 |
| C5 | 9.7–9.8 | `httpsec`: per-request challenge refusal, `errors.go`, events; `httpsec/prblmsec`; `event` names list | Opus | Refusal semantics and events | After C4 |
| D1 | 10.1–10.5 | `httpsec`: `logout.go`, `role_switch.go`, `authorization.go`, `guards.go`, `bearer.go` (403 `insufficient_scope`), `errors.go`; **`internal/guardauth/`**; `httpsec/ginsec/guards.go`, `httpsec/fibersec/guards.go` and their tests; `httpsec/prblmsec` (`insufficient-scope`); session-endpoint test files | Opus | Refusal logic across endpoints and the shared guard rules, in three modules | After C5 |
| E1 | 11.1–11.3 | `test/httpsecconformance/resource_server_scenarios.go`, `README.md`, `CHANGELOG.md`, `httpsec/example_resource_server_test.go` | Sonnet | Fixtures and docs | After D1 |
| — | 11.5 | main session | — | Verification is never delegated | Last |

- **Every dispatch gets a fresh reviewer that edits nothing:** an Opus reviewer for Opus dispatches,
  and a Sonnet reviewer for Sonnet ones.
- **Findings go to a fresh dispatch of the same lane,** and the next dispatch starts only when its
  predecessor is green and reviewed.
- **One whole-branch review** runs before the final gate.

---

### Task A1: Kinds and scope refusal (tasks 1.1–1.3)

**Interfaces produced:**
- `const AccessToken Kind = "access-token"` and `const ExternalAccessToken Kind = "external-access-token"`, neither exempt;
- `type MissingScopesError struct{ Scopes []string; All bool }`, with `Error()` and `Is(target)`, true
  for `ErrAccessDenied` and `ErrNotGranted`.

- [ ] Red: kind-table rows for both kinds (channel, exempt) fail. Add the constants first, so the red
  step is an assertion failure, not a compile error.
- [ ] Green: add both kinds to the channel and exemption tables.
- [ ] Red: `errors.As(err, &mse)` on a refusal by `HasAnyScope("orders:write")` and by
  `AllOf(HasAnyRole("clerk"), HasAnyScope("orders:write"))` fails.
- [ ] Green: return `MissingScopesError`, and make `AnyOf` wrap its members' refusals, leaving the anonymous path unchanged.
- [ ] Verify: the scoped command for `authenticate/factor`, `identity` and `authorize`.

### Task A2: Consumer password rules (tasks 2.1–2.2)

**Interfaces produced:**
- `type RuleFunc func(ctx context.Context, candidate string, user *identity.Details) (bool, error)`;
- `func WithRule(name Rule, check RuleFunc) PolicyOption`.

- [ ] Red, then green, one table case per password-policy scenario. Order:
  1. no rule;
  2. letters and digits;
  3. weak and reused stay distinct;
  4. rule failure;
  5. runs before the breach lookup (a lookup mock expecting no call);
  6. the construction refusals.
- [ ] Verify: the scoped command for `authenticate/password`.

### Task A3: Inactive error (task 3.1)

**Interfaces produced:** `var ErrAccountInactive`, in `authenticate/authenticate.go`.

- [ ] Red: an inactive user with the correct password, where `errors.Is(err, ErrAccountInactive)`
  must hold, fails.
- [ ] Red: an inactive user with a wrong password must carry no inactive error, with equal work spent
  (measured by encoder calls).
- [ ] Green: check active state only after the password verifies, and join beneath the uniform
  failure.
- [ ] Verify: the scoped command for `authenticate`.

### Task A4: Provider fields and grant facts (tasks 4.1–4.4)

**Interfaces produced:**
- `AccessToken.AuthTime time.Time`, `ACR string`, `AMR []string`;
- `func (p *Provider) UserLoader() identity.UserLoader`;
- the introspection answer's members `auth_time`, `acr` and `amr`.

- [ ] Red, then green: a grant records the library's second-factor marker from the session only (a consumer mapping claiming `mfa` does not set it) and the federated evidence of an OIDC sign-in, carried to `AccessToken`.
- [ ] Red, then green, for each: JWT and opaque tokens carry the sign-in's time, context and methods;
  `UserLoader()` returns `Deps.Users`; the introspection answer includes the three members for an
  active token.
- [ ] Verify: the scoped command for `oidcprovider`.

### Task B1: Shared key set (tasks 5.1–5.2)

**Interfaces produced:**
- `keyset.New(name string, fetcher *outbound.Client, opts ...Option) (*Source, error)`;
- `(*Source).Key(ctx, kid string) (jwk.Key, error)`;
- `keyset.ErrUnknownKey`;
- the options `WithIssuer(iss)`, `WithJWKSURL(u)`, `WithTTL`, `WithRefetchCooldown`, `WithBackoff`.

- [ ] Run `go test -count=1 ./authenticate/oidc/...` and save the output as the baseline.
- [ ] Copy the behavioural tests (TTL, backoff, cooldown, singleflight) into `internal/keyset` against a
  stub `Source`. Red: assertion failures against the stub.
- [ ] Green: implement `internal/keyset` from the existing behaviour, then switch `authenticate/oidc`
  to it. Its tests stay byte-identical. Rerun the baseline: identical pass list.
- [ ] Red, then green: fallback to RFC 8414 on 404 only; refuse metadata naming another issuer; refuse a
  discovered key-set URL on another origin; accept a pinned URL; accept a replaced outbound client.
- [ ] Verify: the scoped command for `authenticate/oidc` and `internal/keyset`.

### Task B2: Introspection client (tasks 6.1–6.2)

**Interfaces produced:**
- `introspect.New(cfg Config, fetcher *outbound.Client) (*Client, error)`, with `Config.Issuer` required;
- `(*Client).Introspect(ctx, token string) (*Result, error)`;
- `Result{Active bool; TokenType, Issuer, Subject, ClientID, ACR string; Audience, Scopes, AMR []string; ExpiresAt, AuthTime time.Time; Confirmation map[string]string; Claims map[string]any}`;
- `Config` with `Endpoint`, `ClientID`, `Secret` or `Key`, and `Cache{MaxAge time.Duration; MaxEntries int}`.

- [ ] Red, then green, one table case each:
  1. active;
  2. inactive;
  3. `refresh_token` active, refused by the caller's acceptance helper `Accepts(resource string, now time.Time) bool`;
  4. no `aud`;
  5. no `sub`;
  6. `exp` past;
  7. 503 as a dependency error;
  8. a malformed body;
  9. http refused at `New`;
  10. basic authentication;
  11. a private-key JWT;
  12. a log capture with no token or secret.
- [ ] Red, then green, the cache: within bounds; never past `exp`; no `exp` means no caching; the
  entry bound evicts the oldest; singleflight makes 10 concurrent requests into 1 call.
- [ ] Verify: the scoped command for `internal/introspect`.

### Task C1: Mode core, routing, disclosure (tasks 3.2, 7.1–7.3)

**Interfaces produced:**
- `func EnableResourceServer(resourceID string, opts ...ResourceServerOption) Option`;
- `type ResourceServerOption`;
- `WithPathPrefix(prefixes ...string)`;
- `WithResourceAliases(aliases ...string)`;
- `const OrderResourceServer Order = 425`;
- `func WithInactiveDisclosure() Option`;
- the internal `source` interface (`name() string`, `recognises(t peeked) bool`,
  `verify(ctx, raw string) (*verifiedToken, error)`), which C2 to C4 implement.

- [ ] Red, then green: the construction scenarios (identifier, alias, prefix syntax, overlap,
  unscoped-alone), as a table.
- [ ] Red, then green: refactor the binding check to return typed results and write nothing; UserInfo
  maps them to its settled answers. Run the UserInfo suite before and after, unchanged.
- [ ] Red, then green, against stub sources:
  - path-first routing (two modes trusting one issuer);
  - the size bound;
  - the session-token exclusion and its construction check;
  - "not handed on";
  - off-prefix refusal;
  - the provider's own endpoints.

  Add `FuzzAccessTokenRoute`.
- [ ] Red, then green: the inactive-disclosure scenarios through form login and Basic, and
  prblmsec concealment.
- [ ] Verify: the scoped command for `httpsec` in the root, `fibersec`, `ginsec`, `prblmsec` and
  `test` modules. Run the fuzz target for 30 s.

### Task C2: Challenges, binding, provider source (tasks 7.4–7.5, 8.1)

**Interfaces produced:**
- `var ErrInvalidToken`;
- `func FromProvider(op *oidcprovider.Provider, opts ...SourceOption) ResourceServerOption`;
- `type SourceOption`.

- [ ] Red, then green:
  - the challenge scenarios, with `bearerChallenge` extended and an API-only chain counting as having a
    bearer;
  - exactly one `WWW-Authenticate` per refusal kind, with DPoP on and off;
  - `WithoutBearerChallenge` accepted on an API-only chain.
- [ ] Red, then green: the binding scenarios (Bearer downgrade, nonce, certificate), the
  verifier-of-bound-credentials count, and the DPoP-required opt-out error.
- [ ] Red, then green: the provider source's audience, type, grant and local-user scenarios, against a
  real `oidcprovider` with in-memory stores.
- [ ] Verify: as in C1.

### Task C3: Publication, dependencies, remote issuer (tasks 8.2–8.3, 9.1–9.2)

**Interfaces produced:**
- `type AccessToken struct{ Resource, Issuer, Subject, ClientID string; Audience, Scopes []string; IssuedAt, ExpiresAt, AuthTime time.Time; ACR string; AMR []string; Confirmation map[string]string; Claims map[string]any }`;
- `func AccessTokenFromContext(ctx context.Context) (*AccessToken, bool)`;
- `func FromIssuer(issuer string, opts ...SourceOption) ResourceServerOption`;
- source options `WithSourceAudience`, `WithJWKSURL`, `WithOutboundClient`, `WithAlgorithms`,
  `WithClockSkew`, `WithUnboundTokens`, `WithUntypedTokens(claim, value string)`,
  `WithJWTIntrospection(cfg IntrospectionConfig)`.

- [ ] Red, then green: the publication and scope scenarios (kinds, `scp` forms, a mapper that cannot
  widen scopes, copy on read).
- [ ] Red, then green: the dependency-failure scenarios.
- [ ] Red, then green: each remote-issuer scenario against a local `httptest` TLS issuer serving
  discovery, RFC 8414 metadata and JWKS. That covers rotation, flood, `none`, the embedded `jwk`,
  required claims, `azp`, untyped tokens with a telling claim, the source audience equal to the issuer,
  and JWT introspection.
- [ ] Verify: as in C1.

### Task C4: Introspection source, strategies, throttle, assurance (tasks 9.3–9.6)

**Interfaces produced:**
- `func FromIntrospection(issuer, endpoint, clientID string, opts ...SourceOption) ResourceServerOption`;
- `WithIntrospectionSecret`, `WithIntrospectionKey`,
  `WithIntrospectionCache(maxAge time.Duration, maxEntries int)`, `WithOpaquePrefix`;
- `WithClaimsOnly()`;
- `type MappedCaller struct{ Principal *identity.Principal; Local bool }`;
- `WithClaimsMapper(func(ctx context.Context, claims map[string]any) (MappedCaller, error))`;
- `WithLocalUsers(identity.UserLoader)`;
- `WithLinkedUsers(links oidc.LinkStore, provider string, users identity.UserLoader)`;
- `WithAssuranceSource(policy.FederatedAssuranceSource)`;
- `WithRefusalLimiter(ratelimit.Limiter)`;
- `policy.Input.AccessTokenAssurance` (no public constructor; zero value = a local user, no second
  factor, no evidence);
- `var ErrInsufficientUserAuthentication`, wrapping `ErrReauthenticationRequired`.

- [ ] Red, then green: the introspection-source scenarios, including "the provider's own tokens" and
  "other credentials" (session references and `Bearer`-scheme API keys).
- [ ] Red, then green: the strategy scenarios. That includes the subject-collision case, where local
  user `42` is never loaded; a mapper declaring a local user; and the source-wiring construction table.
- [ ] Red, then green: the throttle. Zero introspection calls past the limit; only verification refusals
  counted, so a nonce challenge is not.
- [ ] Red, then green: the MFA requirement scenarios:
  - the `AccessTokenAssurance` zero value is denied;
  - a provider token whose grant has no library marker is refused, and one with it is allowed;
  - a federated grant is refused after assurance is tightened, and allowed in exempt mode;
  - a password-only external token is refused in challenge mode;
  - a claims-only caller is not judged;
  - an access-token kind on the enrolment allowlist is a construction error.
- [ ] Verify: the scoped command for `httpsec` (as in C1) and for `policy` (its dependents in every
  module).

### Task C5: Per-request challenges and events (tasks 9.7–9.8)

- [ ] Red, then green: a consumer per-request policy raising any challenge for an access-token caller
  is answered 401 `insufficient_user_authentication`, with nothing marked on a session. Add the status
  row and the prblmsec type.
- [ ] Red, then green: the construction error for a local-user source with no assurance source on an
  MFA-required chain; a source with `WithAssuranceSource` builds.
- [ ] Red, then green: the security-events scenarios (refusal event, throttle event, no user reference
  for a claims-only caller).
- [ ] Verify: as in C1, plus the `event` package's dependents.

### Task G1: Grant columns (task 4.5; starts only after PR #149 merges)

- [ ] Red: extend `test/storetest`'s grant suite so a stored grant keeps its second-factor marker and
  its federated evidence. It fails on every SQL store.
- [ ] Green: write a new security-state migration after the folded baseline adding the columns, then
  store and load them in `store/sqlstore`, `store/pgxstore` and `store/gormstore`.
- [ ] Verify: the grant suite on every store (Docker), `make generate-check`, the schema inventory tests,
  and the scoped command for the three store modules.

### Task D1: Endpoints, rule challenges, guards, recency (tasks 10.1–10.5)

**Files:** `httpsec/logout.go`, `role_switch.go`, `authorization.go`, `guards.go`;
`internal/guardauth/recency.go` and `challenge.go`; the session-endpoint test files.

- [ ] Characterization: a table over every session-only endpoint, called with an access token. Each
  returns 401 and changes nothing. Show each case failing once by temporarily publishing a fake
  session in the test, then restore.
- [ ] Red, then green: logout refuses an access-token caller (red today: 200). Settled logout scenarios
  stay green.
- [ ] Red, then green: `insufficient_scope` at chain rules and guards; the API-key caller is unchanged.
- [ ] Red, then green: recency in `internal/guardauth`. A fresh, stale, or `auth_time`-less access
  token is answered 401 with `max_age=300` for a 5-minute window. A stale session still gets 403 with
  no body. Move the gin and fiber guards onto `guardauth`'s time source and error choice.
- [ ] Red, then green: the gin and fiber scope and recency scenarios.
- [ ] Verify: as in C1.

### Task E1: Conformance and docs (tasks 11.1–11.3)

- [ ] Write three conformance scenarios: a provider-and-API chain; an API-only chain with a remote
  issuer; two prefixes trusting one issuer. Run them on all three adapters.
- [ ] Write the README sections (resource server, `password.WithRule`, `WithInactiveDisclosure`), and
  an example test compiling the resource-server examples.
- [ ] Write the CHANGELOG *Added* entry and the three **BREAKING (behaviour)** *Changed* entries, merged
  by hand with the other v0.6.0 entries.
- [ ] Verify: the `test` module's scoped run.

### Task F: Final gate (task 11.5, main session)

- [ ] Run `gofmt -l` (empty), `go vet`, and the scoped command in every workspace module.
- [ ] Run `make check` and `make spec-check` after the last edit, and read the output.
- [ ] Run the whole-branch review against every requirement in `specs/`.
