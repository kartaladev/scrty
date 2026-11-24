# Resource server: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A generic OAuth resource-server mode for the httpsec chain, with these parts:
- `EnableResourceServer` with provider, remote-issuer and introspection sources;
- guard and challenge support;
- consumer password rules;
- inactive-account disclosure.

**Architecture:**
- **Leaf changes first:**
  - the factor kind, `ScopeError`, password rules and the inactive error;
  - provider fields;
  - two internal packages: the key set, extracted from `authenticate/oidc`, and the introspection
    client.
- **Then the mode in `httpsec`**, in sequential dispatches: the core and the provider source first,
  then the external sources, then guards and endpoints.
- **Then the adapters, conformance and docs.**

**Tech Stack:** Go workspace, `lestrrat-go/jwx/v4`, `outbound`, `golang.org/x/sync/singleflight`,
mockgen, testcontainers (conformance only).

**Spec:** `openspec/changes/resource-server/`: `proposal.md`, `design.md` (decisions 1–18,
F1–F33), `specs/` and `tasks.md`.

## Global Constraints

- **Binding rules (every dispatch prompt states them):** test-first (`golang-tdd.md`),
  `library-design.md`, `defensive-coding.md`, `defect-claims.md`, the `table-test`, `use-mockgen` and
  `use-testcontainers` skills, and the read-only legacy reference.
- **Exact values:**
  - `OrderResourceServer = 490`;
  - kind `"access-token"`;
  - a 4 KiB peek bound;
  - a clock-skew bound of 5 minutes, default 0;
  - introspection posts `token_type_hint=access_token`;
  - the challenge error codes `invalid_token`, `insufficient_scope` and
    `insufficient_user_authentication`, the last with `max_age` in whole seconds.
- **No token, secret, key or introspection body in any log, error or event.**
- **Files no dispatch touches:** `store/migrate/**`, the `test/` migration tests, and
  `httpsec/oidc_login.go`'s `callbackCode`. Those belong to PR #149.
- **Git:** never `checkout --`, `restore`, `reset --hard`, `stash` or `clean`.

## Review Focus

1. A session token or session reference reaching a source, or being sent to an introspection
   endpoint (design 5, 11). Expected: never.
2. A recognised-but-refused access token falling through to `EnableBearerToken` (spec "not handed
   on"). Expected: 401 `invalid_token`.
3. A dependency outage (key set, introspection, provider store) answered as 401. Expected: 500, and
   the outage is not counted as a refused credential.
4. Two `WWW-Authenticate` headers on one refusal, because the DPoP challenge and the fallback both
   write. Expected: exactly one.
5. Recency for session callers changing. Expected: still 403, no body.

---

## Lanes and dispatches

| Dispatch | Tasks | Owns | Model | Reason | Runs |
|---|---|---|---|---|---|
| A1 | 1.1–1.3 | `authenticate/factor`, `identity` (godoc), `authorize` | Sonnet | Known patterns; the signatures are given | Wave 1 |
| A2 | 2.1–2.2 | `authenticate/password` | Sonnet | On-hold design 11, already fully specified | Wave 1 |
| A3 | 3.1 | `authenticate` (password provider) | Opus | Security-critical refusal logic and timing | Wave 1 |
| A4 | 4.1–4.2 | `oidcprovider` | Sonnet | Field plumbing and an accessor | Wave 1 |
| B1 | 5.1–5.2 | `authenticate/oidc`, new `internal/keyset` | Opus | A behaviour-preserving extraction with concurrency | Wave 1 |
| B2 | 6.1–6.2 | new `internal/introspect` | Opus | A new security-critical client with a bounded cache | Wave 1 |
| C1 | 3.2, 7.1–7.3, 7.6–7.8 | `httpsec` (mode, routing, shared binding, challenges, inactive disclosure) | Opus | Security-critical routing and refusal; an interface other lanes compile against | Wave 2, after A1, A3, A4 |
| C2 | 7.4–7.5 | `httpsec` (provider source, publication) | Opus | Verification and refusal logic | After C1 |
| C3 | 8.1–8.5 | `httpsec` (external sources, strategies, checks) | Opus | Security-critical verification | After C2, B1, B2 |
| D1 | 9.1–9.4 | `httpsec` (endpoints, rule challenges, guards, recency) | Opus | Refusal logic across many endpoints | After C3 |
| D2 | 9.5 | `httpsec/fibersec`, `httpsec/ginsec` | Sonnet | Parity with the core; tests given | After D1 |
| E1 | 10.1–10.4 | `test/httpsecconformance`, `README.md`, `CHANGELOG.md`, `bff-resource-server` note (main session) | Sonnet | Fixtures and docs | After D2 |
| — | 10.5 | main session | — | Verification is never delegated | Last |

- **Wave 1** runs A1, A2, A3, A4, B1 and B2 in one message. They own disjoint packages, and none
  consumes another's new API.
- **`httpsec` is one lane** (C1 → C2 → C3 → D1), split into sequential dispatches of six tasks or
  fewer.
- **Every dispatch** gets a fresh reviewer that edits nothing. Opus dispatches get an Opus reviewer;
  Sonnet dispatches get a Sonnet reviewer.
- **The `bff-resource-server` note (10.4)** is written by the main session, because it is an
  OpenSpec artifact.

**Scoped tests** (`test-scope.md`), run from each workspace module for the packages a dispatch
changed:

```sh
go list -test -f '{{.ImportPath}}{{range .Deps}} {{.}}{{end}}' ./... \
  | awk -v P="github.com/kartaladev/scrty/<changed>" '{for(i=2;i<=NF;i++) if($i==P){print $1;break}}' \
  | grep -v '\.test$' | sort -u | xargs go test -count=1
```

Root-module dependents, measured 2026-11-25:

| Package | Dependents |
|---|---|
| `authenticate/factor` | 50 |
| `identity` | 54 |
| `authorize` | 46 |
| `authenticate` | 20 |
| `authenticate/password` | 24 |
| `oidcprovider` | 15 |
| `authenticate/oidc` | 8 |
| `httpsec` | 6, plus the `fibersec`, `ginsec`, `prblmsec` and `test` modules |

---

### Task A1: Kind and scope refusal (tasks 1.1–1.3)

**Files:** `authenticate/factor/factor.go`, `factor_test.go`; `identity/principal.go` (godoc);
`authorize/requirements.go`, `authorize/errors.go`, tests.

**Interfaces produced:**
- `const AccessToken Kind = "access-token"`;
- `type ScopeError struct{ Scopes []string; All bool }` with `Error() string` and
  `Is(target error) bool`, true for `ErrAccessDenied` and `ErrNotGranted`.

- [ ] Red: a kind table row `{kind: factor.AccessToken, channel: "", exempt: true}` fails, because the
  kind is undefined at run time through an exported lookup. If it fails only to compile, add the
  constant first and assert on the table.
- [ ] Green: add the kind to the channel and exemption tables.
- [ ] Red: `HasAnyScope("orders:write")` on scopes `[orders:read]` yields `errors.As(err, &se)` with
  `se.Scopes == [orders:write]` and `!se.All`. It fails: no `ScopeError`.
- [ ] Green: return `ScopeError` from both requirements. Keep the anonymous path unchanged.
- [ ] Verify: scoped tests for `authenticate/factor`, `identity`, `authorize`.

### Task A2: Consumer password rules (tasks 2.1–2.2)

**Files:** `authenticate/password/policy.go`, `options.go`, tests.

**Interfaces produced:**
- `type RuleFunc func(ctx context.Context, candidate string, user *identity.Details) (bool, error)`;
- `func WithRule(name Rule, check RuleFunc) Option`.

- [ ] Red, then green, for each password-policy scenario in the spec delta, one table case each. Order:
  1. no rule by default;
  2. letters and digits;
  3. weak and reused stay distinct;
  4. rule failure;
  5. a consumer rule runs before the breach lookup (a lookup mock expecting no call);
  6. the construction refusals.
- [ ] Verify: scoped tests for `authenticate/password`.

### Task A3: Inactive error (task 3.1)

**Files:** `authenticate/errors.go`, `authenticate/password.go` (the provider), tests.

**Interfaces produced:** `var ErrAccountInactive = errors.New(...)`.

- [ ] Red: an inactive user with the correct password gives `errors.Is(err, ErrAccountInactive)`.
  It fails.
- [ ] Red: an inactive user with a wrong password gives `!errors.Is(err, ErrAccountInactive)`, with
  the same work spent.
- [ ] Green: check active state only after the password verifies, and join beneath the uniform
  failure.
- [ ] Verify: scoped tests for `authenticate`.

### Task A4: Provider fields (tasks 4.1–4.2)

**Files:** `oidcprovider/accesstoken.go`, `oidcprovider/provider.go`, tests.

**Interfaces produced:**
- `AccessToken.AuthTime time.Time`, `ACR string`, `AMR []string`;
- `func (p *Provider) UserLoader() identity.UserLoader`.

- [ ] Red: for a JWT and an opaque token issued after a sign-in at a fixed time, `VerifyAccessToken`
  returns that `AuthTime`, `ACR` and `AMR`. It fails with a zero value.
- [ ] Green: read the claims for a JWT, and the loaded grant for an opaque token.
- [ ] Red, then green: `UserLoader()` returns the loader in `Deps`.
- [ ] Verify: scoped tests for `oidcprovider`.

### Task B1: Shared key set (tasks 5.1–5.2)

**Files:** new `internal/keyset/`; `authenticate/oidc/remote.go` and its callers.

**Interfaces produced:**
- `keyset.New(fetcher *outbound.Client, opts ...Option) *Cache`;
- `(*Cache).Key(ctx, issuer, kid string) (jwk.Key, error)`;
- `(*Cache).Metadata(ctx, issuer string) (Metadata, error)`;
- `keyset.ErrUnknownKey`.

- [ ] Run `go test -count=1 ./authenticate/oidc/...` and save the result as the baseline.
- [ ] Move the tests describing TTL, backoff, cooldown and singleflight first, as tests of
  `internal/keyset` against the moved code. They must be red until the code moves.
- [ ] Move the code. `authenticate/oidc` uses it.
- [ ] Rerun the baseline. Expected: identical pass list.
- [ ] Red, then green: RFC 8414 fallback; a direct key-set URL; a `jwks_uri` on another origin refused.
- [ ] Verify: scoped tests for `authenticate/oidc` and `internal/keyset`.

### Task B2: Introspection client (tasks 6.1–6.2)

**Files:** new `internal/introspect/`.

**Interfaces produced:**
- `introspect.New(cfg Config, fetcher *outbound.Client) (*Client, error)`;
- `(*Client).Introspect(ctx, token string) (*Result, error)`;
- `Result{Active bool; Issuer, Subject, ClientID string; Audience, Scopes []string; ExpiresAt, AuthTime time.Time; Confirmation map[string]string; Claims map[string]any}`.

- [ ] Red, then green, one table case each:
  1. active;
  2. inactive;
  3. 503, which is a dependency error;
  4. a malformed body;
  5. a non-https endpoint refused at `New`;
  6. basic authentication;
  7. a private-key JWT;
  8. a log capture holding neither the token nor the secret.
- [ ] Red, then green: the cache returns a stored answer within its bound, and never past `exp`, with a
  fake clock.
- [ ] Verify: scoped tests for `internal/introspect`.

### Task C1: Mode core, routing, challenges (tasks 3.2, 7.1–7.3, 7.6–7.8)

**Files:** new `httpsec/resource_server.go`, `resource_server_options.go`, `resource_route.go`,
`access_challenge.go`; the shared binding check moved out of `oidc_userinfo.go`;
`httpsec/errors.go`; `httpsec/chain.go` (the slot constant and the verifier-of-bound-credentials
count); `httpsec/login.go` (inactive disclosure); tests.

**Interfaces produced:**
- `func EnableResourceServer(resourceID string, opts ...ResourceServerOption) Option`;
- `type ResourceServerOption`;
- `func WithPathPrefix(prefixes ...string) ResourceServerOption`;
- `func WithResourceAliases(aliases ...string) ResourceServerOption`;
- `const OrderResourceServer Order = 490`;
- `var ErrInvalidToken`;
- `func WithInactiveDisclosure() Option`;
- an internal `source` interface that C2 and C3 implement:
  `recognises(peek) bool`, `verify(ctx, raw) (*verified, error)`, `strategy`.

- [ ] Red, then green: the construction scenarios of spec resource-server (identifier, prefixes,
  overlap, unscoped beside another), as a table.
- [ ] Red, then green: the shared binding check. Run the UserInfo suite first as the baseline; it must
  stay green.
- [ ] Red, then green: the routing scenarios with a stub internal source. Add
  `FuzzAccessTokenPeek`.
- [ ] Red, then green: the challenge scenarios, plus exactly one `WWW-Authenticate` per refusal kind,
  with DPoP on and off.
- [ ] Red, then green: the inactive-disclosure scenarios through form login.
- [ ] Verify: scoped tests for `httpsec`, `fibersec`, `ginsec`, `prblmsec` and `test`. Run the fuzz
  target for 30 s.

### Task C2: Provider source and publication (tasks 7.4–7.5)

**Files:** new `httpsec/resource_source_provider.go`, `httpsec/access_token.go`, tests.

**Interfaces produced:**
- `func FromProvider(op *oidcprovider.Provider, opts ...SourceOption) ResourceServerOption`;
- `type SourceOption`;
- `type AccessToken struct{ Resource, Issuer, Subject, ClientID string; Audience, Scopes []string; IssuedAt, ExpiresAt, AuthTime time.Time; ACR string; AMR []string; Confirmation map[string]string; Claims map[string]any }`;
- `func AccessTokenFromContext(ctx context.Context) (*AccessToken, bool)`.

- [ ] Red, then green, each scenario of the spec's provider, audience, type, binding, caller ("role
  removed", "local user inactive") and publication requirements, against a real `oidcprovider` with
  in-memory stores.
- [ ] Verify: scoped tests as in C1.

### Task C3: External sources and strategies (tasks 8.1–8.5)

**Files:** new `httpsec/resource_source_issuer.go`, `resource_source_introspect.go`,
`resource_strategy.go`, tests.

**Interfaces produced:**
- `func FromIssuer(issuer string, opts ...SourceOption) ResourceServerOption`;
- `func FromIntrospection(endpoint, clientID string, opts ...SourceOption) ResourceServerOption`;
- source options: `WithSourceAudience`, `WithJWKSURL`, `WithClockSkew`, `WithUnboundTokens`,
  `WithUntypedTokens(claim, value string)`, `WithJWTIntrospection(cfg IntrospectionConfig)`,
  `WithIntrospectionSecret`, `WithIntrospectionKey`, `WithIntrospectionCache(max time.Duration)`,
  `WithOpaquePrefix`;
- strategy options: `WithClaimsOnly()`,
  `WithClaimsMapper(func(ctx context.Context, claims map[string]any) (*identity.Principal, error))`,
  `WithLocalUsers(identity.UserLoader)`.

- [ ] Red, then green, each external-source scenario against a local `httptest` TLS issuer serving
  discovery, JWKS and introspection:
  - rotation;
  - flood;
  - `none`;
  - spelling;
  - untyped;
  - telling claim;
  - JWT introspection;
  - inactive;
  - cache;
  - session-reference prefix.
- [ ] Red, then green, the caller-strategy scenarios and the remaining F25 construction checks, as a
  table.
- [ ] Verify: scoped tests as in C1.

### Task D1: Endpoints, rule challenges, guards, recency (tasks 9.1–9.4)

**Files:**
- the session-only endpoint files: `password_change.go`, `passkey_manage.go`, `passkey_register.go`,
  `mfa_enrol.go`, `mfa_verify.go`, `reauth_*.go`, `session_renewal.go`, `session_management.go`,
  `logout.go`;
- `authorization.go`;
- `guards.go`;
- tests.

- [ ] Red, then green: a table over every session-only endpoint, called with an access token. Each
  returns 401 auth-required and changes nothing; logout ends nothing.
- [ ] Red, then green: chain-rule `insufficient_scope`; the API-key caller unchanged.
- [ ] Red, then green: the guard scope and privilege scenarios.
- [ ] Red, then green: every recency scenario in the reauthentication delta, plus the 401 challenge
  with `max_age=300`; a stale session still gets 403 with no body.
- [ ] Verify: scoped tests as in C1.

### Task D2: Adapter guards (task 9.5)

**Files:** `httpsec/fibersec/guards.go`, `httpsec/ginsec/guards.go`, their tests.

- [ ] Red, then green: the D1 guard and recency scenarios through each adapter.
- [ ] Verify: `go test -count=1 ./...` in the `httpsec/fibersec` and `httpsec/ginsec` modules.

### Task E1: Conformance and docs (tasks 10.1–10.3)

**Files:** `test/httpsecconformance/resource_server_scenarios.go`, `README.md`, `CHANGELOG.md`,
`httpsec/example_resource_server_test.go`.

- [ ] Write three conformance scenarios: a provider-and-API chain, an API-only chain with a remote
  issuer, and two resource servers by prefix. Run them on all three adapters.
- [ ] Write the README sections and an example test that compiles both examples.
- [ ] Write the CHANGELOG entries: *Added*, plus two **BREAKING (behaviour)** entries under
  *Changed*.
- [ ] Verify: the `test` module's scoped tests.

### Task F: Final gate (task 10.5, main session)

- [ ] Run `gofmt -l` (empty), `go vet`, and the scoped tests in every workspace module.
- [ ] Run `make check` and `make spec-check` after the last edit, and read the output.
- [ ] Whole-branch review against every requirement in `specs/`.
