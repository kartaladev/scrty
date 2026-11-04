# oidc-provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make an application embedding scrty an OpenID Provider for its own other applications. The provider passes the OpenID Foundation's Basic OP, Config OP and logout plans with its defaults, plus one named client setting and one recorded expected result (R1, R5), and every protocol step reuses an existing scrty primitive.

**Architecture:**
- **`oidcprovider` (new core package):** holds the protocol's domain logic. It validates requests, registers and authenticates clients, parks requests, decides consent, issues codes, mints tokens, manages grants and delivers back-channel logout. It has no HTTP framework dependency (design T1).
- **`httpsec`:** adds `EnableOIDCProvider`. It parses and writes HTTP, authenticates the resume's sign-in through the existing bearer modes, verifies DPoP and certificates through `close-security-gaps`, and renders the protocol's error bodies.
- **Refresh tokens:** they reuse `session`'s rotation and reuse detection unchanged. That code runs over a lineage store the provider fixes, and every refresh reads an authoritative grant row first (decision 5, D+). `token` gains a separate `Issuer` and `typ` enforcement (R6).

**Tech Stack:** Go 1.27, `github.com/lestrrat-go/jwx/v4` (the only JOSE stack), `net/http`, gin, fiber v3, testify, `go.uber.org/mock`, and testcontainers-go (PostgreSQL 15 and 18). The OpenID conformance suite (Java and MongoDB) runs in Docker, in CI only.

**Spec:** `openspec/changes/oidc-provider/`: `proposal.md`, `design.md` (decisions 1–5, P1–P9, the spec-time table, T1–T9, R1–R16), `specs/**/spec.md` and `tasks.md`.

## Global Constraints

- **Go and dependencies:**
  - Go 1.27 floor;
  - the core module adds no dependency;
  - JOSE work uses jwx v4 only. No `go-jose`, and no OpenID Provider library (decision 1).
- **The `test` module:** nothing in `github.com/kartaladev/scrty/test` is imported by another scrty module, including from `_test.go` files. The exported store suites live in `test/storetest`.
- **Test-first** (`golang-tdd.md`): every task runs its new test and sees it fail for the intended reason before writing code. Add a stub first so the red step fails on an assertion, never on a compile error.
- **Test mechanics:** table tests follow the `table-test` skill (`assert` closures, a `ctx` modifier, `t.Context()`). Mocks come from `use-mockgen` (typed, test-only files). PostgreSQL comes from the existing `use-testcontainers` helpers in `test/`.
- **Library design** (`library-design.md`): every option's godoc names the default it replaces, and every port says what the library uses when none is supplied. Wiring mistakes fail at construction:
  - in `oidcprovider`, with `oidcprovider.ErrConfig`, naming the client and setting;
  - in `httpsec`, with `httpsec.ErrConfig`, naming `EnableOIDCProvider`.
- **No secrets anywhere visible:** no log line, error text or event carries a code, handle, flow secret, refresh token, access token, ID token, client secret, its digest, or a client assertion.
- **Dependency failures:** a failing store, key source or outbound fetch fails with fixed library text that wraps the cause, maps to 500 and is charged to no throttle. A request whose own context ended matches the context's error (`internal/hangup.ByCaller`) and logs nothing at ERROR.
- **Defaults and bounds pinned by the specs:**

  | Setting | Default | Bound |
  |---|---|---|
  | pending-request lifetime | 10 min | at most 30 min |
  | code lifetime | 60 s | at most 10 min |
  | ID token lifetime | 5 min | within the key cap (key lifetime minus rotation) |
  | access token lifetime | 5 min | within the key cap (key lifetime minus rotation) |
  | logout token `exp` | — | at most 2 min after `iat` |
  | refresh grace | 30 s | at most 5 min (`session.MaxRenewalGrace`) |
  | grant idle timeout | 30 days | at most the absolute lifetime |
  | grant absolute lifetime | 90 days | — |
  | assertion `exp` | 5 min ahead | at most 1 h |
  | metadata `Cache-Control` | `max-age=3600` | — |
  | supplied client secret | — | at least 32 bytes |
  | generated client secret | 256 bits | — |
  | code and handle | — | at least 128 bits |
  | flow secret, browser-session secret | 256 bits | — |
  | browser session | sign-in's absolute deadline; the manager's `IdleTimeout()` without use | — |
  | `state`, `nonce`, `login_hint`, each `resource` | at most 2048 bytes, replaceable | — |
  | `scope` | at most 4096 bytes, replaceable | — |
  | back-channel delivery | 8 workers, queue of 1024, replaceable | — |
  | client `jwks_uri` refetch | 30 s cooldown, replaceable | — |
  | PKCE challenge | — | 43–128 unreserved characters |

- **Fixed values:**
  - **endpoints:** prefix `/oauth2`, with `/authorize`, `/authorize/resume`, `/token`, `/userinfo`, `/revoke`, `/introspect`, `/logout`, `/logout/confirm` and `/consents`. The metadata paths are `/.well-known/openid-configuration` (after the issuer's path) and `/.well-known/oauth-authorization-server` (before it);
  - **token types:** `scrty+jwt` first-party, `at+jwt` access, `JWT` ID, `logout+jwt` logout; `client-authentication+jwt` accepted on an assertion;
  - **grant reference claim:** `gid`, the grant's family (R4);
  - **credential formats (T6):** `rt.<family>.<secret>`, `at.<id>.<secret>` and `rh.<id>.<secret>`;
  - **flow cookie:** `__Host-scrty-op-flow`, with `HttpOnly`, `Secure`, `Path=/` and `SameSite=Lax` (T5), kept across a browser's parallel requests (R9). Under the loopback issuer: `scrty-op-flow`, not `Secure`;
  - **browser-session cookie:** `__Host-scrty-op-session`, with the same attributes (R2);
  - **onetime purpose:** `oidc-provider.code` (T2);
  - **lineage table:** `op_refresh_tokens` (T7).
- **Every provider redirect is 303.** The resume answers 200 JSON `{"redirect_to": ...}`. Token, revocation and introspection responses carry `Cache-Control: no-store`, and so do UserInfo and resume responses.
- **Error bodies:** the provider's endpoints answer protocol errors with the RFC's body and status (P3), with no `error_description`. Every other refusal stays a chain error with no body (`http-error-propagation`).
- **TLS:** authorize, resume, token, revocation, introspection, UserInfo, end-session and its confirmation refuse a request when `Request.Secure()` is false, unless the provider has the loopback issuer (R11).
- **Form bodies:** the token, revocation, introspection, POST UserInfo, POST authorize and POST end-session endpoints read the form from `Request.Body(64 << 10)`, parsed with `url.ParseQuery`. They never use `FormValue`, which falls back to the query. A repeated parameter is `invalid_request`, and an empty one counts as omitted.
- **Never cite the predecessor** (`legacy-reference.md`). A defect is claimed only with a failing test (`defect-claims.md`).

## Review Focus

- **Messy `scope` values.** A `scope` with doubled spaces or duplicates (`openid  openid profile`) is split on single spaces with empty items dropped and duplicates removed. It is accepted, and the token's `scope` is `openid profile`. Test added to 6.1.
- **Reserved characters in `state`, and a query in the redirect URI.** A `state` holding `&`, `=`, `#` and spaces comes back byte-identical after URL decoding. A registered redirect URI that already has a query (`https://rp.example.com/cb?tenant=a`) keeps it, with `code`, `state` and `iss` appended. Test added to 6.7 (success) and 6.1 (error redirect).
- **A Basic secret containing `:`.** The decoded header is split at the first `:`, and each half is URL-decoded afterwards, so `a%3Ab` authenticates the secret `a:b`. Test added to 4.5.
- **Two tabs refreshing at once.** Two concurrent refreshes with one token, both within the grace window, both receive the same successor, and the grant stays live through the next refresh, whichever write landed last (R20). Test added to 7.5 (`-race`).
- **Oversized parameters.** A value past R11's bounds, any other authorization parameter over 4 KiB, or more than 10 `resource` values, is answered `invalid_request` before anything is parked or stored, and the oversized `state` is not reflected. Test added to 6.1.
- **Double-clicked consent, or a lost resume response.** A handle's stage is single-use, so the second attempt is refused as an unknown handle, and the user restarts from the relying party. No code is issued twice. Test added to 6.6.
- **A `state` that changes between tabs.** Two parallel requests share one flow cookie, and each keeps its own `state` and `nonce`. Test added to 6.2.

---

## Delegation lanes

Each lane owns the files listed for it. Two lanes never write one file, and lanes that share a package run in their own worktrees. A lane longer than six tasks runs as sequential dispatches. After each dispatch, the main session runs the verification commands, and a fresh reviewer checks the diff against the tasks' requirements.

| Phase | Lane | Tasks (dispatches) | Owns | Model (reason) |
|---|---|---|---|---|
| 0 | main session | 1.1; 1.2 run by a Haiku agent that reports what the suite does; 1.3 | OpenSpec artifacts only | Haiku for 1.2 (runs a Docker suite and reports; decides nothing) |
| A (parallel, worktrees) | T: token types | 2.1–2.4 | `token/generator.go`, `verifier.go`, `config.go`, `claims.go`, `token/issuer.go` (new), their tests; `httpsec/bearer_tokentype_test.go` (new) | Opus (token verification written for the first time) |
| A | S: session ends | 3.1–3.3 | `session/sessions.go`, `sessions_options.go`, `reuse.go`, `session/end_observer.go` (new), tests | Opus (an interface other lanes compile against; report ordering after writes) |
| A | C: clients | 4.1–4.4; 4.5–4.7 | `oidcprovider/` doc, provider, options, client, redirect, registry, clientauth and assertion files | Opus (client authentication is security-critical) |
| B, after C | D: stores | 5.1–5.4; 5.5–5.8 | `oidcprovider/store*.go`, `oidcprovider/lineage.go`, `internal/oplineage/`, `test/storetest/oidcprovider_*.go` | Opus (conditional writes, tombstone races) |
| C, after B | A: authorization | 6.1–6.4; 6.5–6.7; 6.8 | `oidcprovider/authorize.go`, `pending.go`, `consent.go`, `resume.go`, `code.go`, `browsersession.go`, tests | Opus (refusal ordering, handle binding) |
| C (parallel with A, worktrees) | P: persistence | 12.1; then 12.2, 12.3 and 12.4 in parallel; then 12.5 | `store/migrate/securitystate/2026110300…_oidc_provider.sql`, `internal/pgschema/oidcprovider.go`, `store/{sqlstore,pgxstore,gormstore}/oidcprovider_*.go`, `test/{sqlstore,pgxstore,gormstore}/oidcprovider_test.go`, `test/expirytasks_test.go` | Opus (conditional writes per dialect) |
| D, after A and T and S | G: grants and tokens | 7.1–7.2; 7.3–7.4; 7.5; 7.6–7.8; 7.9–7.10 | `oidcprovider/exchange.go`, `idtoken.go`, `accesstoken.go`, `refresh.go`, `revoke.go`, `userinfo.go`, `claims.go`, `endsignin.go`, `backchannel.go`, `events.go`, tests | Opus for 7.1–7.2, 7.5 and 7.6–7.8 (races, refusal logic); Sonnet for 7.3–7.4 and 7.9–7.10 (claim sets and delivery the plan states) |
| E, after G | H1: chain and authorize | 8.1–8.3; 8.4–8.7 | `httpsec/oidc_provider.go`, `oidc_provider_options.go`, `oidc_authorize.go`, `oidc_resume.go`, `errors.go` (rows), `README.md` (provider section) | Opus (several packages; resume authentication) |
| E2, after H1 (worktrees) | H2: token endpoints | 9.1–9.6 | `httpsec/oidc_token.go`, `oidc_revoke.go`, `oidc_userinfo.go`, `cors.go` (provider rule) | Opus (binding before spend) |
| E2 | H3: metadata | 10.1–10.2 | `httpsec/oidc_metadata.go` | Sonnet (data assembly the spec lists) |
| F, after H2 | H4: logout and revocation | 11.1, 11.8, 11.2–11.4; 11.5–11.7 | `httpsec/oidc_endsession.go`, `oidc_logout_confirm.go`, `oidc_consents.go`, `logout.go`, `oidc_backchannel.go` (the RP-side upstream logout), `session_management.go`, `password_change.go`, the passkey assertion path, `csrf.go` (provider exemptions), `recovery/hold.go`, `authenticate/mfa/reset.go` | Opus (logout ordering; ports in several packages) |
| G | X: integration | 12.6, 13.1; 14.1–14.2; 14.3 per finding | `test/oidcprovider_durable_test.go`, `test/httpsecconformance/oidcprovider_scenarios.go`, `test/cmd/conformanceop/`, `test/conformance/`, the `conformance` target in `Makefile`, and the `conformance` job and `ci-ok`'s needs in the CI workflow `split-ci-jobs` leaves | Sonnet for 12.6, 13.1, 14.1 and 14.2 (scenarios the plan lists); Opus for each 14.3 defect fix |
| H | main session plus reviewer | 15.1–15.3 | OpenSpec artifacts | Opus whole-branch reviewer |

**The status table.** `httpsec/errors.go`'s table is owned by H1. Later lanes add their sentinels in their own files and append rows inside their worktrees. The main session resolves the table merge (a few lines, stated when it happens).

---

## Task group 1: baseline check (main session)

### Task 1.1: Recheck the merged in-flight changes
- [ ] Rebase this change's branch onto `main`, which holds `pre-release-api-fixes` and `close-security-gaps`.
- [ ] Read the merged code with gopls and record in `design.md`:
  - the exact names this plan assumes and leaves open, which the plan's later tasks now use;
  - each difference from the design, R6's retire rule and key cap included.
- [ ] Rewrite every plan line that names a placeholder with the merged name. That is a plan edit (`tasks-plans`), done here before any lane starts.
- [ ] Run `openspec validate oidc-provider --strict`. Expected: `Change 'oidc-provider' is valid`.

### Task 1.2: Confirm the conformance suite's facts by running it
- [ ] A Haiku agent clones `gitlab.com/openid/conformance-suite` at `a5b9635` or newer into the scratchpad, starts it with its `docker-compose.yml`, and reports:
  - that the plan and module names in P9 are those the running suite lists;
  - whether a self-signed `https` OP is accepted by the server side and by HtmlUnit;
  - the exact `scripts/run-test-plan.py` command line, with `--expected-failures-file`.
- [ ] The main session marks in P9 which facts a run confirmed, corrects any that differ, and fixes 14.1 and 14.2's commands to match. Run `openspec validate oidc-provider --strict`.

### Task 1.3: Align `session-signals` with R16
- [ ] Run `/opsx:update session-signals` for: one repeatable `WithEndObserver` over `EndObserver` with `EndObserverFunc`; `EndReport` carrying the upstream issuer and session; `DeleteByExternalSession` reported; `EnableSessionSignals` no longer refusing a manager with an observer; and `EndCause` here against its `EndReason`, as one type.
- [ ] Update its `plans.md` through `/superpowers:writing-plans`. Run `openspec validate session-signals --strict`. Expected: valid.

---

## Task group 2: token types and claims (lane T)

**Interfaces produced:**
- `const TypeFirstParty = "scrty+jwt"`, `TypeAccessToken = "at+jwt"`, `TypeIDToken = "JWT"`, `TypeLogoutToken = "logout+jwt"`
- `func WithTokenType(typ string) Option` and `func WithVerifyTokenType(typ string) VerifyOption`
- `type Issue struct { Type string; Subject string; ID string; Audience []string; Lifetime time.Duration; Claims map[string]any }`. A zero `Lifetime` takes the issuer's, and `Alg` is the issuer's own, so one issuer serves one algorithm. `Alg` is dropped from `Issue`.
- `func NewIssuer(keys signingkey.KeySource, alg signingkey.Alg, issuer string, opts ...Option) (*Issuer, error)`, and `func (i *Issuer) Issue(ctx context.Context, in Issue) (string, error)`. `Generator` gains no method (R6).
- `func (c *Claims) Audience() []string` and `func (c *Claims) Claim(name string) (any, bool)`. They expose the further claims a typed token carried, which `oidcprovider` reads at UserInfo and introspection.

### Task 2.1: `typ` on every first-party token
**Files:** Modify `token/config.go`, `token/generator.go`; Test `token/generator_tokentype_test.go`
- [ ] Red `TestGenerator_TokenType`, a table:
  - the default header `typ` is `scrty+jwt`;
  - `WithTokenType("app+jwt")` gives `app+jwt`;
  - `WithTokenType("at+jwt")`, `"JWT"`, `"logout+jwt"`, `""` and `"AT+JWT"` are each `errors.Is(err, ErrConfig)`.

  Add `WithTokenType` as a no-op first.
- [ ] `go test -run TestGenerator_TokenType -count=1 ./token/`: FAIL on the header value. Set the protected header with `jws.WithProtectedHeaders`, comparing reserved values case-insensitively. PASS. Commit `feat(token): declare typ on first-party tokens`.

### Task 2.2: `typ` enforced at verification
**Files:** Modify `token/verifier.go`, `token/config.go`; Test `token/verifier_tokentype_test.go`
- [ ] Red `TestVerifier_TokenType`, a table built with the existing helpers:
  - `typ` `scrty+jwt` passes, and `application/SCRTY+JWT` passes;
  - no `typ` fails with `ErrInvalid`;
  - `at+jwt` fails with `ErrInvalid`. This is the **token-type confusion red test**: the same keys, issuer and audience;
  - `JWT` fails with `ErrInvalid`;
  - `WithVerifyTokenType("at+jwt")` accepts `application/at+jwt` and refuses `scrty+jwt`;
  - `WithVerifyTokenType("")` fails with `ErrConfig`.

  The "no `typ`" and `at+jwt` rows fail today, because verification ignores `typ`.
- [ ] FAIL; read `typ` from the parsed protected header, then lower-case it and strip `application/`. A mismatch wraps `ErrInvalid`. PASS. Run the whole `./token/...` suite, because existing fixtures may lack `typ`, and update only fixtures built without the generator. Commit.

### Task 2.3: Typed issuance with further claims
**Files:** Create `token/issuer.go`; Modify `token/claims.go`; Test `token/issuer_test.go`
- [ ] Red `TestIssuer`:
  - `Issue{Type: TypeAccessToken, Subject: "u-1", ID: "j-1", Audience: []string{"https://api.example.com"}, Claims: {"client_id": "billing-web", "scope": "openid profile"}}` verifies through a `WithVerifyTokenType(TypeAccessToken)` verifier;
  - `Claims.Claim("client_id")` is `"billing-web"`, and `Audience()` is the one value;
  - `iss` is the issuer's;
  - an empty `Subject` matches `ErrNoSubject`;
  - a `Lifetime` past a `LifetimeReporter`'s window gives `ErrConfig`;
  - `Claims: {"iss": "x"}` gives `ErrConfig` and an empty string, and so do `sub`, `iat`, `exp` and `jti`;
  - an issuer built for `signingkey.ES256` over a key source holding it signs ES256.
- [ ] FAIL; implement. Extend the allow-list in `token/integration_test.go`, which `TestProductionSourceGuards` and `TestJOSEAllowListIsHonest` read, only for new jwx calls. PASS. Commit.

### Task 2.4: Chain refusal and docs
**Files:** Test `httpsec/bearer_tokentype_test.go`; Modify the package godoc in `token/claims.go`
- [ ] Red `TestBearer_RefusesOtherTokenTypes`. `EnableBearerToken` gets an ID token (`typ` `JWT`) and an access token (`at+jwt`), both from a `token.Issuer` over the chain's own keys and issuer. Each answers 401 and reaches the error handler as the uniform authentication failure.
- [ ] Run it. If it passes before 2.2's code, it is not testing the change, so drop 2.2's check temporarily to see it fail. Green comes from 2.2. Godoc names the default type. Run `go doc ./token WithTokenType`. Commit.

---

## Task group 3: session end observers (lane S)

**Interfaces produced:**
- `type EndCause uint8`, with the constants `EndReuse`, `EndFamilyRevoked`, `EndDeleted`, `EndUserSessions`, `EndUserSessionsExcept`, `EndExternalSession`, `EndUserExternalIssuer`, `EndByHandle` and `EndOtherSignIns`
- `type EndReport struct { Cause EndCause; User identity.UserID; Family id.ID; KeptFamily id.ID; ExternalIssuer, ExternalSessionID string; At time.Time }`
- `type EndObserver interface { SignInsEnded(ctx context.Context, r EndReport) }`, and `type EndObserverFunc func(ctx context.Context, r EndReport)`, which implements it (R16)
- `func WithEndObserver(o EndObserver) Option`, which may be given more than once
- `func (m *Sessions) ReportsEndsTo(o EndObserver) bool`

### Task 3.1: Construction and identity
**Files:** Create `session/end_observer.go`; Modify `session/sessions_options.go`; Test `session/end_observer_test.go`
- [ ] Red `TestSessions_EndObserverConstruction`: a nil observer gives `ErrConfig`, and a typed-nil pointer does too.
- [ ] Red `TestSessions_ReportsEndsTo`: a manager built with `o1` and `o2` answers true for both. A different value of the same type answers false. A manager with none answers false.
- [ ] Red row: a manager built with an `EndObserverFunc`, asked about another func, answers false and does not panic.
- [ ] FAIL (stub returns false); implement with `==` on interface values, guarded by `reflect.Value.Comparable`; PASS; commit.

### Task 3.2: Reporting after each explicit end
**Files:** Modify `session/sessions.go`, `session/reuse.go`; Test `session/end_observer_test.go`
- [ ] Red `TestSessions_EndObserver`. It is a table with a recording observer over a memory store and a fixed clock, one row per path:
  - reuse past the grace window (`LoadForRenewal`) → `EndReuse`, with family and user;
  - `RevokeFamily(f)` → `EndFamilyRevoked`;
  - `Delete(id)` → `EndDeleted`, with the family it read;
  - `DeleteByUser` → `EndUserSessions`;
  - `DeleteByUserExcept(u, keep)` → `KeptFamily`;
  - `DeleteByExternalSession(iss, sid)` → `EndExternalSession`, with both values;
  - `DeleteByUserAndExternalIssuer`;
  - `EndSignIn` → `EndByHandle`;
  - `EndOtherSignIns` → `EndOtherSignIns`.

  Every row asserts:
  - the report holds no string equal to any session identifier;
  - two observers are called in the order given;
  - a store mock failing the write calls no observer;
  - `DeleteExpired` calls none.
- [ ] FAIL. Implement:
  - `Delete` and `DeleteByUserExcept` load the session first, only when observers exist, to learn its family. A failed load does not block the deletion. `Delete` then reports no user and a nil family, since it holds only an identifier, and `DeleteByUserExcept` reports the user and a nil `KeptFamily`;
  - reports are sent after the store write returns nil.
- [ ] PASS with `-race`. Commit.
- [ ] Red rows on `TestSessions_EndObserver`: a caller's context cancelled before the report reaches the observer uncancelled, with its values kept (`context.WithoutCancel`); the first of two observers panicking leaves the second called and the end unchanged, with a log line carrying none of the report. FAIL; implement; PASS; commit.

### Task 3.3: Godoc
- [ ] Godoc on `WithEndObserver`, `EndReport` and `ReportsEndsTo`: what is reported, that expiry and sweeping never are, and that observers run synchronously and must not block. Run `go doc ./session WithEndObserver`. Commit.

---

## Task group 4: provider construction and clients (lane C)

**Interfaces produced:**
- **Errors:**
  - `var ErrConfig = errors.New("oidcprovider: invalid configuration")`;
  - `ErrClientNotFound`;
  - `ErrDependency`, wrapped by every store, key-source or fetch failure behind fixed text;
  - `ErrInvalidAuthorization`, `ErrUnknownHandle`, `ErrReauthenticate`, `ErrConsentMalformed` and `ErrForeignConsent`, which group 6 and 7.8 return and `httpsec` maps.
- **Construction:**
  - `type Deps struct { Issuer string; Clients []Client; Registry ClientRegistry; Keys signingkey.KeySource; Users identity.UserLoader; LoginURL, ConsentURL, LogoutURL, LoggedOutURL string }`. Exactly one of `Clients` and `Registry` is set;
  - `func New(d Deps, opts ...Option) (*Provider, error)`.
- **Options:** `WithLoopbackHTTPIssuer()`, `WithoutBrowserSessions()`, `WithLogoutConfirmation()`, `WithRequestBounds(RequestBounds)`, `WithPendingRequestLifetime(d)`, `WithCodeLifetime(d)`, `WithClientAssertionAudience(AudienceRule)`, `WithClientAssertionMaxLifetime(d)`, `WithClientKeysRefetchCooldown(d)`, `WithOutbound(*outbound.Client)`, `WithClock(clock.Clock)`, `WithLogger(*slog.Logger)`, `WithRandom(io.Reader)`.
- **Assertion audience:** `type AudienceRule uint8`, with `AudienceIssuerOnly` (zero, the default) and `AudienceIssuerOrTokenEndpoint`.
- **Client enums:**
  - `type ClientType uint8`: `Confidential`, `Public` (no zero value allowed);
  - `type ApplicationType uint8`: `Web` (zero, the default), `Native`;
  - `type AuthMethod string`: `ClientSecretBasic`, `ClientSecretPost`, `PrivateKeyJWT`, `AuthMethodNone`;
  - `type OfflineAccess uint8`: `OfflineAskOnce` (zero), `OfflinePreAuthorized`;
  - `type BindingRequirement uint8`: `BindingOptional` (zero), `BindingDPoP`, `BindingMTLS`;
  - `type GrantType string`: `GrantAuthorizationCode`, `GrantRefreshToken`;
  - `type PKCERequirement uint8`: `PKCERequired` (zero, the default), `PKCEOrNonce` (R1).
- **`type Client struct`**, field groups:
  - identity and kind: `ID`, `Name`, `Type`, `ApplicationType`, `AuthMethod`, `PKCE`, `Secret []byte`, `JWKS []byte`, `JWKSURI string`;
  - URIs: `RedirectURIs`, `PostLogoutRedirectURIs`, `BackChannelLogoutURI`;
  - scopes and audiences: `Scopes`, `Resources`, `DefaultAudience`, `ResourceIdentifier`, `GrantTypes`;
  - consent: `FirstParty`, `OfflineAccess`;
  - tokens: `IDTokenAlg`, `IDTokenLifetime`, `AccessTokenLifetime`, `OpaqueAccessTokens`, `RequireBinding`;
  - grants: `RefreshGrace`, `GrantIdleTimeout`, `GrantAbsoluteLifetime`, `DisableRotation`, `EndGrantsWithSignIn`, `KeepPublicWebGrantsPastSignIn` (R13);
  - `Metadata map[string]string`, owned by the consumer and returned unchanged.
- **Redirect matching:** `func (c Client) MatchRedirectURI(uri string) bool`.
- **Registry:**
  - `type ClientSecret struct { Digest []byte; ExpiresAt time.Time }`, and `type RegisteredClient struct { Client; Secrets []ClientSecret }`, at most two. `Secret` is nil once registered (R13);
  - `type ClientRegistry interface { Client(ctx context.Context, id string) (*RegisteredClient, error) }`;
  - `type ClientStore interface { ClientRegistry; Put(ctx context.Context, c Client) error; Delete(ctx context.Context, id string) error; GenerateSecret(ctx context.Context, clientID string) (string, error) }`. This is the durable registry's contract: `Put` validates as construction does, apart from the key-algorithm check, which then fails at issue as a dependency failure;
  - `type MemoryRegistry`, built by `NewMemoryRegistry(clients []Client) (*MemoryRegistry, error)`, which implements `ClientStore`.
- **Client authentication:**
  - `type ClientCredentials struct { Authorization string; Form url.Values }`;
  - `func (p *Provider) AuthenticateClient(ctx context.Context, c ClientCredentials) (*RegisteredClient, error)`, whose refusals are `*Error{Code: "invalid_client"}`, or `"invalid_request"` for two methods, two identifiers or a credential in the query (R11).
- **Protocol errors:** `type Error struct { Code string }`, with `Error()` returning `"oidcprovider: " + Code`. The codes are constants: `CodeInvalidRequest`, `CodeInvalidClient`, `CodeInvalidGrant`, `CodeUnauthorizedClient`, `CodeUnsupportedGrantType`, `CodeInvalidScope`, `CodeInvalidTarget`, `CodeAccessDenied`, `CodeUnsupportedResponseType`, `CodeLoginRequired`, `CodeConsentRequired`, `CodeUseDPoPNonce`, `CodeRequestNotSupported`, `CodeRequestURINotSupported`, `CodeInvalidToken`, `CodeInsufficientScope`, `CodeInvalidDPoPProof`.
- **Assertion identifiers (the store port, defined here and stored in group 5):** `type AssertionIDStore interface { Record(ctx context.Context, clientID, jti string, until time.Time) (bool, error) }`.

### Task 4.1: `New`
**Files:** Create `oidcprovider/doc.go`, `errors.go`, `provider.go`, `options.go`; Test `oidcprovider/provider_test.go`
- [ ] Red `TestNew_Construction`, a table. Each failure is `errors.Is(err, ErrConfig)` and names the field:
  - the issuer `https://id.example.com?x=1`, one with `#f`, `http://id.example.com`, and a relative one;
  - `http://127.0.0.1:8080` without the option is refused, and with `WithLoopbackHTTPIssuer()` it is built;
  - `http://id.example.com` with the option is refused, because it is not loopback;
  - an empty `LoginURL` and an empty `ConsentURL` (the error names `ConsentURL`) are refused, and so is a `LoginURL` on another host;
  - an empty `LoggedOutURL` or `LogoutURL` is refused, with logout enabled;
  - nil `Keys` is refused (R6);
  - a login, consent, logout or logged-out URL on another origin than the issuer is refused (R9): `https://login.example.com/` under `https://id.example.com`;
  - `WithPendingRequestLifetime(2*time.Hour)` and `0` are refused;
  - `WithCodeLifetime(15*time.Minute)` is refused;
  - `WithClientAssertionMaxLifetime(2*time.Hour)` is refused;
  - nil `Keys` and nil `Users` are refused, and so are both or neither of `Clients` and `Registry`;
  - the defaults read back through unexported accessors in `export_test.go`: 10 min, 60 s, 5 min and `AudienceIssuerOnly`.
- [ ] FAIL; implement; PASS; commit.

### Task 4.2: Client validation
**Files:** Create `oidcprovider/client.go`; Test `oidcprovider/client_test.go`
- [ ] Red `TestClient_Validation`, one row per `oidc-provider-clients` construction scenario plus the settings below. Each error names the client and the field:
  - a public client with `ClientSecretBasic`; a confidential client with `AuthMethodNone`; `AuthMethod: "client_secret_jwt"`;
  - a confidential client with no method gets `ClientSecretBasic`;
  - redirect URIs: `https://*.example.com/cb`, `https://rp.example.com/cb#x` and web `http://rp.example.com/cb` are refused, and native `http://127.0.0.1/cb` is accepted;
  - a post-logout `https://rp.example.com/*`, and a back-channel `http://rp.example.com/logout`, are refused;
  - duplicate `billing-web` is refused;
  - an `IDTokenAlg` the keys cannot produce is refused, under the rules below;
  - `OfflinePreAuthorized` on a web client, or on a native client that is not first-party, is refused;
  - `DisableRotation` on a public client, or on a confidential client with `BindingOptional`, is refused;
  - `RefreshGrace` of 10 min is refused;
  - an idle timeout of 60 days with an absolute lifetime of 30 days is refused;
  - defaults: `FirstParty` false, `GrantTypes` `[authorization_code]`, and the idle, absolute, grace, ID token and access token defaults;
  - a supplied `Secret` of 20 bytes is refused.
- [ ] **Algorithm rule:** when `Keys` implements `interface{ SupportedAlgs() []signingkey.Alg }`, `IDTokenAlg` must be listed. When it doesn't, only RS256 is accepted. This is fail-closed: the provider cannot confirm another algorithm.
- [ ] FAIL; implement `validate(c Client, algs []signingkey.Alg) (Client, error)`; PASS; commit.
- [ ] Red rows on `TestClient_Validation` (R1, R6, R11, R13): a public client with `PKCEOrNonce` refused; a private-use scheme with no period refused; `javascript:`, `data:`, `vbscript:` and `file:` refused for every client; a URI with user information refused; `http://[::1]/cb` accepted for native; an ID or access token lifetime past `LifetimeReporter`'s window refused; and a public web client's grants end with the sign-in unless `KeepPublicWebGrantsPastSignIn`. FAIL; implement; PASS; commit.

### Task 4.3: Redirect matching
**Files:** Create `oidcprovider/redirect.go`; Test `oidcprovider/redirect_test.go`
- [ ] Red `TestClient_MatchRedirectURI`, with these rows:
  - `/cb` against `/cb/` → false;
  - native `http://127.0.0.1/cb` against `http://127.0.0.1:51004/cb` → true;
  - the same against `:51004/other` → false;
  - web `https://rp.example.com/cb` against `:8443/cb` → false;
  - native `http://[::1]/cb` against `http://[::1]:5000/cb` → true;
  - native `http://localhost/cb` against `http://localhost:5000/cb` → false, because only loopback IP literals vary (RFC 8252 §7.3);
  - a query that differs → false.
- [ ] FAIL; implement. The relaxation applies only when `ApplicationType == Native`, the scheme is `http`, the host parses as a loopback `netip.Addr`, and everything but the port is byte-equal. PASS; commit.

### Task 4.4: Registry and secrets
**Files:** Create `oidcprovider/registry.go`; Test `oidcprovider/registry_test.go`
- [ ] Red `TestMemoryRegistry`:
  - a configured client is found;
  - an unknown one returns `ErrClientNotFound`;
  - a consumer `ClientRegistry` mock is used, and the memory default is never built.
- [ ] Red `TestRegistry_Secrets`:
  - `GenerateSecret` returns a 43-character base64url value (256 bits), and the registry then holds only `sha256(secret)`;
  - a second call replaces the digest;
  - an error's text never contains the secret or its hex digest;
  - comparison uses `subtle.ConstantTimeCompare` on digests.
- [ ] FAIL; implement; PASS; commit.
- [ ] Red rows on `TestRegistry_Secrets` (R13): either of two live secrets authenticates, an expired one does not, and a third is refused at registration. FAIL; implement; PASS; commit.
- [ ] Red `TestProvider_ClientFromRegistryValidated`: a consumer's `ClientRegistry` returning `https://*.example.com/cb` is treated as unknown, and one log line names the setting, not a secret. `validateClient(Client) error` is shared with construction. FAIL; implement; PASS; commit.

### Task 4.5: Secret-based client authentication
**Files:** Create `oidcprovider/clientauth.go`; Test `oidcprovider/clientauth_test.go`
- [ ] Red `TestAuthenticateClient`, a table. A right answer gives the client; every refusal is `*Error` with `invalid_client`:
  - Basic, right and wrong;
  - Basic with the secret `a+b/c` sent form-URL-encoded (`a%2Bb%2Fc`);
  - a secret containing `:`: the header's decoded text is split at the first `:` (Review Focus);
  - Basic that is not base64;
  - `client_secret_post`, right;
  - a Basic client sending its secret in the body;
  - Basic plus `client_assertion`;
  - a public client with only `client_id`;
  - a public client sending a secret;
  - an unknown client.
- [ ] FAIL; implement; PASS; commit.
- [ ] Red rows on `TestAuthenticateClient` (R11): Basic plus a `client_assertion`, and Basic naming `billing-web` with `client_id=crm-web` in the body, are each `invalid_request`, not `invalid_client`. FAIL; implement; PASS; commit.

### Task 4.6: `private_key_jwt`
**Files:** Create `oidcprovider/assertion.go`; Test `oidcprovider/assertion_test.go`
- [ ] Red `TestAuthenticateClient_PrivateKeyJWT`, with ES256 and RS256 client keys generated in the test:
  - valid → authenticated;
  - `aud` the token endpoint URL → refused;
  - with `AudienceIssuerOrTokenEndpoint` → authenticated;
  - `aud` `[issuer, "x"]` → refused;
  - `HS256` → refused;
  - `iss` ≠ `sub` → refused;
  - `exp` missing, past, or 10 min ahead → refused;
  - a replay (the second `Record` returns false) → refused;
  - a `jwks_uri` served by `httptest.NewTLSServer` through an `outbound.Client` trusting it → authenticated, and fetched once over two calls;
  - `jwks_uri` answering 500 → an error that is not `*Error`, with `errors.Is(err, ErrDependency)`;
  - `nbf` 60 s ahead → accepted, and 120 s ahead → refused.
- [ ] FAIL. Implement with jwx v4's `jwt.Parse` against the client's key set:
  - the key set is cached per client with the relying party's refetch cooldown;
  - `jti` is recorded through `AssertionIDStore.Record(ctx, clientID, jti, exp)` only after every other check passes.
- [ ] PASS; commit.
- [ ] Red rows on `TestAuthenticateClient_PrivateKeyJWT` (R13): `typ` absent, `client-authentication+jwt` and `JWT` accepted, and `at+jwt` refused; a new `kid` at `jwks_uri` refetches and authenticates; many assertions with an unknown `kid` within 30 s fetch at most once, and are `invalid_client`. Reuse the relying party's key-set cache. FAIL; implement; PASS; commit.

### Task 4.7: Godoc
- [ ] Package doc: what the provider is, its import direction (T1), and a wiring example. Every option names its default and bound. `go doc ./oidcprovider` and `go vet ./oidcprovider/` are clean. Commit.

---

## Task group 5: stores, in-memory defaults and suites (lane D)

**Interfaces produced** (all in `oidcprovider/store.go`; `var ErrNotFound = errors.New("oidcprovider: not found")`):
- **Pending requests:**
  - `type Stage uint8`: `StageLogin`, `StageConsent`, `StageLogout`, `StageDone`, where `StageLogout` parks an end-session request that must ask the user (R3);
  - `type PendingRequest struct`, field groups:
    - keys: `ID id.ID`, `HandleDigest []byte`, `FlowDigest []byte`;
    - the request: `ClientID`, `RedirectURI`, `Scopes`, `Resources`, `State`, `Nonce`, `Challenge`, `Prompt []string`, `MaxAge *int`, `IDTokenHintSubject`, `DPoPJKT`, `LoginHint`, `UILocales`, `ClaimsLocales`, `ACRValues`;
    - progress: `ParkedAt`, `ExpiresAt`, `Stage`, `SignIn *SignIn`.
  - `type PendingRequestStore interface { Create(ctx, *PendingRequest) error; Load(ctx context.Context, handleDigest []byte) (*PendingRequest, error); Advance(ctx context.Context, handleDigest []byte, from, to Stage, s *SignIn) error; DeleteExpired(ctx context.Context, before time.Time) (int, error) }`. `Advance` returns `ErrNotFound` unless the stored stage equals `from` and `to` is a strictly forward move: login to consent or done, consent to done, logout to done.
- **Sign-ins:** `type SignIn struct { User identity.UserID; Family id.ID; AuthenticatedAt time.Time; AMR []string; ACR string; AbsoluteExpiresAt time.Time; ExternalIssuer, ExternalSessionID string }`.
- **Code records:**
  - `type CodeRecord struct { TokenID id.ID; ClientID, RedirectURI, Challenge, Nonce, DPoPJKT string; Scopes, Resources []string; SignIn SignIn; GrantFamily id.ID; Offline, EndsWithSignIn bool; ExpiresAt time.Time }`. Issuing a code (6.7) sets `EndsWithSignIn` from the client. `SignIn` already holds the upstream issuer and session (R7);
  - `type CodeStore interface { Create(ctx, *CodeRecord) error; Load(ctx, tokenID id.ID) (*CodeRecord, error); DeleteExpired(ctx, before time.Time) (int, error) }`.
- **Consents:**
  - `type Consent struct { User identity.UserID; ClientID string; Scopes []string; Offline bool; LastGivenAt time.Time }`;
  - `type ConsentStore interface { Give(ctx, user identity.UserID, clientID string, scopes []string, offline bool, at time.Time) error; Load(ctx, user, clientID) (*Consent, error); Revoke(ctx, user, clientID) (bool, error); ListByUser(ctx, user) ([]Consent, error) }`.
- **Grants:**
  - `type RevocationCause string`: `CauseReuse`, `CauseCodeReplay`, `CauseSignInEnded`, `CauseConsentRevoked`, `CauseRevokedByClient`, `CauseUserDisabled`, `CauseRecovery`, `CauseMFAReset`, `CausePasskeyClone`, `CausePasswordChange`, `CauseUserRequest`;
  - `type Grant struct`, field groups:
    - who: `Family id.ID`, `User`, `ClientID`, `Scopes`, `Resources`;
    - authentication facts: `AuthTime`, `AMR`, `ACR`, `KeyBinding string`, `CodeID id.ID`;
    - the sign-in: `SignInFamily id.ID`, `ExternalIssuer`, `ExternalSessionID`, `Offline`, `EndsWithSignIn bool`, `HoldsLineage bool` (R10);
    - times: `CreatedAt`, `ExpiresAt`;
    - state: `Revoked bool`, `RevokedAt`, `RevokeCause`, `SignInEndedAt time.Time`.
  - `type SignInSelector struct { Family id.ID; User identity.UserID; ExceptFamily id.ID; ExternalIssuer, ExternalSessionID string }`. Exactly one shape is valid: the family; the user; the user and the excepted family; the upstream issuer and session; or the user and the upstream issuer.
  - `type GrantStore interface`:
    - `Create(ctx, *Grant) error`, which keeps `Revoked` when a tombstone exists;
    - `Load(ctx, family id.ID) (*Grant, error)`;
    - `Revoke(ctx, family id.ID, cause RevocationCause, at time.Time) error`, which upserts a tombstone;
    - `RevokeByUser(ctx, user, cause, at) ([]Grant, error)`, and
    - `RevokeByUserAndClient(ctx, user, clientID, cause, at) ([]Grant, error)`, each also writing a tombstone for each matching unspent code, `Offline` or not (R7);
    - `EndSignIns(ctx, sel SignInSelector, at time.Time) ([]Grant, error)`, which also writes a tombstone for the `GrantFamily` of each matching unspent code without `Offline`;
    - `DeleteExpired(ctx, now time.Time, keepRevoked time.Duration) (int, error)`;
- **Tombstones across the code and grant stores (R7).** The tombstones above span `CodeStore` and `GrantStore`, so `CodeStore` embeds `UnspentCodes`, with `UnspentBySignIn(ctx, sel, includeOffline, at)` and `UnspentByClient(ctx, user, clientID, at)`, and `oidcprovider.New` joins them through `GrantStore.UseCodes(UnspentCodes) error`. The grant store writes each tombstone itself, with the sign-in-ended mark when an end recorded it. A listing excluding offline codes still includes one with `EndsWithSignIn`. `EndSignIns` does not touch browser sessions. A store outage on either fails the call.
- **Browser sessions (R2):**
  - `type BrowserSession struct { Digest []byte; SignIn SignIn; IdleExpiresAt, AbsoluteExpiresAt time.Time }`;
  - `type BrowserSessionStore interface { Put(ctx, *BrowserSession) error; Load(ctx, digest []byte, now time.Time) (*BrowserSession, error); Touch(ctx, digest []byte, idleUntil time.Time) error; Delete(ctx, digest []byte) error; DeleteBySignIn(ctx, sel SignInSelector) (int, error); DeleteExpired(ctx, before time.Time) (int, error) }`.
- **Opaque access tokens:**
  - `type AccessTokenRecord struct { ID id.ID; Digest []byte; GrantFamily id.ID; ClientID string; User identity.UserID; Scopes, Audience []string; Confirmation map[string]string; IssuedAt, ExpiresAt time.Time; Revoked bool }`;
  - `type AccessTokenStore interface { Create; Load(ctx, id id.ID) (*AccessTokenRecord, error); Revoke(ctx, id id.ID) error; DeleteExpired }`.
- `AssertionIDStore`, from group 4, gains `DeleteExpired`.
- **Memory stores:** `NewMemoryPendingRequestStore()`, `NewMemoryCodeStore()`, `NewMemoryConsentStore()`, `NewMemoryGrantStore()`, `NewMemoryAccessTokenStore()`, `NewMemoryAssertionIDStore()`, `NewMemoryBrowserSessionStore()`, each with a clock option.
- **Store options:** `WithPendingRequestStore`, `WithCodeStore`, `WithCodeTokenStore(onetime.Store)`, `WithConsentStore`, `WithGrantStore`, `WithAccessTokenStore`, `WithAssertionIDStore`, `WithBrowserSessionStore`, `WithRefreshTokenStore(RefreshTokenStore)`.
- **The lineage store type:** `type RefreshTokenStore = oplineage.Store`, where `internal/oplineage.Store` has one unexported field. `func New(s session.Store) Store` is reachable only inside scrty's import path (T7).
- **Suites:** `storetest.PendingRequestSuite(t, newStore func(t) oidcprovider.PendingRequestStore)`, and the same shape for codes, consents, grants, access tokens and assertion identifiers. Race cases go in `storetest/race.go`.

### Task 5.1: Pending requests
**Files:** Create `oidcprovider/store.go`, `store_memory.go`, `test/storetest/oidcprovider_pending_suite.go`; Test `test/storetest/memory_test.go` (a new subtest)
- [ ] Red `PendingRequestSuite` cases:
  - create and load by digest;
  - a load by another digest → `ErrNotFound`;
  - `Advance(login→consent)` then `Advance(login→consent)` again → `ErrNotFound`;
  - `Advance(consent→done)` stores nothing new but the stage;
  - an expired record is still returned by `Load`, because expiry is the provider's to judge;
  - `DeleteExpired` removes only expired records;
  - the returned record is a copy.

  Wire it as `TestMemory/PendingRequests`.
- [ ] FAIL; implement the memory store under one mutex; PASS; commit.

### Task 5.2: Code records
- [ ] Red `CodeRecordSuite`: create, load, a missing record → `ErrNotFound`, `DeleteExpired`, and a copy on load. Run as `TestMemory/CodeRecords`. FAIL; implement; PASS; commit.
- [ ] Red row on the code suite: `UnspentBySignIn(ctx, sel, includeOffline)` returns the `GrantFamily` of each unspent matching record, by every selector shape, and leaves out `Offline` records unless asked. FAIL; implement; PASS; commit.

### Task 5.3: Consents
- [ ] Red `ConsentSuite`:
  - giving `openid profile` and then `openid email` gives `openid profile email`;
  - `Offline` stays true once given, and giving other scopes later does not clear it;
  - `LastGivenAt` moves;
  - `Revoke` → true, then false;
  - `ListByUser("u-1")` never returns `u-2`'s consents.

  Run as `TestMemory/Consents`. FAIL; implement; PASS; commit.

### Task 5.4: Grants
**Files:** `test/storetest/oidcprovider_grant_suite.go`
- [ ] Red `GrantSuite`:
  - create and load;
  - `Revoke(F)` before `Create(F)` → loads revoked (the H2 store guarantee), and `Create` returns nil;
  - `Revoke` twice is idempotent and keeps the first cause;
  - `RevokeByUser` returns the revoked grants, offline grants included;
  - `RevokeByUserAndClient` touches one client only;
  - `EndSignIns`, for each selector shape:
    - with an online and an offline grant from `s-1`: the online one is revoked, both are marked, and both are returned;
    - a second identical call returns none;
    - `EndsWithSignIn` revokes the offline grant too;
    - `ExceptFamily` leaves that family's grants untouched;
    - an upstream issuer and session match only grants that recorded them;
  - an invalid selector shape → `ErrConfig`;
  - `DeleteExpired` keeps a revoked grant until `keepRevoked` passes;
- [ ] FAIL; implement; PASS; commit.
- [ ] Red rows on the grant suite (R7, R10): `EndSignIns` for a sign-in with an unspent code leaves that code's `GrantFamily` revoked, and a later `Create` keeps it revoked; an `Offline` code survives `EndSignIns` and not `RevokeByUser`. FAIL; implement; PASS; commit.

### Task 5.5: The lineage store type
**Files:** Create `internal/oplineage/oplineage.go`, `oidcprovider/lineage.go`; Test `oidcprovider/lineage_test.go`
- [ ] Red `TestRefreshTokenStore`:
  - the zero `RefreshTokenStore` given to `WithRefreshTokenStore` → `ErrConfig`;
  - with no option, the provider uses a private memory store that is not the sign-in store a test also builds: an identifier created through one is `ErrNotFound` through the other.
- [ ] Add `oidcprovider/example_lineage_test.go`, behind the build tag `//go:build oplineage_negative`. It shows that `oidcprovider.RefreshTokenStore{}` cannot be filled from outside, and the test asserts that `go vet -tags oplineage_negative` fails with "cannot refer to unexported field" (run through `os/exec` in the test, and skipped when `go` is not on `PATH`).
- [ ] FAIL; implement; PASS; commit.

### Task 5.6: Opaque access tokens and assertion identifiers
- [ ] Red `AccessTokenSuite`: create, load, `Revoke`, `DeleteExpired`, and records holding only `Digest`.
- [ ] Red `AssertionIDSuite`: `Record` → true, then false for the same client and `jti`; the same `jti` for another client → true; after `DeleteExpired` past `until`, `Record` → true.
- [ ] Run as `TestMemory/AccessTokens` and `TestMemory/AssertionIDs`. FAIL; implement; PASS; commit.

### Task 5.7: Race suite
**Files:** Modify `test/storetest/race.go`, `broken_race_test.go`
- [ ] Red race cases, each run with 32 goroutines behind a start barrier:
  - `Advance(login→consent)` succeeds exactly once;
  - `onetime.Store.Consume` of one code succeeds exactly once (already pinned, so it is only wired here for the provider's purpose);
  - `AssertionIDStore.Record` returns true exactly once;
  - `Create(F)` racing `Revoke(F)` always ends revoked;
  - `EndSignIns(s-1)` from two goroutines returns each grant once in total.
- [ ] A broken store (`broken_race_test.go`: an `Advance` that reads, then writes) must fail its case, which proves the suite catches it.
- [ ] Run `go test -race -run 'TestMemory|TestRace|TestBroken' ./storetest/` in `test/`. Commit.
- [ ] Red row (R7): `EndSignIns` racing `Create` for a code's `GrantFamily`, from many goroutines, always ends with the grant revoked, or the suite fails, shown against a deliberately broken store. FAIL; implement; PASS; commit.

### Task 5.8: Browser sessions (R2)
**Files:** Create in `oidcprovider/store.go` and `test/storetest/oidcprovider_browsersessions.go`
- [ ] Red `BrowserSessionSuite`: `Load` by digest; refused past `IdleExpiresAt` or `AbsoluteExpiresAt` at the caller's time; `Touch` never moves the idle deadline past the absolute one; `Put` under a new digest with a `Delete` of the old replaces; `DeleteBySignIn` by each selector shape; `DeleteExpired` keeps unexpired rows; no secret is held in clear.
- [ ] Run `go test -run 'TestMemory/BrowserSessions' ./storetest/` in the `test` module: FAIL on the assertion against a stub. Implement the memory store. PASS. Commit.

---

## Task group 6: authorization and consent (lane A)

**Interfaces produced:**
- `func (p *Provider) Authorize(ctx context.Context, in AuthorizeInput) (AuthorizeResult, error)`, with `AuthorizeInput{Params url.Values; FlowSecret, BrowserSessionSecret string; IdleTimeout time.Duration}`, the last filled by H1 from the chain's manager, and which prints redacted as `AuthorizeResult` does
  - `type AuthorizeResult struct { Location string; FlowSecret string }`. `FlowSecret` is empty unless the request was parked.
  - The error is `ErrInvalidAuthorization` (the client or redirect URI is unredirectable) or a dependency failure. Every redirectable error comes back as a `Location` carrying `error`.
- `func (p *Provider) PendingRequest(ctx context.Context, handle, flowSecret string) (*PendingView, error)`
  - `type PendingView struct { ClientID, ClientName string; Scopes, GrantedScopes []string; Prompt []string; MaxAge *int; LoginHint string; UILocales, ClaimsLocales, ACRValues []string; Stage Stage }`. `GrantedScopes` is everything the user has given that client
- `func (p *Provider) Resume(ctx context.Context, in ResumeInput) (ResumeResult, error)`, with `ResumeInput` and `ResumeResult` as built in `oidcprovider/resume.go`. Both print redacted. H1 fills `IdleTimeout` from the chain's manager
  - `type ConsentAnswer struct { Deny bool; Scopes []string }`. It is nil at the login stage.
  - It returns `redirect_to`. The errors are `ErrUnknownHandle`, `ErrReauthenticate`, `ErrConsentMalformed` or a dependency failure.
- `func consentNeeded(c *RegisteredClient, req *PendingRequest, remembered *Consent) bool`, unexported and table-tested.

### Task 6.1: Request validation
**Files:** Create `oidcprovider/authorize.go`; Test `oidcprovider/authorize_test.go`
- [ ] Red `TestValidateAuthorizationRequest`, a table over `url.Values`. The `assert` closure checks either the error, or `Location`'s query (`error`, `state`, `iss`, and no `error_description`). The rows are every `oidc-provider-authorization` scenario, plus:
  - `scope` given twice;
  - `prompt=none login`;
  - a missing `response_type`, `response_mode=form_post` and `max_age=-1` → `invalid_request`;
  - `display=popup` and `prompt=create` proceed, and are not errors;
  - a repeated `client_id` or `redirect_uri` → unredirectable;
  - `state=` counts as omitted;
  - a `state` of 1 MiB → `invalid_request`, without that `state`;
  - a confidential `PKCEOrNonce` client: `nonce` and no challenge proceeds, neither is `invalid_request`;
  - `offline_access` from a client with no refresh grant is dropped;
  - `dpop_jkt` with `dpopEnabled` false → `invalid_request` (R12);
  - an `id_token_hint`: an access token → `invalid_request`; an unpublished `kid` → no hint, or `login_required` with `prompt=none` (R6);
  - `code_challenge` of 42 characters;
  - `code_challenge_method` missing (it is not defaulted to `plain`, so it is refused);
  - `resource=https://api.example.com#x`;
  - `request_uri` given, with an `outbound` mock expecting no call;
  - an `id_token_hint` signed by another key → `invalid_request`;
  - an expired hint from this provider → accepted;
  - the Review Focus rows: `scope=openid  openid profile` is accepted with scopes `[openid profile]`; a 5 KiB `state` → `invalid_request` and nothing parked; 11 `resource` values → `invalid_request`; a `state` of `a&b=c #d` comes back exact on an error redirect; a redirect URI with `?tenant=a` keeps `tenant=a`.
- [ ] FAIL. Implement `validate(ctx, params) (*PendingRequest, *RegisteredClient, error)` in this order: client and redirect URI, then the remaining checks in `oidc-provider-authorization`'s order. The hint is verified with jwx against `Keys.VerificationKeys`, with `typ` `JWT`, `iss` the issuer, and `jwt.WithValidate(false)` for expiry only, then the signature checked. PASS; commit.

### Task 6.2: Parking
**Files:** Create `oidcprovider/pending.go`; Test `oidcprovider/pending_test.go`
- [ ] Red `TestProvider_Park`:
  - `Authorize` with valid params gives a 303 target equal to the login URL with `req=rh.…`;
  - the store holds no string equal to the handle or the flow secret, only their SHA-256;
  - the handle's secret part decodes to at least 16 bytes, and the flow secret to 32;
  - with a fixed clock, a resume at 10 min 1 s → `ErrUnknownHandle`;
  - with `WithPendingRequestLifetime(5*time.Minute)`, one at 6 min → `ErrUnknownHandle`.
- [ ] FAIL; implement; PASS; commit.
- [ ] Red rows on `TestProvider_Park` (R9): `Authorize` given a flow secret of the shape the provider mints keeps it, and returns it as the `FlowSecret`; two requests parked with it both resume, each with its own `state` and `nonce`. FAIL; implement; PASS; commit.

### Task 6.3: The page view
- [ ] Red `TestProvider_PendingRequest`:
  - with the right flow secret, the view holds the client name and scopes;
  - a `reflect` walk of `PendingView` finds no field holding the challenge, nonce, state or redirect URI values;
  - a wrong flow secret → `ErrUnknownHandle`;
  - `login_hint=ada@example.com` comes back with the user loader mock expecting no call.
- [ ] FAIL; implement; PASS; commit.

### Task 6.4: Whether consent is needed
**Files:** Create `oidcprovider/consent.go`; Test `oidcprovider/consent_test.go`
- [ ] Red `TestConsentNeeded`, one row per `oidc-provider-consent` decision scenario:
  - first time → true;
  - covered → false;
  - a new scope → true;
  - `prompt=consent` → true, even for a first-party client;
  - first-party with ordinary scopes → false;
  - first-party with `offline_access` → true;
  - remembered `Offline` → false;
  - other consent only, asked for `offline_access` → true;
  - pre-authorized native → false.
- [ ] FAIL; implement; PASS; commit.

### Task 6.5: Resuming the login stage
**Files:** Create `oidcprovider/resume.go`; Test `oidcprovider/resume_test.go`
- [ ] Red `TestProvider_ResumeLogin`:
  - another flow secret → `ErrUnknownHandle`, and nothing is issued;
  - a second resume of the stage → `ErrUnknownHandle`;
  - `max_age=300` with `AuthenticatedAt` 20 min ago → `ErrReauthenticate`, and the handle still resumes after re-authentication;
  - `prompt=login` with `AuthenticatedAt` before `ParkedAt` → `ErrReauthenticate`, even when the session was renewed after parking;
  - `max_age=0` behaves as `login`;
  - a hint for `u-1` with a sign-in of `u-2` → a `Location` with `error=login_required`;
  - a principal with an empty identifier fails matching `token.ErrNoSubject`, and no code is issued (R6);
  - consent needed → the consent URL with the same handle;
  - not needed → the redirect URI with `code`, `state` and `iss`.
- [ ] FAIL; implement. Freshness is checked before `Advance`, so a refusal spends nothing. PASS; commit.
- [ ] Red row: a resume that succeeds returns a `BrowserSessionSecret` on its result, and only the digest is stored, replacing any session whose secret it was given. It takes `AbsoluteExpiresAt` from the sign-in, and the manager's `IdleTimeout()` for its idle deadline. FAIL; implement; PASS; commit.

### Task 6.6: Resuming the consent stage
- [ ] Red `TestProvider_ResumeConsent`:
  - a partial grant of `openid profile` from `openid profile email` gives a code record with `[openid profile]`;
  - a denial gives `error=access_denied`, `state` and `iss`, and `ConsentStore.Load` → `ErrNotFound`;
  - `u-2` resuming a stage `u-1` began → `ErrUnknownHandle`, and no code is issued;
  - granting `admin` → `ErrConsentMalformed`, and the stage still resumes;
  - dropping `openid` while it was requested → `ErrConsentMalformed`;
  - a grant accumulates in `ConsentStore`, and `Offline` is set only when `offline_access` was granted here.
- [ ] FAIL; implement; PASS; commit.
- [ ] Red rows: a consent answer with no sign-in and a valid browser session is taken for that session's user; another user's session is refused; a second answer on a spent stage is refused as an unknown handle, and no second code exists. FAIL; implement; PASS; commit.

### Task 6.7: Issuing codes
**Files:** Create `oidcprovider/code.go`; Test `oidcprovider/code_test.go`
- [ ] Red `TestProvider_IssueCode`:
  - the code is an `onetime` string of purpose `oidc-provider.code`, issued unbound;
  - the `CodeRecord` holds every binding, a fresh `GrantFamily`, and `ExpiresAt` = issue time + 60 s;
  - with `WithCodeLifetime(5*time.Minute)`, it is + 5 min;
  - the Review Focus row: a redirect URI `https://rp.example.com/cb?tenant=a` and a `state` of `a&b=c #d` give a `Location` that parses with `tenant=a`, the exact `state`, `code` and `iss`.
- [ ] FAIL; implement. Godoc covers `Authorize`, `PendingRequest`, `Resume` and the view's guarantees. PASS; commit.
### Task 6.8: Answering from the browser session (R2)
**Files:** Create `oidcprovider/browsersession.go`; Test `oidcprovider/browsersession_test.go`
**Interfaces:** Consumes `BrowserSessionStore` (5.8). Produces `type AuthorizeInput struct { Params url.Values; FlowSecret, BrowserSessionSecret string }`, which `Authorize` takes in place of its parameters.
- [ ] Red `TestProvider_BrowserSession`, a table, with the two named cases first:
  - **after a first login, `prompt=none` issues a code with the same `auth_time`, `amr`, `acr` and `sid`;**
  - **after the sign-in ended, `prompt=none` answers `login_required`;**
  - no `prompt`, valid session, consent not needed → `Location` with `code`, and `Touch` called;
  - consent needed, no `prompt` → `Location` at the consent URL; `prompt=none` → `consent_required`;
  - `prompt=login`, `max_age=0` or an unmet `max_age` → the login URL; with `prompt=none` → `login_required`;
  - a hint for the session's user proceeds, another's → `login_required`;
  - a missing or disabled user counts as no session;
  - `WithoutBrowserSessions`: `prompt=none` → `login_required` always.
- [ ] Run `go test -run 'TestProvider_BrowserSession' -count=1 ./oidcprovider/`: FAIL on the assertions against a stub. Implement. PASS. Commit.

---

## Task group 7: grants and tokens (lane G)

**Interfaces produced:**
- **Token requests:**
  - `type Binding struct { JKT string; X5T string }`, filled by `httpsec` after verifying the DPoP proof or the certificate;
  - `type TokenRequest struct { Credentials ClientCredentials; Form url.Values; Query url.Values; Binding Binding }`. A credential in `Query` is `invalid_request`;
  - `type TokenResponse struct { AccessToken, TokenType string; ExpiresIn int; Scope, IDToken, RefreshToken string }`;
  - `func (p *Provider) Token(ctx context.Context, r TokenRequest) (*TokenResponse, error)`, whose errors are `*Error` or a dependency failure.
- **Revocation and introspection:**
  - `func (p *Provider) Revoke(ctx context.Context, c ClientCredentials, form url.Values) error`;
  - `func (p *Provider) Introspect(ctx context.Context, c ClientCredentials, form url.Values) (map[string]any, error)`.
- **Access tokens and UserInfo:**
  - `type AccessToken struct { Subject identity.UserID; ClientID string; Scopes, Audience []string; Confirmation map[string]string; Opaque bool; GrantFamily id.ID }`;
  - `func (p *Provider) VerifyAccessToken(ctx context.Context, token string) (*AccessToken, error)`;
  - `type ClaimSource interface { Claims(ctx context.Context, user identity.UserID, scopes []string) (map[string]any, error) }`, set with `WithClaimSource`;
  - `func (p *Provider) UserInfo(ctx context.Context, at *AccessToken) (map[string]any, error)`.
- **Ending grants:**
  - `func (p *Provider) EndSignIn(ctx context.Context, sel SignInSelector) error`;
  - `func (p *Provider) SignInsEnded(ctx context.Context, r session.EndReport)`, which implements `session.EndObserver`;
  - `func (p *Provider) RevokeUserGrants(ctx context.Context, user identity.UserID, cause RevocationCause) error`;
  - `func (p *Provider) Consents(ctx context.Context, user identity.UserID) ([]ConsentView, error)`;
  - `func (p *Provider) RevokeConsent(ctx context.Context, user identity.UserID, clientID string) error`.
- **Back-channel delivery:** `type LogoutDelivery interface { Deliver(ctx context.Context, uri string, logoutToken string) error }`, set with `WithLogoutDelivery`. The default posts through the outbound client with a 5 s timeout.
- **Events:** `WithEventSink(<D13 sink type, per 1.1>)`.

### Task 7.1: Code exchange
**Files:** Create `oidcprovider/exchange.go`; Test `oidcprovider/exchange_test.go`
- [ ] Red, first: **H3** `TestProvider_ExchangeCode/auth_time_is_the_sign-in's`. A sign-in authenticated at 10:00, and an exchange at 10:04 on a fixed clock, give `Grant.AuthTime == 10:00` and an ID token `auth_time` of 10:00. Run it, record the output, and label it `REPRODUCED` or `UNREPRODUCED` in the task report.
- [ ] Red, the rest of `TestProvider_ExchangeCode`:
  - a wrong secret → `invalid_client`, and the code still exchanges;
  - client `b` with `a`'s code → `invalid_grant`, and then `a` → `invalid_grant`;
  - a wrong verifier, a missing verifier, another `redirect_uri`, or a `dpop_jkt` mismatch → `invalid_grant`, and the code still exchanges;
  - 61 s after issue → `invalid_grant`;
  - success writes `Grant` before the lineage (T9), asserted with an ordered mock;
  - an online grant from a sign-in with 12 h left gets `ExpiresAt` at that deadline;
  - a client with no refresh grant gets no `RefreshToken`.
- [ ] FAIL; implement in T2's order; PASS; commit.
- [ ] Red rows on `TestProvider_ExchangeCode`, H5 first (R7): a code outstanding when `EndSignIn` runs → `invalid_grant`, and an `Offline` code survives it; a code outstanding when `RevokeUserGrants` runs → `invalid_grant`, `Offline` included; a disabled user → `invalid_grant`. Then: a `code_verifier` of 16 characters whose hash matches → `invalid_grant`; a `code_verifier` for a code with no challenge → `invalid_grant` (R1); a client without the refresh grant gets a row with `HoldsLineage` false, expiring at the sign-in's deadline (R10). FAIL; implement; PASS; commit.
- [ ] The write order is T9's: the grant row, then the lineage, with no cross-store transaction.

### Task 7.2: Code replay (H2)
- [ ] Red, first: **H2** `TestProvider_CodeReplay/racing_commit`. A barrier `GrantStore` wrapper blocks the first exchange's `Create` until the replay has returned. Afterwards `Load(F).Revoked` is true, and a refresh with the first response's token → `invalid_grant`. Record the red output and its label.
- [ ] Red `after_exchange`: a replay → `invalid_grant`, then the refresh token → `invalid_grant`.
- [ ] Red `concurrent`: 16 goroutines exchanging one code get exactly one success.
- [ ] FAIL; implement. A replay (onetime reports the code consumed) calls `GrantStore.Revoke(record.GrantFamily, CauseCodeReplay)` and the lineage manager's `RevokeFamily`. Revoking opaque tokens is handled by their grant check in 7.4. Run with `go test -race`: PASS. Commit.
- [ ] Red rows on `TestProvider_CodeReplay` (R17), each seen failing first:
  - `invalid_replay`, as a table of a wrong verifier, no verifier, and another client: `invalid_grant`, and `Load(F).Revoked` stays false. The earlier row saying another client's replay revokes is replaced by this one;
  - `valid_within_the_minute`: 30 s past the code's expiry, after another issue has run the default stores' sweeps, a valid replay gets `invalid_grant` and `Load(F).Revoked` is true;
  - `valid_past_the_minute`: 2 min past expiry, after a sweep, a valid replay gets `invalid_grant` and `Load(F).Revoked` stays false;
  - `consumer_store_retains`: code stores that keep the spent code past the minute revoke on a later valid replay;
  - `end_reaches_exchange_in_flight`: a code spent, `Create` held at a barrier, the clock 61 s on, another issue sweeps, `EndSignIns` runs, `Create` released: the grant ends revoked.
- [ ] Red rows on `TestProvider_ExchangeCode`:
  - a store failure during the spend, and a transient failure of the read after it, for the owner and for another client: `oidcprovider: dependency failure`, with the cause wrapped, and no `invalid_grant`;
  - a caller hanging up at the check and at the spend: the error matches `context.Canceled`, and no ERROR line is logged, including from `token/onetime`.
- [ ] A spend or check failure wraps the fixed `errCodeStoreUnanswered`, or `ctx.Err()` when the caller has gone, and not the store's own error, which `token/onetime` keeps to itself and logs at ERROR. A failure of the read after it wraps the real error.
- [ ] FAIL; implement:
  - `refuseSpentCode` revokes only when `record.ClientID == rc.ID` and `codeBindingsHold` passes; once the secret matches, an unspent and unexpired token is a dependency failure carrying `ctx.Err()` when the caller has gone;
  - the default stores keep a code a minute past its expiry, through one constant, `codeKeptPastExpiry`. `MemoryCodeStore.Create` sweeps at `now.Add(-codeKeptPastExpiry)`. `DeleteExpiredBefore`'s argument is a cutoff on when a token was *issued*, and it removes only what has also expired by the store's clock, so moving the cutoff keeps nothing past expiry: the default token store's inner `MemoryStore` reads a clock lagging by that minute, which it reads only when sweeping;
  - `token/onetime` logs a store failure the caller caused below ERROR, through `internal/hangup.ByCaller`.

  Run with `go test -race`: PASS. Commit.
- [ ] **Task 7.2 stays unticked until 7.5** adds the refresh-refused assertions to `racing_commit` and `after_exchange`. Tick 7.1 when this lane merges.

### Task 7.3: ID tokens
**Files:** Create `oidcprovider/idtoken.go`
- [ ] Red `TestProvider_IDToken`:
  - header `typ` `JWT`, `alg` RS256;
  - claims `iss`, `sub` (`u-1`), `aud` `[billing-web]`, `azp`, `iat`, and `exp` = `iat` + 300;
  - `auth_time`;
  - `nonce` `n-1`;
  - `amr` `["pwd","otp"]` from a password and TOTP sign-in;
  - `sid` equal to the sign-in family's text, and the same after the sign-in renews;
  - an ES256 client signs with ES256;
  - `IDTokenLifetime` of 10 min gives 600.
- [ ] Red row (R18): a key source failing at signing answers a dependency failure, with the code unspent, no grant row and no lineage, and the same request then succeeds. Mint before `tokens.Consume`, for `record.GrantFamily`.
- [ ] Red row (R6): a chain reading usernames does not change `sub`, which is `Grant.User`. FAIL; implement through `token.Issuer`, one per algorithm the keys hold, built in `New`; PASS; commit.

### Task 7.4: Access tokens
**Files:** Create `oidcprovider/accesstoken.go`
- [ ] Red `TestProvider_AccessToken`:
  - `typ` `at+jwt`, `client_id`, `scope`, and `exp` = `iat` + 300;
  - audience rules: the default audience, plus the issuer when the scope holds `openid` (R4); a `resource` within the allowlist and the grant; a `resource` outside either → `invalid_target`, including one the client is allowed that the code did not grant (R15); a refresh may ask for another of the grant's resources; none configured → the issuer;
  - `gid` equal to the grant's family (R4);
  - `AccessTokenLifetime` of 15 min;
  - `cnf.jkt` when `Binding.JKT` is set;
  - an opaque client gets `at.<id>.<secret>`, stored as a digest, and `VerifyAccessToken` refuses it once its grant is revoked;
  - `VerifyAccessToken` on an ID token or an `rt.` value → `invalid_token`;
  - `VerifyAccessToken` on a token whose grant row is gone → refused as revoked, because a revoked row is swept while a token set to a longer lifetime can outlive it;
  - a `resource` outside the allowlist or the grant, at the exchange → `invalid_target` with the code unspent, judged before the spend beside `codeBindingsHold` (R18);
  - a code granted one resource, `openid` in scope, exchanged with none named → `aud` is exactly that resource, with no issuer (R15);
  - a code granted several, exchanged with none named → `invalid_target`, the code unspent, and the same code naming one succeeds (R15);
  - a code granted none → the default audience with the issuer for `openid`, else the issuer alone; `AllowedResources` is never a default.
- [ ] FAIL; implement; PASS; commit.

### Task 7.5: Refresh
**Files:** Create `oidcprovider/refresh.go`
- [ ] Red, first: **H4** `TestProvider_Refresh/missing_lineage_reads_revoked`. A grant row is live and its lineage is deleted directly → `invalid_grant`, with no panic and no write. Record the label.
- [ ] Red, the rest of `TestProvider_Refresh`, a table:
  - `rt.bad` → `invalid_grant`, with mocks expecting no store call;
  - another client's token → `invalid_grant`, and the owner's still works;
  - a revoked grant → `invalid_grant`;
  - a `DPoP` binding mismatch → `invalid_dpop_proof`, and the token still works with `k1`;
  - a disabled user (`Details.Active == false`) or a missing one → `invalid_grant`, and `Load(F).Revoked`;
  - scope narrowed to `openid profile` → that scope;
  - `openid admin` → `invalid_scope`;
  - rotation gives a new `rt.`;
  - the old token 10 s later → tokens, with the grant live;
  - with a client grace of 2 min, the old token at 90 s → tokens;
  - the old token after the grace window → `invalid_grant`, `r2` → `invalid_grant`, and the reuse event emitted;
  - `DisableRotation` returns no new token, and the same one works again;
  - an idle grant at 31 days, and one refreshed daily at 90 days → `invalid_grant`;
  - a client absolute lifetime of 7 days ends at 7 days;
  - the refreshed ID token keeps `auth_time`, `sub` and `aud`, with no `nonce`.
- [ ] Red, the Review Focus row `TestProvider_Refresh/two_tabs_within_grace`: two concurrent refreshes with `r1` both succeed under `-race`, and the grant stays live.
- [ ] FAIL. Implement over a private `session.Sessions`, built per request because a registry's clients change over time (R13), with:
  - the lineage store;
  - `WithIdleTimeout` and `WithAbsoluteTimeout` per client, applied through `WithAbsoluteLifetime` at creation;
  - a `WithReuseObserver` that calls `GrantStore.Revoke(F, CauseReuse)`.

  `WithUnusedSuccessorRecovery` is never passed. Use `RotateWithGraceIssuing` with the client's grace. PASS with `-race`; commit.
- [ ] Red rows on `TestProvider_Refresh` (R20):
  - `two_tabs_same_successor`: a raced pair, and a pair 1 s apart, both answered the same `r2`, one head left, and `r2` then refreshes with the grant live;
  - `diverged_holders_are_caught`: `r2` rotated to `r3`, the grace passed, and `r2` presented: revoked with cause `reuse`;
  - `another_key_re_rotates`: `r1` re-presented to a provider with another key inside the grace receives tokens, and the grant is not revoked;
  - `no_key_no_successor`: nothing but the provider can compute `r2`: a successor derived under another key is refused, and writes nothing.
- [ ] FAIL; implement `func WithRefreshSuccessorKey(key []byte) Option` (at least 32 bytes, else `ErrConfig`; the default is 32 random bytes drawn once in `New`) and `HMAC-SHA256(key, family, presented secret)`, through the per-request manager's `WithRandom` or `oidcprovider`'s own read of the stored successor digest. Replace the rows pinning the old behaviour, including `two_tabs_the_token_knocked_out_is_reuse`, and `doc.go`'s sentence on it.
- [ ] Red rows on `TestProvider_Refresh`, H6 first (R8): `rt.<real family>.<never issued>` → `invalid_grant`, with no write of any kind, and the real token still works. An omitted `scope` means the grant's; scopes the client has lost are left out and reported, and regained later when allowed again; a removed client → `invalid_client`. FAIL; implement; PASS; commit.

### Task 7.6: Revocation and introspection
**Files:** Create `oidcprovider/revoke.go`
- [ ] Red `TestProvider_Revoke`:
  - a refresh token → nil, and every token of the grant → `invalid_grant`;
  - an opaque token → that token is inactive;
  - a JWT access token, an unknown value, or an expired token → nil, with nothing revoked;
  - client `b` with `a`'s refresh token → `invalid_grant`, and `a`'s still works;
  - `token_type_hint` of `access_token` on a refresh token still revokes it.
- [ ] Red `TestProvider_Introspect`:
  - no credentials → `invalid_client`;
  - `b` on `a`'s token → `{"active": false}` exactly;
  - a resource server whose `ResourceIdentifier` is in the token's `aud` → active;
  - an active opaque token by its holder → `active`, `scope`, `client_id`, `sub`, `exp`, `iat`, `iss`, `aud`, `token_type` and `cnf` when bound;
  - revoked or expired tokens → `{"active": false}`.
- [ ] FAIL; implement; PASS; commit.
- [ ] Red rows (R8, R13, R4): a public client revokes by `client_id`; a real family with a forged secret answers success and revokes nothing; a superseded secret at `Revoke` ends the grant, and at `Introspect` answers inactive, neither counting as a reuse; a public client at `Introspect` → `invalid_client`; a JWT whose `gid` is revoked → inactive. FAIL; implement; PASS; commit.

### Task 7.7: UserInfo
**Files:** Create `oidcprovider/userinfo.go`, `claims.go`
- [ ] Red `TestProvider_UserInfo`:
  - `openid profile` for a user named "Ada" → `{"sub", "name", "preferred_username"}`, with no `email`;
  - `openid email` with the default source → `{"sub"}` only, because `identity.Details` has no email field;
  - a consumer source releasing `department` for `org` → returned unchanged;
  - a token without `openid` → `insufficient_scope`;
  - a disabled user → `invalid_token`;
  - a source error → a dependency failure, not `*Error`;
  - an audience without the issuer → `invalid_token`, whose grant is live or not (R4);
  - a JWT of a revoked grant → `invalid_token` (R4).
- [ ] FAIL; implement; PASS; commit.

### Task 7.8: Ending grants
**Files:** Create `oidcprovider/endsignin.go`
- [ ] Red `TestProvider_EndSignIn`:
  - `SignInsEnded` chooses its `SignInSelector` from the report's fields, not by listing causes, so a cause added later cannot silently stop ending grants: a family selects that family, a user with a `KeptFamily` the user except it, a user with an issuer that pair, an issuer with an upstream session that pair, and a user alone the whole user. So `EndDeleted` selects the family, and `EndUserSessionsExcept` or `EndOtherSignIns` with a nil `KeptFamily` select the whole user. A row asserts an unknown cause naming a family still ends it;
  - a report naming nobody ends nothing and is logged;
  - the online grant is revoked and the offline one survives;
  - an `EndsWithSignIn` client loses both;
  - the clients returned are queued for delivery, once each;
  - a grant-store error from `SignInsEnded` is logged once at ERROR and reported as an event, and nothing panics;
  - `EndSignIn` returns the same error.
- [ ] Red `TestProvider_RevokeUserGrants`: every grant of `u-1` is revoked with the cause, and `RevokeConsent` revokes only `(u-1, billing-web)` grants and forgets the consent.
- [ ] FAIL; implement; PASS; commit.
- [ ] Red row (R2): `EndSignIn` by each selector also deletes the browser sessions, through `DeleteBySignIn`, and a failure there fails the call. FAIL; implement; PASS; commit.

### Task 7.9: Logout tokens and delivery
**Files:** Create `oidcprovider/backchannel.go`
- [ ] Red `TestProvider_LogoutToken`:
  - `typ` `logout+jwt`;
  - claims `aud` the client, and `exp` − `iat` ≤ 120;
  - `events` `{"http://schemas.openid.net/event/backchannel-logout": {}}`;
  - `sub`, `sid`, no `nonce`, and the client's ID token algorithm.
- [ ] Red `TestProvider_BackChannelDelivery`:
  - an `httptest.NewTLSServer` receives one form POST with `logout_token`;
  - a server that never answers: `EndSignIn` returns within 50 ms, and the delivery times out after 5 s on a fake clock;
  - a 500 answer → logged and reported, with no retry;
  - a consumer `LogoutDelivery` receives the URI and token instead.
- [ ] FAIL. Deliver on a goroutine with `context.WithoutCancel` and a 5 s timeout, tracked by a `sync.WaitGroup` that `(*Provider).Close(ctx)` waits on. PASS with `-race`; commit.
- [ ] Red rows on `TestProvider_LogoutToken`: `events` is exactly `{"http://schemas.openid.net/event/backchannel-logout":{}}`, and `sid` equals the ID tokens'.
- [ ] Red rows on `TestProvider_BackChannelDelivery` (`-race`, R14): a 302 is not followed and is reported as failed; 204 is a success; with 8 workers and a queue of 1024 a further delivery is dropped and reported; a delivery ending its goroutine is replaced, with the pool's size unchanged; `Shutdown` drains until its context ends, and reports what it leaves; a store or fetch cut off by `Shutdown` is not reported as a failure; a cancelled caller's context still delivers. FAIL; implement; PASS; commit.
- [ ] `Provider` gains `Start(ctx) error` and `Shutdown(ctx) error`, following `signingkey`'s pattern. `EnableOIDCProvider`'s godoc names them.

### Task 7.10: Events and redaction
**Files:** Create `oidcprovider/events.go`
- [ ] Red `TestProvider_Events`: a recording sink sees one event per outcome in `security-events`. Reuse yields two events, the reuse and the revocation for reuse. With no sink, a code replay is still refused and still revokes.
- [ ] Red `TestProvider_NoSecretsInLogs`: run the full happy path and every refusal with a `slog` handler that captures everything. The captured text, the events and every `err.Error()` contain none of the code, handle, flow secret, refresh token, access token, ID token, client secret or assertion.
- [ ] FAIL; implement; PASS; commit.

---

## Task group 8: chain wiring, authorize and resume (lane H1)

**Interfaces produced:**
- `func EnableOIDCProvider(p *oidcprovider.Provider, opts ...OIDCProviderOption) Option`, and `func WithOIDCPagesCarryFrameAncestors() OIDCProviderOption`, the consumer's statement (R11)
- `func WithOIDCProviderPrefix(prefix string) OIDCProviderOption` and `func WithOIDCProviderPath(endpoint OIDCEndpoint, path string) OIDCProviderOption`
  - `type OIDCEndpoint uint8`: `OIDCAuthorize`, `OIDCResume`, `OIDCToken`, `OIDCUserInfo`, `OIDCRevoke`, `OIDCIntrospect`, `OIDCEndSession`, `OIDCLogoutConfirm`, `OIDCConsents`
- `func PendingOIDCRequest(ctx context.Context, p *oidcprovider.Provider, r Request, handle string) (*oidcprovider.PendingView, error)`
- `var ErrOIDCInvalidAuthorization, ErrOIDCUnknownHandle, ErrOIDCConsentMalformed` (400), `ErrOIDCReauthenticate` (401) and `ErrOIDCForeignConsent` (404). Each wraps its `oidcprovider` counterpart.

### Task 8.1: Construction
**Files:** Create `httpsec/oidc_provider.go`, `oidc_provider_options.go`; Test `httpsec/oidc_provider_test.go`
- [ ] Red `TestOIDCProvider_Construction`, a table. Each failure is `ErrConfig` and names `EnableOIDCProvider`:
  - form login and no bearer mode;
  - no `EnableJWKSEndpoint`;
  - enabled twice;
  - the end-session path set to the chain's logout path;
  - two provider paths equal;
  - a session manager on the chain (bearer, renewal or logout deps) without `session.WithEndObserver(p)`, checked in a `c.wire` step so an observer added during wiring counts;
  - a client with `RequireBinding: BindingDPoP` and no `EnableDPoP`;
  - `(*Provider).DPoPEnabled()` differing from whether `EnableDPoP` is on → `ErrConfig` naming `WithDPoP`;
  - `(*Provider).AssertionTokenEndpoint()` not empty and differing from the chain's token URL, after the prefix and path options → `ErrConfig` naming `WithAssertionTokenEndpoint`;
  - `EnableJWKSEndpoint` given a `*signingkey.Keys` for which `(*Provider).SignsWith` answers false → `ErrConfig`, and a consumer's wrapped provider of any other type, which cannot be compared → built, as the godoc says;
  - a provider-only chain (`EnableSessionBearer`, `EnableJWKSEndpoint`, `EnableOIDCProvider`, `EnableDPoP`) → built, because the provider adds `"EnableOIDCProvider"` to `bindingVerifiers` (`httpsec/options.go`).
- [ ] FAIL; implement; PASS; commit.
- [ ] Red rows on `TestOIDCProvider_Construction` (R2, R11): browser sessions on without CSRF protection refused; `WithoutBrowserSessions` without it built; no security headers refused; `WithOIDCPagesCarryFrameAncestors` without them built. FAIL; implement; PASS; commit.

### Task 8.2: Routes
- [ ] Red `TestOIDCProvider_Routes`:
  - `/api/orders` passes through to `next`;
  - `POST /oauth2/token` reaches the token handler (a stub at this point);
  - with `WithOIDCProviderPrefix("/op")`, `/op/token` is reached and `/oauth2/token` passes through;
  - a per-path override moves one endpoint.
- [ ] FAIL; implement; PASS; commit.

### Task 8.3: Status table
**Files:** Modify `httpsec/errors.go`; Test `httpsec/errors_test.go`
- [ ] Red rows in `TestStatusForError`:
  - 400: `ErrOIDCInvalidAuthorization`, `ErrOIDCUnknownHandle` and `ErrOIDCConsentMalformed`;
  - 401: `ErrOIDCReauthenticate`;
  - 404: `ErrOIDCForeignConsent`;
  - 500: an `oidcprovider` dependency failure, with the body empty under no error handler.
- [ ] FAIL; add the rows; PASS; commit.

### Task 8.4: The authorization endpoint
**Files:** Create `httpsec/oidc_authorize.go`; Test `httpsec/oidc_authorize_test.go`
- [ ] Red `TestOIDCAuthorize`:
  - GET valid → 303 to the login URL, with `Set-Cookie: __Host-scrty-op-flow=…; Path=/; Secure; HttpOnly; SameSite=Lax`;
  - form POST valid → 303;
  - an unregistered redirect URI → no `Location`, the error handler receives `ErrOIDCInvalidAuthorization`, and a consumer handler writing HTML shows its page;
  - a missing scope → 303 with `error=invalid_request`;
  - a POST form with a repeated parameter → `invalid_request`;
  - past the source throttle's limit → refused before validation (a provider mock expecting no call).
- [ ] FAIL; implement; PASS; commit.
- [ ] Red rows on `TestOIDCAuthorize` (R2, R9, R11): an existing flow cookie is kept; two parked requests in one cookie jar both resume; a valid session cookie gives a 303 with `code`; the loopback issuer sets `scrty-op-flow`, not `Secure`; a 303 carries `Cache-Control: no-store`; `Secure()` false is refused and nothing parks. FAIL; implement; PASS; commit.

### Task 8.5: The resume endpoint
**Files:** Create `httpsec/oidc_resume.go`
- [ ] Red `TestOIDCResume`:
  - `POST {"req": h}` with `Authorization: Bearer <session ref>` and the cookie → 200 `{"redirect_to": …}`, with `Cache-Control: no-store` and no `Location`;
  - no `Authorization` → 401 unauthenticated;
  - the session reference only in a cookie or the query → 401;
  - no flow cookie → 400 `ErrOIDCUnknownHandle`;
  - a session owing a second factor → the same refusal `EnableMFA` gives, and the handle resumes afterwards;
  - stale for `max_age` → `ErrOIDCReauthenticate` at 401;
  - a consent body `{"req": h, "scopes": ["openid"]}` and a `{"req": h, "deny": true}` body;
  - unknown handles past the throttle's limit → refused before lookup;
  - a JWT bearer sign-in (`EnableBearerToken`) resumes too, its session loaded by `jti`.

  `SignIn` is built from the loaded session: `AMR` from `internal/assurance` as the relying-party path computes it, `ExternalIssuer` and `ExternalSessionID` from the session's external fields.
- [ ] FAIL; implement; PASS; commit.
- [ ] Red rows on `TestOIDCResume` (R2, R6, R12): an API key and Basic credentials → unauthenticated, handle unspent; a session only a late renewal may recover → refused; a bound sign-in with no proof → the chain's refusal, handle unspent; a credential in the query → unauthenticated; a successful login stage sets `__Host-scrty-op-session`; a consent answer with only the session cookie is accepted, and with CSRF's cross-site headers refused. FAIL; implement; PASS; commit.

### Task 8.6: Reading a pending request
- [ ] Red `TestOIDCPendingRequest`: the flow cookie is read from the `Request`. Without it → `ErrOIDCUnknownHandle`. FAIL; implement; PASS; commit.

### Task 8.7: Docs
- [ ] Godoc on `EnableOIDCProvider`, naming the defaults (prefix, paths, cookie) and the construction rules.
- [ ] The README gets an "OpenID Provider" section:
  - the wiring sketch with `session.WithEndObserver(op)`;
  - the login and consent pages: on the issuer's origin, `fetch` the resume with the `Authorization` header, then `window.location = redirect_to`, or a server-rendered form resuming through the Go API;
  - a login finished in another browser, such as a magic link opened elsewhere, must restart from the relying party (R9);
  - `frame-ancestors` for pages served outside the chain;
  - the browser session: what it does, what it does not see, and what `WithoutBrowserSessions` gives up, Basic OP included (R2).
- [ ] `go vet ./...`. Commit.

---

## Task group 9: token-side endpoints (lane H2)

### Task 9.1: The token endpoint
**Files:** Create `httpsec/oidc_token.go`; Test `httpsec/oidc_token_test.go`
- [ ] Red `TestOIDCToken`:
  - GET → 405 with no token;
  - `grant_type=password` → 400 `{"error":"unsupported_grant_type"}`;
  - an unregistered refresh grant → `unauthorized_client`;
  - a repeated `code` → `invalid_request`;
  - a wrong Basic secret → 401, `WWW-Authenticate: Basic realm="oauth2"`, `{"error":"invalid_client"}`;
  - an expired code → 400 `{"error":"invalid_grant"}`, exactly that body;
  - success → 200 JSON with the five fields, and `Cache-Control: no-store` and `Pragma: no-cache` on every response;
  - wrong secrets past the throttle's limit → refused before the secret is checked.
- [ ] FAIL; implement; PASS; commit.
- [ ] Red rows on `TestOIDCToken` (R11): `client_secret` in a POST's query → 400 `invalid_request`; an empty parameter counts as omitted; `Secure()` false is refused. FAIL; implement; PASS; commit.

### Task 9.2: Binding at the token endpoint

**Where the check lives:** `RequireBinding` is enforced in `Provider.Token`, before the spend and before a rotation, and not only in `httpsec`, so a direct caller of `Provider.Token` cannot get a Bearer token for a client that requires binding.
- [ ] Red `TestOIDCToken_SenderConstrained`:
  - a public client with a `k1` proof → `cnf.jkt(k1)` and `token_type` `DPoP`, and a refresh with a `k2` proof → `invalid_dpop_proof`;
  - a proof with another `htu` → 400 `invalid_dpop_proof`, and the code still exchanges;
  - a confidential client refreshing with `k2` → success, with `cnf.jkt(k2)`;
  - a `RequireBinding: BindingDPoP` client without a proof → `invalid_dpop_proof`, and the code is unspent;
  - `dpop_jkt(k1)` exchanged with `k2` → `invalid_grant`;
  - a TLS client certificate `C` with no proof → `cnf["x5t#S256"]` of `C`.
- [ ] FAIL; implement by calling `issuingBinding(ctx, ex.dpop(), ex.certBinding(), ex.Request, ex.bearerCredential)` before `p.Token`, and mapping its `session.KeyBinding{JKT, X5TS256}` to `Binding{JKT, X5T}`; PASS; commit.
- [ ] Red rows on `TestOIDCToken_SenderConstrained` (R12): nonces on and a proof with none → 400 `{"error":"use_dpop_nonce"}` with `DPoP-Nonce` and `no-store`, and the same code exchanges with that nonce; a proof and a certificate → `cnf.jkt` alone; a refresh of a bound public grant → `token_type` `DPoP`; a confidential client refreshing with no proof → `Bearer`, and a required one refused; a `DPoP` header while DPoP is off → ignored, `Bearer`. FAIL; implement; PASS; commit.

### Task 9.3: Revocation and introspection endpoints
**Files:** Create `httpsec/oidc_revoke.go`
- [ ] Red `TestOIDCRevoke` and `TestOIDCIntrospect`: the HTTP forms of 7.6's rows, plus the protocol bodies and `no-store`. FAIL; implement; PASS; commit.

### Task 9.4: UserInfo
**Files:** Create `httpsec/oidc_userinfo.go`
- [ ] Red `TestOIDCUserInfo`:
  - GET with a header → 200;
  - a POST body `access_token` → 200;
  - `?access_token=` → 401 with `WWW-Authenticate: Bearer` and no `error`;
  - expired → 401 with `Bearer error="invalid_token"`;
  - no `openid` → 403 with `error="insufficient_scope"`;
  - a bound token sent as `Bearer` → 401 with a `DPoP` challenge;
  - a bound token with a valid proof and `ath` → 200;
  - a claim-source error → 500 with an empty body;
  - every response carries `no-store`.
- [ ] FAIL; implement; PASS; commit.
- [ ] Red rows on `TestOIDCUserInfo`: nonces on → 401 with `WWW-Authenticate: DPoP error="use_dpop_nonce"` (R12); `Secure()` false is refused (R11). FAIL; implement; PASS; commit.

### Task 9.5: A refresh token is never a sign-in
- [ ] Red `TestRefreshToken_NotASignIn`. An `rt.…` value is refused as an unknown credential at each of:
  - `EnableSessionBearer`;
  - `EnableSessionRenewal`;
  - `EnableBearerToken`.

  The session store mock asserts no `Load` call for the `EnableSessionBearer` case.
- [ ] It may pass at once, because `session.ValidIdentifier` already refuses the value. Then invert temporarily: let the bearer accept any identifier and see the test fail, as `golang-tdd.md` asks. Commit.

### Task 9.6: CORS
- [ ] Red `TestCORS_OIDCProvider`:
  - a preflight from an allowed origin to `/oauth2/token` is allowed;
  - a cross-origin GET to `/oauth2/authorize` from an allowed origin carries no `Access-Control-*` header;
  - the same holds for `/oauth2/logout`.
- [ ] FAIL; implement as a provider-registered exclusion in `cors.go` (a path set read at construction); PASS; commit.
- [ ] Red rows on `TestCORS_OIDCProvider`: a preflight for `DPoP` is allowed; `DPoP-Nonce` and `WWW-Authenticate` are exposed; no credentials are allowed; `/authorize/resume` and `/logout/confirm` never carry CORS headers. FAIL; implement; PASS; commit.

---

## Task group 10: metadata (lane H3)

### Task 10.1: Building the documents
**Files:** Create `httpsec/oidc_metadata.go`; Test `httpsec/oidc_metadata_test.go`
- [ ] Red `TestOIDCMetadata`, decoding JSON:
  - `issuer` exact; `token_endpoint` `https://id.example.com/oauth2/token`;
  - `response_types_supported` `["code"]`; `response_modes_supported` `["query"]`; `grant_types_supported`; `subject_types_supported` `["public"]`; `code_challenge_methods_supported` `["S256"]`;
  - `id_token_signing_alg_values_supported` includes `RS256`;
  - `token_endpoint_auth_methods_supported` lists the four methods;
  - `request_parameter_supported`, `request_uri_parameter_supported` and `claims_parameter_supported` are false;
  - `authorization_response_iss_parameter_supported`, `backchannel_logout_supported` and `backchannel_logout_session_supported` are true;
  - `jwks_uri` names the chain's JWKS URL;
  - with DPoP on ES256, `dpop_signing_alg_values_supported` is `["ES256"]`, and without it the member is absent;
  - the certificate member appears only when binding is enabled;
  - an issuer `https://example.com/id` serves `/id/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server/id`;
  - a consumer `service_documentation` is published, and a consumer `token_endpoint` → `ErrConfig`.
- [ ] FAIL; implement; PASS; commit.
- [ ] Red rows on `TestOIDCMetadata` (R11): `end_session_endpoint` with logout on; `revocation_endpoint_auth_methods_supported` and `introspection_endpoint_auth_methods_supported`, the latter without `none`; `token_endpoint_auth_signing_alg_values_supported` without `none`, once a client may use `private_key_jwt`; `offline_access` in `scopes_supported` when any client may ask for it. FAIL; implement; PASS; commit.

### Task 10.2: Serving the documents
- [ ] Red `TestOIDCMetadata_Serving`:
  - an unauthenticated GET → 200 with `Cache-Control: public, max-age=3600`;
  - `WithOIDCMetadataCacheLifetime(5*time.Minute)` → `max-age=300`;
  - after `signingkey.Keys` rotates, `/.well-known/jwks.json` still lists the previous `kid`.
- [ ] FAIL; implement; PASS; commit.

---

## Task group 11: logout, consents and revocation (lane H4)

### Task 11.1: The end-session endpoint (R3)
**Files:** Create `httpsec/oidc_endsession.go`; Test `httpsec/oidc_endsession_test.go`
- [ ] Red `TestOIDCEndSession`, a table:
  - a hint naming the browser session's sign-in, expired included → `p.EndSignIn({Family: sid})` then `sessions.RevokeFamily`, and a 303 to the logged-out page. `session-signals` changes that call to `Logout(ctx, user, family)` at its rebase, as `Logout` is on its branch and this change merges first;
  - with a registered `post_logout_redirect_uri` and `state=s-1` → 303 there with `state=s-1`; no `state` → none added; an unregistered URI, or one with a query added → the logged-out page, the sign-in still ended;
  - `WithLogoutConfirmation` → 303 to the logout page with a handle, nothing ended;
  - no hint, a hint with an unpublished `kid`, or a valid hint for another sign-in → the same, with `StageLogout` parked;
  - `client_id` with a registered URI and no hint → never that URI;
  - a forged hint, a hint whose audience is not `client_id`, and an access token as a hint → chain 400 with no `Location`, nothing ended;
  - `logout_hint` accepted and not acted on;
  - GET and form POST behave alike.
- [ ] Run `go test -run 'TestOIDCEndSession' -count=1 ./httpsec/`: FAIL on the assertions. Implement. PASS. Commit.

### Task 11.8: The logout confirmation (R3)
**Files:** Create `httpsec/oidc_logout_confirm.go`; Test `httpsec/oidc_logout_confirm_test.go`
**Interfaces:** Produces `func (p *Provider) ConfirmLogout(ctx, handle, flowSecret, browserSessionSecret string, confirmed bool) (*LogoutResult, error)`, with `type LogoutResult struct { RedirectTo string; Ended *SignInSelector }`.
- [ ] Red `TestOIDCLogoutConfirm`, a table:
  - a confirmation with a browser session ends that sign-in, and answers 200 with `redirect_to` and `no-store`;
  - a hint for another sign-in, confirmed → the browser's sign-in ends, and the hint's does not;
  - a hint in a browser with no session, confirmed → nothing ends, no error;
  - `WithoutBrowserSessions`, a valid hint, confirmed → the hint's sign-in ends;
  - declined → nothing ends;
  - no flow cookie, or a spent handle → `ErrOIDCUnknownHandle`;
  - a cross-site POST with CSRF on → refused.
- [ ] Run `go test -run 'TestOIDCLogoutConfirm' -count=1 ./httpsec/`: FAIL on the assertions. Implement. PASS. Commit.

### Task 11.2: The chain's logout comes first
**Files:** Modify `httpsec/logout.go`
- [ ] Red `TestLogout_EndsProviderGrants`:
  - a logout → 200, and the online grant is revoked;
  - a grant-store mock failing → 500, the session still loads, and a retry after the store recovers → 200;
  - a delivery failure → 200.
- [ ] FAIL; call `p.EndSignIn` before deleting; PASS; commit.

### Task 11.3: Other ends reach the provider
- [ ] Red `TestOIDCProvider_SignInEnds`, a table:
  - reuse of a superseded session identifier past its window;
  - D12's end-others;
  - passkey removal ending other sessions;
  - `sessions.DeleteByUser` called directly.

  Each row: the online grant ends, and `billing-web` receives one logout token. A grant-store failure leaves the sessions ended, logs, and emits the event. A sign-in reaching its idle deadline sends nothing.
- [ ] It passes once 3.2 and 7.8 are in. To prove it, remove `WithEndObserver` from the fixture and see the reuse row fail. Commit.
- [ ] Red rows on `TestOIDCProvider_SignInEnds`: `EndSignIn` reaches the provider; each end also ends the sign-in's browser session, so `prompt=none` then answers `login_required` (R2). FAIL; implement; PASS; commit.

### Task 11.4: Upstream back-channel logout
**Files:** Modify the relying-party back-channel handler in `httpsec`
- [ ] Red `TestOIDCBackchannel_EndsProviderGrants`:
  - a verified upstream token ending `s-1` → the online grant is revoked and `billing-web` notified;
  - the offline grant survives;
  - the upstream response bytes are identical to the response without the provider.
- [ ] FAIL. The handler goes through `sessions.DeleteByExternalSession`, whose end report reaches the provider (T3, T4). PASS; commit.

### Task 11.5: `/consents`
**Files:** Create `httpsec/oidc_consents.go`
- [ ] Red `TestOIDCConsents`:
  - GET → `[{client_id, client_name, scopes, offline_access, last_given_at}]` for the caller only;
  - `DELETE /oauth2/consents/billing-web` → 204, the next authorization shows consent, and the refresh tokens → `invalid_grant`;
  - another user's (`?user=` ignored; only the caller's identity counts) → `ErrOIDCForeignConsent` at 404, when the client was never consented by the caller;
  - a cross-site POST with CSRF on → refused.
- [ ] FAIL; implement; PASS; commit.

### Task 11.6: Revocation on security events (T8)
**Files:** Modify `recovery/hold.go`, `authenticate/mfa/reset.go`, `httpsec/password_change.go`, `httpsec/session_management.go`, the passkey assertion path in `httpsec`
- [ ] Ports, each declared in its own package: `interface{ RevokeUserGrants(ctx context.Context, user identity.UserID, cause oidcprovider.RevocationCause) error }`. The cause is a string type, so the packages take a `string` alias to avoid importing `oidcprovider`. Options:
  - `recovery`: `WithGrantRevoker(r)` and `WithoutRecoveryGrantRevocation()`;
  - `mfa`: `ResetDeps.Grants` and `WithoutResetGrantRevocation()`;
  - `httpsec`: `WithPasswordChangeGrantRevocation()` (off by default), `WithoutPasskeyCloneGrantRevocation()`, and the session-management body field `"revoke_application_access": true`.
- [ ] Red:
  - `TestRecoverer_RevokesGrants`: revoked, offline grants included; the keep option keeps them; a revoker error is returned; with no revoker, the behaviour is unchanged;
  - `TestResetEnrolment_RevokesGrants`: revoked after the removals; a failure is returned after them; the keep option keeps grants while sessions still end;
  - `TestPasskey_CloneRevokesGrants`: a clone suspension revokes, and removing one's own passkey does not;
  - `TestPasswordChange_RevokesGrants`: the default keeps grants; with the option, the grants are revoked before the password write (an ordered mock), and a revoker failure → 500 with the password unchanged;
  - `TestSessionManagement_RevokeApplicationAccess`: with the choice, every grant ends and the current sign-in is kept; without it, the offline grants survive.
- [ ] FAIL; implement; PASS; commit.

### Task 11.7: CSRF exemptions and docs
- [ ] Red `TestCSRF_OIDCProviderExemptions`:
  - cross-site POSTs to authorize, token, revoke, introspect and logout are not refused by CSRF;
  - cross-site POSTs to resume, `/logout/confirm` and `/consents` are refused, a consent answer with the victim's handle included;
  - each exempt endpoint still runs the throttle.
- [ ] FAIL; register the exemptions from `EnableOIDCProvider`, each the exact method and path `WithCSRFExemption(method, pattern)` takes, on the chain's CSRF layer; PASS.
- [ ] Godoc and README: logout, consents, and the four event options with their defaults. Commit.

---

## Task group 12: durable stores, migration, sweeping (lane P)

### Task 12.1: The migration
**Files:** Create `store/migrate/securitystate/20261103000000_oidc_provider.sql`, `internal/pgschema/oidcprovider.go`; Test `test/migrate_securitystate_test.go`
- [ ] Tables: `op_clients`, `op_pending_requests`, `op_authorization_codes`, `op_consents`, `op_grants`, `op_refresh_tokens` (the `sessions` schema), `op_access_tokens`, `op_client_assertions` and `op_browser_sessions`.
- [ ] Indexes on `op_grants`: `(user_ref)`, `(user_ref, client_id)`, `(sign_in_family)` and `(external_issuer, external_session_id)`. Unique `(client_id, jti)` on assertions. Unique `handle_digest` on pending requests.
- [ ] Red `TestMigrations/oidc_provider`:
  - applied over a database holding sessions → the tables exist and the session rows are unchanged;
  - rolled back → exactly those nine are gone.

  Run against PostgreSQL 15 and 18.
- [ ] FAIL; write the migration; PASS; commit.
- [ ] The ninth table is `op_browser_sessions`. Add indexes for browser sessions and unspent code records by user, by sign-in and by upstream session, and a `holds_lineage` column on `op_grants`, not null, defaulting to true (R2, R7, R10).

### Tasks 12.2–12.4: The three adapters (parallel worktrees, one per adapter)
**Files per adapter `<a>` ∈ {sqlstore, pgxstore, gormstore}:** Create `store/<a>/oidcprovider_stores.go`, `store/<a>/oidcprovider_lineage.go`; Test `test/<a>/oidcprovider_test.go`
- [ ] Constructors: `New{PendingRequest,Code,Consent,Grant,AccessToken,AssertionID,Client}Store(db, opts...)` and `NewRefreshTokenStore(db, c seal.Cipher, opts...) (oidcprovider.RefreshTokenStore, error)`. The last builds the adapter's session store bound to `op_refresh_tokens` through `internal/pgschema`, with no exported table option, and wraps it with `internal/oplineage.New`.
- [ ] Red: wire every `storetest` suite and race case (`TestSQLStore/…`, `TestPgxStore/…`, `TestGormStore/…`). The first adapter's dispatch also writes `storetest.ClientStoreSuite`: put and load, a secret stored only as a digest, `GenerateSecret` replacing it, and `Delete`. It runs against `MemoryRegistry` too. Add:
  - `lineage_not_a_session`: an identifier created through the lineage store → `ErrNotFound` from the adapter's `NewSessionStore`;
  - `no_credential_in_any_column`: `SELECT *` from every `op_` table after an issue, compared against the code, refresh token and client secret.
- [ ] Conditional writes:
  - `Advance` checks the move, then is `UPDATE … WHERE stage = $from`;
  - `Grant.Create` is `INSERT … ON CONFLICT (family) DO UPDATE SET … , revoked = op_grants.revoked OR EXCLUDED.revoked WHERE <the row is a tombstone>`, and no row affected is the refusal the suite requires, keeping any sign-in-ended mark;
  - `Revoke` is `INSERT … ON CONFLICT DO UPDATE SET revoked = true` (the first cause kept);
  - `EndSignIns`, `RevokeByUser` and `RevokeByUserAndClient` are `pgschema.GrantBulkWrite`: a Hold in ascending `family` order, then a Write over the set it took;
  - `pgxstore` and `gormstore` reuse `internal/pgschema`'s statements, row types and encodings, and wire `storetest.RunGrantOrderRaces` and `ClientStoreSuite`;
  - `AssertionID.Record` is `INSERT … ON CONFLICT DO NOTHING`, with a row count of 1 meaning new.
- [ ] Run `go test -race -run 'Test<Adapter>Store' ./<a>/...` in `test/` against PostgreSQL 15 and 18: PASS. Commit per adapter.
- [ ] Each adapter also implements `BrowserSessionStore` and `CodeStore.UnspentBySignIn`, driven by the suites.

### Task 12.5: Expiry tasks
**Files:** Create `oidcprovider/expiry.go`; Test `test/expirytasks_test.go`
- [ ] `func ExpiryTasks(p *Provider) []expiry.Task`, with these task names:
  - `oidc-provider.pending-requests`, `oidc-provider.codes` (the onetime purge plus the code records), `oidc-provider.access-tokens` and `oidc-provider.assertion-ids`;
  - `oidc-provider.codes`, sweeping a record only one minute past its expiry, so an exchange in flight keeps what an end needs. The onetime purge must keep the code's token as long (R17). `DeleteExpiredBefore`'s argument is a cutoff on when a token was issued, so a durable purge passes `now - maxCodeLifetime - 1 minute`, not `now - 1 minute`: the maximum, as `keepRevoked` uses, so that lowering the configured lifetime in a redeploy cannot purge a code in flight early. Spent tokens then stay up to 11 minutes, which is harmless, since a replay whose record has gone revokes nothing. Prove it on each backend with a replay inside the minute after the task has run;
  - `oidc-provider.grants`, with `keepRevoked` one minute past the longest code lifetime, as the memory store keeps it, so a code spent as it expires cannot land after its tombstone is swept;
  - `oidc-provider.refresh-tokens` (the lineage `DeleteExpired`);
- [ ] Red `TestExpiryTasks_OIDCProvider`:
  - after the clock passes, each task deletes only expired rows;
  - a revoked grant survives until the code lifetime passes;
  - there is no orphan task, and a grant whose lineage went idle stays stored, its client told when the sign-in ends, on each durable backend and the memory defaults (R19).
- [ ] FAIL; implement; PASS; commit.
- [ ] Add browser sessions to the task list.
- [ ] Remove the orphan pass (R19): `GrantStore.DeleteOrphans`, its memory implementation and `orphanable`, each adapter's, `pgschema.GrantOrphanCandidates`, `GrantOrphanDelete`, `GrantOrphanPage` and their tests, the suite rows, and the row in `exchange_test.go` that relied on it. `Grant.HoldsLineage` and its column stay, as H4's rule reads them. Regenerate the `GrantStore` mock. A lineage that cannot be written still answers a dependency failure, and that row then asserts the grant is kept and refused at refresh once 7.5 lands.

### Task 12.6: Durable round trip (lane X)
- [ ] Red `TestOIDCProvider_Durable`, per backend: authorize → resume → exchange. Then build a second `Provider` over the same database (a restart) and refresh with the first's refresh token. Then revoke. Every step succeeds. FAIL until wired; PASS; commit.

---

## Task group 13: framework adapters (lane X)

### Task 13.1: Conformance scenarios
**Files:** Create `test/httpsecconformance/oidcprovider_scenarios.go`; wire them in `httpsec_{nethttp,gin,fiber}_test.go`
- [ ] Scenarios:
  - `authorize_redirect_and_cookie`: 303, and the cookie's attributes as sent by each adapter;
  - `resume_json`;
  - `token_json_no_store`;
  - `userinfo_challenge`;
  - `metadata`;
  - `endsession_redirect`.
- [ ] Run `go test -run 'TestConformance(NetHTTP|Gin|Fiber)/oidcprovider' ./...` in `test/`. FAIL first on the adapter that lacks a fix; implement; PASS; commit.
- [ ] Add scenarios: the browser-session cookie's attributes, the kept flow cookie, and the logout confirmation's JSON answer.

---

## Task group 14: OpenID conformance in CI (lane X)

### Task 14.1: The conformance OP
**Files:** Create `test/cmd/conformanceop/main.go`, `test/conformance/compose.yaml`, `test/conformance/oidcc.json`, `test/conformance/expected-failures.json`
- [ ] A `net/http` server built from the provider's defaults over `https`, on a self-signed certificate (R5). Its clients: `client`, `client2` and a third using `client_secret_post`, each `PKCEOrNonce` and registered for the refresh grant, with `BackChannelLogoutURI` and `PostLogoutRedirectURIs` the suite gives.
- [ ] Its users hold `name`, `preferred_username`, `email`, `email_verified`, `phone_number`, `phone_number_verified` and `address`, through a `ClaimSource`.
- [ ] Its login, consent and logout pages are plain server-rendered forms that resume through the Go API, with no `fetch`, because the suite drives HtmlUnit. `oidcc.json`'s `browser` section fills and submits them, with a per-module override for `oidcc-prompt-login`.
- [ ] `expected-failures.json` holds exactly `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`, as R1 records.
- [ ] Verify: `docker compose -f test/conformance/compose.yaml up -d`, then the suite's discovery module run headless reports `PASSED`.

### Task 14.2: `make conformance` and the CI job
**Files:** Modify `Makefile`, and the CI workflow `split-ci-jobs` leaves
- [ ] Add `make conformance`, outside `make check`, which brings up the compose file and runs `scripts/run-test-plan.py --expected-failures-file test/conformance/expected-failures.json` over `oidcc-basic-certification-test-plan`, `oidcc-config-certification-test-plan`, `oidcc-rp-initiated-logout-certification-test-plan` and `oidcc-backchannel-rp-initiated-logout-certification-test-plan`. The runner already fails on an unexpected result, and on an expected one that stops occurring.
- [ ] Pin the suite to a full commit hash, at `475e8bf` or newer, since it builds from source, and pin every image the job names by digest, so `pincheck` passes. The target creates the export directory before calling `run-test-plan.py --export-dir`, which requires it to exist.
- [ ] Add the job `conformance`, which calls that target, runs on pull requests and on `main`, uploads the logs with `actions/upload-artifact` pinned by SHA, and is in `ci-ok`'s `needs`.
- [ ] Verify: the job appears on the PR and reports all four plans, and a deliberately failing module fails `ci-ok`.

### Task 14.3: Triage
- [ ] For each failing module:
  - **a provider defect:** a fresh Opus dispatch writes a failing unit test in the owning package, labelled `REPRODUCED` with its output, then the fix;
  - **a job misconfiguration:** a Sonnet dispatch fixes the job;
  - **anything else that would need an expected-failures entry:** back to the main session, as a decision recorded in `design.md`. No dispatch adds one.
- [ ] Verify: all four plans pass in CI.

---

## Task group 15: integration and release gate (main session)

### Task 15.1: Amend `release-readiness`
- [ ] Edit `openspec/changes/release-readiness/tasks.md`: its gate names the `conformance` job, its first changelog entry summarises this change, and its README task drops the `prompt=none` limitation in favour of R2's and R9's. Regenerate its `plans.md` through `/superpowers:writing-plans`. Run `openspec validate release-readiness --strict`. Commit on that change's branch.

### Task 15.2: Whole-branch review
- [ ] A fresh Opus reviewer checks the branch diff against every requirement in `specs/` and the design's decisions. It reports `REPRODUCED` or `UNREPRODUCED` for each finding and edits nothing. The findings go to fresh dispatches of the owning lanes. Verify: a re-review reports nothing open.

### Task 15.3: The final gate
- [ ] The main session runs:
  - `make check` in the core module;
  - `go test -race ./...` in `test/` with `SCRTY_PG_VERSIONS=15,18`, or the helper's equivalent;
  - the `conformance` job, confirmed green.

  Each must pass.
