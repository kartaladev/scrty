# API Token Forwarding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A handler on a scrty cookie chain obtains a per-API access token, either minted by scrty or the federated provider's (kept sealed and refreshed). It calls downstream APIs through a confined transport that never sends the session cookie.

**Architecture:**
- A redacted carrier type `session.ProviderTokens` holds the provider tokens on the session. A
  `RoleSelector`-style conditional port replaces them.
- `authenticate/oidc` keeps the tokens for opted-in providers and refreshes them.
- `httpsec` adds an `EnableOutboundTokens` option with three source kinds (minted, provider,
  consumer), a context accessor, and a transport.
- `outbound` gains a confined `http.RoundTripper`.

**Tech Stack:** Go 1.27, `lestrrat-go/jwx/v4` (through `token.Issuer`), `golang.org/x/sync/singleflight` (already in `go.mod`), testify, mockgen, testcontainers-go (PostgreSQL 15/18).

**Spec:** `openspec/changes/api-token-forwarding/{proposal.md,design.md,specs/**,tasks.md}`. Every
plan task maps to the `tasks.md` numbers in its heading. This plan adds no scope beyond `tasks.md`.

## Global Constraints

- Test-first for every task (`golang-tdd.md`):
  1. Run a focused `go test -run '<Name>' -count=1` and record a red failure for the intended
     reason. A compile error is not red.
  2. Then green.
  3. Then refactor.
- Table tests use the `table-test` skill: an `assert` closure, a `ctx` modifier, `t.Context()`.
  Mocks use `use-mockgen` and PostgreSQL uses `use-testcontainers`. No hand-rolled fakes of heavy
  services.
- Minted token:
  - header `typ` `at+jwt` (`token.TypeAccessToken`);
  - claims `iss`, `sub`, `aud` (exactly one), `client_id` (default = the chain's issuer), `iat`,
    `exp`, `jti` (fresh, from `crypto/rand`, never the session identifier);
  - lifetime 5 minutes by default, allowed range 1 s to 5 min in whole seconds;
  - `exp` = min(iat + lifetime, the session's absolute deadline).
- Thresholds:
  - renew or refresh when **less than 1 minute** remains;
  - provider token without `expires_in`: 5-minute fallback;
  - kept-token size cap: **16 KiB**.
- Errors: dependency failures keep their cause reachable and never match an authentication
  refusal. A cancelled context gives an error that matches `ctx.Err()`.
- Tokens never appear in a log, an error, an event or a response. They print `[redacted]` under
  `%v`, `%+v`, `%#v`, `%s` and as a slog value.
- Constraints on agents:
  - Never cite the legacy reference.
  - No agent edits `openspec/`.
  - No agent runs `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`.

## Review Focus

These are the input classes that no single scenario in the specs fully pins.

1. **A provider that rotates refresh tokens and detects reuse**, hit by two requests from different
   family members within a grace window. Expected: the provider never sees one refresh token twice.
   Test added to Task 5.4/5.5: `TestOutboundProvider_FamilyNeverPresentsOneRefreshTokenTwice`.
2. **A transport request whose URL differs from the configured base URL only by case, a default
   port (`:443`), a trailing dot, or `..` segments.** Expected: it is matched after normalisation,
   or refused if it cannot be normalised. It never matches more widely. Test added to Task 6.1:
   `TestOutboundTransport_DestinationNormalisation`.
3. **A refresh response whose `expires_in` is zero, negative or absurdly large.** Expected: zero or
   negative is treated as absent (fallback). Anything over 24 h is capped at 24 h, so a hostile
   value cannot pin a stale token forever. Test added to Task 3.4:
   `TestRefreshProviderTokens_ExpiresInBounds`.
4. **A handler that calls the accessor after the request context is done**, for example from a
   goroutine that outlived the request. Expected: an error matching the context's error, nothing
   minted. Test added to Task 4.4: `TestOutboundToken_AfterRequestDone`.
5. **A consumer token source that returns a token with surrounding whitespace or a newline.**
   Expected: it is refused as malformed, because a header-injection vector is never sent. Test
   added to Task 4.8: `TestConsumerSource_RefusesHeaderUnsafeToken`.

---

## Lanes, waves and models

Ownership follows the call graph. No two agents own one file.

| Lane | Tasks | Owns | Model (reason) |
|---|---|---|---|
| S | 1.1–1.7 | `session/**` | Opus: conditional writes, sealing (security-critical, first time) |
| T | 6.3 (outbound part only) | `outbound/**` | Opus: confinement of redirects and destinations |
| D | 2.1–2.5 | `store/migrate/securitystate/**`, `internal/pgschema/**`, `internal/storekit/**`, `store/sqlstore/session*.go`, `store/pgxstore/session*.go`, `store/gormstore/{models,session}*.go`, `test/storetest/**`, `test/internal/storefix/**` | Opus: single-statement conditional writes across backends |
| F | 3.1–3.5 | `authenticate/oidc/**`, `httpsec/oidc_*.go` | Sonnet: follows the code-exchange pattern and the given signatures |
| H | 4.1–4.9, then 5.1–5.7, then 6.1, 6.2, 6.4 | `httpsec/outbound_*.go`, `httpsec/errors.go`, `httpsec/config.go` (outbound section), `test/httpsecconformance/**` (outbound only), `test/oidc/**` (5.7) | Opus: security-critical refusal logic, singleflight and races |
| G | 7.1 | `docs/guides/outbound-tokens.md`, `httpsec/example_outbound_*_test.go` | Sonnet: documentation against existing examples |

Waves run in order. Lanes within a wave run in parallel, launched in one message.

1. **Wave 1:** S (dispatch S1 = 1.1–1.3, 1.6; then S2 = 1.4, 1.5, 1.7) ∥ T.
2. **Wave 2:** D ∥ F ∥ H1 (4.1–4.4). F and H both live in `httpsec`, but on disjoint files. H1
   consumes F's `oidc.RelyingParty.ForwardingProviders()`, so **F's 3.1 lands first inside wave 2**,
   and H1 starts after it.
3. **Wave 3:** H2 (4.5–4.9).
4. **Wave 4:** H3 (5.1–5.7), after D, F and H2 are green. Then H4 (6.1, 6.2, 6.4), after H3 and T.
   Lane H is serial, so H3 and H4 never run together.
5. **Wave 5:** G.
6. **Wave 6:** 8.1–8.2 in the main session.

After each dispatch:
- The main session runs the lane's scoped commands and reads the red outputs the agent reports.
- A fresh reviewer that did not write the code checks it. Opus lanes get an Opus reviewer, and
  lanes F and G a Sonnet reviewer.

### Scoped verification per lane (`test-scope.md`)

In-module dependents were computed on 2026-11-28 with the `go list` recipe from `test-scope.md`.
Re-run the recipe if imports change.

- **S:**
  ```sh
  go test -race -count=1 ./session/... ./authenticate/... ./httpsec/... ./internal/... ./oidcprovider/... ./policy/... ./recovery/... ./store/...
  ( cd test && go test -count=1 ./storetest/... ./internal/... ./sqlstore/... ./pgxstore/... ./gormstore/... ./crossbackend/... ./oidc/... ./httpsecconformance/... )
  ( cd store/pgxstore && go test -count=1 ./... )
  ( cd store/gormstore && go test -count=1 ./... )
  ( cd httpsec/ginsec && go test -count=1 ./... )
  ( cd httpsec/fibersec && go test -count=1 ./... )
  ( cd httpsec/prblmsec && go test -count=1 ./... )
  ( cd expiry/sweep && go test -count=1 ./... )
  ```
- **T:**
  ```sh
  go test -race -count=1 ./outbound/... ./authenticate/... ./httpsec/... ./internal/introspect/... ./internal/keyset/... ./oidcprovider/...
  ( cd test && go test -count=1 ./oidc/... ./httpsecconformance/... )
  ```
- **D:**
  ```sh
  go test -count=1 ./store/... ./internal/pgschema/... ./internal/storekit/...
  ( cd store/pgxstore && go test -count=1 ./... )
  ( cd store/gormstore && go test -count=1 ./... )
  ( cd test && go test -count=1 ./storetest/... ./sqlstore/... ./pgxstore/... ./gormstore/... ./crossbackend/... )
  ```
- **F:**
  ```sh
  go test -race -count=1 ./authenticate/oidc/... ./httpsec/... ./policy/... ./store/sqlstore/...
  ( cd test && go test -count=1 ./oidc/... ./httpsecconformance/... ./crossbackend/... )
  ```
  Plus the `httpsec/*sec` modules, as listed for lane S.
- **H:**
  ```sh
  go test -race -count=1 ./httpsec/...
  ( cd test && go test -count=1 ./httpsecconformance/... ./oidc/... )
  ```
  Plus the `httpsec/*sec` modules.
- **Every lane:** `go vet` and `gofmt -l` on the packages it touched.

---

### Task 1 (tasks 1.1–1.3, 1.6): ProviderTokens on the session

**Files:**
- Create: `session/provider_tokens.go`, `session/provider_tokens_test.go`
- Modify: `session/session.go` (field), `session/sessions_options.go` (create option), the
  rotation, renewal and re-authentication paths in `session/` that already copy `CSRFToken`, and
  `session/store_memory.go`

**Interfaces:**
- Produces:
  ```go
  // ProviderTokens is opaque. Its only field is a pointer, and it prints redacted.
  type ProviderTokens struct{ p *providerTokens }
  func NewProviderTokens(access, refresh string, accessExpiresAt time.Time) ProviderTokens
  // RestoreProviderTokens is for stores: the values as stored, plus the stored digest.
  func RestoreProviderTokens(access, refresh string, accessExpiresAt time.Time, refreshDigest string) ProviderTokens
  func (t ProviderTokens) AccessToken() string
  func (t ProviderTokens) RefreshToken() string
  func (t ProviderTokens) AccessExpiresAt() time.Time
  func (t ProviderTokens) RefreshDigest() string // lowercase hex SHA-256 of the refresh token; "" when there is none
  func (t ProviderTokens) IsZero() bool
  // plus Format, String, GoString and LogValue, all returning "[redacted]"
  // Session gains:  ProviderTokens ProviderTokens
  func WithProviderTokens(t ProviderTokens) CreateOption
  ```

- [ ] **Step 1: Write failing tests** in `session/provider_tokens_test.go`:
  - `TestProviderTokens_RecordedAtCreation`: create on `MemoryStore` with
    `NewProviderTokens("at-1","rt-1",11:00)`, load, and assert all three values.
  - `TestProviderTokens_SaveCannotChange`: load, set `ProviderTokens{}`, `Save`, load, and assert
    `"at-1"`.
  - `TestProviderTokens_ConsumerDataCannotSet`: consumer data
    `{"provider_access_token":"forged"}` leaves `"at-1"`.
  - `TestProviderTokens_CarriedThroughRotation`: a table with one case per rotation kind (privilege
    change, renewal, re-authentication, second-factor rotation). The successor handed to the
    issuing step holds `at-1`/`rt-1`.
  - `TestProviderTokens_Redacted`: `%v`, `%+v`, `%#v`, `%s`, `slog` attribute, and as an exported
    and unexported field of a consumer struct. The output contains neither `AT-SENTINEL` nor
    `RT-SENTINEL`, and `RefreshDigest()` equals the hex SHA-256 of `RT-SENTINEL`.
- [ ] **Step 2: Run** `go test -run 'TestProviderTokens_' -count=1 ./session/`. Expected: failures
  on missing values or unredacted output, recorded. If it does not compile yet, add the stub type
  first, so the red is behavioural.
- [ ] **Step 3: Implement.** Follow `CSRFToken`'s carrying rules exactly. `Save` keeps the stored
  `ProviderTokens`, as it keeps the family fields.
- [ ] **Step 4: Run** the step 2 command, then lane S's scoped commands. Expected: PASS.
- [ ] **Step 5: Commit**:
  `feat(session): sessions carry redacted provider tokens through every rotation`.

### Task 2 (tasks 1.4, 1.5, 1.7): Conditional replace and sealing

**Files:**
- Create: `session/provider_tokens_replace_test.go`
- Modify: `session/store_memory.go`, `session/store_encrypted.go`, `session/provider_tokens.go`

**Interfaces:**
- Consumes: Task 1.
- Produces:
  ```go
  var ErrProviderTokensChanged = errors.New("session: the session's provider tokens changed")
  type ProviderTokenReplacer interface {
      // ReplaceProviderTokens writes next (zero = clear) to the session with this identifier in one
      // atomic conditional write: the session is stored, not superseded, before both deadlines, and
      // its stored RefreshDigest equals expectRefreshDigest. Errors: ErrNotFound, ErrSuperseded,
      // ErrExpired, ErrProviderTokensChanged. Nothing else is written.
      ReplaceProviderTokens(ctx context.Context, id, expectRefreshDigest string, next ProviderTokens) error
  }
  func (s *Sessions) ReplaceProviderTokens(ctx context.Context, id, expectRefreshDigest string, next ProviderTokens) error // ErrConfig when the store does not implement ProviderTokenReplacer
  func (s *Sessions) ReplacesProviderTokens() bool // used by httpsec's construction check
  ```
  `NewEncryptedStore` returns a store that implements `ProviderTokenReplacer` when the inner store
  does, as it already does for `RoleSelector`. It seals the access and refresh values with
  `additionalData(sess.ID)` and passes the digest through unsealed.

- [ ] **Step 1: Write failing tests:**
  - `TestReplaceProviderTokens` (table, `MemoryStore` and `NewEncryptedStore(MemoryStore)`). Cases:
    - replace succeeds: digest of `rt-1` → `at-2`/`rt-2`, deadlines unchanged;
    - lost write: names `rt-1`, holds `rt-2`, so `ErrProviderTokensChanged`;
    - superseded: `ErrSuperseded`;
    - deleted: `ErrNotFound`, nothing created;
    - clear: zero next, session still valid;
    - expired: `ErrExpired`.
  - `TestReplaceProviderTokens_Race`: a barrier releases two goroutines naming `rt-1` with
    `rt-2`/`rt-3`. Exactly one gets nil, and the other gets `ErrProviderTokensChanged`. Run with
    `-race`.
  - `TestEncryptedStore_ProviderTokens`:
    - sealed round trip: the inner record contains neither sentinel;
    - copied to another session: `ErrUnreadable`;
    - outage: the cipher returns `ErrCipherUnavailable`, so a store failure that does not match
      `ErrUnreadable`;
    - conditional replace through the wrapper stores sealed values.
- [ ] **Step 2: Run**
  `go test -race -run 'TestReplaceProviderTokens|TestEncryptedStore_ProviderTokens' -count=1 ./session/`.
  Expected: the behavioural failures, recorded.
- [ ] **Step 3: Implement.** Godoc on the port and the option names the default (empty, not kept)
  and the sealing requirement (task 1.7).
- [ ] **Step 4: Run** lane S's scoped commands and `go doc ./session ProviderTokenReplacer`.
  Expected: PASS, and the godoc shows.
- [ ] **Step 5: Commit**:
  `feat(session): conditional, sealed replacement of provider tokens on the newest session`.

### Task 3 (tasks 2.1–2.5): Durable stores

**Files:**
- Create: `store/migrate/securitystate/20261129000000_provider_tokens.sql`
- Modify: `internal/pgschema/sessions.go`, `internal/storekit/storekit.go`,
  `store/sqlstore/session.go`, `store/pgxstore/session.go`, `store/gormstore/models.go`,
  `store/gormstore/session.go`, `test/storetest/session_suite.go`, `test/internal/storefix/sealed.go`

**Interfaces:**
- Consumes: Task 2's port and `RestoreProviderTokens`.
- Columns, all nullable: `provider_access_token text`, `provider_refresh_token text`,
  `provider_access_expires_at timestamptz`, `provider_refresh_digest text`.
- The conditional replace is one `UPDATE … WHERE id=$1 AND superseded_at IS NULL AND <both
  deadlines after the store's now()> AND coalesce(provider_refresh_digest,'')=$2`. Zero rows
  triggers a follow-up read that tells `ErrNotFound`, `ErrSuperseded`, `ErrExpired` and
  `ErrProviderTokensChanged` apart, as `SelectRole` does.

- [ ] **Step 1: Write failing conformance cases** in `test/storetest/session_suite.go`
  (`sessionProviderTokenCases`):
  - reloaded;
  - survives supersession;
  - a copied sealed token does not open (via `storefix`);
  - a pre-migration row loads empty: insert without the columns, then load;
  - replace: success, lost, superseded, deleted, expired;
  - racing replacements: exactly one success.

  Add `TestProviderTokenColumnsSealed` for the `secrets-at-rest` scenario (2.5): read the columns
  directly, decode, and assert that neither sentinel appears.
- [ ] **Step 2: Run** them against `MemoryStore` (expected PASS), and against
  `sqlstore`/`pgxstore`/`gormstore` (expected FAIL: missing column or port, recorded).
- [ ] **Step 3: Implement** the migration and the three stores. Test the migration up and down on
  PostgreSQL 15 and 18 via the existing `RunTestPostgres` helper.
- [ ] **Step 4: Run** lane D's scoped commands. Expected: PASS on all backends and both PostgreSQL
  majors.
- [ ] **Step 5: Commit**:
  `feat(store): durable stores keep provider tokens sealed and replace them conditionally`.

### Task 4 (tasks 3.1–3.5): Keeping and refreshing a forwarding provider's tokens

**Files:**
- Create: `authenticate/oidc/forwarding.go`, `authenticate/oidc/forwarding_test.go`
- Modify: `authenticate/oidc/remote.go` (exchange and refresh through `RelyingParty.confined`),
  the `CallbackResult` definition, `httpsec/oidc_redeem.go` and `httpsec/oidc_cookie.go` (pass the
  tokens into session creation)

**Interfaces:**
- Consumes: `session.ProviderTokens`, `session.WithProviderTokens`.
- Produces:
  ```go
  func WithProviderTokenForwarding(provider string, opts ...ForwardingOption) Option // off by default
  type ForwardingOption func(*forwarding) error
  func WithForwardingExpiryFallback(d time.Duration) ForwardingOption // default 5m; d must be > 0
  func (rp *RelyingParty) ForwardingProviders() []string
  // CallbackResult gains: ProviderTokens session.ProviderTokens (zero unless the provider forwards)
  var ErrRefreshRejected = errors.New("oidc: the provider rejected the refresh token")
  func (rp *RelyingParty) RefreshProviderTokens(ctx context.Context, provider string, current session.ProviderTokens) (session.ProviderTokens, error)
  // errors: ErrRefreshRejected (invalid_grant), otherwise a dependency error wrapping the cause
  ```

- [ ] **Step 1: Write failing tests** (a table against an `httptest` provider):
  - `TestCallback_ForwardingTokens`:
    - `corp` forwards, `at-1`/`expires_in` 3600/`rt-1` at 10:00, so the session holds them with
      expiry 11:00; flow and handoff records hold neither; `%+v` of the result contains neither;
    - no refresh token: access token only;
    - no access token: login proceeds, zero tokens;
    - a provider not forwarding: zero tokens (keeps "Access token outlives no callback" green).
  - `TestCallback_ForwardingTokenTooLarge`: a 20 KiB access token is a provider failure and no
    session is stored.
  - `TestRefreshProviderTokens`:
    - rotated refresh token;
    - absent refresh token keeps the old one;
    - absent `expires_in`: 10:00 gives 10:05 by default, and 10:15 with a 15-minute fallback;
    - `invalid_grant` with `DESC-SENTINEL` gives `ErrRefreshRejected`, and the error text lacks the
      sentinel;
    - 503, timeout and a malformed body each give a dependency error.
  - `TestRefreshProviderTokens_ExpiresInBounds` (Review Focus 3): 0 and −5 take the fallback,
    `1e9` is capped at 24 h.
  - A godoc example for the option, mentioning `offline_access` (3.5).
- [ ] **Step 2: Run**
  `go test -run 'TestCallback_Forwarding|TestRefreshProviderTokens' -count=1 ./authenticate/oidc/ ./httpsec/`.
  Expected: the behavioural failures, recorded.
- [ ] **Step 3: Implement.** The refresh request authenticates exactly as the code exchange does
  (form body or HTTP Basic). Bound the error description in logs with the existing helper.
- [ ] **Step 4: Run** lane F's scoped commands. Expected: PASS.
- [ ] **Step 5: Commit**:
  `feat(oidc): forwarding providers keep their tokens on the session and refresh them`.

### Task 5 (tasks 4.1–4.4): Outbound wiring and the accessor

**Files:**
- Create: `httpsec/outbound_config.go`, `httpsec/outbound_access.go`,
  `httpsec/outbound_config_test.go`, `httpsec/outbound_access_test.go`,
  `httpsec/outbound_jti_test.go`
- Modify: `httpsec/errors.go`, `httpsec/config.go` (register the option and run the checks at
  build time)

**Interfaces:**
- Consumes: `session.(*Sessions).ReplacesProviderTokens`, `oidc.(*RelyingParty).ForwardingProviders`.
- Produces:
  ```go
  func EnableOutboundTokens(opts ...OutboundOption) Option
  type OutboundOption func(*outboundConfig) error
  func WithOutboundAPI(resourceID string, source OutboundSource, baseURLs ...string) OutboundOption
  type OutboundSource struct{ /* unexported: exactly one kind */ }
  func MintedTokens(issuer *token.Issuer, opts ...MintOption) OutboundSource
  type MintOption func(*mintConfig) error
  func WithMintedLifetime(d time.Duration) MintOption // default 5m, range [1s, 5m], whole seconds
  func WithMintedClientID(id string) MintOption       // default: the chain's issuer
  func ForwardedProviderTokens(provider string) OutboundSource
  func ConsumerTokens(src OutboundTokenSource) OutboundSource
  type OutboundTokenSource interface {
      OutboundToken(ctx context.Context, req OutboundTokenRequest) (string, error)
  }
  type OutboundTokenRequest struct {
      ResourceID string
      Principal  *identity.Principal // never the session identifier
  }
  func OutboundToken(ctx context.Context, resourceID string) (string, error)
  var ErrNoOutboundToken          = errors.New("httpsec: no outbound token for this request")
  var ErrProviderTokenUnavailable = errors.New("httpsec: provider token unavailable")
  var ErrOutboundUnavailable      = errors.New("httpsec: outbound token source unavailable") // wraps the cause
  ```

- [ ] **Step 1: Write the F3 red test first** (4.1).
  `TestMintedToken_NeverOpensTheSession`:
  - mint for session `S`;
  - assert that `jti != S` and that `jti` does not contain `S`;
  - present `jti` as the session cookie: 401, no session loaded;
  - present the token under `Bearer` on a chain with signed bearer tokens sharing the keys: refused
    as an invalid token.

  Run it. Before 4.5 the test does not compile, so record the red at 4.5, Step 2. That is the only
  deferral, and it is noted in the report.
- [ ] **Step 2: Write failing tests:**
  - `TestOutboundTokens_Enabling`: "Default chain" gives `ErrNoOutboundToken`; "Consumer enables
    outbound tokens" gives a token with `aud` `https://orders.example`.
  - `TestOutboundTokens_ConstructionErrors`, a table with one case per D6 line:
    - no cookie session;
    - empty, relative (`orders`) or fragment resource identifier;
    - duplicate identifier;
    - overlapping base URLs (`https://api.example/` vs `https://api.example/orders`);
    - zero or two sources;
    - lifetime of 10 min, 500 ms or 1.5 s;
    - unknown provider;
    - a kept-but-unused provider;
    - a used-but-not-kept provider;
    - a store without the replacer;
    - a missing cipher for durable provider tokens;
    - `http` base URL without `http` allowed.

    Each case asserts `errors.Is(err, ErrConfig)` and that the message names the setting.
  - `TestOutboundToken_WhoGetsOne`: API key, session reference, resource-server source, anonymous,
    and second factor owed. Each gives `ErrNoOutboundToken`, and the issuer mock expects no call.
  - `TestOutboundToken_AfterRequestDone` (Review Focus 4).
- [ ] **Step 3: Run**
  `go test -run 'TestOutboundTokens_|TestOutboundToken_' -count=1 ./httpsec/`. Expected: the
  behavioural failures, recorded.
- [ ] **Step 4: Implement.** The accessor reads the exchange's authentication result. Only the
  cookie authenticator's result, with no challenge owed, qualifies.
- [ ] **Step 5: Run** lane H's scoped commands. Expected: PASS, apart from
  `TestMintedToken_NeverOpensTheSession`, which is pending until Task 6.
- [ ] **Step 6: Commit**:
  `feat(httpsec): outbound tokens are opt-in per API and only for cookie-authenticated requests`.

### Task 6 (tasks 4.5–4.9): Minting, reuse, failures, consumer source, no response leak

**Files:**
- Create: `httpsec/outbound_mint.go`, `httpsec/outbound_mint_test.go`,
  `httpsec/outbound_consumer_test.go`
- Modify: `httpsec/outbound_access.go`

**Interfaces:**
- Consumes: `token.(*Issuer).Issue(ctx, token.Issue{Type: token.TypeAccessToken, Subject, ID, Audience: []string{resourceID}, Lifetime, Claims: map[string]any{"client_id": …}})`.
  `Lifetime` is reduced to reach the session's absolute deadline when that is sooner.
- Produces: no new exported names.

- [ ] **Step 1: Write failing tests:**
  - `TestMintedToken_Claims` (table):
    - "Default claims": 10:00:00, `u-1`, issuer `https://app.example`, so `exp` 10:05:00 and
      `client_id` = issuer;
    - "Consumer sets the client identifier" (`bff-web`);
    - "Session ends sooner": 20:58 with deadline 21:00 gives `exp` 21:00;
    - "Consumer shortens the lifetime": 2 min;
    - "Two tokens for one session": `jti` values differ.
  - `TestMintedToken_VerifiedByResourceServer`: a second chain with `EnableResourceServer` and a
    remote-issuer source on the app's JWKS (`httptest`), binding opted out. Accepted, with subject
    `u-1`.
  - `TestMintedToken_Reuse`:
    - same request, two calls 10 s apart: the same token;
    - under 1 minute left: a new `jti`;
    - after the request: the session record equals the record before.
  - `TestMintedToken_Failures`: a key-source failure gives `ErrOutboundUnavailable` with
    `errors.Is(err, keyErr)`, not `ErrNoOutboundToken` and not `ErrAuthenticationRequired`, and the
    session is unchanged. A cancelled context gives `errors.Is(err, context.Canceled)`.
  - `TestConsumerSource`: `tok-1` is returned unchanged; an error or `""` gives
    `ErrOutboundUnavailable`.
  - `TestConsumerSource_RefusesHeaderUnsafeToken` (Review Focus 5): `" tok"`, `"tok\n"` and
    `"a\r\nX: y"` are each refused.
  - `TestOutboundToken_NeverInResponse`: a handler obtains a token. No header, cookie or body
    written by the library contains it, and `%+v` of logged errors lacks it.
- [ ] **Step 2: Run**
  `go test -run 'TestMintedToken_|TestConsumerSource|TestOutboundToken_NeverInResponse' -count=1 ./httpsec/`.
  Expected: the behavioural failures, including Task 5's
  `TestMintedToken_NeverOpensTheSession`, recorded as F3's red step.
- [ ] **Step 3: Implement.** `jti` = 128 bits from `crypto/rand`, base64url. The per-request cache
  lives in the exchange.
- [ ] **Step 4: Run** lane H's scoped commands. Expected: PASS.
- [ ] **Step 5: Commit**:
  `feat(httpsec): minted outbound tokens are typed, single-audience, short and never the session`.

### Task 7 (tasks 5.1–5.7): Provider tokens on the outbound path

**Files:**
- Create: `httpsec/outbound_provider.go`, `httpsec/outbound_provider_test.go`,
  `test/oidc/outbound_provider_test.go`
- Modify: `httpsec/outbound_access.go`

**Interfaces:**
- Consumes:
  - `oidc.(*RelyingParty).RefreshProviderTokens` and `oidc.ErrRefreshRejected`;
  - `session.(*Sessions).ReplaceProviderTokens` and its errors;
  - `session.ErrSuperseded`, `session.ErrNotFound`, `session.ErrProviderTokensChanged`.
- Algorithm (the signatures do not determine it):
  ```text
  t := sess.ProviderTokens
  if t.IsZero() or provider mismatch          -> ErrProviderTokenUnavailable
  if t.AccessExpiresAt() - now >= 1m          -> t.AccessToken()
  if sess is superseded (grace window)        -> ErrProviderTokenUnavailable   // never refresh
  if t.RefreshToken() == ""                   -> ErrProviderTokenUnavailable
  singleflight key = sess.FamilyID + "/" + t.RefreshDigest()   // context.WithoutCancel inside
    next, err := RefreshProviderTokens(...)
    ErrRefreshRejected -> ReplaceProviderTokens(id, digest, zero) ; ErrProviderTokenUnavailable
    other err          -> ErrOutboundUnavailable (tokens untouched)
    ReplaceProviderTokens(id, digest, next):
      nil                      -> next.AccessToken()
      ErrProviderTokensChanged -> reload session by id, return its access token if >= 1m left, else ErrProviderTokenUnavailable
      ErrSuperseded            -> resolve the newest successor, ReplaceProviderTokens(successor, digest, next), then the same mapping
      ErrNotFound              -> ErrNoOutboundToken
  each waiter: select on its own ctx.Done() -> ctx.Err()
  ```

- [ ] **Step 1: Write failing tests** (the refresh endpoint is an `httptest` provider that counts
  requests):
  - `TestOutboundProvider_Serve`: "Federated session", "Local sign-in", "Another provider".
  - `TestOutboundProvider_Refresh`: 40 s left gives one refresh and the new token. Also covers the
    rotated and kept refresh-token cases and both fallbacks.
  - `TestOutboundProvider_Coalesced`: a barrier releases 10 requests, with `-race`. One refresh
    request; all 10 get the same token.
  - `TestOutboundProvider_WaiterCancelled`: one of three waiters is cancelled and gets
    `context.Canceled`; the other two get the token.
  - `TestOutboundProvider_LostWrite` (table):
    - another replica first: pre-replace the store's digest, so the winner's token is returned;
    - rotated during the refresh: supersede the session in the provider handler, so the successor
      holds the new tokens;
    - deleted during the refresh: `ErrNoOutboundToken`, nothing re-created.
  - `TestOutboundProvider_SupersededNeverRefreshes`: zero refresh requests and
    `ErrProviderTokenUnavailable`.
  - `TestOutboundProvider_FamilyNeverPresentsOneRefreshTokenTwice` (Review Focus 1): a rotating
    provider that revokes on reuse, with requests on the old identifier (in grace) and on the
    successor. The provider never sees `rt-1` twice.
  - `TestOutboundProvider_Failures`:
    - `invalid_grant`: tokens cleared, and the next cookie request still 200;
    - no refresh token: no request sent;
    - 503: `ErrOutboundUnavailable`, and the session still holds `rt-1`.
  - `test/oidc/outbound_provider_test.go` (5.7): PostgreSQL via testcontainers. Federated sign-in
    through a forwarding provider, a forced refresh, then an API call. The stored columns are
    sealed.
- [ ] **Step 2: Run**
  `go test -race -run 'TestOutboundProvider_' -count=1 ./httpsec/` and
  `(cd test && go test -run TestOutboundProvider -count=1 ./oidc/)`. Expected: the behavioural
  failures, recorded.
- [ ] **Step 3: Implement** the algorithm above.
- [ ] **Step 4: Run** lane H's scoped commands with `-race`. Expected: PASS.
- [ ] **Step 5: Commit**:
  `feat(httpsec): provider outbound tokens refresh once per family and survive lost races`.

### Task 8 (task 6.3, outbound part; lane T, wave 1): Confined round tripper

**Files:**
- Create: `outbound/transport.go`, `outbound/transport_test.go`

**Interfaces:**
- Produces:
  ```go
  // NewTransport returns a RoundTripper under the same Options as New: allowed schemes (https by
  // default), allowed origins, timeout and max response bytes. It refuses a request redirected
  // (req.Response != nil) to an origin other than the redirecting request's.
  func NewTransport(base http.RoundTripper, opts ...Option) (http.RoundTripper, error)
  var ErrDestinationNotAllowed = errors.New("outbound: destination not allowed")
  ```

- [ ] **Step 1: Write failing tests**, `TestTransport` (table):
  - disallowed scheme gives `ErrDestinationNotAllowed`;
  - disallowed origin: refused, and the recording dialer sees zero dials;
  - a cross-origin redirect via `http.Client`: not sent;
  - a same-origin redirect: sent;
  - a body over the max gives an error on read;
  - the timeout fires;
  - `http` allowed by the option: sent.
- [ ] **Step 2: Run** `go test -run TestTransport -count=1 ./outbound/`. Expected: the behavioural
  failures, recorded.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** lane T's scoped commands. Expected: PASS.
- [ ] **Step 5: Commit**:
  `feat(outbound): a confined RoundTripper for requests the consumer builds`.

### Task 9 (tasks 6.1, 6.2, 6.4, plus 6.3 wiring): Outbound transport in httpsec

**Files:**
- Create: `httpsec/outbound_transport.go`, `httpsec/outbound_transport_test.go`,
  `httpsec/example_outbound_test.go`

**Interfaces:**
- Consumes: `outbound.NewTransport`, `OutboundToken`.
- Produces:
  ```go
  func (c *Chain) OutboundTransport() (http.RoundTripper, error) // ErrConfig when outbound tokens are not enabled
  ```
  It resolves the API by longest segment-bounded base-URL match after URL normalisation, then:
  1. obtains the token with `OutboundToken(req.Context(), api)`;
  2. clones the request;
  3. removes `Cookie`;
  4. sets `Authorization`;
  5. delegates to the confined transport, whose allowed origins are the APIs' base-URL origins.

- [ ] **Step 1: Write failing tests:**
  - `TestOutboundTransport_Destinations`: "Unconfigured destination" and "Prefix is not a segment
    boundary" (`/orders` vs `/orders-admin/1`). Zero dials, no issuer call.
  - `TestOutboundTransport_DestinationNormalisation` (Review Focus 2): `HTTPS://API.EXAMPLE:443/orders/1`
    and `https://api.example./orders/1` match. `https://api.example/orders/../admin` is refused.
  - `TestOutboundTransport_Headers`: "Cookie and stale authorization present"; the caller's
    `*http.Request` is unmodified.
  - `TestOutboundTransport_NoToken`: a non-cookie context gives `ErrNoOutboundToken`, nothing sent.
  - `TestOutboundTransport_Confinement`: a cross-origin redirect does not reach `other.example`.
    "Plain HTTP by default" is covered by Task 5's construction table; "Consumer allows plain HTTP"
    is sent.
  - `ExampleChain_OutboundTransport` (6.4): a cookie chain, one minted API and one provider API,
    both called. It has `// Output:`.
- [ ] **Step 2: Run** `go test -run 'TestOutboundTransport_|ExampleChain_OutboundTransport' -count=1 ./httpsec/`.
  Expected: the behavioural failures, recorded.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** lane H's scoped commands and `go doc ./httpsec Chain.OutboundTransport`.
  Expected: PASS.
- [ ] **Step 5: Commit**:
  `feat(httpsec): an outbound transport that only reaches configured APIs and never sends the cookie`.

### Task 10 (task 7.1): Consumer guide

**Files:**
- Create: `docs/guides/outbound-tokens.md`, and `httpsec/example_outbound_resource_server_test.go`
  (the downstream API side)

- [ ] **Step 1: Write the example test first:** `ExampleEnableResourceServer_outboundTokens`, where
  the API verifies a minted token with the binding opt-out. Run it: it fails until the opt-out
  option is wired in the example. Record the red.
- [ ] **Step 2: Write the guide.** Sections:
  - enabling (minted, provider, consumer);
  - the downstream API (verify and opt out of binding);
  - the transport;
  - obligations it cannot enforce: `Cache-Control: private, no-store`, pass-through routes, TLS on
    the hop;
  - provider forwarding and `offline_access`;
  - accepted limits F4, F20, F21 and F22, each with what the consumer sees.

  Every snippet is copied from an `Example` test.
- [ ] **Step 3: Run** `go test -run 'Example' -count=1 ./httpsec/`, plus a check that each guide
  snippet appears verbatim in an example file. Expected: PASS.
- [ ] **Step 4: Commit**: `docs: consumer guide for outbound tokens`.

### Task 11 (tasks 8.1, 8.2): Final gate (main session only)

- [ ] **Step 1:** Run `make check` and `make spec-check` after the last code edit. The main session
  reads the output. Expected: both green, with the output recorded in the PR.
- [ ] **Step 2:** Dispatch a whole-branch Opus reviewer against all five spec deltas and F1–F26.
  It enumerates the failures first, and labels every claimed defect REPRODUCED or UNREPRODUCED.
  Each finding goes to a fresh dispatch of its lane, followed by a rerun of Step 1, or is recorded
  as accepted in `design.md` by the main session.
- [ ] **Step 3:** Tick 8.1 and 8.2 in `tasks.md` (main session), and commit.

## Workflow follow-up

- `/opsx:archive api-token-forwarding` after review. Verify that `openspec/specs/token-forwarding/`
  exists, and that `oidc-login`, `sessions`, `secrets-at-rest` and `security-state-stores` carry
  the deltas.
