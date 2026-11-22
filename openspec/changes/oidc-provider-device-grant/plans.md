# Device Authorization Grant Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Ticking boxes in `tasks.md` is the main session's job alone.

**Goal:** Add the OAuth 2.0 Device Authorization Grant (RFC 8628) to scrty's OpenID Provider, opt-in per provider and per client, with the RFC 10027 mitigations on by default.

**Architecture:** The protocol lives in `oidcprovider`: a new device authorization record and store port, `Provider.AuthorizeDevice` and `Provider.EnterUserCode`, a device branch in consent and resume, and a third grant in `Provider.Token`. `httpsec` adds two endpoints that call those methods, and derives the metadata. The SQL adapters gain a device store and grant/pending-request columns through one security-state migration.

**Tech Stack:** Go 1.27, `ratelimit.SourceGuard`, `crypto/hmac` + SHA-256, `uber-go/mock` (typed), testcontainers PostgreSQL 15 and 18, goose migrations, `golang.org/x/oauth2` (already a test dependency) for the end-to-end test.

**Spec:** `openspec/changes/oidc-provider-device-grant/` — `proposal.md`, `design.md` (D1–D13, Failure modes), `specs/*/spec.md`, `tasks.md`. Every plan task names the `tasks.md` items it covers. Executors read the design section each task cites.

## Global Constraints

- **Test-first, always** (`golang-tdd.md`): write the test, run it, see it fail **for the intended reason** (a compile error is not a red step: add the signature with a stub body that returns a zero value or `errors.New("not implemented")` first), then implement. Report the red output.
- **Table tests** follow the `table-test` skill (`assert` closure, `ctx` modifier, `t.Context()`). **Mocks** follow `use-mockgen` (`--typed`, placement by consumer). **Databases** follow `use-testcontainers` (existing helpers only).
- **Defensive coding** (`defensive-coding.md`) is binding: every failure in design.md's Failure modes table that a task touches is tested in that task.
- **Additions only.** No existing exported signature changes. New `Grant` and `PendingRequest` fields are zero-valued for existing rows and mean what the old rows meant.
- **No secret in output.** No error text, log line or event carries a device code, user code, digest, handle or flow secret. New input/result types implement `Format` and `LogValue` with the package's `redacted` form, as `AuthorizeInput` does.
- **Expiry rule:** a record is expired when `!now.Before(ExpiresAt)` (`now >= ExpiresAt`), judged by the provider's clock, never a store's.
- **Exact values:** `GrantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"`; default user-code alphabet `BCDFGHJKLMNPQRSTVWXZ`, length 8, shown `XXXX-XXXX`; minimum code space 2^29; device code 32 random bytes, base64url (no padding); lifetime default 600 s, bounds [60 s, 30 min]; interval default 5 s, bounds [1 s, 60 s] and below the lifetime; `slow_down` adds 5 s; entry throttle 5 failures / 10 min per source; device authorization endpoint throttle 10 failed client authentications / 15 min per source, namespace `oidc-device-authorization`; entry namespace `oidc-device-entry`; user-code key ≥ 32 bytes; collision bound 5 attempts in all (no sixth `Create`); replay window expiry + 1 minute; paths `/device-authorization` and `/device` under the provider prefix.
- **No legacy citations** (`legacy-reference.md`). The established design has no OpenID Provider side, so there is nothing to consult for this change.
- **Agents never edit `openspec/`**, never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and never commit.

### Verification during the change (decided by the user 2026-11-22)

Each dispatch runs only the packages it changed **and the packages that transitively depend on them**, never the whole workspace. The full suite runs once, at task 13.2.

| Changed | Run |
|---|---|
| `oidcprovider` | `go test -race -count=1 ./oidcprovider/... ./internal/pgschema/... ./store/sqlstore/... ./httpsec/...` |
| `event` | the `oidcprovider` row above, plus `./event/...` |
| `internal/pgschema`, `store/migrate`, `store/sqlstore` | `go test -race -count=1 ./internal/pgschema/... ./store/...` and, in `test/`, `go test -race -count=1 ./sqlstore/... ./storetest/... -run 'Device|Grant|Pending|Migrat'` |
| `store/pgxstore` / `store/gormstore` | `(cd store/pgxstore && go test -race -count=1 ./...)` / `(cd store/gormstore && go test -race -count=1 ./...)`, plus the matching `test/pgxstore` or `test/gormstore` packages |
| `test/storetest` | `(cd test && go test -race -count=1 ./storetest/...)` |
| `httpsec` | `go test -race -count=1 ./httpsec/...` plus `(cd test && go test -race -count=1 -run 'OIDC|Provider|Device' ./...)` |

Every dispatch also runs `go vet` and `gofmt -l` on the packages it touched. The red step always uses a focused `go test -run '<Name>' -count=1 <pkg>` first.

## Review Focus

The five inputs or conditions the spec implies but does not pin, most likely first. Each has its test in the owning task.

1. **Timestamp precision in a durable compare-and-set.** PostgreSQL keeps microseconds, so a compare on `LastPolledAt` would never match after a round-trip. Polls compare-and-set on `PollCount` instead (Task 3, Task 10: `PollCASSurvivesRoundTrip`).
2. **An alphabet containing `-`, whitespace or non-ASCII** can never be entered, because normalisation strips or mangles it. Construction refuses it (Task 2: `TestWithUserCodeFormat` rows).
3. **Claim succeeds but parking fails** leaves a record claimed with no pending request. The same browser's re-entry must recover (Task 5, tasks.md 5.6).
4. **The sign-in ends, or consent is revoked, after approval but before the poll.** No grant row exists yet to revoke (Task 8, tasks.md 8.4: the union `UnspentCodes`).
5. **Two issuers draw the same user code at once** on a durable store. A unique index plus the in-transaction release of expired holders keeps exactly one (Task 3 suite case `CreateConcurrentSameUserCode`, Task 10).

## Dispatch map

Almost every task writes `oidcprovider`, so lanes A1–A9 run **in order** (one package; signatures flow forward). Parallelism opens after A9:

```
A1 → A2 → A3 → A4 → A5 → A6 → A7 → A8 → A9 ─┬─ B1 → (B2 ∥ B3)      stores (store/*, internal/pgschema, test/*)
                                             ├─ C1 → C2             httpsec
                                             └─ D1                  docs (README, CHANGELOG, oidcprovider/example_device_test.go)
                                                      all ──→ E1 → E2 (main session) → E3 (review)
```

B, C and D own disjoint files. B touches no `httpsec` file, and C touches no store file. D touches only the files listed for it. After each dispatch: the main session verifies, then a fresh reviewer (Opus for Opus dispatches, Sonnet otherwise) checks the diff against the cited spec requirements. Its findings go to a fresh dispatch of the same lane.

---

### Task A1: Provider option and client registration (tasks 1.1–1.4) — Sonnet: config validation in an existing pattern

**Files:**
- Create: `oidcprovider/device.go` (option, constants, `deviceConfig`), `oidcprovider/device_config_test.go`
- Modify: `oidcprovider/client.go` (`GrantDeviceCode`, two fields, `validateGrantTypes`, `validateURIs`, a device-settings validator called beside the existing ones), `oidcprovider/options.go` (`config.device *deviceConfig`, validation in the existing `validate`), `oidcprovider/registry.go` only if the registry path needs the provider's device flag passed to client validation
- Test: `oidcprovider/device_config_test.go`, `oidcprovider/client_test.go` (new rows)

**Interfaces — Produces:**
```go
const GrantDeviceCode GrantType = "urn:ietf:params:oauth:grant-type:device_code"
type DeviceOption func(*deviceConfig)
func WithDeviceAuthorization(entryURL string, opts ...DeviceOption) Option
// Client fields:
DeviceCompleteURI         bool // default false; needs GrantDeviceCode
DeviceGrantsOutliveSignIn bool // default false; needs GrantDeviceCode; contradicts EndGrantsWithSignIn (incl. public-web default)
// unexported, used by later tasks:
type deviceConfig struct { entryURL *url.URL; lifetime, interval time.Duration; /* A2/A3/A5 add fields */ }
func (p *Provider) DeviceEnabled() bool // exported: httpsec registers the device endpoints only when true
```

- [ ] **Step 1: Write failing tests.**
  - `TestWithDeviceAuthorization` (table): the grant is off with no option (`p.DeviceEnabled()` is false). The rows `entry URL on another origin`, `with a fragment`, `relative`, `empty` and `http on an https issuer` each fail `New` with `errors.Is(err, ErrConfig)` and the text containing `WithDeviceAuthorization`. A same-origin https URL with a query is accepted.
  - `TestClient_DeviceGrant` (table, in `client_test.go`). A configured client listing `GrantDeviceCode` on a provider without the option fails, naming the client ID and `GrantTypes`. A public native client with only `GrantDeviceCode` and no redirect URIs is accepted. `DeviceCompleteURI` without the grant fails, naming `DeviceCompleteURI`. `DeviceGrantsOutliveSignIn` with `EndGrantsWithSignIn`, on a public web client without `KeepPublicWebGrantsPastSignIn`, and without the grant, each fail naming both settings. It is accepted on a public native client.
  - `TestRegistry_DeviceClientOnProviderWithout`. A registry client listing the grant, on a provider without the option, reads as unknown (`ErrUnknownClient` or the package's existing unknown-client refusal), and the captured log names `GrantTypes`.
- [ ] **Step 2: Run** `go test -run 'TestWithDeviceAuthorization|TestClient_DeviceGrant|TestRegistry_DeviceClientOnProviderWithout' -count=1 ./oidcprovider`. Expect assertion failures (stubs present), not compile errors.
- [ ] **Step 3: Implement.** Client validation needs to know whether the provider enabled the grant. Pass it the same way the package already passes provider facts into `Client.validate…` (follow the existing parameter or closure). Do not read a global.
- [ ] **Step 4: Run** the focused tests, then the `oidcprovider` verification row.

### Task A2: Codes (tasks 2.1–2.5) — Opus: first-time security-critical code generation and keyed digests

**Files:**
- Create: `oidcprovider/devicecode.go`, `oidcprovider/devicecode_test.go`, `oidcprovider/devicecode_internal_test.go` (uniformity with a scripted reader)
- Modify: `oidcprovider/device.go` (options and their validation)

**Interfaces — Produces:**
```go
const (
  DefaultUserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
  DefaultUserCodeLength   = 8
  MinUserCodeKeyBytes     = 32
)
func WithUserCodeFormat(alphabet string, length int) DeviceOption
func WithUserCodeKey(key []byte) DeviceOption // copies key
// unexported:
type userCodeFormat struct{ alphabet string; length, group int; upper bool }
func (f userCodeFormat) generate(r io.Reader) (raw string, err error)  // rejection sampling
func (f userCodeFormat) display(raw string) string                      // grouped with "-"
func (f userCodeFormat) normalise(entered string) (raw string, ok bool) // strip space/"-", upper-case iff upper
func mintDeviceCode(r io.Reader) (code string, digest []byte, err error) // 32 bytes, base64url, SHA-256
func (c *deviceConfig) userCodeDigest(raw string) []byte                 // HMAC-SHA-256(key, raw)
```

- [ ] **Step 1: Write failing tests.**
  - `TestMintDeviceCode`: decoded length 32. The digest equals the SHA-256 of the 32 decoded bytes, as handles are digested (D4), so reading a code back with the package's handle decoder yields the same digest. A reader returning an error yields that error wrapped, and an empty code and digest.
  - `TestUserCode_DefaultFormat`: 1 000 draws match `^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`.
  - `TestUserCode_RejectionSampling` (internal): a scripted reader supplies bytes ≥ 240 (the rejection zone for a 20-letter alphabet: `256 - 256%20 = 240`) before each accepted byte. The output uses only the accepted bytes, and each byte `b < 240` maps to `alphabet[b%20]`.
  - `TestWithUserCodeFormat` (table). A 9-digit format is accepted and displays as `123-456-789`. These fail naming `WithUserCodeFormat`: 6 digits (10^6 < 2^29); a repeated character `"AAB…"`; a non-printable `"\x01…"`; a non-ASCII character; an alphabet containing `-`; an alphabet containing a space; a length of 0; a length of 33; an alphabet of 1 character.
  - `TestUserCodeKey` (table). With no key given, two providers digest the same code differently. Two providers given the same 32-byte key digest it identically. A 31-byte key fails naming `WithUserCodeKey`. A key given and then mutated by the caller does not change the digest.
  - `TestUserCode_Normalise` (table). `bcdf ghjk`, `BCDF-GHJK` and ` bc-df gh jk ` all normalise to `BCDFGHJK`. `BCDA-GHJK` (vowel), 7 letters and 9 letters are `ok=false`. For a lower-case alphabet `"bcdfghjkmnpqrstvwxz"`, the input `BCDFGHJK` is `ok=false` (not lowered).
  - The durable-store-without-key refusal is tested in Task A3, once `WithDeviceAuthorizationStore` exists.
- [ ] **Step 2: Run** `go test -run 'TestMintDeviceCode|TestUserCode|TestWithUserCodeFormat' -count=1 ./oidcprovider` and see the assertion failures.
- [ ] **Step 3: Implement.** Compute the code space with `math/big` or an overflow-checked multiply, never a float. The random source is the provider's existing one (the same reader handles use). The grouping rule is in design D4.
- [ ] **Step 4: Run** the focused tests, then the `oidcprovider` row.

### Task A3: Device authorization store (tasks 3.1–3.5) — Opus: conditional writes and race suite

**Files:**
- Create: `oidcprovider/devicestore.go` (types, port, `ErrUserCodeTaken`), `oidcprovider/devicestore_memory.go`, `oidcprovider/devicestore_mock_test.go` (generated), `test/storetest/oidcprovider_device_suite.go`, `test/storetest/broken_device_test.go` (the clock-cheating stub), and a memory registration in `test/storetest/oidcprovider_memory_test.go`
- Modify: `oidcprovider/device.go` (`WithDeviceAuthorizationStore`, durable-without-key check), `test/storetest/oidcprovider_race.go` (race cases)

**Interfaces — Produces:**
```go
type DeviceState uint8
const ( DeviceIssued DeviceState = iota; DeviceClaimed; DeviceApproved; DeviceDenied; DeviceSpent )

type DeviceApproval struct {
  User identity.UserID; GrantedScopes []string; SignIn SignIn
  GrantFamily id.ID; Offline, EndsWithSignIn, SurvivesSignInEnd bool
}
type DeviceAuthorization struct {
  ID id.ID
  DeviceCodeDigest, UserCodeDigest, ClaimFlowDigest []byte
  ClientID string; Scopes, Resources []string
  IssuedAt, ExpiresAt, LastPolledAt time.Time
  Interval time.Duration; PollCount int
  State DeviceState
  Approval *DeviceApproval // nil until approved
}
var ErrUserCodeTaken = errors.New("oidcprovider: user code taken")

type DeviceAuthorizationStore interface {
  UnspentCodes // over Approved and Spent records' Approval.GrantFamily
  Create(ctx context.Context, record *DeviceAuthorization, now time.Time) error
  LoadByDeviceCode(ctx context.Context, digest []byte) (*DeviceAuthorization, error)
  LoadByUserCode(ctx context.Context, digest []byte, now time.Time) (*DeviceAuthorization, error)
  Claim(ctx context.Context, deviceID id.ID, flowDigest []byte, now time.Time) error              // Issued→Claimed
  Decide(ctx context.Context, deviceID id.ID, approval *DeviceApproval, now time.Time) error       // Claimed→Approved (approval!=nil) / Denied (nil)
  RecordPoll(ctx context.Context, deviceID id.ID, seenPolls int, at time.Time, interval time.Duration) error // State∈{Issued,Claimed} && PollCount==seenPolls → PollCount+1
  Spend(ctx context.Context, deviceID id.ID, now time.Time) error                                 // Approved→Spent
  DeleteExpired(ctx context.Context, now time.Time) (int, error)                                  // expired, but Spent kept until ExpiresAt+1m
}
type MemoryDeviceAuthorizationStore struct{ /* mutex-guarded */ }
func NewMemoryDeviceAuthorizationStore() *MemoryDeviceAuthorizationStore
func WithDeviceAuthorizationStore(store DeviceAuthorizationStore) DeviceOption
// storetest (exported, test module):
func DeviceAuthorizationSuite(t *testing.T, newStore func(t *testing.T) oidcprovider.DeviceAuthorizationStore)
```
Every transition refuses with `ErrNotFound` and writes nothing when the state, the expiry (`now >= ExpiresAt`, except `RecordPoll`, which the provider calls only before expiry) or `PollCount` does not hold. Records are copied in and out: no aliasing of slices.

- [ ] **Step 1 (3.1):** Write the port with godoc stating the contract: digests only, no store clock, no digest in errors, the `Create` release-then-insert rule, and retention. Add `//go:generate` per `use-mockgen`. Write `TestDeviceStoreMock_Compiles` using the typed mock once. Verify with `go vet ./oidcprovider`.
- [ ] **Step 2 (3.2): Write the suite** and register it against a stub that answers `ErrNotFound` everywhere. Cases:
  - `Create/LoadByDeviceCode` round-trips every field.
  - `CreateDuplicateDeviceDigest` is refused, and the stored record is unchanged.
  - `CreateLiveUserCodeTaken` answers `errors.Is(err, ErrUserCodeTaken)`.
  - `CreateOverExpiredUserCode` succeeds, and `LoadByUserCode` returns the new record.
  - `LoadByUserCodeExpired` answers `ErrNotFound` at `now == ExpiresAt`.
  - Each transition from each wrong state answers `ErrNotFound` and changes nothing (table over states × transitions).
  - `DecideAfterExpiry` and `SpendAfterExpiry` are refused.
  - `RecordPollStaleCount` is refused.
  - `UnspentBySignIn` returns an approved record's family. It leaves out an `Offline && !EndsWithSignIn` record unless `includeOffline`, and leaves out a `SurvivesSignInEnd` record unless `includeOffline`. `UnspentByClient` returns approved families for that user and client.
  - `DeleteExpired` deletes expired issued/claimed/approved/denied records, keeps spent ones until `ExpiresAt+1m`, and keeps unexpired ones.
  - **`StoreClockCheat`** is a case against `broken_device_test.go`'s store, which compares with `time.Now()` instead of `now`. The suite, run with a `now` far from wall time, fails with a message naming `LoadByUserCode judged expiry by its own clock`.
  - See it fail against the empty stub.
- [ ] **Step 3 (3.3): Race cases** in `oidcprovider_race.go`, each with N=16 goroutines behind a start barrier:
  - `ClaimOnce`: exactly 1 nil.
  - `DecideApproveVsDeny`: exactly 1 nil, and the stored state matches the winner.
  - `RecordPollOnce` (same `seenPolls`): exactly 1 nil.
  - `SpendOnce`: exactly 1 nil.
  - `CreateConcurrentSameUserCode` (distinct device digests, the same user digest): exactly 1 nil, the rest `ErrUserCodeTaken`.
- [ ] **Step 4 (3.4):** Implement `MemoryDeviceAuthorizationStore` until the suite and race cases pass under `-race`. Wire it as the default in `New` when the grant is enabled. Then write `TestWithDeviceAuthorizationStore`:
  - a mock store is the one called on `AuthorizeDevice` (use a stub call path available now, or assert through `export_test.go`'s accessor);
  - a nil store, including a typed nil, fails naming the option;
  - a non-memory store without `WithUserCodeKey` fails naming `WithUserCodeKey`;
  - `*MemoryDeviceAuthorizationStore` given explicitly needs no key.
- [ ] **Step 5 (3.5):** `DeleteExpired` per the suite's sweep cases.
- [ ] **Step 6: Run** the `oidcprovider` and `test/storetest` rows.

### Task A4: Device authorization request (tasks 4.1–4.4) — Sonnet: reuses client authentication and scope rules the plan names

**Carried from A2's review:** `generate` and `mintDeviceCode` wrap the random source's error unchanged. `AuthorizeDevice` passes it through `porterr.SanitizeTo`, as `mintSecret`'s callers do, before it reaches a caller or a log. `userCodeDigest` is always given the raw code `generate` returns, never the displayed form.

**Files:**
- Create: `oidcprovider/deviceauthorize.go`, `oidcprovider/deviceauthorize_test.go`
- Modify: `oidcprovider/device.go` (`WithDeviceLifetime`, `WithDevicePollInterval`)

**Interfaces — Consumes:** `AuthenticateClient`, the authorization endpoint's scope/resource/bound validators (find them in `authorize.go`), `repeatedParam`, `mintDeviceCode`, `userCodeFormat`, the store. **Produces:**
```go
const ( DefaultDeviceLifetime = 600 * time.Second; DefaultDevicePollInterval = 5 * time.Second )
func WithDeviceLifetime(d time.Duration) DeviceOption
func WithDevicePollInterval(d time.Duration) DeviceOption
type DeviceAuthorizationRequest struct { Credentials ClientCredentials; Form, Query url.Values } // Format/LogValue redacted
type DeviceAuthorizationResponse struct {                                                       // Format/LogValue redacted
  DeviceCode, UserCode, VerificationURI, VerificationURIComplete string
  ExpiresIn, Interval int
}
func (p *Provider) AuthorizeDevice(ctx context.Context, req DeviceAuthorizationRequest) (*DeviceAuthorizationResponse, error)
```
Errors are `*Error{Code: …}` as `Token` uses: `invalid_client`, `invalid_request`, `unauthorized_client`, `invalid_scope`, `invalid_target`. A provider without the grant answers `unauthorized_client` (the chain never routes there anyway).

- [ ] **Step 1: Failing tests** (`TestAuthorizeDevice`, table, store mock with `.Times(0)` on refusals):
  - a wrong secret gives `invalid_client` and no `Create`;
  - `client_secret` in the Query gives `invalid_request`;
  - a code-only client gives `unauthorized_client`;
  - `scope` repeated gives `invalid_request`;
  - an empty `scope=` is treated as omitted;
  - a NUL byte or invalid UTF-8 in `scope` gives `invalid_request`, and `err.Error()` does not contain the value;
  - a disallowed scope gives `invalid_scope`;
  - a disallowed resource gives `invalid_target`;
  - an oversized scope gives `invalid_request`;
  - a valid public client gets 600/5, `VerificationURI` equal to the entry URL, and no complete URI;
  - a `DeviceCompleteURI` client gets `entryURL?user_code=<display>`, keeping any existing query;
  - the stored record holds the digests, and `bytes.Contains(gob/fmt dump, code)` is false for both codes;
  - a failing random source fails as a dependency error with no `Create`.
- [ ] **Step 2:** `TestDeviceLifetimeAndInterval` (table): 15 min gives `ExpiresIn` 900 and `ExpiresAt = now+900s`. These fail naming their option: 1 h, 59 s, an interval of 0, 61 s, and an interval ≥ the lifetime.
- [ ] **Step 3:** `TestAuthorizeDevice_UserCodeCollision`. The store mock answers `ErrUserCodeTaken` once, then nil, and the response carries the second code. Five `ErrUserCodeTaken` in a row give a dependency/server error and no sixth call. A store error other than `ErrUserCodeTaken` fails at once, without retrying.
- [ ] **Step 4:** Run red, implement, run the focused tests and the `oidcprovider` row.

### Task A5: User-code entry (tasks 5.1–5.6) — Opus: throttle-before-lookup and claim/park ordering

**Carried from A2's review:** `normalise` scans its input without a length limit. `EnterUserCode` caps the entered code's size before normalising it, refusing an oversized one as `ErrInvalidUserCode` charged to the throttle. It digests only `normalise`'s raw output, and compares any digest read back with `hmac.Equal`.

**Files:**
- Create: `oidcprovider/deviceentry.go`, `oidcprovider/deviceentry_test.go`
- Modify: `oidcprovider/store.go` (`PendingRequest.DeviceAuthorizationID id.ID`, `PendingRequest.DeviceUserCode string`), `oidcprovider/store_memory.go` (copy the new fields), `oidcprovider/pending.go` (`PendingView.Device *DeviceView`), `oidcprovider/device.go` (`WithUserCodeEntryLimiter`, the default guard), `oidcprovider/redaction_test.go`, `oidcprovider/errors.go`

**Interfaces — Produces:**
```go
const ( DefaultUserCodeEntryLimit = 5; DefaultUserCodeEntryWindow = 10 * time.Minute )
func WithUserCodeEntryLimiter(limiter ratelimit.Limiter) DeviceOption // nil (incl. typed nil) fails construction
func (p *Provider) UseUserCodeEntryLimiter(limiter ratelimit.Limiter) error // design D6: no-op if the consumer set one; same value no-op; different value ErrConfig; nil ErrConfig; concurrency-safe
var ErrInvalidUserCode = errors.New("oidcprovider: invalid user code")
var ErrUserCodeThrottled = errors.New("oidcprovider: user code entry throttled")
type DeviceEntryInput struct { UserCode, FlowSecret, BrowserSessionSecret, Source string; IdleTimeout time.Duration } // redacted
func (p *Provider) EnterUserCode(ctx context.Context, in DeviceEntryInput) (AuthorizeResult, error)
type DeviceView struct { UserCode string; RequestedAt time.Time } // client and scopes are already on PendingView
```
Order inside `EnterUserCode`:
1. `guard.Check(Source)`. When refused or the limiter errors, return `ErrUserCodeThrottled` and emit `UserCodeEntryThrottled` in A9.
2. Normalise. When it fails, record a failure and return `ErrInvalidUserCode`.
3. `LoadByUserCode`. `ErrNotFound`, an expired record, a decided or spent state, or a claim by another flow digest each record a failure and return `ErrInvalidUserCode`.
4. A record claimed by **this** flow digest: find its pending request by `DeviceAuthorizationID`, or park again if none exists, and redirect to the stage reached.
5. Otherwise `Claim` (`ErrNotFound` from it is `ErrInvalidUserCode`), then park a `PendingRequest` with `DeviceAuthorizationID`, `DeviceUserCode` = display form, `ClientID`, `Scopes`, `Resources`, `StageLogin`, then answer from the browser session (→ consent) or the login page, reusing `park`/`parkAt`/`answerFromSession`.

Step 4 needs a pending lookup by device ID. Add `PendingRequestStore`-independent tracking: the re-entry parks a **new** pending request whenever the old handle is unknown to this call. This is safe, because the device record stays bound to the flow digest and only that browser can drive either request. Do not widen `PendingRequestStore`.

- [ ] **Step 1 (5.1):** `TestEnterUserCode_Throttle`:
  - after 5 invalid entries from `"198.51.100.7"`, a sixth entry carrying a **valid** code gives `ErrUserCodeThrottled`, with the store mock's `LoadByUserCode` `.Times(5)` overall;
  - a limiter whose methods return an error gives `ErrUserCodeThrottled`;
  - `WithUserCodeEntryLimiter(mockLimiter)` is the limiter consulted;
  - a different source is unaffected.
- [ ] **Step 1b (5.1):** `TestUseUserCodeEntryLimiter` (table): with the default, the given limiter is consulted afterwards; when the consumer gave `WithUserCodeEntryLimiter`, nil is returned and the consumer's limiter is still consulted; the same limiter twice gives nil; a different second limiter gives `ErrConfig`; nil and typed nil give `ErrConfig`; 8 concurrent calls with distinct limiters give exactly one nil (run with `-race`).
- [ ] **Step 2 (5.2):** `TestEnterUserCode_SingleRefusal` (table). The rows are unknown, expired (also at exactly `ExpiresAt`), claimed by another flow, approved, denied and spent. Each gives `errors.Is(err, ErrInvalidUserCode)`, `err.Error()` is identical across rows, a failure is charged (the limiter mock sees `Charge` or the guard's record call), and the record is unchanged.
- [ ] **Step 3 (5.3):** `TestEnterUserCode_ClaimAndPark`:
  - with no flow secret, the result's `FlowSecret` is non-empty and the `Location` is the login URL with `req=<handle>`;
  - with a valid browser session, the `Location` is the consent URL;
  - the stored record is `DeviceClaimed` with `ClaimFlowDigest` = the flow digest;
  - the parked request has the `DeviceAuthorizationID` and `DeviceUserCode` `BCDF-GHJK` (display form, even when entered as `bcdfghjk`);
  - the same browser re-entering reaches the stage reached (login, then consent after a login resume).
  - Add `TestEnterUserCode_ConcurrentClaims`: two flows with a barrier, exactly one `AuthorizeResult` and one `ErrInvalidUserCode`.
- [ ] **Step 4 (5.4):** `TestPendingRequest_DeviceView`. `view.Device.UserCode == "BCDF-GHJK"`, `RequestedAt` is the record's `IssuedAt`, and `ClientID`, `ClientName` and `Scopes` are filled. The view printed with `%+v` contains neither the device code, the handle nor the flow secret. A non-device request has `Device == nil`.
- [ ] **Step 5 (5.5):** add `DeviceEntryInput`, `DeviceAuthorizationRequest` and `DeviceAuthorizationResponse` to `redaction_test.go`'s table (`%v %+v %#v %s` and `slog` JSON).
- [ ] **Step 6 (5.6):** `TestEnterUserCode_ParkFailsAfterClaim`. The pending store mock fails `Create` once, giving a dependency error (`errors.Is(err, ErrDependency)` or the package's matcher). The record is claimed. The same flow re-enters and reaches login. Another flow gets `ErrInvalidUserCode`.
- [ ] **Step 7:** Run red per step, implement, and run the `oidcprovider` row.

### Task A6: Consent and resume for device requests (tasks 6.1–6.5) — Opus: two-record ordering with a half-applied case

**Files:**
- Modify: `oidcprovider/consent.go` (`consentNeeded`: a device request returns true first), `oidcprovider/resume.go` (`resumeConsent` device branch, plus the login-stage expiry check), `oidcprovider/browsersession.go` (only if `answerFromSession`'s skip-consent path needs the same rule)
- Test: `oidcprovider/device_consent_test.go`

**Rules:**
- A device request is one with `DeviceAuthorizationID != id.Nil` (or the package's zero ID).
- Approval sequence: load the device record. Expired gives `RedirectTo = entryURL?result=expired`. Otherwise call `Decide(approval)`, with `GrantFamily` newly minted, `Offline` meaning `offline_access ∈ granted`, `EndsWithSignIn` from the client, and `SurvivesSignInEnd = rc.DeviceGrantsOutliveSignIn && !Offline`. `ErrNotFound` from `Decide` gives `result=expired` when expired, otherwise `ErrUnknownHandle`. Then `Advance(StageConsent→StageDone)`, then remember consent, then `RedirectTo = entryURL?result=approved`.
- Denial: `Decide(nil)`, `Advance`, no consent remembered, `result=denied`. Existing consent-denied event semantics apply.
- The login stage resumed after `ExpiresAt` redirects with `result=expired` and parks nothing further.
- `result` is the only query parameter added. An existing entry-URL query is kept.

- [ ] **Step 1 (6.1):** `TestConsentNeeded_Device` (table: first-party, offline pre-authorized native, consent remembered for all scopes). Each is `true` for a device request and unchanged for a non-device one.
- [ ] **Step 2 (6.2):** `TestResume_DeviceApprove`. Granting `openid` of `openid offline_access` gives a record with `Approval.GrantedScopes == ["openid"]`, `Offline` false, a non-zero `GrantFamily` and the approving `SignIn`. `RedirectTo` parses to the entry URL with `result=approved` and no other added parameter. `Consents` lists the client.
- [ ] **Step 3 (6.3):** `TestResume_DeviceDeny`: the state is `DeviceDenied`, `result=denied`, and `Consents` is empty.
- [ ] **Step 4 (6.4):** `TestResume_DeviceExpired` (table: consent at `ExpiresAt-1ns` is approved; at `ExpiresAt` and later, and the login stage resumed after expiry, give `result=expired` and the record is not approved).
- [ ] **Step 5 (6.5):** `TestResume_DeviceAdvanceFailsAfterDecide`. The pending store mock fails `Advance`, giving a dependency error. The device record is approved. Re-entry of the code gives `ErrInvalidUserCode`. A resume again does not call `Decide` a second time with success, and no second consent is recorded.
- [ ] **Step 6:** Run red, implement, and run the `oidcprovider` row.

### Task A7: Token endpoint — dispatch, states and slow_down (tasks 7.1–7.4) — Opus

**Files:**
- Create: `oidcprovider/devicetoken.go`, `oidcprovider/devicetoken_test.go`
- Modify: `oidcprovider/exchange.go` (dispatch case only; `newGrant` gains a sibling `newDeviceGrant(record *DeviceAuthorization, rc *RegisteredClient, binding Binding, holdsLineage bool, now, expiresAt time.Time) *Grant`, without changing `newGrant`'s signature), `oidcprovider/store.go` (`Grant.Origin GrantOrigin`, `Grant.SurvivesSignInEnd bool`, `type GrantOrigin uint8; const (OriginCode GrantOrigin = iota; OriginDevice)`), `oidcprovider/errors.go` (`CodeAuthorizationPending`, `CodeSlowDown`, `CodeAccessDenied` if absent, `CodeExpiredToken`)

**Dispatch:** in `Token`, `GrantDeviceCode` is accepted only when `p.DeviceEnabled()`. Otherwise it gives `unsupported_grant_type`. `requireBinding` stays ahead of every grant.

**Poll algorithm (`p.pollDevice`):**
1. Get the digest of `device_code`. A missing code gives `invalid_request`.
2. `LoadByDeviceCode`. `ErrNotFound` gives `invalid_grant`. Any other error is a dependency failure (never pending).
3. `ClientID != rc.ID` gives `invalid_grant`, with nothing written.
4. `State == Spent` goes to replay (A8 step).
5. `now >= ExpiresAt` gives `expired_token`.
6. `Denied` gives `access_denied`.
7. `Approved` goes to the exchange.
8. `Issued`/`Claimed`: when `now < LastPolledAt+Interval` (and `LastPolledAt` is set), `RecordPoll(seen, now, Interval+5s)` and answer `slow_down`. Otherwise `RecordPoll(seen, now, Interval)` and answer `authorization_pending`. `ErrNotFound` from `RecordPoll` gives `slow_down`. Any other error is a dependency failure.

**Exchange:**
1. Load the user; missing or disabled gives `invalid_grant`.
2. Check the sign-in-end rule (D8). The union `UnspentCodes` of A8 handles an end recorded **before** the poll, through the grant's revocation. Here, check `Approval.SignIn.AbsoluteExpiresAt` against `now` for a grant that would not survive.
3. Run `Spend`. `ErrNotFound` gives `invalid_grant`.
4. Build `newDeviceGrant`, with `CodeID = record.ID`, `Origin = OriginDevice`, `Family = Approval.GrantFamily`, and `ExpiresAt` capped at `SignIn.AbsoluteExpiresAt` unless `Offline || SurvivesSignInEnd`.
5. Issue through the same issuer path `exchangeCode` uses, with no `nonce`.
6. When the grant is created over a recorded revocation (read it back as `exchangeCode` does), answer `invalid_grant` and issue nothing.

- [ ] **Step 1 (7.1):** `TestToken_DeviceDispatch` (table): a provider without the grant gives `unsupported_grant_type`; a client without the grant gives `unauthorized_client`; a `RequireBinding: BindingDPoP` client without a proof gives `invalid_dpop_proof` with no store call.
- [ ] **Step 2 (7.2):** `TestToken_DeviceStates` (table):
  - issued and claimed give `authorization_pending`;
  - denied gives `access_denied`;
  - expired gives `expired_token`, at exactly `ExpiresAt` too, and for approved-but-expired as well;
  - an unknown code gives `invalid_grant`;
  - another client's code gives `invalid_grant`, and the record compares equal before and after.
- [ ] **Step 3 (7.3):** `TestToken_DeviceSlowDown`:
  - polls at t=0 (pending), t=2 s (`slow_down`, interval 10 s), and t=8 s (`slow_down`, 6 s after the previous poll, as the spec scenario says), then t=19 s (pending);
  - `TestToken_DeviceConcurrentPolls` with a barrier: 2 goroutines after the interval give exactly one pending and one `slow_down`;
  - approved, denied and expired records polled at 1 s intervals are answered by their state, with no `RecordPoll` call (mock `.Times(0)`).
- [ ] **Step 4 (7.4):** `TestToken_DeviceExchange`:
  - `openid offline_access` for a refresh-registered client gives access, ID and refresh tokens. The ID token has no `nonce` claim, and its `auth_time` equals the approving `SignIn.AuthenticatedAt`. The stored grant has `Origin == OriginDevice`, `CodeID == record.ID` and `Family == Approval.GrantFamily`;
  - a client not registered for refresh gets no refresh token;
  - a user disabled after approval gives `invalid_grant`, no grant row (`grants.Load` gives `ErrNotFound`) and the record not spent;
  - a sign-in absolute deadline passed under the default, without `offline_access`, gives `invalid_grant` and no grant.
- [ ] **Step 5:** Run red, implement, and run the `oidcprovider` row.

### Task A8: Exchange concurrency, replay, DPoP, failures, sign-in end (tasks 7.5–7.9, 8.1–8.4) — Opus: races and revocation reach

**Carried from A3's review:** the device store's `UnspentBySignIn` already leaves out `SurvivesSignInEnd` approvals unless `includeOffline`. The grant store's own sign-in end rule (`store_memory.go`, and later the SQL adapters) must apply the same `SurvivesSignInEnd` exclusion to stored grants, or ending a sign-in revokes a device grant that should outlive it.

**Files:**
- Modify: `oidcprovider/devicetoken.go`, `oidcprovider/provider.go` (join `UseCodes(unspentUnion{codes: …, devices: …})` when the grant is enabled; the union is a comparable **value** struct), `oidcprovider/store_memory.go` (`EndSignIns` selection becomes `(!g.Offline && !g.SurvivesSignInEnd) || g.EndsWithSignIn`), `oidcprovider/events.go` (the `survives` computation matches that rule), `oidcprovider/store.go` (`GrantStore.EndSignIns` godoc states the new rule)
- Create: `oidcprovider/unspent_union.go`, `oidcprovider/devicetoken_race_test.go`, `oidcprovider/device_signin_test.go`

**Interfaces — Produces:**
```go
type unspentUnion struct{ codes, devices UnspentCodes } // both methods concatenate; any error fails the call
```

- [ ] **Step 1 (7.5):** `TestToken_DeviceConcurrentExchange`: N=8 polls of one approved code behind a barrier give exactly 1 `*TokenResponse`, 7 `invalid_grant`, and one grant row.
- [ ] **Step 2 (7.6):** `TestToken_DeviceReplay` (table):
  - the same client after the exchange gives `invalid_grant`, and the refresh token and an opaque access token then fail (`invalid_grant` and `VerifyAccessToken` refused), with `RevokeCause == CauseCodeReplay`;
  - the replay at `ExpiresAt+59s` still revokes; after the sweep at `+61s` it gives `invalid_grant` with nothing revoked;
  - another client presenting the code revokes nothing;
  - a DPoP-bound grant replayed without the key's proof revokes nothing, and with the proof revokes.
- [ ] **Step 3 (7.7):** `TestToken_DeviceDPoP`: a public client's exchange with a proof gives `TokenType == "DPoP"` and a grant `KeyBinding` equal to the JKT; a refresh without a proof is refused.
- [ ] **Step 4 (7.8):** `TestToken_DeviceStoreDown`. The store mock errors on `LoadByDeviceCode`, then on `RecordPoll`. Each gives an error matching the package's dependency matcher, never an `*Error` with pending or slow_down. The captured log does not contain the device code.
- [ ] **Step 5 (7.9):** `TestToken_DeviceGrantCreateFails`. The grant store mock fails `Create` after `Spend`, giving a dependency error and no token. The record is spent with no grant row.
- [ ] **Step 6 (8.1–8.3):** `TestDeviceGrant_SignInEnd` (table):
  - under the default, a grant without offline is revoked by `EndSignIn` and one with offline survives;
  - under `DeviceGrantsOutliveSignIn`, a grant without offline survives;
  - `EndGrantsWithSignIn` revokes an offline device grant;
  - `RevokeConsent` and `RevokeUserGrants` revoke device grants;
  - `ExpiresAt` equals the sign-in's `AbsoluteExpiresAt` under the default without offline, and `now + GrantAbsoluteLifetime` when the grant survives.
  - Code-grant rows of the existing `EndSignIn` tests must stay green unchanged.
- [ ] **Step 7 (8.4):** `TestDeviceGrant_UnexchangedApproval` (table: `EndSignIn` without offline, `RevokeConsent`, `RevokeUserGrants`, each between approval and poll). The poll gives `invalid_grant` with no token, and the grant row is revoked.
  - `TestUnspentUnion_SecondProviderJoins`: two providers built over the same code, device and grant stores give `New` nil for both.
  - `TestUnspentUnion_ErrorFails`: when either side errors, the union errors.
- [ ] **Step 8:** Run red, implement, then the `oidcprovider` row. The `store/sqlstore` grant store changes in B1, so its grant suite may lag until then. Report any red there; do not fix it in this dispatch.

### Task A9: Events and expiry (tasks 9.1–9.2) — Sonnet: emission at points the plan names

**Files:**
- Modify: `event/event.go` (seven names), `oidcprovider/events.go` (report helpers), call sites in `deviceauthorize.go`, `deviceentry.go`, `resume.go`, `devicetoken.go`, and `oidcprovider/expiry.go` (task, godoc list)
- Test: `oidcprovider/device_events_test.go`, `oidcprovider/expiry_test.go` (rows)

**Names:**
```go
DeviceAuthorizationIssued   = "scrty_device_authorization_issued"
DeviceAuthorizationClaimed  = "scrty_device_authorization_claimed"
DeviceAuthorizationApproved = "scrty_device_authorization_approved"
DeviceAuthorizationDenied   = "scrty_device_authorization_denied"
DeviceCodeExchanged         = "scrty_device_code_exchanged"
DeviceCodeReplayed          = "scrty_device_code_replayed"
UserCodeEntryThrottled      = "scrty_user_code_entry_throttled"
```
The task is named `"oidc-provider.device-authorizations"` and runs `devices.DeleteExpired(ctx, clock.Now())`. It is present only when the grant is enabled.

- [ ] **Step 1:** `TestDeviceEvents` (table over the seven outcomes, with a recording sink). Exactly one event of the name fires. It names the client, and the user once known (approved, denied, exchanged and replayed). Its JSON contains neither code nor any 43-character base64url run. A replay also gives the existing grant-revoked event, once.
- [ ] **Step 2:** `TestExpiryTasks_Device`. The task is present with the grant and absent without it. It deletes an expired record and keeps a spent one at `ExpiresAt+30s`.
- [ ] **Step 3:** Run red, implement, and run the `event` row.

### Task B1: Migration and `sqlstore` (tasks 10.1–10.2) — Opus: durable conditional writes

**Carried from A3:** register the suite with `storetest.DeviceAuthorizationSuite`, and the races with `storetest.RunDeviceAuthorizationRaces(t, h)`, given a full `DurableHarness` whose `PoolSize` is at least `storetest.DeviceRaceRacers` (16), as `RunGrantRaces` is registered. The suite pins microsecond precision, a spent record swept at exactly `ExpiresAt+1m`, and a refused `Create` releasing nothing. `Create`'s release and insert must run in one transaction under the unique user-code index.

**Files:**
- Create: `store/migrate/securitystate/20261122000000_oidc_provider_device.sql`, `store/sqlstore/oidcprovider_device.go`, `internal/pgschema/oidcprovider_device.go` (shared SQL and arg mapping)
- Modify: `internal/pgschema` grant and pending mappings (new columns), `store/sqlstore/oidcprovider_grants.go` (`EndSignIns` rule), `store/sqlstore/oidcprovider_stores.go` (pending columns), `test/migrate_securitystate_test.go`, `test/sqlstore/` (suite registration)

**Schema** (no foreign keys, `''`/`false`/`0` defaults, as the existing set does):
- `op_device_authorizations`:
  - `id` PK;
  - `device_code_digest bytea UNIQUE NOT NULL`;
  - `user_code_digest bytea NULL`, with a partial `UNIQUE` index where not null;
  - `client_id`, `scopes` jsonb, `resources` jsonb;
  - `issued_at`, `expires_at`, `last_polled_at` (nullable), `interval_ms bigint`, `poll_count int`;
  - `state smallint`, `claim_flow_digest bytea`;
  - approval columns (`user_id`, `granted_scopes` jsonb, `sign_in` jsonb, `grant_family`, `offline`, `ends_with_sign_in`, `survives_sign_in_end`);
  - indexes on `expires_at` and on `(user_id, client_id)`, plus the sign-in lookup that `UnspentBySignIn` needs, matching how `op_authorization_codes` indexes it.
- `op_grants` adds `origin smallint NOT NULL DEFAULT 0` and `survives_sign_in_end boolean NOT NULL DEFAULT false`.
- `op_pending_requests` adds `device_authorization_id text NOT NULL DEFAULT ''` and `device_user_code text NOT NULL DEFAULT ''`.
- The Down section drops exactly these.

`Create` runs in one transaction: `UPDATE … SET user_code_digest = NULL WHERE user_code_digest = $1 AND expires_at <= $now`, then `INSERT`. A unique violation on the user-code index maps to `ErrUserCodeTaken`, and on the device digest to a plain error. Each transition is one `UPDATE … WHERE id = $1 AND state = $from AND expires_at > $now [AND poll_count = $seen]`, and zero rows gives `ErrNotFound`. No error text carries a digest.

- [ ] **Step 1 (10.1):** `TestMigrateSecurityState_DeviceGrant` in `test/`. Populate grants and pending requests through the previous migrations, then apply. Check that the table exists, existing grants read `Origin == OriginCode` and `SurvivesSignInEnd == false`, and pending rows are unchanged with empty device columns. A rollback leaves the table and the 4 columns gone and every other column intact (compare `information_schema.columns` before and after). See it fail, then write the SQL.
- [ ] **Step 2 (10.2):** Register `storetest.DeviceAuthorizationSuite`, the race cases and the existing grant and pending suites against `sqlstore` on PostgreSQL 15 and 18. Add `PollCASSurvivesRoundTrip`, a suite case in A3's file that **B1 may extend** (this file passes to B1 after A3): `RecordPoll` with times carrying nanoseconds still succeeds after a reload. See the failures, then implement.
- [ ] **Step 3:** Run the store rows.

### Task B2: `pgxstore` (task 10.3) — Sonnet: mirrors B1's SQL through `internal/pgschema` · runs parallel to B3

**Files:** `store/pgxstore/oidcprovider_device.go`, the pgx grant `EndSignIns` rule and the pending columns in `store/pgxstore`, and registration in `test/pgxstore/`.
- [ ] Register the suites first (red), implement, and run the pgxstore row on PostgreSQL 15 and 18.

### Task B3: `gormstore` (task 10.4) — Sonnet · parallel to B2

**Files:** `store/gormstore/oidcprovider_device.go`, the gorm grant rule and pending columns in `store/gormstore/oidcprovider_stores.go`, and registration in `test/gormstore/`.
- [ ] Same as B2 for GORM.

### Task C1: Chain endpoints and throttles (tasks 11.1–11.5) — Opus: TLS, throttle namespaces, flow-cookie conversion

**Files:**
- Create: `httpsec/oidc_device.go` (both handlers and their options), `httpsec/oidc_device_test.go`
- Modify: `httpsec/oidc_provider_options.go` (`OIDCDeviceAuthorization`, `OIDCDeviceEntry` before `oidcEndpointCount`, names, suffixes `/device-authorization` and `/device`), `httpsec/oidc_provider.go` (register only when `provider.DeviceEnabled()`; pass the factory limiter), `httpsec/oidc_options.go` if per-endpoint limiter options live there, and the endpoint inventory, base-path, moved-path and collision tests (new rows only)

**Interfaces — Consumes:** `Provider.AuthorizeDevice`, `Provider.EnterUserCode`, `Provider.DeviceEnabled() bool` (A1), `Provider.UseUserCodeEntryLimiter` (A5), `WithUserCodeEntryLimiter`, `DefaultUserCodeEntryLimit` and `DefaultUserCodeEntryWindow`. **Produces:** `WithOIDCDeviceAuthorizationLimiter(limiter ratelimit.Limiter) OIDCProviderOption`, with the default `oidc-device-authorization` namespace at 10 per 15 minutes, built like `oidcTokenGroup`'s throttle.

`EnableOIDCProvider`, when a `WithRateLimiterFactory` is configured and the device grant is enabled, builds `factory.NewLimiter("oidc-device-entry", oidcprovider.DefaultUserCodeEntryLimit, oidcprovider.DefaultUserCodeEntryWindow)` and calls `provider.UseUserCodeEntryLimiter` during the chain's `New`. An error from either fails `New`, naming `EnableOIDCProvider` (design D6).

- [ ] **Step 1 (11.1):** new rows in the inventory, base-path, moved-path and collision tests. Both paths appear only with the grant, and `WithOIDCProviderPath(OIDCDeviceEntry, "/activate")` moves it.
- [ ] **Step 2 (11.2):** `TestDeviceAuthorizationEndpoint` (table):
  - a GET gives 405, with no `AuthorizeDevice` call (the provider is built over a store whose `Create` would fail the test);
  - plain HTTP on an https issuer is refused;
  - a valid POST gives 200 with JSON `{device_code,user_code,verification_uri,expires_in,interval}` and `Cache-Control: no-store`;
  - an `*oidcprovider.Error` gives the token endpoint's error body and status.
- [ ] **Step 3 (11.3):** `TestDeviceAuthorizationEndpoint_Throttle`. 10 wrong secrets, then a correct one, give `invalid_client`. The token endpoint from the same source is still judged on its own (a valid token request succeeds).
- [ ] **Step 4 (11.4):** `TestDeviceEntryEndpoint`:
  - GET `?user_code=` gives 303 to login, with the flow cookie set;
  - a POST with the cookie gives 303;
  - a POST without the cookie gives 303 to `/oauth2/device?user_code=…`, with no `Set-Cookie`;
  - plain HTTP is refused;
  - behind `WithTrustedProxies`, two `X-Forwarded-For` client addresses each get their own 5-failure budget: the 6th from address A is 429, while address B still gives 400.
- [ ] **Step 5 (11.5):** `TestDeviceEntry_FactoryLimiter`. With a recording factory, the chain asks for `oidc-device-entry` with (5, 10 min), and that limiter is the one consulted on entry. A provider whose consumer gave `WithUserCodeEntryLimiter` keeps it: the factory's limiter is never consulted. A factory error fails `New`.
- [ ] **Step 6:** Run red, implement, and run the `httpsec` row.

### Task C2: CSRF, CORS, metadata, error mapping (tasks 11.6–11.9) — Sonnet

**Files:** `httpsec/csrf_exemption.go` (`providerEndpointsExempt` gains `OIDCDeviceAuthorization` **only when registered**: a nil or absent path must not create an exemption for `""`), `httpsec/oidc_cors.go`, `httpsec/oidc_metadata.go` (derive `grant_types_supported`; add `device_authorization_endpoint`), the error-propagation helper that maps provider errors (`ErrInvalidUserCode` → 400, `ErrUserCodeThrottled` → 429, both status-only), and tests beside each.
- [ ] **Step 1 (11.6):** `TestCSRF_DeviceEndpoints`. A POST to device authorization with no `Origin` and no `Sec-Fetch-Site` passes. A POST to `/oauth2/device` with `Sec-Fetch-Site: cross-site` is refused, and the device record stays `DeviceIssued`. With the grant off, no exemption exists for the path.
- [ ] **Step 2 (11.7):** `TestCORS_DeviceEndpoints`: an allowed origin hitting either endpoint (preflight and actual request) gets no `Access-Control-*` header.
- [ ] **Step 3 (11.8):** `TestMetadata_Device` (table: enabled or not × both documents × a moved path). The exact `grant_types_supported` slices from the spec. `device_authorization_endpoint` is `issuer + "/oauth2/device-authorization"`, or the moved path. The code-entry path never appears in either document.
- [ ] **Step 4 (11.9):** `TestErrorPropagation_UserCode`: 400 and 429, with an empty body.
- [ ] **Step 5:** Run red, implement, and run the `httpsec` row.

### Task D1: Documentation (tasks 12.1–12.3) — Sonnet

**Files:** godoc across the new identifiers (comment-only edits in files A1–A9 created; D1 runs after A9, so no conflict), `oidcprovider/example_device_test.go`, `README.md` ("CLI clients"), `test/example_device_cli_test.go` (README snippet as a compiling example), `CHANGELOG.md`.
- [ ] `ExampleWithDeviceAuthorization` with a public native client and output-less body, plus `go test -run Example -count=1 ./oidcprovider`.
- [ ] README "CLI clients" covers:
  - loopback + PKCE first;
  - the device grant with `oauth2.Config.DeviceAuth` and `DeviceAccessToken`;
  - the entry-page contract: a form posting `user_code` to the code-entry endpoint, `result=approved|denied|expired`, and never auto-submitting a prefilled code;
  - phishing guidance (enable only for clients that need it; keep `DeviceCompleteURI` off unless a TV/QR client);
  - `WithUserCodeKey` being required for durable stores and shared across replicas;
  - the accepted distributed-guessing limit, and the global-key limiter option.
- [ ] CHANGELOG under the next minor: the option, the device options, the two client fields, `GrantDeviceCode`, the store port and memory store, the migration, the events, and `Grant.Origin` and `SurvivesSignInEnd`.
- [ ] Verify `go doc ./oidcprovider WithDeviceAuthorization` names each default, and the example tests pass. `make spec-check` is run by the main session at E2.

### Task E1: End-to-end (task 13.1) — Sonnet: assembles tested parts in the test module

**Files:** `test/oidcprovider_device_test.go`.
- [ ] `TestOIDCProvider_DeviceGrantEndToEnd` (table: in-memory stores; sqlstore on PostgreSQL 18):
  1. An `httptest` TLS chain with the provider.
  2. `oauth2.Config.DeviceAuth`.
  3. A scripted browser (cookie jar) GETs `/oauth2/device?user_code=` and follows the redirect to login.
  4. It resumes with a sign-in, receives consent, and approves `openid offline_access`.
  5. `DeviceAccessToken` returns tokens.
  6. A refresh through `TokenSource` succeeds.
  7. Replaying the device code at the token endpoint gives `invalid_grant`, and the refresh then fails.
- [ ] Run `(cd test && go test -race -count=1 -run TestOIDCProvider_DeviceGrantEndToEnd ./...)`.

### Task E2: Final gate (task 13.2) — main session

- [ ] Run `make check` (the full suite, the only full run), `make spec-check` and `openspec validate oidc-provider-device-grant --strict`. Keep all three outputs.

### Task E3: Whole-branch review (task 13.3) — Opus reviewer

- [ ] A fresh Opus reviewer, given the specs and design but not this plan's conclusions, first enumerates how the change fails, category by category (`defensive-coding.md`), then checks every requirement and scenario in `specs/`. Findings follow `defect-claims.md`. They are fixed in a fresh dispatch of the owning lane, then E2 runs again.

---

## Not in a task

- `tasks.md` 0.1 (gate on `split-ci-jobs` being archived) was waived by the user on 2026-11-22 ("not tightly related to this change"). It stays unticked, and is noted at archive time.
