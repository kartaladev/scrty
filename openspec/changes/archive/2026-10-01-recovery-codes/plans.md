# recovery-codes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Account recovery with two independent proofs. Saved and issued recovery codes lead to a confined recovery-pending session, which becomes full only once a new authenticator is bound. The authenticators are reset, other sessions end, the user is notified, and opt-in holds and a cool-down are available.

**Architecture:**
- A new core package, `recovery`, owns:
  - saved-code generation and parsing, plus the `Codes` manager;
  - the authenticator-reset port and its MFA adapter;
  - the recovery-record store contract;
  - the flow (`Recoverer`: start, recover, finish, cancel);
  - the way-back check.
- `session` gains a recovery-pending state and `RecoveredAt`. `factor` gains `Recovery`.
- `httpsec` only parses, gates and responds:
  - unauthenticated endpoints at `OrderAccountRecoveryEndpoints` (375);
  - the recovery gate and the saved-code endpoints at `OrderAccountRecovery` (598);
  - the cool-down at `After(OrderBearerToken)`.
- The durable stores are `sqlstore`, `pgx` and `gorm`, over shared SQL in `internal/pgschema`. The schema is added in place to the single security-state migration.

**Tech Stack:** Go 1.27, `onetime`, `ratelimit`, `notify`, `pkg/clock` with clockwork fakes in tests, testify, mockgen (`use-mockgen`), testcontainers PostgreSQL (`use-testcontainers`, the `test` module), gopls.

**Spec:** `openspec/changes/recovery-codes/`: `proposal.md`, `design.md` (D1–D15), `specs/account-recovery`, `specs/sessions`, `specs/identity-model`, `specs/http-security-chain`, `specs/http-error-propagation`, `specs/multi-factor-auth`, `specs/security-policy`, `specs/security-state-stores`, `specs/schema-migrations`, `specs/store-conformance`, and `tasks.md`. Task numbers below (`1.1`…`7.3`) are `tasks.md`'s.

## Global Constraints

- **Saved codes:**
  - 16 bytes from the configured random source, written as 26 Crockford base32 characters (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`) grouped `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XX`, with the first character in `0`–`7`.
  - Parsing folds case, drops `-`, and maps `O→0`, `I→1`, `L→1`. Any other character is refused.
  - Stored as `sha256.Sum256(decoded16)`, looked up by (user, hash).
- **Defaults:**
  - set size 10 (range 1–100); low threshold 2;
  - saved-code limiter 5 per 15 minutes under key `recovery-code|<user>`;
  - issued-code TTL 15 minutes (≤ 24 hours); issuance limit 5 per one-time window;
  - start source guard 10 per hour (flow `account-recovery-start`);
  - complete source guard 10 failures per 15 minutes (flow `account-recovery`);
  - per-user recovery limiter 5 per 15 minutes under `recovery|<user>`;
  - recovery session lifetime 15 minutes; regeneration freshness 15 minutes; completion window 24 hours;
  - holds off; cool-down off.
- **One-time purposes:** `account-recovery`, `account-recovery-finish` and `account-recovery-cancel`. The subject is the user reference for the first, and the record ID for the other two.
- **Default paths:** `/recovery/start`, `/recovery/complete`, `/recovery/finish`, `/recovery/cancel` and `/recovery/codes`.
- **Form fields:** `username`, `saved_code`, `issued_code`, `password`, `mfa_method`, `mfa_code` and `lost` (repeatable, `kind:id`), plus `completion_token` and `cancel_token`. The body is URL-encoded, at most 16 KiB, and the query is never read.
- **Proof shape:** exactly two enabled kinds, different from each other, at least one of them `saved` or `issued`. Anything else is `recovery.ErrMalformed`.
- **Recovery order:**
  1. throttles;
  2. resolve the user;
  3. check the codes without spending;
  4. pre-authentication phase, then the password;
  5. the MFA method's eligibility, the plan, the risk hook and the consumer checks;
  6. spend the MFA proof, then `Consume` the issued code, then `Spend` the saved code.
- **Completion order:** record, reset, revoke, reissue or remaining, create and mark the session and save it, respond, notify.
- **Sentinels, in `recovery/errors.go`:**

  | Sentinel | Status |
  |---|---|
  | `ErrConfig` | — |
  | `ErrRefused` (wraps `authenticate.ErrAuthenticationFailed`) | 401 |
  | `ErrMalformed` | 400 |
  | `ErrNotYetCompletable` | 409 |
  | `ErrCooldown` | 403 |
  | `ErrReauthenticationRequired` | 403 |
  | `ErrCodeThrottled` (wraps `ratelimit.ErrThrottled`) | 401 |
  | `ChallengeError{Kind: policy.ChallengeAccountRecovery}` | 403 |

- **No code, token, username or contact address** appears in any log record or error text.
- **`session.MFARecoveryPending`** is appended after `MFAEnrolmentPending`. The confinement marker is the existing `EnrolmentOriginDeadline`.
- **Godoc:** every new option names the default it replaces (`library-design.md`). Every in-memory default states its single-process limit.
- **Test-first** (`golang-tdd.md`): red for the intended reason, where a compile error is not red. Tables follow the `table-test` skill (the `assert` closure, `t.Context()`). Mocks come from mockgen per `use-mockgen`. PostgreSQL comes through the `test` module's helper per `use-testcontainers`.
- **No git command that discards work. No edit under `openspec/`.**

## Review Focus

1. **A form carrying `saved_code` twice** (two values). Expected: refused as `ErrMalformed` (400) before anything is checked, never "first value wins". Pinned in 6.3.
2. **An issued code minted for `u-2` presented with `username=u-1`**, together with `u-1`'s valid saved code. Expected: `ErrRefused`, with neither code spent. Pinned in 4.2.
3. **A finish token posted to the cancel endpoint** (wrong purpose). Expected: 204 as always, nothing cancelled, and the finish token still completes. Pinned in 6.5.
4. **A recovery-pending session posting to `/recovery/codes`.** Expected: refused with the account-recovery challenge (403), and no set generated. Pinned in 6.1.
5. **The same user completing two recoveries back to back** (two tabs). Expected: the second revokes the first's recovery-pending session, so only the latest loads. Pinned in 4.3.

---

## Dispatch map

Lanes run in parallel where they own disjoint files and compile independently. Within a lane, dispatches run in order.

| Dispatch | Tasks | Owns | Must not touch | Starts after | Model | Why |
|---|---|---|---|---|---|---|
| A1 | 1.1–1.2 | `factor/**`, `session/**`, every in-root caller of `MFAState` switches (`httpsec/*` only where a `switch s.MFA` needs the new case to compile or stay exhaustive) | `recovery/**`, `test/**`, drivers | — | Opus | Session deadline semantics that later lanes compile against |
| B1 | 2.1–2.3 | `recovery/codes*.go`, `recovery/errors.go`, `recovery/doc.go`, `recovery/store*.go` (code store), `recovery/*_mock_test.go` it generates | `session/**`, `httpsec/**` | — (parallel with A1) | Opus | Security-critical parsing, hashing and throttling |
| B2 | 3.1–3.4 | `recovery/reset*.go`, `recovery/records*.go`, `recovery/wayback*.go`, their tests | `session/**`, `httpsec/**`, `recovery/codes*.go` except to call it | B1 | Opus | Reset policy and fail-closed lookups |
| C1 | 5.1–5.2 | `migrate/securitystate/*.sql`, `internal/pgschema/sessions.go`, `sqlstore/session.go`, `pgx/session.go`, `gorm/models.go`, `gorm/session.go`, `test/migrate_securitystate_test.go`, `test/storetest/session_suite.go`, `test/crossbackend/**` | `recovery/**`, `httpsec/**` | A1 (parallel with B2) | Sonnet | Column threading along an existing pattern |
| B3a | review fixes of B2, 4.1–4.2 | `recovery/recoverer*.go`, `recovery/messages*.go`, `recovery/start*.go`, `recovery/recover*.go`, their tests; `recovery/plan*.go`, `recovery/mfakind*.go`, `recovery/records_mem*.go` for the fixes | `session/**`, drivers, `test/**` | A1, B2 | Opus | Check-then-consume across four proofs, races |
| B3b | 4.3–4.4 | `recovery/complete*.go`, `recovery/hold*.go`, `recovery/recoverer*.go`, `recovery/recover*.go` (wiring `Recover`), their tests | `session/**`, drivers, `test/**`, the other `recovery/` files except to call them | B3a | Opus | Completion order, holds, the finish–cancel race |
| B3b-fix | 4.4 after the D10 revision, review findings of B3b | `recovery/hold*.go`, `recovery/complete*.go`, `recovery/messages*.go`, `recovery/plan*.go`, `recovery/recoverer*.go`, their tests | the other `recovery/` files except to call them | B3b | Opus | Hold voiding, finish order, error-path coverage |
| C2a | 5.3–5.4 | `internal/pgschema/recovery*.go`, `sqlstore/recovery*.go`, `test/storetest/recovery*_suite.go`, `test/storetest/broken_recovery_test.go`, `test/storetest/memory_test.go` (append only), `test/internal/storefix/recovery.go`, `test/sqlstore/recovery*_test.go` | `recovery/**` | B2, C1 (parallel with B3a) | Opus | Conditional writes, savepoints, race suites |
| C2b | the 5.4 overlapping-replacement fix, 5.5 | `internal/pgschema/recovery*.go`, `sqlstore/recoverycode.go`, `pgx/recovery*.go`, `gorm/recovery*.go`, `gorm/models.go` (append only), `test/internal/storefix/recovery.go`, `test/{sqlstore,pgxstore,gormstore}/recovery*_test.go`, `test/gormstore/statements_test.go` if needed, `test/crossbackend/**` | `recovery/**` | C2a (parallel with B3b) | Opus | Per-user serialisation of replacements, three drivers |
| D1 | 6.1–6.2 | `policy/policy.go` (append the kind), `httpsec/order.go`, `httpsec/recoverygate*.go`, `httpsec/bearer.go`, `httpsec/mfaenrol.go`, `httpsec/passwordchange.go`, `httpsec/status.go`, `recovery/errors.go` (append two sentinels), their tests | `recovery/recoverer*.go`, drivers | B3 | Opus | Confinement gate and refusal mapping |
| D1-fix | 6.2 step 3a | `policy/enrolmentpath.go` and its tests, `httpsec/recoverybind_test.go` | everything else | D1 | Sonnet | A default list and its tests, fully specified |
| D2 | 6.3–6.4 | `httpsec/recovery*.go` (complete, start, options), `httpsec/options.go` (build wiring), `httpsec/flush*.go` if needed, their tests | `recovery/**` except reading | D1 | Opus | Endpoint wiring over security logic |
| D2-fix | 6.3–6.4 review findings | `recovery/recover*.go`, `recovery/complete*.go`, `recovery/recoverer*.go`, `httpsec/recovery*.go` (not the gate), their tests | everything else | D2 | Opus | Timing enumeration, the credential path, proof gating |
| D3 | 6.5–6.7 | `httpsec/recoveryhold*.go`, `httpsec/recoverycodes*.go`, `httpsec/recoverycooldown*.go`, `httpsec/logincomplete.go`, their tests, `fibersec`/`ginsec` tests if affected | `recovery/**` except reading | D2 | Opus | Login-path side effect and fail-closed guard |
| D3b | 6.6, the login-cancel move, the OIDC cancel test | `recovery/regenerate*.go`, `httpsec/recoverycodes*.go`, `httpsec/recoverygate.go`, `httpsec/recoveryoptions.go`, `httpsec/recoverycomplete.go`, `httpsec/logincomplete.go`, their tests | other `recovery/` files | D3 | Opus | The core-owned regeneration notice, freshness, login-path ordering |
| D3-fix | 6.6 review findings | `httpsec/recoverycodes*.go`, `httpsec/recoveryhold_test.go` | everything else | D3b | Sonnet | One condition and test pins, fully specified |
| E1 | 7.1 | `test/httpsecconformance/**`, `test/httpsec_*_test.go` | everything else | C2, D3 | Sonnet | Scenario plumbing over a finished API |
| E2 | 7.2 | `README.md`, `recovery/example_test.go` | everything else | D3 (parallel with E1) | Sonnet | Documentation plus a compiled example |
| E1-fix | 7.1: each recovery endpoint driven over HTTP | `test/httpsecconformance/**` | everything else | E1 | Sonnet | Scenario plumbing, shared durable one-time store |
| F-A | whole-branch review fixes | `recovery/wayback*.go`, recovery and httpsec test files, `README.md` | everything else | 7.3 review | Sonnet | One wrap, test pins, a README note |
| F-B | whole-branch review: `/recovery/codes` over HTTP | `test/httpsecconformance/**` | everything else | 7.3 review (parallel with F-A) | Sonnet | Scenario plumbing |
| — | 7.3 | main session | — | E1, E2 | — | Final gate and whole-branch review |

Each dispatch is followed by the main session's verification run and a fresh reviewer against its spec requirements (`subagent-delegation.md`).

**Why B3 and C2 were split:** each covers four tasks with heavy tests, so each is split at its natural seam to keep a dispatch reviewable. The B2, B3a and C2a reviews' findings travelled as the first step of the lane's next dispatch.

**Why B and D are sequential lanes:**
- B's dispatches share the `recovery` package, so a half-written file from one would break the other's `go test`.
- D's dispatches share `httpsec` and its option wiring.

---

### Task 1.1: `factor.Recovery`

**Files:**
- Modify: `factor/factor.go:28-33` (the kinds) and `:57` (`Channel`)
- Modify: `factor/export_test.go` (`AllKinds`)
- Test: `factor/factor_test.go`

**Interfaces:**
- Produces: `const Recovery Kind = "recovery"`. `Recovery.Channel() == ""` and `Recovery.MFAExempt() == false`.

- [ ] **Step 1: Write the failing test.** Add a row to the existing kind table in `factor/factor_test.go`:

```go
{
	name: "recovery reports no channel and is not exempt", kind: factor.Recovery,
	assert: func(t *testing.T, k factor.Kind) {
		assert.Equal(t, factor.Channel(""), k.Channel())
		assert.False(t, k.MFAExempt())
		assert.Equal(t, "recovery", string(k))
	},
},
```

Add `factor.Recovery` to `AllKinds` in `export_test.go`.

- [ ] **Step 2: Run** `go test -run 'TestKind' -count=1 ./factor/...`. **Expected:** it fails because `factor.Recovery` is undefined. That is a compile error, not a red step. So first add the constant with value `"password"`, and see the row fail on `string(k)`.
- [ ] **Step 3: Implement.** Add `Recovery Kind = "recovery"` with godoc: "the session an account recovery produces; it rested on two proofs of different kinds, so it reports no channel, and it is not exempt from MFA". `Channel()` returns `""` for it by falling through the existing default.
- [ ] **Step 4: Run** `go test -race ./factor/... ./identity/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(factor): the recovery first-factor kind`

### Task 1.2: The recovery-pending session

**Files:**
- Modify: `session/session.go:18-60` (state, `String`), `:63-156` (`RecoveredAt` field)
- Modify: `session/enrolment.go` (add `MarkRecoveryPending`, widen godoc of the marker and restore)
- Modify: `session/manager.go:366` (`Rotate` carries `RecoveredAt`, which it does if it copies the struct; the test proves it)
- Modify: `session/memory*.go` if the copy is field-by-field
- Test: `session/recovery_test.go`

**Interfaces:**
- Produces:
  ```go
  const MFARecoveryPending MFAState = iota + 4 // appended after MFAEnrolmentPending; String() "recovery-pending"
  type Session struct { /* … */ RecoveredAt time.Time }
  func (m *Manager) MarkRecoveryPending(s *Session, lifetime time.Duration, at time.Time)
  ```

- [ ] **Step 1: Write the failing table test** (`session/recovery_test.go`), on a clockwork fake at 09:00 with default timeouts:

```go
func TestManager_MarkRecoveryPending(t *testing.T) {
	t.Parallel()
	nine := time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)

	type testCase struct {
		name   string
		steps  func(t *testing.T, m *session.Manager, clk *clockwork.FakeClock, s *session.Session)
		assert func(t *testing.T, s *session.Session, err error)
	}

	cases := []testCase{
		{
			name:  "entered at recovery",
			steps: func(t *testing.T, m *session.Manager, _ *clockwork.FakeClock, s *session.Session) { m.MarkRecoveryPending(s, 15*time.Minute, nine) },
			assert: func(t *testing.T, s *session.Session, _ error) {
				assert.Equal(t, session.MFARecoveryPending, s.MFA)
				assert.Equal(t, nine.Add(15*time.Minute), s.AbsoluteExpiresAt)
				assert.Equal(t, nine.Add(15*time.Minute), s.IdleExpiresAt)
				assert.Equal(t, nine, s.RecoveredAt)
				assert.Equal(t, nine.Add(12*time.Hour), s.EnrolmentOriginDeadline)
			},
		},
		{
			name: "activity cannot extend the state",
			steps: func(t *testing.T, m *session.Manager, clk *clockwork.FakeClock, s *session.Session) {
				m.MarkRecoveryPending(s, 15*time.Minute, nine)
				require.NoError(t, m.Save(t.Context(), s))
				clk.Advance(14 * time.Minute)
				require.NoError(t, m.Touch(t.Context(), s))
			},
			assert: func(t *testing.T, s *session.Session, _ error) { assert.Equal(t, nine.Add(15*time.Minute), s.IdleExpiresAt) },
		},
		{
			name: "restored by a later binding keeps the recovery time",
			steps: func(t *testing.T, m *session.Manager, clk *clockwork.FakeClock, s *session.Session) {
				m.MarkRecoveryPending(s, 15*time.Minute, nine)
				clk.Advance(5 * time.Minute)
				require.NoError(t, m.RestoreEnrolmentDeadlines(s))
			},
			assert: func(t *testing.T, s *session.Session, _ error) {
				assert.Equal(t, nine.Add(12*time.Hour), s.AbsoluteExpiresAt)
				assert.True(t, s.EnrolmentOriginDeadline.IsZero())
				assert.Equal(t, nine, s.RecoveredAt)
			},
		},
		{
			name: "recovery time survives rotation",
			steps: func(t *testing.T, m *session.Manager, _ *clockwork.FakeClock, s *session.Session) {
				m.MarkRecoveryPending(s, 15*time.Minute, nine)
				require.NoError(t, m.Save(t.Context(), s))
				rotated, err := m.Rotate(t.Context(), s)
				require.NoError(t, err)
				*s = *rotated
			},
			assert: func(t *testing.T, s *session.Session, _ error) { assert.Equal(t, nine, s.RecoveredAt) },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			clk := clockwork.NewFakeClockAt(nine)
			m, err := session.NewManager(session.WithClock(clk))
			require.NoError(t, err)
			s, err := m.Create(t.Context(), "u-1", session.WithFirstFactor(factor.Recovery))
			require.NoError(t, err)
			tc.steps(t, m, clk, s)
			tc.assert(t, s, nil)
		})
	}
}
```

Also add a round-trip row to the existing "consumer data cannot forge state" table: consumer data `{"recovered_at": "…"}` leaves `RecoveredAt` zero.

- [ ] **Step 2: Run** `go test -run 'TestManager_MarkRecoveryPending' -count=1 ./session/...`. **Expected:** after stubbing `MarkRecoveryPending` as an empty method and adding the constant and field, every row fails on its first assertion (state still `MFANone`, deadlines unchanged).
- [ ] **Step 3: Implement.** `MarkRecoveryPending` sets `s.MFA`, sets `s.RecoveredAt = at`, and then applies the same body as `MarkEnrolmentPending`. Extract the shared deadline-lowering into an unexported `m.confine(s, lifetime)` used by both. `String()` returns `"recovery-pending"`. Widen the godoc of `EnrolmentOriginDeadline` and `RestoreEnrolmentDeadlines` to "confinement marker — set by the enrolment path or by a recovery". Make sure `Rotate` and the in-memory copy include `RecoveredAt`.
- [ ] **Step 4: Run** `go test -race ./session/...`, then `go build ./...` and `go vet ./...` in every `go.work` module. Add the new case to any exhaustive `switch s.MFA` that `go vet` or a linter flags. **Expected:** PASS.
- [ ] **Step 5: Refactor.** Consider `/simplify` on `session/enrolment.go`, then re-run the tests.
- [ ] **Step 6: Commit** `feat(session): recovery-pending state and RecoveredAt`

### Task 2.1: Saved code format

**Files:**
- Create: `recovery/doc.go`, `recovery/errors.go`, `recovery/code.go`, `recovery/code_test.go`

**Interfaces:**
- Produces:
  ```go
  var ErrConfig = errors.New("recovery: invalid configuration")
  var ErrRefused = fmt.Errorf("recovery: refused: %w", authenticate.ErrAuthenticationFailed)
  const codeBytes = 16
  func newCode(random io.Reader) (text string, hash [32]byte, err error)
  func parseCode(presented string) (hash [32]byte, err error) // err is ErrRefused
  ```

- [ ] **Step 1: Write the failing tests.** `TestParseCode` is a table in the `assert` closure form, with these rows:
  - **canonical:** a code from `newCode` hashes to the hash it returned;
  - **lower case, no dashes:** it matches;
  - **dashes anywhere** (`"AB-CD…"`): it matches;
  - **`O` for `0`, `l` for `1`:** it matches;
  - **25 characters:** `ErrRefused`;
  - **27 characters:** `ErrRefused`;
  - **contains `U`:** `ErrRefused`;
  - **first character `8`:** `ErrRefused`;
  - **empty:** `ErrRefused`;
  - **space inside:** `ErrRefused`.

  `TestNewCode_Shape` generates 1,000 codes and checks each one:
  - it matches `^[0-7][0-9A-HJKMNP-TV-Z]{3}(-[0-9A-HJKMNP-TV-Z]{4}){5}-[0-9A-HJKMNP-TV-Z]{2}$`;
  - it is 26 alphabet characters once the dashes are stripped;
  - `parseCode` round-trips it.

  `TestNewCode_RandomFailure` uses an `iotest.ErrReader` and expects an error with a zero hash. `TestCodeBytesPinned` asserts `codeBytes == 16`. Its comment says the constant is the whole guarantee, so the test pins it.
- [ ] **Step 2: Run** `go test -run 'TestParseCode|TestNewCode|TestCodeBytesPinned' -count=1 ./recovery/...`, with stub bodies that return a zero value and nil. **Expected:** the rows fail on their hash and error assertions.
- [ ] **Step 3: Implement** Crockford encoding by hand over a 130-bit big-endian value with two leading zero bits. Do not use `encoding/base32`: its alphabet and padding differ. Decoding inverts it after normalising. Hash with `sha256.Sum256` over the 16 bytes.
- [ ] **Step 4: Run** `go test -race ./recovery/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(recovery): 128-bit saved code format`

### Task 2.2: `CodeStore` and the in-memory store

**Files:**
- Create: `recovery/store.go` (the contract), `recovery/memstore.go`, `recovery/memstore_test.go`

**Interfaces:**
- Produces:
  ```go
  type CodeStore interface {
      ReplaceSet(ctx context.Context, user identity.UserID, hashes [][]byte, at time.Time) error
      Match(ctx context.Context, user identity.UserID, hash []byte) (bool, error)
      Spend(ctx context.Context, user identity.UserID, hash []byte, at time.Time) (bool, error)
      Remaining(ctx context.Context, user identity.UserID) (int, error)
      DeleteUser(ctx context.Context, user identity.UserID) (int, error)
  }
  func NewMemoryCodeStore() *MemoryCodeStore
  ```

- [ ] **Step 1: Write the failing table test**, one row per spec scenario of "Saved recovery codes are replaced as a set and spent by the write":
  - concurrent spends with 8 goroutines and a `sync.WaitGroup` start barrier: exactly 1 true;
  - another user's hash is refused;
  - replacement is whole: 10 codes with 3 spent, replaced by 10, gives `Remaining` 10 and no old hash matching;
  - a match writes nothing, asserted through a counting wrapper;
  - the caller's slice mutated after `ReplaceSet` leaves the stored state unchanged.

  This test is the seed of the shared suite in 5.3, so keep the cases in a helper `codeStoreCases()` in the test file. 5.3 moves them.
- [ ] **Step 2: Run** `go test -run 'TestMemoryCodeStore' -count=1 ./recovery/...` against stub methods returning zero values. **Expected:** FAIL on counts.
- [ ] **Step 3: Implement** a `sync.Mutex`-guarded `map[identity.UserID]map[[32]byte]*entry{spentAt time.Time}`. Copy hashes on the way in. Godoc states the single-process limit.
- [ ] **Step 4: Run** `go test -race -count=3 ./recovery/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(recovery): saved-code store contract and in-memory store`

### Task 2.3: The `Codes` manager

**Files:**
- Create: `recovery/codes.go`, `recovery/codes_options.go`, `recovery/codes_test.go`
- Generate: `recovery/limiter_mock_test.go` (mockgen over `ratelimit.Limiter`, per `use-mockgen`)

**Interfaces:**
- Consumes: `newCode`, `parseCode`, `CodeStore`.
- Produces:
  ```go
  var ErrCodeThrottled = fmt.Errorf("recovery: saved-code presentations throttled: %w", ratelimit.ErrThrottled)
  type Count struct{ N int; Low bool }
  func NewCodes(opts ...CodesOption) (*Codes, error)
  func WithCodeStore(CodeStore) CodesOption; func WithSetSize(n int) CodesOption; func WithLowThreshold(n int) CodesOption
  func WithCodeLimiter(ratelimit.Limiter) CodesOption; func WithCodesClock(clock.Clock) CodesOption; func WithCodesRandom(io.Reader) CodesOption; func WithCodesLogger(*slog.Logger) CodesOption
  func (c *Codes) Generate(ctx context.Context, user identity.UserID) ([]string, error)
  func (c *Codes) Confirm(ctx context.Context, user identity.UserID, presented string) error
  func (c *Codes) Remaining(ctx context.Context, user identity.UserID) (Count, error)
  // package-internal, for the Recoverer (4.2):
  func (c *Codes) check(ctx context.Context, user identity.UserID, presented string) ([32]byte, error) // throttled, no write
  func (c *Codes) spend(ctx context.Context, user identity.UserID, hash [32]byte) error
  func CodeThrottleKey(user identity.UserID) string // "recovery-code|" + user
  ```

- [ ] **Step 1: Write the failing tables.**

  `TestNewCodes_Config` covers:
  - size 0: `ErrConfig`;
  - size 101: `ErrConfig`;
  - low threshold -1: `ErrConfig`;
  - a nil store, limiter, clock or random: `ErrConfig`;
  - defaults: 10 codes and a low threshold of 2.

  `TestCodes` covers:
  - default count 10, and a consumer count of 16;
  - regeneration voids the old set;
  - confirmation spends nothing (`Remaining` unchanged);
  - a spent code is refused (spend through `check`+`spend`, then confirm): `ErrRefused`;
  - the low count: 8 of 10 spent gives `Count{2, true}`;
  - consumer threshold 4 with 4 left: low;
  - guessing: 5 wrong confirms, then a valid one, gives `ErrCodeThrottled`, with the mock limiter asserting `Exceeded` is called before any store call;
  - a malformed code is charged and the store is not called;
  - a cancelled context still records: `RecordFailure` receives a context whose `Err()` is nil;
  - a limiter error refuses;
  - random failure leaves the existing set;
  - no codes in logs: capture a `slog` JSON handler, generate, present one wrong and one right, and assert no generated code or its dashless form appears in any record or in any returned error's `Error()`.

- [ ] **Step 2: Run** `go test -run 'TestNewCodes_Config|TestCodes' -count=1 ./recovery/...`, stubbed. **Expected:** FAIL on assertions.
- [ ] **Step 3: Implement.** Record failures with `context.WithoutCancel(ctx)`. The default limiter is `ratelimit.NewMemoryLimiter(5, 15*time.Minute)`. `Generate` builds all hashes first, then calls `ReplaceSet` once.
- [ ] **Step 4: Run** `go test -race ./recovery/...` and `go vet ./recovery/...`. **Expected:** PASS.
- [ ] **Step 5: Refactor.** Consider `/simplify` on `recovery/`, then re-run the tests.
- [ ] **Step 6: Commit** `feat(recovery): saved-code manager with throttled confirmation`

### Task 3.1: The authenticator-reset port and the MFA kind

**Files:**
- Create: `recovery/reset.go`, `recovery/mfakind.go`, `recovery/mfakind_test.go`
- Generate: `recovery/mfamethod_mock_test.go` (mockgen over `mfa.Method` and `mfa.EnrolmentRemover`)

**Interfaces:**
- Produces:
  ```go
  type AuthenticatorRef struct{ Kind, ID string }
  func (r AuthenticatorRef) String() string // "kind:id"
  func ParseAuthenticatorRef(s string) (AuthenticatorRef, error) // ErrMalformed on no colon / empty parts / newline
  type AuthenticatorKind interface {
      Kind() string
      Held(ctx context.Context, user identity.UserID) ([]AuthenticatorRef, error)
      Remove(ctx context.Context, user identity.UserID, refs []AuthenticatorRef) error
  }
  const MFAKind = "mfa"
  func MFAEnrolments(methods ...mfa.Method) (AuthenticatorKind, error)
  ```
  `ErrMalformed = errors.New("recovery: malformed recovery")` is added to `errors.go` here.

- [ ] **Step 1: Write the failing table.**
  - Listing: TOTP enrolled and `email-code` not gives `[{mfa totp}]`.
  - A method that is not an `EnrolmentRemover` gives `ErrConfig`.
  - A lookup failure returns the error with no refs.
  - `Remove` of `{mfa totp}` calls TOTP's remover only.
  - `Remove` of an unknown ID is ignored.
  - An empty method set gives `ErrConfig`.
  - Duplicate names give `ErrConfig`, through `mfa.LookupsFor`.
- [ ] **Step 2: Run** `go test -run 'TestMFAEnrolments' -count=1 ./recovery/...`, stubbed. **Expected:** FAIL.
- [ ] **Step 3: Implement.** `Held` calls `Enrolled` in configuration order. `Remove` goes in the order of the refs, and returns the first error.
- [ ] **Step 4: Run** `go test -race ./recovery/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(recovery): authenticator-reset port and MFA kind`

### Task 3.2: The reset plan

**Files:**
- Create: `recovery/plan.go`, `recovery/plan_test.go`

**Interfaces:**
- Produces:
  ```go
  type ResetInput struct{ User identity.UserID; Held, Reported, Proven []AuthenticatorRef }
  type ResetPolicy func(ctx context.Context, in ResetInput) ([]AuthenticatorRef, error)
  type resetMode int // resetAll (default), resetReported, resetCustom
  type planner struct{ kinds []AuthenticatorKind; mode resetMode; policy ResetPolicy }
  func (p planner) plan(ctx context.Context, user identity.UserID, reported, proven []AuthenticatorRef) ([]AuthenticatorRef, error)
  func (p planner) execute(ctx context.Context, user identity.UserID, plan []AuthenticatorRef) error
  ```
  The options live on the Recoverer (4.2) and wrap these: `WithResetReported()`, `WithResetPolicy(ResetPolicy)` and `WithAuthenticatorKinds(kinds ...AuthenticatorKind)`. A duplicate `Kind()` or an empty list is `ErrConfig`.

- [ ] **Step 1: Write the failing table**, one row per scenario of "A completed recovery resets…":
  - **default:** held TOTP and email with nothing proven removes both;
  - **proven kept:** TOTP proven removes email only;
  - **reported:** email reported removes email;
  - **reporting an unheld method:** `ErrMalformed`;
  - **consumer policy:** returns TOTP, which is removed;
  - **policy returns an unheld ref:** ignored;
  - **policy error:** the error is returned;
  - **listing failure:** the error, with no plan;
  - **execution** over two kinds with the second failing: the first kind's removal happened and the error is returned.
- [ ] **Step 2: Run** `go test -run 'TestPlanner' -count=1 ./recovery/...`, stubbed. **Expected:** FAIL.
- [ ] **Step 3: Implement.** The policy's godoc states that a policy returning nothing leaves possibly-compromised authenticators valid. `WithResetReported`'s godoc states that it trusts the user's report at the moment they are least sure.
- [ ] **Step 4: Run** `go test -race ./recovery/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(recovery): reset plan with reported and custom modes`

### Task 3.3: `RecordStore` and the in-memory store

**Files:**
- Create: `recovery/records.go`, `recovery/records_mem.go`, `recovery/records_mem_test.go`

**Interfaces:**
- Produces:
  ```go
  type Record struct {
      ID id.ID; User identity.UserID
      StartedAt, NotBefore, CompletedAt, CancelledAt time.Time
      Proven, Reported []AuthenticatorRef
      SavedSpent bool
  }
  var ErrRecordNotFound = errors.New("recovery: record not found")
  type RecordStore interface {
      Insert(ctx context.Context, r Record) error
      Find(ctx context.Context, id id.ID) (*Record, error)
      Complete(ctx context.Context, id id.ID, at time.Time) (bool, error)
      Cancel(ctx context.Context, id id.ID, at time.Time) (int, error)
      CancelPending(ctx context.Context, user identity.UserID, at time.Time) (int, error)
      LatestCompletion(ctx context.Context, user identity.UserID) (time.Time, bool, error)
  }
  func NewMemoryRecordStore() *MemoryRecordStore
  ```

- [ ] **Step 1: Write the failing table**, seeding `recordStoreCases()` for 5.3:
  - completing before `NotBefore` is refused and the record stays pending;
  - completing at exactly `NotBefore` succeeds;
  - cancel then complete: the completion is refused;
  - racing complete and cancel: 8 of each, exactly 1 success;
  - the latest completion is 11:00 Tuesday;
  - a user with no completion reports `false`;
  - `CancelPending` cancels only pending records of that user and returns the count;
  - `Find` of an unknown ID gives `ErrRecordNotFound`;
  - inserting a completed record makes it immediately visible to `LatestCompletion`.
- [ ] **Step 2: Run** `go test -run 'TestMemoryRecordStore' -count=1 ./recovery/...`, stubbed. **Expected:** FAIL.
- [ ] **Step 3: Implement** mutex-guarded storage, returning copies.
- [ ] **Step 4: Run** `go test -race -count=3 ./recovery/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(recovery): recovery-record store contract and in-memory store`

### Task 3.4: The way-back check

**Files:**
- Create: `recovery/wayback.go`, `recovery/wayback_test.go`
- Generate: `recovery/userloader_mock_test.go` (mockgen over `identity.UserLoader`)

**Interfaces:**
- Produces:
  ```go
  type WayBackDeps struct {
      Users        identity.UserLoader
      Codes        *Codes
      Kinds        []AuthenticatorKind
      IssuedCodes  bool
      LinkedLogins func(ctx context.Context, user identity.UserID) ([]factor.Kind, error)
      Exempt       func(factor.Kind) bool
  }
  func NewWayBackCheck(deps WayBackDeps) (*WayBackCheck, error) // nil Users or Codes → ErrConfig; nil Exempt → factor.Kind.MFAExempt
  func (c *WayBackCheck) HasWayBack(ctx context.Context, user identity.UserID) (bool, error)
  ```

- [ ] **Step 1: Write the failing table**, one row per spec scenario:
  - a password with issued codes enabled: yes;
  - a password without issued codes: no;
  - 3 saved codes: yes;
  - a linked OIDC login under the default exemption: yes;
  - a linked OIDC login with the consumer's `Exempt` returning false: no;
  - no `LinkedLogins` supplied: a linked user with nothing else reports no;
  - an enrolment lookup failure: error;
  - a user loader failure: error;
  - `LinkedLogins` failure: error.
- [ ] **Step 2: Run** `go test -run 'TestWayBackCheck' -count=1 ./recovery/...`, stubbed. **Expected:** FAIL.
- [ ] **Step 3: Implement.** Check in the cheapest order: remaining codes, then details, then kinds, then links. Stop at the first yes, and propagate any error seen before it. The godoc states the linked-login limit (design D12).
- [ ] **Step 4: Run** `go test -race ./recovery/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(recovery): way-back check for passwordless registration`

### Task 4.1: Issued codes and `Start`

**Files:**
- Create: `recovery/recoverer.go` (the type, deps, options, construction), `recovery/messages.go`, `recovery/start.go`, `recovery/start_test.go`
- Generate: `recovery/sender_mock_test.go` (over `notify.Sender`)

**Interfaces:**
- Produces:
  ```go
  type ProofKind string
  const (ProofSaved ProofKind = "saved"; ProofIssued ProofKind = "issued"; ProofPassword ProofKind = "password"; ProofMFA ProofKind = "mfa")
  type Deps struct {
      Users    identity.UserLoader
      Sessions *session.Manager
      Records  RecordStore           // nil → in-memory
      Sender   notify.Sender         // required when issued codes are enabled, or always for the notice
      Codes    *Codes                // required when saved codes are enabled
  }
  type Notice struct{ At time.Time; Removed []AuthenticatorRef; CodesReplaced bool; Repudiation string }
  type Messages interface {
      IssuedCode(code string, until time.Time) (subject, body string)
      Recovered(n Notice) (subject, body string)
      Held(n Notice, cancelLink string, until time.Time) (subject, body string)
      Cancelled(n Notice) (subject, body string)
      Regenerated(at time.Time) (subject, body string)
  }
  func NewRecoverer(deps Deps, opts ...Option) (*Recoverer, error)
  func WithProofs(kinds ...ProofKind) Option                 // required; see 4.2 for the shape checks
  func WithRepudiationContact(text string) Option            // required, non-empty
  func WithIssuedCodeTTL(d time.Duration) Option             // 15m; ≤0 or >24h → ErrConfig
  func WithIssuedCodeStore(onetime.Store) Option             // in-memory default
  func WithIssuedCodeLimit(n int) Option                     // 5; <1 → ErrConfig
  func WithContactResolver(mfa.ContactResolver) Option       // mfa.UsernameAsAddress
  func WithMessages(Messages) Option; func WithSynchronousDelivery() Option
  func WithClock(clock.Clock) Option; func WithLogger(*slog.Logger) Option
  func (r *Recoverer) Start(ctx context.Context, username string) // returns nothing, by design
  ```

- [ ] **Step 1: Write the failing tables.**

  `TestNewRecoverer_IssuedConfig` covers:
  - TTL 0: `ErrConfig`;
  - TTL 25h: `ErrConfig`;
  - limit 0: `ErrConfig`;
  - a synchronous sender without acceptance: `ErrConfig`;
  - a synchronous sender with `WithSynchronousDelivery`: OK;
  - a missing repudiation contact: `ErrConfig`.

  `TestRecoverer_Start` covers:
  - a code is sent to `ana@example.com`: the mock sender receives `To: "ana@example.com"` and a body containing the code;
  - a consumer resolver sends to `ana.home@example.com`;
  - an unknown username sends nothing;
  - a disabled user sends nothing;
  - the issuance limit: after 5 issues the sixth sends nothing;
  - the sender refuses: nothing panics and a log record carries the reason;
  - an expired code: issue at 10:00, then an internal `checkIssued` at 10:16 gives `ErrRefused`;
  - no log record contains the username, the address or the code.

  Each "nothing" row asserts the absence through the mock sender's `Times(0)`.
- [ ] **Step 2: Run** `go test -run 'TestNewRecoverer_IssuedConfig|TestRecoverer_Start' -count=1 ./recovery/...`, stubbed. **Expected:** FAIL.
- [ ] **Step 3: Implement.** Use the magic-link manager's uniform branches as the template (read `go doc ./magiclink`, not its code verbatim). The default `Messages` are plain text with no brand, and state the expiry and single use.
- [ ] **Step 4: Run** `go test -race ./recovery/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(recovery): issued codes and a uniform start`

### Task 4.2: The proof rules and order

**Files:**
- Create: `recovery/recover.go`, `recovery/recover_test.go`, `recovery/recover_race_test.go`
- Modify: `recovery/recoverer.go` (options)

**Interfaces:**
- Consumes: `Codes.check/spend`, the planner, and `onetime.Manager`.
- Produces:
  ```go
  type Request struct {
      Username, Saved, Issued, MFAMethod, MFACode string
      Password []byte
      Lost     []string // "kind:id"
      Source   string   // canonical client source, for the risk hook
  }
  type PasswordCheck func(ctx context.Context, username string, password []byte) error   // injected by httpsec: pre-auth phase + authenticator + attempt recording
  type Check func(ctx context.Context, user identity.UserID, proofs []ProofKind) error    // consumer refusal checks
  func WithPasswordCheck(PasswordCheck) Option               // required when ProofPassword is enabled
  func WithMFAMethods(methods ...mfa.Method) Option           // required when ProofMFA is enabled; only FormField, non-challenge methods count
  func WithChecks(checks ...Check) Option
  func WithUserLimiter(ratelimit.Limiter) Option             // 5 per 15m under "recovery|<user>"
  func UserThrottleKey(user identity.UserID) string
  // internal:
  func (r *Recoverer) verify(ctx context.Context, req Request) (*verified, error) // steps 1–5, no spend
  func (r *Recoverer) spend(ctx context.Context, v *verified) error               // step 6
  type verified struct{ user identity.UserID; details *identity.Details; proofs []ProofKind; savedHash [32]byte; issued onetime.Checked; mfa mfa.Method; plan []AuthenticatorRef; proven, reported []AuthenticatorRef; hold time.Duration }
  ```
  The construction checks are:
  - no recovery-code kind, or fewer than two kinds, is `ErrConfig`;
  - `ProofMFA` with no eligible method is `ErrConfig`;
  - `ProofPassword` without `WithPasswordCheck` is `ErrConfig`;
  - `ProofSaved` without `Deps.Codes` is `ErrConfig`.

- [ ] **Step 1: Write the failing tables.**

  `TestRecoverer_Shape` checks that the malformed cases return `ErrMalformed` before any mock is called:
  - one proof;
  - three proofs;
  - password with MFA and no code;
  - a disabled kind;
  - an MFA method name not configured.

  `TestRecoverer_Verify` covers:
  - saved with issued: OK;
  - saved with password: OK;
  - issued with TOTP: OK;
  - an unknown user and a wrong saved code give the same `ErrRefused` with identical `Error()`;
  - a locked account: the `PasswordCheck` returns the lockout error, which comes back unchanged, and no code is spent;
  - a wrong password keeps the codes, and a retry succeeds;
  - a consumer check refuses, returned unchanged, and the codes stay redeemable;
  - an issued code for `u-2` with `username=u-1`: `ErrRefused` and nothing spent (Review Focus 2);
  - a challenge method is not eligible (`ErrMalformed`);
  - the spend order: the MFA mock `Verify` is called before `onetime` consume and code spend, asserted with `gomock.InOrder`;
  - a wrong MFA code spends no recovery code;
  - every refusal records a failure on the user limiter.

  `TestRecoverer_RacingRecoveries` releases 16 goroutines through a start barrier, all presenting the same saved and issued codes. Exactly one succeeds. Run it with `-count=3`.
- [ ] **Step 2: Run** `go test -run 'TestRecoverer_Shape|TestRecoverer_Verify|TestRecoverer_RacingRecoveries' -count=1 ./recovery/...`, stubbed. **Expected:** FAIL.
- [ ] **Step 3: Implement** in the global constraints' order. Settled during implementation (design D4, D6):
  - The per-user limiter runs right after the user is resolved, before any proof is checked, because its key is the user reference. A user at the limit gets the same `ErrRefused` as an unknown user.
  - In the reported mode the shape check also refuses an empty `Lost` and a `Lost` naming the MFA method presented as a proof, counted nowhere. `Lost` refs outside the reported mode are parsed, handed to a custom policy, and ignored by the default.
  - `RefusedAfterValidCode(err)` tells the HTTP layer whether a refusal came after the recovery codes passed, for `WithRecoveryCountRefusals`.
  - `spend` runs on `context.WithoutCancel`, so a spend that has started runs to the end. A saved-code store outage during it is returned uncounted and unmarked.
  - An unknown or disabled user is refused at once, before any lookup. No expensive work runs before the recovery codes pass, for any user, so neither an unknown user nor a known user with a wrong code pays for a password hash (design D4 step 2). Pin it by counting password-check calls: both make zero.
  - `spend`: `mfa.Verify`, then `onetime.Consume`, then `Codes.spend`. The first failure maps to `ErrRefused`.
- [ ] **Step 4: Run** `go test -race -count=3 ./recovery/...`. **Expected:** PASS.
- [ ] **Step 5: Refactor.** Consider `/simplify`, then re-run the tests.
- [ ] **Step 6: Commit** `feat(recovery): two-proof check-then-consume`

### Task 4.3: The completion sequence

**Files:**
- Create: `recovery/complete.go`, `recovery/complete_test.go`

**Interfaces:**
- Produces:
  ```go
  type Result struct {
      Session   *session.Session // recovery-pending, saved
      Codes     []string         // new set, when a saved code was spent
      Remaining Count            // otherwise
      Held      *Hold            // non-nil only when held (4.4)
  }
  func (r *Recoverer) Recover(ctx context.Context, req Request) (*Result, error) // verify → spend → complete (or hold, 4.4)
  func WithoutSessionRevocation() Option
  func WithSessionLifetime(d time.Duration) Option // 15m; ≤0 or > Sessions.AbsoluteTimeout() → ErrConfig
  func WithIDGenerator(id.Generator) Option
  ```

- [ ] **Step 1: Write the failing table.**
  - A new set after recovery: 10 codes, and the old set refused.
  - No saved code spent: no codes, and `Remaining` `{2, true}`.
  - Other sessions end: two prior sessions no longer load, and the result's session loads with `MFARecoveryPending`, `factor.Recovery` and `RecoveredAt` equal to now.
  - The notice is sent to `ana@example.com`, naming the removed `mfa:totp` and the repudiation text, with no code.
  - Keeping sessions: `WithoutSessionRevocation` leaves the prior sessions loading.
  - The session expires at +16 minutes, through the manager's fake clock.
  - A reset failure: the error is returned, no session is created, and the other sessions still load.
  - A refused queue is logged and the result is still returned.
  - A completed record exists: `LatestCompletion` equals now.
  - Two recoveries back to back: the first result's session no longer loads (Review Focus 5).
  - `WithSessionLifetime` of 13h against a 12h absolute timeout: `ErrConfig`.
- [ ] **Step 2: Run** `go test -run 'TestRecoverer_Complete' -count=1 ./recovery/...`, stubbed. **Expected:** FAIL.
- [ ] **Step 3: Implement** the completion order from the global constraints. `Deps.Sender` is required whichever proof kinds are enabled, because the notice is mandatory (design D7); the construction table gains the row "no sender with only saved codes and password: `ErrConfig`". `Sessions.Create(ctx, user, session.WithFirstFactor(factor.Recovery))`, then `MarkRecoveryPending`, then `Save`.
- [ ] **Step 4: Run** `go test -race ./recovery/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(recovery): completion resets, revokes, reissues and confines`

### Task 4.4: Holds, finish and cancel

**Files:**
- Create: `recovery/hold.go`, `recovery/hold_test.go`, `recovery/hold_race_test.go`

**Interfaces:**
- Produces:
  ```go
  var ErrNotYetCompletable = errors.New("recovery: not yet completable")
  type Hold struct{ CompletionToken string; CompletableAt time.Time }
  type RiskInput struct{ User identity.UserID; Source string; Proofs []ProofKind; Now time.Time }
  func WithDelay(d time.Duration) Option                                   // no default; ≤0 → ErrConfig
  func WithRisk(fn func(ctx context.Context, in RiskInput) (time.Duration, error)) Option
  func WithCompletionWindow(d time.Duration) Option                        // 24h; ≤0 → ErrConfig
  func WithCancelLink(baseURL string) Option                               // required with any hold; https or loopback http
  func WithHoldTokenStore(onetime.Store) Option                            // in-memory default
  func (r *Recoverer) Finish(ctx context.Context, completionToken string) (*Result, error)
  func (r *Recoverer) Cancel(ctx context.Context, cancelToken string)      // returns nothing, by design
  func (r *Recoverer) CancelPending(ctx context.Context, user identity.UserID) error
  func (r *Recoverer) Holds() bool
  ```

- [ ] **Step 1: Write the failing tables** on a fake clock set to Monday 09:00.

  Construction:
  - a hold without a cancel link: `ErrConfig`;
  - `http://app.example.com`: `ErrConfig`;
  - `http://localhost:3000`: OK;
  - delay 0: `ErrConfig`.

  Behaviour:
  - by default the recovery completes at once;
  - a fixed 72h delay: `Result.Held` carries the token and Thursday 09:00, the `Held` notice carries a link starting with the base URL, and the authenticators and sessions are unchanged;
  - a held recovery that spent a saved code voids the remaining set at once: `Codes.Remaining` is 0, the old codes are refused, and the `Held` notice has `CodesVoided` set and its default text says so;
  - finishing too early (Wednesday): `ErrNotYetCompletable`, and the same token works on Thursday;
  - finishing after the hold (Thursday 10:00): reset and revocation run, and a recovery-pending session is returned;
  - the risk hook returns 48h: held; it returns 0: completes at once; it returns an error: refused before any spend;
  - the login cancels: `CancelPending(u-1)`, then `Finish` gives `ErrRefused`;
  - the cancel link cancels: `Cancel(token)`, then `Finish` gives `ErrRefused`, and exactly one `Cancelled` notice is sent whether or not a saved code was spent; nothing is deleted at cancel;
  - a finish token given to `Cancel` does nothing, and `Finish` still succeeds (Review Focus 3);
  - a finish past the window gives `ErrRefused`;
  - the plan is recomputed at finish: an enrolment added during the hold is removed;
  - reported mode, the reported method removed during the hold: `Finish` succeeds, the gone ref is dropped from the plan;
  - an inactive or unknown user at finish: `ErrRefused`, the record stays pending and the token stays usable;
  - a listing failure at finish: refused, the record stays pending (planning precedes `Complete`).

  Error paths (each asserting the returned error, the record state and whether the token is still usable):
  - completion: a failing `DeleteByUser`, `Generate`, `Remaining`, `Create` or `Save` is returned (D7 steps 3–5);
  - finish: a `Find` outage; a `Complete` error; `Complete` returning false (`ErrRefused`); a user-lookup error; a failed `Consume`, which is ignored;
  - hold start: an `Insert` failure, a token-issue failure and a saved-set deletion failure are returned;
  - cancel: a failing `records.Cancel` sends no notice; a failed user lookup sends none.

  Overrides: a consumer `WithIDGenerator`'s identifier is the inserted record's ID; a consumer `WithHoldTokenStore` receives the finish and cancel tokens.

  `TestRecoverer_FinishCancelRace` runs 8 `Finish` and 8 `Cancel` calls after the hold, with exactly one success across both (a finish result, or a cancel observed through the record). Run it with `-count=3`.
- [ ] **Step 2: Run** `go test -run 'TestRecoverer_Hold|TestRecoverer_FinishCancelRace' -count=1 ./recovery/...`, stubbed. **Expected:** FAIL.
- [ ] **Step 3: Implement** design D10. The finish and cancel token TTL is hold plus window. The record keeps `Proven`, `Reported` and `SavedSpent`. `Notice` gains `CodesVoided bool`. Finish order: check, find, not-before, load the user, plan (dropping reported refs no longer held), conditional `Complete`, `Consume` (a failure ignored), then the completion sequence detached from cancellation. Cancel: check, conditional `Cancel`, consume, `Messages.Cancelled`.
- [ ] **Step 4: Run** `go test -race -count=3 ./recovery/...` and `go vet ./...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(recovery): opt-in holds with finish, cancel and login cancellation`

### Task 5.1: Schema

**Files:**
- Modify: `migrate/securitystate/20260926000000_security_state.sql` (up: two tables, one column, index, unique; down: drop in reverse)
- Modify: `test/migrate_securitystate_test.go:70` (`securityStateTables`) and the column and nullable scenarios

- [ ] **Step 1: Write the failing tests.**
  - Add `recovery_codes` and `account_recoveries` to `securityStateTables`.
  - Add rows asserting that `recovery_codes.spent_at`, `account_recoveries.completed_at` and `account_recoveries.cancelled_at` are nullable with no default.
  - Assert that `recovery_codes` has a unique index on `(user_id, code_hash)`, that `account_recoveries` has an index on `user_id`, and that `sessions.recovered_at` is a nullable `timestamptz`.
  - Assert that the primary keys are `uuid` and the `user_id` columns `text`.
- [ ] **Step 2: Run** `go test -run 'TestSecurityState' -count=1 ./...` in `test/` (Docker). **Expected:** FAIL naming the missing tables.
- [ ] **Step 3: Implement** the DDL from design D14. The down section drops `account_recoveries` and `recovery_codes` and removes `recovered_at`.
- [ ] **Step 4: Run** the same command. **Expected:** PASS, including the leftover-table check at rollback.
- [ ] **Step 5: Commit** `feat(migrate): recovery tables and sessions.recovered_at`

### Task 5.2: `recovered_at` through the session stores

**Files:**
- Modify: `internal/pgschema/sessions.go` (`SessionInsert`, `SessionUpdate`, `SessionSelect`: one more column)
- Modify: `sqlstore/session.go:78-100`, `:155-189`, `pgx/session.go:98`, `:190`, `gorm/models.go:39-52`, `gorm/session.go:98`, `:202`
- Test: `test/storetest/session_suite.go:82` (fixture), `test/crossbackend/**`

- [ ] **Step 1: Write the failing test.**
  - Extend the session suite fixture with a recovery-pending session: marker 21:00, `RecoveredAt` 09:00.
  - Add a case "never recovered reads with zero RecoveredAt".
  - Add a cross-backend row: saved through sqlstore, loaded through pgx and gorm.
- [ ] **Step 2: Run** `go test -run 'Session' -count=1 ./...` in `test/`. **Expected:** FAIL on `RecoveredAt` read as zero.
- [ ] **Step 3: Implement** a `nullTs(sess.RecoveredAt)` write and scan back in each driver.
- [ ] **Step 4: Run** `go test -race ./...` in the root, `pgx`, `gorm` and `test` modules. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(stores): sessions keep their recovery time`

### Task 5.3: Behavioural and race suites

**Files:**
- Create: `test/storetest/recoverycode_suite.go`, `test/storetest/recoveryrecord_suite.go`, `test/storetest/broken_recovery_test.go`
- Create: `test/internal/storefix/recovery.go` (the race and ambient fixtures)
- Modify: `test/storetest/memory_test.go` (append)
- Move: the cases seeded in `recovery/memstore_test.go` and `recovery/records_mem_test.go` into the suites. The recovery tests then call nothing from `test` (the module rule), so keep their own minimal copies.

**Interfaces:**
- Produces:
  ```go
  func RunRecoveryCodeStoreSuite(t *testing.T, factory func(t *testing.T, clk clock.Clock) recovery.CodeStore)
  func RunRecoveryRecordStoreSuite(t *testing.T, factory func(t *testing.T, clk clock.Clock) recovery.RecordStore)
  func RunRecoveryCodeTx(t *testing.T, ...) // ambient transaction cases, including the rolled-back replacement
  // In test/internal/storefix/recovery.go, each run through the existing storetest.RunConsumeRace on the DurableHarness:
  func RecoverySpendRace(...)   // 50 independent users × 8 racers spending one code
  func RecoveryRecordRace(...)  // 50 records × (8 Complete + 8 Cancel); needs a pool of at least 16
  func RecoveryReplaceRace(...) // overlapping ReplaceSet calls for one user leave exactly one set (added by C2b)
  ```

- [ ] **Step 1: Write the failing test.** `broken_recovery_test.go` defines a read-then-write `CodeStore` variant and a read-then-write `RecordStore.Complete`. It asserts that the race suites fail against them, as `broken_race_test.go` does for one-time tokens.
- [ ] **Step 2: Run** `go test -run 'Broken.*Recovery|Memory.*Recovery' -count=1 ./storetest/...` in `test/`. **Expected:** FAIL, because the suites do not exist yet (implement the suite functions as empty to make it a non-compile red), then because "broken variant passed".
- [ ] **Step 3: Implement** the suites, exact counts, clock-driven time, and per-run isolation.
- [ ] **Step 4: Run** `go test -race ./storetest/...` in `test/`. **Expected:** PASS. The memory stores pass, and the broken variants are caught.
- [ ] **Step 5: Commit** `test(storetest): recovery store suites and race fixtures`

### Task 5.4: `sqlstore` recovery stores

**Files:**
- Create: `internal/pgschema/recovery.go` (the shared SQL), `sqlstore/recoverycode.go`, `sqlstore/recoveryrecord.go`
- Create: `test/sqlstore/recovery_test.go`

**Interfaces:**
- Produces: `sqlstore.NewRecoveryCodeStore(db *sql.DB, opts ...Option) (*RecoveryCodeStore, error)` and `sqlstore.NewRecoveryRecordStore(db *sql.DB, opts ...Option) (*RecoveryRecordStore, error)`.
  - Both take the existing `WithTxResolver`. The code store also takes `WithIDGenerator`, for its row identifiers.
  - `WithClock` is `ErrConfig` on both, since neither reads a clock (`WithClock`'s own rule for stores that take their times from the caller). The record store refuses `WithIDGenerator` too, because records carry their own identifier.
  - A nil db or a nil option value is `ErrConfig`.

- [ ] **Step 1: Write the failing test.** Register both behavioural suites, `RecoverySpendRace`, `RecoveryRecordRace`, `RecoveryReplaceRace` and the ambient fixtures under `t.Run("sqlstore", …)`. `RecoveryReplaceRace` sequences the overlap without sleeps: the first replacement runs in a caller transaction left open, a second starts on its own transaction, then the first commits; expected exactly 5 unspent codes, not 10. Add the case "Replacement rolled back with the caller": begin, attach, `ReplaceSet`, roll back, then check through a separate connection that the old unspent codes still match.
- [ ] **Step 2: Run** `go test -run 'Recovery' -count=1 ./sqlstore/...` in `test/`. **Expected:** FAIL (constructors return a not-implemented error from stubs).
- [ ] **Step 3: Implement** the design D14 SQL:
  - Spend: `UPDATE recovery_codes SET spent_at=$3 WHERE user_id=$1 AND code_hash=$2 AND spent_at IS NULL`.
  - Complete: `UPDATE account_recoveries SET completed_at=$2 WHERE id=$1 AND completed_at IS NULL AND cancelled_at IS NULL AND not_before <= $2`.
  - Cancel: the mirror of Complete, on `cancelled_at`.
  - `ReplaceSet`: `SAVEPOINT` under a caller transaction, else its own `BeginTx`. Its first statement is `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))` on the user, shared from `internal/pgschema/recovery.go`, so overlapping replacements of one user's set take effect one after the other (spec scenario "Overlapping replacements"). Under a caller transaction the lock lasts until the caller commits.
  - `proven` and `reported`: newline-joined `kind:id` refs.
- [ ] **Step 4: Run** `go test -race ./sqlstore/...` in `test/`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(sqlstore): recovery code and record stores`

### Task 5.5: `pgx` and `gorm` recovery stores

**Files:**
- Create: `pgx/recoverycode.go`, `pgx/recoveryrecord.go`, `gorm/recoverycode.go`, `gorm/recoveryrecord.go`; append the models to `gorm/models.go`
- Create: `test/pgxstore/recovery_test.go`, `test/gormstore/recovery_test.go`; add a row to `test/crossbackend`

- [ ] **Step 1: Write the failing tests.** They mirror 5.4's registration for each backend. Add the cross-backend row "a code spent through sqlstore is refused through pgx and gorm".
- [ ] **Step 2: Run** `go test -run 'Recovery' -count=1 ./pgxstore/... ./gormstore/... ./crossbackend/...` in `test/`. **Expected:** FAIL.
- [ ] **Step 3: Implement** over `internal/pgschema/recovery.go`, with the same options rules and the same per-user advisory lock at the start of `ReplaceSet` as sqlstore. gorm uses its model and a `Raw`/`Exec` for the conditional writes, as its one-time store does. Register `RecoveryReplaceRace` for both backends.
- [ ] **Step 4: Run** `go test -race ./...` in the `pgx`, `gorm` and `test` modules. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(pgx,gorm): recovery code and record stores`

### Task 6.1: The recovery gate and the status rows

**Files:**
- Modify: `policy/policy.go:214` (append `ChallengeAccountRecovery`, with a `String()` case)
- Modify: `httpsec/order.go` (add `OrderAccountRecovery = OrderMFAEnrolment - 1` and `OrderAccountRecoveryEndpoints Order = 375`)
- Create: `httpsec/recoverygate.go`, `httpsec/recoverygate_test.go`
- Modify: `httpsec/bearer.go:195` (skip `markChallenge` for `MFARecoveryPending`), `httpsec/status.go:24-67`, `httpsec/chain.go:169` (`builtInEnforcers`)
- Modify: `recovery/errors.go` (append `ErrCooldown` and `ErrReauthenticationRequired`)

**Interfaces:**
- Produces: `policy.ChallengeAccountRecovery`, `httpsec.OrderAccountRecovery`, `httpsec.OrderAccountRecoveryEndpoints`, and an unexported `recoveryGate{enrolPrefixes []string; resolvePath, logoutPath, codesPath string}`, registered by `EnableAccountRecovery` (6.3). For this task, tests build it through an `export_test.go` seam.

- [ ] **Step 1: Write the failing tables.**

  `TestRecoveryGate`, one row per scenario of "A recovery-pending session reaches only…":
  - a protected route gives a 403 challenge carrying the session, and the handler is not called;
  - enrolment begin is reachable;
  - the verify path is refused;
  - the password resolve path is reachable;
  - logout deletes the session;
  - GET on an enrolment path is refused;
  - a per-request challenge is not marked: a required user with no enrolment requests `/invoices`, and the stored session is still `MFARecoveryPending`;
  - a recovery-pending session POSTing `/recovery/codes` is refused with the challenge (Review Focus 4);
  - a full session passes through untouched.

  `TestStatusForError`: add rows for `ErrRefused` (401), `ErrMalformed` (400), `ErrNotYetCompletable` (409), `ErrCooldown` (403), `ErrReauthenticationRequired` (403), `ErrCodeThrottled` (401) and the `ChallengeAccountRecovery` challenge (403). Extend `TestStatusForErrorCoversEverySentinel`'s list.
- [ ] **Step 2: Run** `go test -run 'TestRecoveryGate|TestStatusForError' -count=1 ./httpsec/...`. **Expected:** FAIL on status 500 and on the handler being reached.
- [ ] **Step 3: Implement.** The gate serves only `s.MFA == session.MFARecoveryPending`, and lets through POSTs under the enrolment prefixes, a POST to the resolve path, and a POST to logout. Everything else gets `&ChallengeError{Kind: policy.ChallengeAccountRecovery, Session: s}`. In bearer, when `s.MFA == session.MFARecoveryPending`, still return on `Deny` but skip the `Challenge` branch.
- [ ] **Step 4: Run** `go test -race ./httpsec/... ./policy/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(httpsec): recovery gate and recovery status rows`

### Task 6.2: The binding routes

**Files:**
- Modify: `httpsec/mfaenrol.go:399-420` (serve `MFARecoveryPending` on the endpoints, and pass it through elsewhere); confirm keeps the marker and `RecoveredAt` when moving to `MFAPending`
- Modify: `httpsec/passwordchange.go:95-115` (resolve: for a recovery-pending session, restore, set `MFANone` and save; no rotation, with godoc)
- Test: `httpsec/recoverybind_test.go`

- [ ] **Step 1: Write the failing tables.**
  - Enrol after recovery: the session was created at 09:00, runs begin, confirm and email-confirm, then verifies at 09:09. It ends satisfied, with an absolute deadline of 21:00 and a recovery time of 09:00.
  - Confirmation alone is not enough: `/invoices` gives the MFA challenge.
  - The password route: the resolve succeeds, and `/invoices` reaches the handler.
  - The password route for a required user with the enrolment path on: the next request gives the enrolment challenge.
  - The consumer's function fails: the session is still `MFARecoveryPending`.
  - The password route restores the deadline to 21:00, and the session handle is unchanged.
- [ ] **Step 2: Run** `go test -run 'TestRecoveryBind' -count=1 ./httpsec/...`. **Expected:** FAIL (the enrolment interceptor passes the request through, so begin is not served).
- [ ] **Step 3: Implement** the changes above.
- [ ] **Step 3a: The default allowlist** (added after D1 reproduced the gap: a required user's recovery-pending session was denied by the requirement policy, since `factor.Recovery` was not on the enrolment allowlist). In `policy/enrolmentpath.go`, the default first-factor allowlist becomes password, magic link, recovery and the unrecorded kind. The `WithEnrolmentFirstFactors` godoc says that leaving `factor.Recovery` off gives required users no enrolment route after a recovery. Tests, red first:
  - `policy`: a required user with no usable method and a `factor.Recovery` session, path on, default options: the outcome is the enrolment challenge (red: deny with `ErrMFAEnrollmentRequired`);
  - `policy`: the default allowlist lists exactly those four kinds;
  - `httpsec` `TestRecoveryBind`: the required-user rows run with the default allowlist, with no `WithEnrolmentFirstFactors` override;
  - `httpsec`: with the path off, a required user left with no usable method after the reset has the recovery-pending session refused with `ErrMFAEnrollmentRequired` (the stated limit, D8).
- [ ] **Step 4: Run** `go test -race ./httpsec/... ./policy/...`. **Expected:** PASS, with the existing enrolment tests unchanged.
- [ ] **Step 5: Commit** `feat(httpsec): enrolment and password change complete a recovery`

### Task 6.3: `EnableAccountRecovery` and the complete endpoint

**Files:**
- Create: `httpsec/recoveryoptions.go`, `httpsec/recoverycomplete.go`, `httpsec/recoverycomplete_test.go`
- Modify: `httpsec/options.go` (`build()` wiring: `wireAccountRecovery`)

**Interfaces:**
- Produces:
  ```go
  type RecoveryDeps recovery.Deps                                  // Users, Sessions, Records, Sender, Codes
  func EnableAccountRecovery(d RecoveryDeps, opts ...RecoveryOption) Option
  func WithRecoveryCore(opts ...recovery.Option) RecoveryOption    // the core's own options (proofs, reset, holds, messages…)
  func WithRecoveryCompletePath(p string) RecoveryOption          // "/recovery/complete"
  func WithRecoveryStartPath, WithRecoveryFinishPath, WithRecoveryCancelPath, WithRecoveryCodesPath // defaults as in Global Constraints
  func WithRecoveryLimiter(ratelimit.Limiter) RecoveryOption       // complete source guard, 10 failures / 15m
  func WithRecoveryStartLimiter(ratelimit.Limiter) RecoveryOption  // start source guard, 10 / hour
  func WithRecoveryCountRefusals(bool) RecoveryOption              // true
  type RecoveryResult struct{ Token string; Recovery *recovery.Result }
  type RecoveryResponder func(ex *Exchange, result RecoveryResult) error
  func WithRecoveryResponder(fn RecoveryResponder) RecoveryOption  // the package's responder pattern: the credential travels with the result
  func WithRecoveryHoldResponder(fn RecoveryHoldResponder) RecoveryOption
  func WithRecoveryTokens(g token.Generator) RecoveryOption       // default FormLoginDeps.Tokens; required without form login
  // The credential's principal comes from recovery.Result.Details, never a second lookup.
  // The start endpoint is registered only when Recoverer.Enabled(recovery.ProofIssued).
  // Cache-Control: no-store is set by the endpoint before any responder.
  func WithRecoveryLogInterval(d time.Duration) RecoveryOption
  ```
  **The chain builds the Recoverer itself** in `build()`, with `recovery.NewRecoverer(recovery.Deps(d), coreOpts...)`. When `ProofPassword` is enabled, it adds `recovery.WithPasswordCheck`, wired to this chain's form login:
  1. pre-authentication evaluation;
  2. `FormLoginDeps.Authenticator`;
  3. attempt recording on failure.

  A consumer never supplies the password check through the chain. Its godoc says so.

- [ ] **Step 1: Write the failing tables.**

  `TestEnableAccountRecovery_Config`:
  - saved codes only: `ErrConfig`;
  - no binding route (no enrolment path and no resolve endpoint): `ErrConfig`;
  - `ProofPassword` without form login: `ErrConfig`;
  - start path equal to logout: `ErrConfig`;
  - off by default: a POST to `/recovery/complete` reaches the terminal handler.

  `TestRecoveryComplete_HTTP`, one row per `account-recovery` scenario that has an HTTP face:
  - the pairs;
  - an emailed code alone gives 400;
  - password with TOTP gives 400;
  - a locked account gives 423;
  - unknown and wrong look alike (401, empty bodies);
  - the consumer path;
  - an unattributable source (`0.0.0.0`): 401, and the Recoverer is not called;
  - a refusal of a valid code counts against the source; with `WithRecoveryCountRefusals(false)` it does not;
  - `saved_code` given twice: 400 (Review Focus 1);
  - the query is ignored: a valid code in the query with an empty body gives 400;
  - a body over 16 KiB gives 413;
  - the default JSON response is `{"access_token","expires_at","recovery_codes","remaining","low"}`, and a consumer responder replaces it;
  - the chain flush reaches the recovery samplers.
- [ ] **Step 2: Run** `go test -run 'TestEnableAccountRecovery_Config|TestRecoveryComplete_HTTP' -count=1 ./httpsec/...`. **Expected:** FAIL.
- [ ] **Step 3: Implement.** Follow the Enable* pattern (`mfaenroloptions.go:181-221`). Register the endpoint at `OrderAccountRecoveryEndpoints` and the gate at `OrderAccountRecovery`, and call `c.enableGate(policy.ChallengeAccountRecovery)`. Reuse the `sourceGuard` seam (`httpsec/throttle.go:64`).
- [ ] **Step 4: Run** `go test -race ./httpsec/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(httpsec): account recovery completion endpoint`

### Task 6.4: The start endpoint

**Files:**
- Create: `httpsec/recoverystart.go`, `httpsec/recoverystart_test.go`

- [ ] **Step 1: Write the failing table** over every cause in "Starting a recovery reveals nothing":
  - sent;
  - unknown;
  - disabled;
  - lookup fails;
  - limit reached;
  - source throttled;
  - token store fails;
  - sender refuses;
  - missing body;
  - malformed JSON.

  Every row asserts status 202, a zero-length body, and no `Set-Cookie`. The rows compare against the first row's recorded status, headers and body.
- [ ] **Step 2: Run** `go test -run 'TestRecoveryStart' -count=1 ./httpsec/...`. **Expected:** FAIL (404 from the terminal handler).
- [ ] **Step 3: Implement** POST-only exact path matching. Read form or JSON the way magic link does, and treat every failure as an empty username. The source guard records every start, and a throttled source still gets 202.
- [ ] **Step 4: Run** `go test -race ./httpsec/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(httpsec): uniform recovery start endpoint`

### Task 6.5: Finish, cancel and login cancellation

**Files:**
- Create: `httpsec/recoveryhold.go`, `httpsec/recoveryhold_test.go`
- Modify: `httpsec/logincomplete.go` (when `Recoverer.Holds()`, call `CancelPending(user)` right after the first factor authenticates, before the policy phase and before `Sessions.Create`; an error refuses; a denied form login still cancels, while a denied magic-link or OIDC redemption never reaches completion and cancels nothing)

- [ ] **Step 1: Write the failing tables.**
  - Fixed delay over HTTP: 202 with `{"completion_token","completable_at"}`.
  - Finish too early: 409.
  - Finish after the hold: 200 with a recovery-pending credential.
  - Cancel: always 204, including for a garbage token.
  - A finish token posted to cancel: 204, and the finish still succeeds (Review Focus 3).
  - A password login cancels a held recovery.
  - A magic-link login cancels a held recovery.
  - A record store outage at login: the login is refused.
  - Racing cancel and finish over HTTP: exactly one effective, with `-count=3`.
- [ ] **Step 2: Run** `go test -run 'TestRecoveryHold' -count=1 ./httpsec/...`. **Expected:** FAIL.
- [ ] **Step 3: Implement** both endpoints and the login hook. Finish reads the complete endpoint's body rules and answers like complete; it has no source guard, because the completion token is a one-time secret held only by the client. Cancel answers 204 with an empty body on every path and reads its token from the form body only. Both exist only when `Recoverer.Holds()`.
- [ ] **Step 4: Run** `go test -race -count=3 ./httpsec/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(httpsec): held recoveries finish, cancel and yield to login`

### Task 6.6: Saved-code endpoints

**Files:**
- Create: `httpsec/recoverycodes.go`, `httpsec/recoverycodes_test.go`

**Interfaces:**
- Produces: `WithRegenerationFreshness(d time.Duration) RecoveryOption` (15m; ≤ 0 is `ErrConfig`), `WithRecoveryCodesResponder` and `WithRecoveryCountResponder`.

- [ ] **Step 1: Write the failing table.**
  - A fresh session regenerates: 200 with 10 codes, `Cache-Control: no-store`, the old set void, and the notice queued.
  - A stale session (created at 09:00, POST at 09:20): 403 `ErrReauthenticationRequired`, and the set unchanged.
  - The second factor satisfied at 09:15 counts as fresh at 09:20.
  - A consumer window of 2h regenerates at 10:30.
  - GET gives `{"remaining","low"}` with no code.
  - An MFA-pending session is refused by the MFA gate.
  - No session: 401.
  - A synchronous sender without acceptance: `ErrConfig`.
- [ ] **Step 2: Run** `go test -run 'TestRecoveryCodes' -count=1 ./httpsec/...`. **Expected:** FAIL.
- [ ] **Step 3: Implement.** Serve the endpoint from the gate interceptor at `OrderAccountRecovery`, after the recovery-pending refusal, only when `Recoverer.Enabled(recovery.ProofSaved)`. A session owing any challenge, built-in (`challengePending`) or consumer-raised (`ex.RaisedChallenge()`), is passed on to the gate that enforces it. The latest authentication is `max(s.CreatedAt, s.MFASatisfiedAt)`. POST calls `(*recovery.Recoverer).Regenerate(ctx, user)`, which generates the set and sends `Messages.Regenerated` through the recovery's messages, contact resolver and sender (design D9).
- [ ] **Step 4: Run** `go test -race ./httpsec/...`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(httpsec): saved-code regeneration and count`

### Task 6.7: The cool-down guard

**Files:**
- Create: `httpsec/recoverycooldown.go`, `httpsec/recoverycooldown_test.go`

**Interfaces:**
- Produces: `type Route struct{ Method, Path string }` and `func EnableRecoveryCooldown(records recovery.RecordStore, d time.Duration, routes ...Route) Option`.

- [ ] **Step 1: Write the failing table.**
  - Email change during the cool-down after a re-login: the latest completion is 3h ago and the session was created 1h ago, giving 403 `ErrCooldown`.
  - After the cool-down (49h): the handler is reached.
  - An unmarked route: the handler is reached.
  - An unauthenticated marked request: passed on to the next interceptor.
  - A lookup failure: 500, with fixed text that does not contain the store's error text.
  - `d = 0`: `ErrConfig`. No routes: `ErrConfig`. A nil store: `ErrConfig`.
- [ ] **Step 2: Run** `go test -run 'TestRecoveryCooldown' -count=1 ./httpsec/...`. **Expected:** FAIL.
- [ ] **Step 3: Implement.** Register at `After(OrderBearerToken)`.
- [ ] **Step 4: Run** `go test -race ./httpsec/...`, then `go test ./...` in `fibersec` and `ginsec`. **Expected:** PASS.
- [ ] **Step 5: Commit** `feat(httpsec): opt-in recovery cool-down`

### Task 7.1: Conformance scenarios

**Files:**
- Create: `test/httpsecconformance/recovery_scenarios.go`; register it in `runner.go`
- Modify: `test/httpsec_nethttp_test.go`, `test/httpsec_gin_test.go`, `test/httpsec_fiber_test.go` only if registration needs it

- [ ] **Step 1: Write the scenarios**, which fail until they are registered:
  - saved and issued codes lead to a recovery-pending session;
  - enrolment, then verify, leads to a full session;
  - the password route leads to a full session;
  - a held recovery is cancelled by login;
  - the cool-down is still refused after a re-login.

  All of them run over the pgx durable backend.
- [ ] **Step 2: Run** `go test -run 'Recovery' -count=1 ./...` in `test/`. **Expected:** FAIL until the scenarios are wired into the runner.
- [ ] **Step 3: Wire them**, then run `go vet ./...` and `go test -race ./...` in `test/`. **Expected:** PASS.
- [ ] **Step 4: Commit** `test(conformance): account recovery scenarios`

### Task 7.2: README

**Files:**
- Modify: `README.md` (add an account-recovery section)
- Create: `recovery/example_test.go` (`ExampleNewRecoverer`, `ExampleNewWayBackCheck`), and `httpsec/example_recovery_test.go` (`ExampleEnableAccountRecovery`)

- [ ] **Step 1: Write the Example functions**, each mirroring one README snippet, with `// Output:` where it is deterministic.
- [ ] **Step 2: Run** `go vet ./recovery/... ./httpsec/...` and `go test -run Example ./recovery/... ./httpsec/...`. **Expected:** PASS.
- [ ] **Step 3: Commit** `docs: account recovery in the README`

### Task 7.3: Close out (main session)

- [ ] Run across every module in `go.work`: `go build ./...`, `go vet ./...`, `gofmt -l .` (empty) and `go test -race ./...`. Run `openspec validate recovery-codes --strict`.
- [ ] Dispatch one fresh whole-branch reviewer against every requirement in the change's nine spec deltas. It reports and edits nothing. Findings go back to fresh dispatches of the owning lane.
- [ ] Tick `tasks.md` only after verification and review are green.
