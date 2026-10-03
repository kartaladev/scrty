# Atomic TOTP Attempt Charge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository code is written by subagents and OpenSpec artifacts and git by the main session (`.claude/rules/subagent-delegation.md`): a "Commit" step is the main session's, after verification and review.

**Goal:** Bound the TOTP codes compared against one enrolment to 5 per 15-minute window, whatever the concurrency or replica count, by charging each attempt with one conditional store write before the compare and giving it back on success.

**Architecture:**
- `mfa.EnrolmentStore` gains `ChargeVerifyAttempt` and `RefundVerifyAttempt`, backed by two columns on `mfa_enrolments` and implemented in memory, `seal`, `sqlstore`, `pgx` and `gorm` over shared SQL in `internal/pgschema`.
- `(*TOTP).Verify` charges after reading the enrolment and before matching, refuses a refused charge with `ErrVerifyAttemptsExhausted` (which matches `ErrVerifyThrottled`), and gives the charge back after `AcceptStep` accepts.
- `httpsec`'s verify endpoint stops recording a throttled refusal on the limiter.

**Tech Stack:**
- Go 1.27 with a `go.work` workspace: the root module, `pgx`, `gorm` and `test`.
- PostgreSQL through testcontainers (`test.RunTestPostgres`).
- testify, uber-go/mock (`mockgen --typed`) and clockwork.

**Spec:**
- `openspec/changes/atomic-code-attempts/` holds `proposal.md`, `design.md`, `specs/multi-factor-auth/spec.md`, `specs/security-state-stores/spec.md`, `specs/store-conformance/spec.md` and `tasks.md`.
- Each task below carries its `tasks.md` number.

## Global Constraints

**Defaults and limits**
- Default attempt limit is 5 per window, and the default window is 15 minutes (`mfa.DefaultVerifyAttemptLimit`, `mfa.DefaultVerifyAttemptWindow`).
- A limit of zero or less, or a window of zero or less, is a configuration error from `NewTOTP` that wraps `mfa.ErrConfig`.
- The charge cannot be switched off.

**Ordering and errors**
- Every presented code, well formed or not, is charged before it is compared. A pending or absent enrolment is refused with `ErrInvalidCode` and charges nothing.
- A refused charge returns an error matching both `mfa.ErrVerifyAttemptsExhausted` and `mfa.ErrVerifyThrottled`, and the code is not compared.
- A store failure while charging is an error matching neither `ErrInvalidCode` nor `ErrVerifyThrottled`. Its text is the package's own, and the store's error still matches through `errors.Is`.

**Windows and give-back**
- A window has ended from its end instant onward (`until <= at`). Window ends are truncated to the microsecond in every store.
- A charge is given back only after `AcceptStep` reports true, under `context.WithoutCancel`, naming the window end the charge returned. A failed give-back is logged at WARN and never refuses.

**Stores and schema**
- `PutPending` clears `VerifyAttempts` and `VerifyWindowUntil`.
- The new columns are folded into `migrate/securitystate/20260926000000_security_state.sql`. Nothing is tagged.

**Process rules**
- Code, tests and godoc never cite the predecessor (`.claude/rules/legacy-reference.md`).
- Agents never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`.
- Agents never edit `openspec/`.

## Review Focus

1. **Precision between charge and give-back.** A durable store returns the window end it wrote (microseconds), and a give-back naming it must match. Task 1.5 adds a round-trip case starting from `preciseStart`.
2. **A charge at exactly the window end.** It must open a new window, not count in the old one. Covered in 1.1 by "The window ends at its end instant".
3. **A cancelled request context at give-back.** The success must still give its charge back. Covered in 2.3.
4. **A replay of a matching but spent step.** It must keep its charge, because `AcceptStep` refused it. Covered in 2.3.
5. **The recovery path.** `recovery` calls `Method.Verify` directly, and must be bound without changes of its own. Covered in 2.5.

---

## File Structure

**Root module (`github.com/kartaladev/scrty`)**

| File | Change |
|---|---|
| `mfa/store.go` | `Enrolment` fields, two `EnrolmentStore` methods, godoc |
| `mfa/mfa.go` | `ErrVerifyAttemptsExhausted`, `DefaultVerifyAttemptLimit`, `DefaultVerifyAttemptWindow` |
| `mfa/memory.go` | memory implementation; `PutPending` already rebuilds the record, so it clears the new fields for free |
| `mfa/memory_test.go` | memory unit cases |
| `mfa/store_mock_test.go` | regenerated (`go generate ./mfa/...`) |
| `mfa/totp.go` | `Verify` order: charge, match, accept, give back |
| `mfa/totpoptions.go` | `WithVerifyAttempts` |
| `mfa/totpattempts_test.go` (new) | Verify tests for 2.1 to 2.4 |
| `seal/mfa.go`, `seal/mfa_test.go` | pass-through |
| `internal/pgschema/mfa.go` | two statements; `EnrolmentPutPending` and `EnrolmentGet` gain the columns |
| `migrate/securitystate/20260926000000_security_state.sql` | two columns |
| `sqlstore/mfa.go` | implementation and Get scan |
| `recovery/totpcharge_test.go` (new) | 2.5 |
| `httpsec/mfaverify.go`, `httpsec/mfaverify_attempts_test.go` (new) | 3.1 |

**Other modules**
- `pgx` module: `pgx/mfa.go`, for the implementation and the Get scan.
- `gorm` module: `gorm/mfa.go`, for the implementation and the Get scan.
- `test` module:

  | File | Change |
  |---|---|
  | `storetest/mfa_suite.go` | cases |
  | `storetest/race.go` | `RunVerifyChargeRace`, `verifyChargeRule` |
  | `internal/storefix/races.go` | `VerifyChargeRace` |
  | `storetest/broken_mfa_test.go` | four defects |
  | `storetest/broken_race_test.go` | race variants |
  | `sqlstore/mfa_test.go`, `pgxstore/mfa_test.go`, `gormstore/mfa_test.go` | wiring |

---

### Task 1.1: Contract and in-memory store

**Files:**
- Modify: `mfa/mfa.go`, `mfa/store.go`, `mfa/memory.go`, `mfa/memory_test.go`, `mfa/store_mock_test.go` (regenerated)
- Modify: `test/storetest/mfa_suite.go`, `test/storetest/race.go`, `test/internal/storefix/races.go`
- Every other `mfa.EnrolmentStore` implementer must still compile by the end of group 1. In tasks 1.3 and 1.5, `seal`, `sqlstore`, `pgx` and `gorm` get real implementations. Until then a temporary method returning `(time.Time{}, false, errors.New("not implemented"))` is allowed only within this group's dispatch, and must be gone before 1.5 reports.

**Interfaces:**
- Produces:

```go
// mfa/mfa.go
const (
	// DefaultVerifyAttemptLimit is how many TOTP verification attempts may be
	// charged against one enrolment within a window, unless WithVerifyAttempts
	// replaces it.
	DefaultVerifyAttemptLimit = 5
	// DefaultVerifyAttemptWindow is the length of a charging window, unless
	// WithVerifyAttempts replaces it.
	DefaultVerifyAttemptWindow = 15 * time.Minute
)

// ErrVerifyAttemptsExhausted refuses a TOTP verification whose attempt could
// not be charged: the enrolment's window already holds its limit. The code is
// not compared. It matches ErrVerifyThrottled.
var ErrVerifyAttemptsExhausted = fmt.Errorf("%w: the enrolment's verification attempts are spent for this window", ErrVerifyThrottled)

// mfa/store.go, on Enrolment
	// VerifyAttempts counts the TOTP verification attempts charged in the
	// window ending at VerifyWindowUntil. PutPending clears it.
	VerifyAttempts int
	// VerifyWindowUntil is when the current charging window ends. Zero means
	// no window is open. PutPending clears it.
	VerifyWindowUntil time.Time

// mfa/store.go, on EnrolmentStore
	// ChargeVerifyAttempt charges one TOTP verification attempt at at against
	// the user's confirmed enrolment, in one operation that decides and writes.
	// When the window has ended (its end at or before at, or none open) it
	// opens one ending at at+window, truncated to the microsecond, counting
	// one; otherwise it counts one more while fewer than limit are charged. It
	// returns the end of the window charged in. ok is false, with nothing
	// changed, for an absent or pending enrolment or a full window.
	ChargeVerifyAttempt(ctx context.Context, user identity.UserID, at time.Time,
		limit int, window time.Duration) (until time.Time, ok bool, err error)

	// RefundVerifyAttempt gives back one attempt charged in the window ending
	// at until, in one operation that decides and writes. It reports false,
	// with nothing changed, when the enrolment's window end is not until or
	// no attempt is charged.
	RefundVerifyAttempt(ctx context.Context, user identity.UserID, until time.Time) (bool, error)
```

- Test module produces `storetest.RunVerifyChargeRace[S mfa.EnrolmentStore](t, h DurableHarness[S], r Race[S])` and `storefix.VerifyChargeRace[S mfa.EnrolmentStore]() storetest.Race[S]`.

- [ ] **Step 1: Write the failing suite cases.** In `test/storetest/mfa_suite.go`, append to the `cases` slice of `RunEnrolmentStoreSuite`. The cases need a confirmed enrolment; add this helper beside `pendingEnrolment`:

```go
// confirmedEnrolment stores and confirms an enrolment for user at suiteStart.
func confirmedEnrolment(ctx context.Context, t *testing.T, s mfa.EnrolmentStore, user identity.UserID) {
	t.Helper()
	require.NoError(t, s.PutPending(ctx, pendingEnrolment(user, "secret", 0)))
	ok, err := s.Confirm(ctx, user, 1000, suiteStart)
	require.NoError(t, err)
	require.True(t, ok)
}
```

Cases, named exactly after the spec scenarios. "Concurrent charges against one enrolment" lives in the race suite, not here:

```go
{
	name: "The window ends at its end instant",
	assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
		confirmedEnrolment(ctx, t, s, mfaUser)
		for range 5 {
			until, ok, err := s.ChargeVerifyAttempt(ctx, mfaUser, suiteStart, 5, 15*time.Minute)
			require.NoError(t, err)
			require.True(t, ok)
			assertTimeEqual(t, suiteStart.Add(15*time.Minute), until, "window end")
		}
		_, ok, err := s.ChargeVerifyAttempt(ctx, mfaUser, suiteStart.Add(14*time.Minute), 5, 15*time.Minute)
		require.NoError(t, err)
		assert.False(t, ok, "a sixth charge inside the window must be refused")

		until, ok, err := s.ChargeVerifyAttempt(ctx, mfaUser, suiteStart.Add(15*time.Minute), 5, 15*time.Minute)
		require.NoError(t, err)
		require.True(t, ok, "a charge at the window's end instant opens a new window")
		assertTimeEqual(t, suiteStart.Add(30*time.Minute), until, "new window end")
		got, _, err := s.Get(ctx, mfaUser)
		require.NoError(t, err)
		assert.Equal(t, 1, got.VerifyAttempts)
	},
},
{
	name: "Pending enrolment is not charged",
	assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
		require.NoError(t, s.PutPending(ctx, pendingEnrolment(mfaUser, "secret", 0)))
		_, ok, err := s.ChargeVerifyAttempt(ctx, mfaUser, suiteStart, 5, 15*time.Minute)
		require.NoError(t, err)
		assert.False(t, ok)
		got, _, err := s.Get(ctx, mfaUser)
		require.NoError(t, err)
		assert.Zero(t, got.VerifyAttempts)
		assert.True(t, got.VerifyWindowUntil.IsZero())

		_, ok, err = s.ChargeVerifyAttempt(ctx, "absent-user", suiteStart, 5, 15*time.Minute)
		require.NoError(t, err)
		assert.False(t, ok, "an absent enrolment is not charged")
	},
},
{
	name: "Give-back in the window it was charged in",
	assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
		confirmedEnrolment(ctx, t, s, mfaUser)
		until, ok, err := s.ChargeVerifyAttempt(ctx, mfaUser, suiteStart, 5, 15*time.Minute)
		require.NoError(t, err)
		require.True(t, ok)
		_, ok, err = s.ChargeVerifyAttempt(ctx, mfaUser, suiteStart, 5, 15*time.Minute)
		require.NoError(t, err)
		require.True(t, ok)

		ok, err = s.RefundVerifyAttempt(ctx, mfaUser, until)
		require.NoError(t, err)
		assert.True(t, ok)
		got, _, err := s.Get(ctx, mfaUser)
		require.NoError(t, err)
		assert.Equal(t, 1, got.VerifyAttempts)
	},
},
{
	name: "Give-back after the window was replaced",
	assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
		confirmedEnrolment(ctx, t, s, mfaUser)
		first, ok, err := s.ChargeVerifyAttempt(ctx, mfaUser, suiteStart, 5, 15*time.Minute)
		require.NoError(t, err)
		require.True(t, ok)
		_, ok, err = s.ChargeVerifyAttempt(ctx, mfaUser, suiteStart.Add(15*time.Minute), 5, 15*time.Minute)
		require.NoError(t, err)
		require.True(t, ok)

		ok, err = s.RefundVerifyAttempt(ctx, mfaUser, first)
		require.NoError(t, err)
		assert.False(t, ok, "a give-back naming a replaced window must be refused")
		got, _, err := s.Get(ctx, mfaUser)
		require.NoError(t, err)
		assert.Equal(t, 1, got.VerifyAttempts)
	},
},
{
	name: "Give-back at zero",
	assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
		confirmedEnrolment(ctx, t, s, mfaUser)
		until, ok, err := s.ChargeVerifyAttempt(ctx, mfaUser, suiteStart, 5, 15*time.Minute)
		require.NoError(t, err)
		require.True(t, ok)
		ok, err = s.RefundVerifyAttempt(ctx, mfaUser, until)
		require.NoError(t, err)
		require.True(t, ok)

		ok, err = s.RefundVerifyAttempt(ctx, mfaUser, until)
		require.NoError(t, err)
		assert.False(t, ok)
		got, _, err := s.Get(ctx, mfaUser)
		require.NoError(t, err)
		assert.Zero(t, got.VerifyAttempts)
	},
},
{
	name: "A new begin clears the count",
	assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
		confirmedEnrolment(ctx, t, s, mfaUser)
		for range 3 {
			_, ok, err := s.ChargeVerifyAttempt(ctx, mfaUser, suiteStart, 5, 15*time.Minute)
			require.NoError(t, err)
			require.True(t, ok)
		}
		require.NoError(t, s.Delete(ctx, mfaUser))
		require.NoError(t, s.PutPending(ctx, pendingEnrolment(mfaUser, "secret-2", 1)))
		got, _, err := s.Get(ctx, mfaUser)
		require.NoError(t, err)
		assert.Zero(t, got.VerifyAttempts)
		assert.True(t, got.VerifyWindowUntil.IsZero())
	},
},
```

Also extend `assertEnrolment` with:

```go
assert.Equal(t, want.VerifyAttempts, got.VerifyAttempts, "VerifyAttempts")
assertTimeEqual(t, want.VerifyWindowUntil, got.VerifyWindowUntil, "VerifyWindowUntil")
```

- [ ] **Step 2: Add the race rule and fixture.** In `test/storetest/race.go`:

```go
verifyChargeRule = raceRule{
	name:   "exactly the limit of verification charges win per enrolment",
	noun:   "verification charge",
	wins:   mfa.DefaultVerifyAttemptLimit,
	racers: defaultChargeRacers,
}

// RunVerifyChargeRace holds an MFA enrolment store to capping the TOTP
// verification attempts charged in one window: Racers callers charge the same
// confirmed enrolment at once for each of Records independent enrolments, and
// exactly mfa.DefaultVerifyAttemptLimit charges of each must succeed. Seed
// stores and confirms an enrolment and returns its user reference; Attempt
// reports the bool ChargeVerifyAttempt returns with that limit.
// storefix.VerifyChargeRace is such a race. Its inputs are checked as
// RunChargeRace checks them.
func RunVerifyChargeRace[S any](t *testing.T, h DurableHarness[S], r Race[S]) {
	t.Helper()
	runRace(t, h, r, verifyChargeRule)
}
```

In `test/internal/storefix/races.go`:

```go
// VerifyChargeRace is the race over TOTP verification charges: Seed stores and
// confirms the enrolment of race-user-i, every racer charges it at
// RaceAttemptAt with the default limit and window, and Check requires the
// count to be the limit.
func VerifyChargeRace[S mfa.EnrolmentStore]() storetest.Race[S] {
	return storetest.Race[S]{
		Seed: func(ctx context.Context, t *testing.T, s S, i int) string {
			user := identity.UserID(fmt.Sprintf("race-user-%d", i))
			require.NoError(t, s.PutPending(ctx, Pending(user, "secret")))
			ok, err := s.Confirm(ctx, user, 1000, EnrolmentBegun.Add(time.Minute))
			require.NoError(t, err)
			require.True(t, ok)
			return string(user)
		},
		Attempt: func(ctx context.Context, s S, key string, _ int) (bool, error) {
			_, ok, err := s.ChargeVerifyAttempt(ctx, identity.UserID(key), RaceAttemptAt,
				mfa.DefaultVerifyAttemptLimit, mfa.DefaultVerifyAttemptWindow)
			return ok, err
		},
		Check: func(ctx context.Context, t *testing.T, s S, key string) {
			t.Helper()
			e, ok, err := s.Get(ctx, identity.UserID(key))
			require.NoError(t, err)
			require.True(t, ok)
			assert.Equal(t, mfa.DefaultVerifyAttemptLimit, e.VerifyAttempts,
				"%q: VerifyAttempts after the race must be the limit", key)
		},
	}
}
```

In `test/storetest/broken_race_test.go`, add to `enrolmentRaceVariants` a memory run that must pass:

```go
{
	name: "race-verify-charge-memory",
	run: func(t *testing.T) {
		storetest.RunVerifyChargeRace(t, sharedHarness(mfa.NewMemoryEnrolmentStore),
			storefix.VerifyChargeRace[*mfa.MemoryEnrolmentStore]())
	},
},
```

- [ ] **Step 3: Add the contract with a refusing memory implementation, then run the tests to see them fail.** Add the fields and methods from **Interfaces**. Give `MemoryEnrolmentStore` both methods returning `(time.Time{}, false, nil)` and `(false, nil)`. Regenerate the mocks:

Run: `go generate ./mfa/...`, then in `test`: `go test -race -count=1 -run 'TestMemoryEnrolmentStore|TestBroken' ./storetest/...`
Expected: FAIL. The case "The window ends at its end instant" fails at `require.True(t, ok)`, the give-back cases fail likewise, and "race-verify-charge-memory" reports `fewer than 5 successful verification charge`. Record this output in the report.

- [ ] **Step 4: Implement the memory store.**

```go
// ChargeVerifyAttempt charges one TOTP verification attempt at at against the
// user's confirmed enrolment. Deciding and writing happen under one lock, so
// of any number of concurrent charges in one window exactly limit succeed.
func (s *MemoryEnrolmentStore) ChargeVerifyAttempt(
	_ context.Context, user identity.UserID, at time.Time, limit int, window time.Duration,
) (time.Time, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.enrolments[user]
	if !ok || e.ConfirmedAt.IsZero() {
		return time.Time{}, false, nil
	}

	switch {
	case e.VerifyWindowUntil.IsZero() || !at.Before(e.VerifyWindowUntil):
		e.VerifyAttempts = 1
		e.VerifyWindowUntil = at.Add(window).Truncate(time.Microsecond)
	case e.VerifyAttempts < limit:
		e.VerifyAttempts++
	default:
		return time.Time{}, false, nil
	}
	s.enrolments[user] = e

	return e.VerifyWindowUntil, true, nil
}

// RefundVerifyAttempt gives back one attempt charged in the window ending at
// until, under the same lock as the charge.
func (s *MemoryEnrolmentStore) RefundVerifyAttempt(
	_ context.Context, user identity.UserID, until time.Time,
) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.enrolments[user]
	if !ok || e.VerifyAttempts <= 0 || !e.VerifyWindowUntil.Equal(until) {
		return false, nil
	}
	e.VerifyAttempts--
	s.enrolments[user] = e

	return true, nil
}
```

Add a `mfa/memory_test.go` table case for the default truncation: a charge at `preciseStart`-like time `10:00:00.123456789` returns `10:15:00.123456`.

- [ ] **Step 5: Run the tests to see them pass.**

Run: `go test -race ./mfa/...`, and in `test`: `go test -race -count=1 -run 'TestMemoryEnrolmentStore|TestBroken' ./storetest/...`
Expected: PASS.

### Task 1.2: Broken-store variants

**Files:**
- Modify: `test/storetest/broken_mfa_test.go`, `test/storetest/broken_race_test.go`

**Interfaces:**
- Consumes `ChargeVerifyAttempt`, `RefundVerifyAttempt`, `RunVerifyChargeRace` and `storefix.VerifyChargeRace` from 1.1.

- [ ] **Step 1: Add the defects and a conforming implementation to the `mfaStore` fake.**

```go
// ChargeVerifyAttempt counts every charge in the window, however many were
// charged before.
mfaVerifyChargeWithoutCap mfaDefect = "verify-charge-without-cap"
// ChargeVerifyAttempt reads the count, then writes it plus one outside the
// lock, so concurrent charges all win.
mfaVerifyChargeReadThenWrite mfaDefect = "verify-charge-read-then-write"
// ChargeVerifyAttempt never opens a new window, so an ended one keeps counting.
mfaVerifyWindowNeverEnds mfaDefect = "verify-window-never-ends"
// RefundVerifyAttempt lowers the count whatever window it names.
mfaVerifyRefundIgnoresWindow mfaDefect = "verify-refund-ignores-window"
```

Implement `(*mfaStore).ChargeVerifyAttempt` and `RefundVerifyAttempt` like the memory store, branching on `s.defect`. For read-then-write, read under the lock, release it, `runtime.Gosched()`, then write `count+1` under the lock, as the existing `mfaChargeReadThenWrite` does.

- [ ] **Step 2: Register the variants**, each naming the case that must catch it:

```go
mfaVariant(mfaVerifyChargeWithoutCap, "The window ends at its end instant"),
mfaVariant(mfaVerifyWindowNeverEnds, "The window ends at its end instant"),
mfaVariant(mfaVerifyRefundIgnoresWindow, "Give-back after the window was replaced"),
```

and in `enrolmentRaceVariants`:

```go
{
	name: "race-verify-charge-conforming",
	run: func(t *testing.T) {
		storetest.RunVerifyChargeRace(t, sharedHarness(mfaRaceStore(mfaConforming)),
			storefix.VerifyChargeRace[*mfaStore]())
	},
},
{
	name: "race-verify-charge-read-then-write",
	run: func(t *testing.T) {
		storetest.RunVerifyChargeRace(t, sharedHarness(mfaRaceStore(mfaVerifyChargeReadThenWrite)),
			storefix.VerifyChargeRace[*mfaStore]())
	},
	failsCase: verifyChargeCase,
	failsWith: "more than 5 successful verification charge",
},
```

Define `verifyChargeCase` beside `chargeCase`, as the rule name `"exactly the limit of verification charges win per enrolment"`.

- [ ] **Step 3: Show each variant is caught by its own case.** Temporarily make each defect branch behave conformingly, run the tests, and confirm the guard reports the variant as "passed when it must fail". Then restore the branch by editing it back. Never use git to restore.

Run: `go test -race -count=1 -run 'TestBroken' ./storetest/` in `test`
Expected: PASS, with every new variant failing in its named case.

### Task 1.3: Sealing store pass-through

**Files:**
- Modify: `seal/mfa.go`, `seal/mfa_test.go`

**Interfaces:**
- Consumes `mfa.EnrolmentStore.ChargeVerifyAttempt` and `RefundVerifyAttempt`.

- [ ] **Step 1: Write the failing test.** Add a table test `TestEnrolmentStore_PassesVerifyAttemptsThrough` using the typed mock of `mfa.EnrolmentStore` that `seal` already uses (`use-mockgen`). It has three cases:
  - a charge, expecting the inner store to receive exactly `(user, at, 5, 15*time.Minute)` and checking its `(until, true, nil)` is returned unchanged;
  - a give-back, expecting `(user, until)` and returning `true`;
  - an inner error, which is returned matching the inner error by `errors.Is`, with a `seal:` text.

  Run: `go test -race -count=1 -run TestEnrolmentStore_PassesVerifyAttemptsThrough ./seal/`
  Expected: FAIL, with the mock reporting a missing call, because the temporary method from 1.1 does not call the inner store.

- [ ] **Step 2: Implement.**

```go
// ChargeVerifyAttempt passes through to inner.
func (s *enrolmentStore) ChargeVerifyAttempt(
	ctx context.Context, user identity.UserID, at time.Time, limit int, window time.Duration,
) (time.Time, bool, error) {
	until, ok, err := s.inner.ChargeVerifyAttempt(ctx, user, at, limit, window)

	return until, ok, enrolmentFailed(err, "seal: the inner store could not charge the TOTP attempt")
}

// RefundVerifyAttempt passes through to inner.
func (s *enrolmentStore) RefundVerifyAttempt(ctx context.Context, user identity.UserID, until time.Time) (bool, error) {
	ok, err := s.inner.RefundVerifyAttempt(ctx, user, until)

	return ok, enrolmentFailed(err, "seal: the inner store could not give back the TOTP attempt")
}
```

- [ ] **Step 3:** Run `go test -race ./seal/...`. Expected: PASS.

### Task 1.4: Schema and shared SQL

**Files:**
- Modify: `migrate/securitystate/20260926000000_security_state.sql`, `internal/pgschema/mfa.go`

**Interfaces:**
- Produces `pgschema.EnrolmentChargeVerifyAttempt` (`$1 user_id, $2 at, $3 new window end, $4 limit`, returning `verify_window_until`) and `pgschema.EnrolmentRefundVerifyAttempt` (`$1 user_id, $2 window end`).
- `EnrolmentGet` gains `verify_attempts, verify_window_until` as its last two columns, in that order.

- [ ] **Step 1: Write the failing test.** Add a case to the existing migration test in `migrate` (or `test/sqlstore`'s schema test, wherever columns of `mfa_enrolments` are asserted today; find it with `rg -n 'email_code_attempts' --glob '!.claude/.legacy' migrate test`). It asserts that `verify_attempts` is an `integer NOT NULL DEFAULT 0` column and that `verify_window_until` is a nullable `timestamptz`.
  Run that test. Expected: FAIL, because the column does not exist.

- [ ] **Step 2: Add the columns** after `email_code_attempts`:

```sql
    email_code_attempts integer NOT NULL DEFAULT 0,
    -- TOTP verification attempts charged in the window ending at
    -- verify_window_until. NULL = no window open.
    verify_attempts     integer NOT NULL DEFAULT 0,
    verify_window_until timestamptz NULL
```

- [ ] **Step 3: Add the statements** and extend `EnrolmentPutPending` (`verify_attempts = 0, verify_window_until = NULL` in its `DO UPDATE SET`; the insert path uses the defaults) and `EnrolmentGet`:

```go
	// EnrolmentChargeVerifyAttempt charges one TOTP verification attempt
	// against user $1's confirmed enrolment at $2. When the window has ended
	// (none open, or its end at or before $2) it opens one ending at $3,
	// counting one; otherwise it counts one more while fewer than $4 are
	// charged. It returns the window's end. No row returned means no charge.
	EnrolmentChargeVerifyAttempt = `UPDATE mfa_enrolments SET
  verify_attempts = CASE WHEN verify_window_until IS NULL OR verify_window_until <= $2
                         THEN 1 ELSE verify_attempts + 1 END,
  verify_window_until = CASE WHEN verify_window_until IS NULL OR verify_window_until <= $2
                             THEN $3 ELSE verify_window_until END
 WHERE user_id = $1 AND confirmed_at IS NOT NULL
   AND (verify_window_until IS NULL OR verify_window_until <= $2 OR verify_attempts < $4)
RETURNING verify_window_until`

	// EnrolmentRefundVerifyAttempt gives back one attempt charged against user
	// $1's enrolment in the window ending at $2. Zero rows affected means the
	// window was replaced or nothing is charged.
	EnrolmentRefundVerifyAttempt = `UPDATE mfa_enrolments SET verify_attempts = verify_attempts - 1
 WHERE user_id = $1 AND verify_window_until = $2 AND verify_attempts > 0`
```

- [ ] **Step 4:** Run `go test -race ./migrate/... ./internal/pgschema/...`. Expected: PASS. The Get scanners break here until 1.5; that is within the group.

### Task 1.5: Durable adapters

**Files:**
- Modify: `sqlstore/mfa.go`, `pgx/mfa.go`, `gorm/mfa.go`
- Modify: `test/sqlstore/mfa_test.go`, `test/pgxstore/mfa_test.go`, `test/gormstore/mfa_test.go`, `test/storetest/mfa_suite.go`

**Interfaces:**
- Consumes the 1.4 statements.

- [ ] **Step 1: Wire the suites and the race first, then add the precision case.**
  - The enrolment suite already runs per backend, so the 1.1 cases reach these backends with no further wiring.
  - Add a race test per backend, next to `TestEnrolmentStore_StepAcceptRace`, for example in `test/sqlstore/mfa_test.go`:

```go
func TestEnrolmentStore_VerifyChargeRace(t *testing.T) {
	t.Parallel()

	c := storefix.TestCipher(t)
	h := durableHarness(migratedDB(t), func(t *testing.T, db *sql.DB, opts ...sqlstore.Option) mfa.EnrolmentStore {
		return newEnrolmentStore(t, db, c, opts...)
	})
	h.PoolSize = 20

	t.Run("sqlstore", func(t *testing.T) {
		storetest.RunVerifyChargeRace(t, h, storefix.VerifyChargeRace[mfa.EnrolmentStore]())
	})
}
```

  - Add the same test in `test/pgxstore/mfa_test.go` and `test/gormstore/mfa_test.go`, using each file's own `durableHarness` constructor and store type as its `TestEnrolmentStore_StepAcceptRace` does. Set `PoolSize` to 20 in each; check how `RunChargeRace` sets its pool there and copy that.
  - Add a precision case to `RunEnrolmentStoreSuite`:

```go
{
	name: "a charge's window end is matched by its give-back at microsecond precision",
	assert: func(t *testing.T, ctx context.Context, s mfa.EnrolmentStore, _ *clockwork.FakeClock) {
		confirmedEnrolment(ctx, t, s, mfaUser)
		until, ok, err := s.ChargeVerifyAttempt(ctx, mfaUser, preciseStart, 5, 15*time.Minute)
		require.NoError(t, err)
		require.True(t, ok)
		assert.True(t, until.Equal(preciseStart.Add(15*time.Minute).Truncate(time.Microsecond)),
			"window end %v must be the charge instant plus the window, truncated to the microsecond", until)
		ok, err = s.RefundVerifyAttempt(ctx, mfaUser, until)
		require.NoError(t, err)
		assert.True(t, ok, "the give-back naming the returned window end must match")
	},
},
```

  Run in `test`: `go test -race -count=1 -run 'TestEnrolmentStore' ./sqlstore/ ./pgxstore/ ./gormstore/`
  Expected: FAIL, from the temporary refusing methods (no successful charges) and from the Get scan column mismatch. Record the output.

- [ ] **Step 2: Implement `sqlstore`.** Add the two columns to the Get scan, mapping a NULL `verify_window_until` to the zero time as `email_code_until` is mapped. Then:

```go
// ChargeVerifyAttempt charges one TOTP verification attempt against the user's
// confirmed enrolment at at, in one conditional update that returns the
// window's end.
func (s *enrolmentStore) ChargeVerifyAttempt(
	ctx context.Context, user identity.UserID, at time.Time, limit int, window time.Duration,
) (time.Time, bool, error) {
	if !storekit.Storable(string(user)) {
		return time.Time{}, false, nil
	}

	var until time.Time
	err := s.c.queryRow(ctx, "charge TOTP verification attempt", pgschema.EnrolmentChargeVerifyAttempt,
		[]any{string(user), storekit.Time(at), storekit.Time(at.Add(window).Truncate(time.Microsecond)), limit},
		&until)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}

	return until.UTC(), true, nil
}

// RefundVerifyAttempt gives back one attempt charged in the window ending at
// until, in one conditional update.
func (s *enrolmentStore) RefundVerifyAttempt(ctx context.Context, user identity.UserID, until time.Time) (bool, error) {
	if !storekit.Storable(string(user)) {
		return false, nil
	}

	n, err := s.c.exec(ctx, "give back TOTP verification attempt", pgschema.EnrolmentRefundVerifyAttempt,
		string(user), storekit.Time(until))

	return n > 0, err
}
```

- [ ] **Step 3: Implement `pgx`** with the same statements, through the `queryRow` and `exec` helpers its `ChargeEmailCode` uses, mapping `pgxv5.ErrNoRows` to `(time.Time{}, false, nil)`. Extend its Get scan.

- [ ] **Step 4: Implement `gorm`** through the `s.returning(...)` helper its `ChargeEmailCode` uses for the charge, and its exec helper for the give-back, reporting affected rows greater than 0. Extend its Get scan, and its `PutPending` map of cleared columns with `"verify_attempts": 0, "verify_window_until": nil`. A struct would skip zero fields.

- [ ] **Step 5: Remove every temporary method from 1.1, and run the whole workspace.**

Run: `go test -race ./...` in the root, `pgx`, `gorm` and `test` modules
Expected: PASS.

- [ ] **Step 6: Commit (main session)** after review:

```bash
git add mfa seal internal/pgschema migrate sqlstore pgx gorm test
git commit -m "feat(mfa): charge TOTP verification attempts atomically in every enrolment store"
```

### Task 2.1: Red step for the overshoot

**Files:**
- Create: `mfa/totpattempts_test.go`

**Interfaces:**
- Consumes `mfa.NewVerifyThrottle(mfa.WithVerifyLimiter(l))`. Check the exact option name with `go doc ./mfa ThrottleOption` after `shared-rate-limiting` lands, and use that name.

- [ ] **Step 1: Write the test.**

```go
// barrierLimiter holds every Exceeded call until n callers have checked, so
// all of them pass the check before any failure is recorded.
type barrierLimiter struct {
	wg sync.WaitGroup
}

func newBarrierLimiter(n int) *barrierLimiter {
	l := &barrierLimiter{}
	l.wg.Add(n)
	return l
}

func (l *barrierLimiter) Exceeded(context.Context, string) (bool, error) {
	l.wg.Done()
	l.wg.Wait()
	return false, nil
}

func (l *barrierLimiter) RecordFailure(context.Context, string) error { return nil }

func TestTOTP_ConcurrentWrongCodesAreComparedAtMostTheLimit(t *testing.T) {
	t.Parallel()

	const racers = 20
	ctx := t.Context()
	clk := clockwork.NewFakeClockAt(time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC))
	store := mfa.NewMemoryEnrolmentStore()
	totp, err := mfa.NewTOTP(store, "scrty-test", mfa.WithClock(clk))
	require.NoError(t, err)
	user := identity.UserID("u-1")
	enrolConfirmed(t, totp, store, user, clk) // existing helper in mfa tests; see totp_test.go

	throttle, err := mfa.NewVerifyThrottle(mfa.WithVerifyLimiter(newBarrierLimiter(racers)))
	require.NoError(t, err)

	var compared atomic.Int32
	var wg sync.WaitGroup
	for range racers {
		wg.Go(func() {
			if throttle.Check(ctx, user) != nil {
				return
			}
			if errors.Is(totp.Verify(ctx, user, []byte("000000")), mfa.ErrInvalidCode) {
				compared.Add(1)
			}
		})
	}
	wg.Wait()

	assert.LessOrEqual(t, int(compared.Load()), mfa.DefaultVerifyAttemptLimit,
		"wrong codes compared against one enrolment")
}
```

If `000000` happens to be valid at the fake instant, pick a code computed to differ. The existing TOTP tests have a helper for the valid code; use its complement.

- [ ] **Step 2: Run it.**

Run: `go test -race -run TestTOTP_ConcurrentWrongCodesAreComparedAtMostTheLimit -count=1 ./mfa/`
Expected: FAIL with `"20" is not less than or equal to "5"`. Record it.

### Task 2.2: Charge before compare

**Files:**
- Modify: `mfa/totp.go`, `mfa/totpattempts_test.go`

**Interfaces:**
- Produces fields `verifyLimit int` and `verifyWindow time.Duration` on `TOTP`, defaulted in `NewTOTP` to the `Default*` constants.

- [ ] **Step 1: Write the failing table**, `TestTOTP_VerifyCharges`, in the project's `assert`-closure form (`table-test`). Use a mock `mfa.EnrolmentStore` where the case needs a failure, and the memory store otherwise. Cases:
  - "malformed code is charged": `Verify(ctx, u, []byte("12"))` returns `ErrInvalidCode`, and `Get` shows `VerifyAttempts == 1`.
  - "pending enrolment is not charged": `ErrInvalidCode` and `VerifyAttempts == 0`.
  - "absent enrolment is not charged": `ErrInvalidCode`, and the mock expects no `ChargeVerifyAttempt`.
  - "refused charge is not compared": a mock returns `ok=false`. Assert `errors.Is(err, mfa.ErrVerifyAttemptsExhausted)` and `errors.Is(err, mfa.ErrVerifyThrottled)`, and that the mock expects no `AcceptStep`, even for a valid code.
  - "store failure while charging": the mock returns `errBoom`. Assert `errors.Is(err, errBoom)`, `!errors.Is(err, mfa.ErrInvalidCode)` and `!errors.Is(err, mfa.ErrVerifyThrottled)`, and that the text starts `mfa:`.
  - "a new window admits a valid code": with the memory store, five wrong codes at 12:00, then a valid code at 12:16 (advance the fake clock), which returns nil.

  Run: `go test -race -run 'TestTOTP_VerifyCharges' -count=1 ./mfa/`
  Expected: FAIL. "malformed code is charged" reads `VerifyAttempts` 0, and "refused charge is not compared" sees `AcceptStep` called.

- [ ] **Step 2: Implement** in `(*TOTP).Verify`, between the enrolment check and `t.match`:

```go
	until, charged, err := t.store.ChargeVerifyAttempt(ctx, user, t.clock.Now(), t.verifyLimit, t.verifyWindow)
	if err != nil {
		return enrolmentStoreFailed(err, "mfa: totp could not charge the verification attempt")
	}
	if !charged {
		t.record(ctx, slog.LevelDebug, msgCodeRefused, user, slog.String("reason", "attempts-spent"))

		return ErrVerifyAttemptsExhausted
	}
```

  Keep `until` for 2.3. Until then, write it as `_` and change it in 2.3. Update `Verify`'s godoc to state the order: read, charge, compare, accept.

- [ ] **Step 3:** Run `go test -race ./mfa/...`. Expected: PASS, and 2.1's test now passes.

### Task 2.3: Give back on success

**Files:**
- Modify: `mfa/totp.go`, `mfa/totpattempts_test.go`

- [ ] **Step 1: Write the failing table**, `TestTOTP_VerifyGivesBack`. Cases:
  - "successes spend nothing": seven valid codes at successive 30-second steps within 15 minutes all return nil, and `VerifyAttempts == 0` afterwards.
  - "replayed step keeps its charge": a valid code is accepted, then the same code at the same instant returns `ErrInvalidCode`, and `VerifyAttempts == 1`.
  - "give-back failure is logged": a mock store's `RefundVerifyAttempt` returns `errBoom`. Verify returns nil, and the captured `slog` handler (`WithTOTPLogger`) holds one WARN record carrying the fixed `reason` and the error's `error_type`, never the error's text (diagnostic-redaction "Log records carry no dependency error text").
  - "cancelled context still gives back": wrap the memory store so `RefundVerifyAttempt` fails when `ctx.Err() != nil`. Call Verify with a context cancelled after the charge (cancel inside a `ChargeVerifyAttempt` wrapper), and expect nil and `VerifyAttempts == 0`.

  Run: `go test -race -run 'TestTOTP_VerifyGivesBack' -count=1 ./mfa/`
  Expected: FAIL. "successes spend nothing" reads `VerifyAttempts` 5 and the sixth valid code is refused with `ErrVerifyAttemptsExhausted`.

- [ ] **Step 2: Implement**, after `AcceptStep` reports true and before the accepted log:

```go
	// A success gives back its own charge, in the window it was charged in,
	// so a user who proves the factor spends nothing. The caller hanging up
	// after the code was accepted must not cost them an attempt.
	if _, err := t.store.RefundVerifyAttempt(context.WithoutCancel(ctx), user, until); err != nil {
		t.record(ctx, slog.LevelWarn, msgGiveBackFailed, user,
			diag.Failure("enrolment-store", err)...)
	}
```

  Check `t.record`'s signature in `totp.go`, and match it. The record carries the error's type through `diag.Failure`, never its text, as `throttle.go` already does: a store's error text can hold connection details the redaction spec keeps out of logs.

- [ ] **Step 3:** Run `go test -race ./mfa/...`. Expected: PASS.

### Task 2.4: `WithVerifyAttempts`

**Files:**
- Modify: `mfa/totpoptions.go`, `mfa/totp.go` (validation in `NewTOTP`), `mfa/totpoptions_test.go`, `mfa/totpattempts_test.go`

**Interfaces:**
- Produces `func WithVerifyAttempts(limit int, window time.Duration) TOTPOption`.

- [ ] **Step 1: Write the failing tests.**
  - In the existing option table of `totpoptions_test.go`, add a limit of 0, a limit of -1, a window of 0 and a window of -1. Each must fail `NewTOTP` with `errors.Is(err, mfa.ErrConfig)`.
  - Add "the default is 5 per 15 minutes": six concurrent wrong codes through the barrier race of 2.1 compare at most 5.
  - Add "consumer limit": `WithVerifyAttempts(3, 10*time.Minute)` with 4 concurrent wrong codes compares at most 3.
  
  Run: `go test -race -run 'TestNewTOTP|TestTOTP_' -count=1 ./mfa/`
  Expected: FAIL, because `WithVerifyAttempts` is undefined. That is a compile error, not a red step. So first add the option as a no-op, then run again. Expected: FAIL, with "consumer limit" comparing 4 and the zero-limit cases constructing successfully.

- [ ] **Step 2: Implement.**

```go
// WithVerifyAttempts replaces how many TOTP verification attempts may be
// charged against one enrolment within a window, and the window's length. The
// default is DefaultVerifyAttemptLimit attempts per DefaultVerifyAttemptWindow
// (5 per 15 minutes). A limit or window of zero or less fails NewTOTP with
// ErrConfig.
//
// Each attempt is charged against the enrolment before its code is compared,
// so at most limit codes are compared per window however many requests arrive
// at once or however many replicas serve them. The window is fixed, so up to
// twice limit can be compared around a window's end. There is no way to turn
// the charge off: without it, concurrent requests are compared without bound.
func WithVerifyAttempts(limit int, window time.Duration) TOTPOption {
	return func(t *TOTP) {
		t.verifyLimit = limit
		t.verifyWindow = window
	}
}
```

In `NewTOTP`, after the period check:

```go
	if t.verifyLimit <= 0 {
		return nil, fmt.Errorf("%w: totp verification attempt limit must be positive, got %d", ErrConfig, t.verifyLimit)
	}
	if t.verifyWindow <= 0 {
		return nil, fmt.Errorf("%w: totp verification attempt window must be positive, got %s", ErrConfig, t.verifyWindow)
	}
```

- [ ] **Step 3:** Run `go test -race ./mfa/...` and `go doc ./mfa WithVerifyAttempts`. Expected: PASS, and the doc shows the default and the 2× note.

### Task 2.5: A recovery's TOTP proof is charged

**Files:**
- Create: `recovery/totpcharge_test.go`

- [ ] **Step 1: Write the test.**
  - Build a `Recoverer` the way `recover_test.go`'s helpers do, with a real `mfa.NewTOTP` over a `mfa.NewMemoryEnrolmentStore` as the MFA proof method, and a confirmed enrolment for the user.
  - Recover with a wrong TOTP code, and assert the enrolment reads `VerifyAttempts == 1`.
  - Then recover with a valid code, and assert success and `VerifyAttempts == 1`, since the success gave its own charge back.

  Run: `go test -race -run TestRecoverer_TOTPProofIsCharged -count=1 ./recovery/`
  Expected: PASS at once, because group 2 already charges inside the method. This task proves a property rather than driving code, so to show the test can fail, temporarily comment out the charge in `mfa/totp.go`, see it fail reading `VerifyAttempts` 0, then edit it back. Record both runs.
  If it fails on the real code, stop and report. Do not change `recovery`.

- [ ] **Step 2: Commit (main session)** after review:

```bash
git add mfa recovery
git commit -m "feat(mfa): TOTP verification charges each attempt before comparing it"
```

### Task 3.1: The verify endpoint does not record a refused charge

**Files:**
- Modify: `httpsec/mfaverify.go` (the step-8 comment and the `method.Verify` branch)
- Create: `httpsec/mfaverify_attempts_test.go`

- [ ] **Step 1: Write the failing tests.** Use the `httpsec` MFA test harness `mfaverify_test.go` already has (find its constructor with gopls references to `mfaInterceptor`).
  - `TestMFAVerify_RefusedChargeIsNotRecorded`: a typed mock `ratelimit.Limiter` expects `Exceeded` to return `false` and expects **no** `RecordFailure`. The MFA method's `Verify` returns `mfa.ErrVerifyAttemptsExhausted`. Expect HTTP 401 and that the error matches `mfa.ErrVerifyThrottled`.
  - `TestMFAVerify_ConcurrentWrongCodesComparedAtMostTheLimit`: 20 concurrent POSTs of a wrong code for one pending session, with a real TOTP over the memory store and the barrier limiter of 2.1, copied into the `httpsec` test file. Assert that at most 5 responses carry `mfa.ErrInvalidCode`, and the rest `mfa.ErrVerifyThrottled`.

  Run: `go test -race -run 'TestMFAVerify_RefusedCharge|TestMFAVerify_Concurrent' -count=1 ./httpsec/`
  Expected: FAIL on the first, with the mock reporting an unexpected `RecordFailure` call. The second passes already, because group 2 bounds it; record that it does.

- [ ] **Step 2: Implement.**

```go
	if err := method.Verify(ctx, user, response); err != nil {
		// A refusal of the authenticator itself, such as a suspected clone,
		// is not a wrong guess at the response, and a refused attempt charge
		// compared nothing: neither costs an attempt.
		if !errors.Is(err, mfa.ErrAuthenticatorRefused) && !errors.Is(err, mfa.ErrVerifyThrottled) {
			i.throttle.RecordFailure(ctx, user)
		}

		return err
	}
```

Update step 8 of the godoc list above `verify` to say that a throttled refusal from the method is returned unchanged and not recorded.

- [ ] **Step 3:** Run `go test -race ./httpsec/...`. Expected: PASS.

- [ ] **Step 4: Commit (main session):**

```bash
git add httpsec
git commit -m "fix(httpsec): do not count a refused TOTP attempt charge as a failed verification"
```

### Task 4.1: Whole-branch review

- [ ] **Step 1:** Dispatch a fresh Opus reviewer: security-critical refusal logic and a multi-package contract change. It reads `openspec/changes/atomic-code-attempts/` and the branch diff, and checks every requirement and scenario of the three spec deltas and design decisions 1–8 against the code and tests. It edits nothing. Each finding is `REPRODUCED`, with a failing test name and output, or `UNREPRODUCED`, with the reason.
- [ ] **Step 2:** Findings go back to a fresh dispatch of the owning group's lane. Unfixed findings are recorded in `design.md` by the main session.

### Task 4.2: Final gate

- [ ] **Step 1:** In each module of `go.work` (root, `pgx`, `gorm`, `test` and the rest), run:

```bash
go test -race ./...
go vet ./...
gofmt -l .
golangci-lint run
```

Then, at the root:

```bash
openspec validate atomic-code-attempts --strict
```

Expected: every test passes, `gofmt -l` prints nothing, lint is clean, and the change is valid.
