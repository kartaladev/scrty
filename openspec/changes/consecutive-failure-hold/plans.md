# Consecutive Failure Hold Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in cap on consecutive failed logins that holds an identifier, refused before its password is checked, until its failures are cleared by a password change through the chain or by the policy's `Reset`. A count below the cap expires after 30 days of inactivity.

**Architecture:**
- A new optional store contract, `policy.FailureStreakStore`, keeps one streak record per identifier. One atomic write advances it. The in-memory store and the three durable stores implement it, and each one's `Reset` clears the streak with the log.
- The lockout policy's `Attempts()` view advances the streak whenever a cap is set. The chain refuses construction when a capped policy's view is not what its password logins record into.
- Evaluation reads the streak first, and refuses a held identifier with a `*LockoutError` that also matches `ErrAccountHeld`.

**Tech Stack:** Go 1.27; testify (`assert`/`require`); `go.uber.org/mock` typed mocks; `github.com/jonboulle/clockwork` fake clocks; `log/slog`; PostgreSQL through `database/sql` (`sqlstore`), pgx v5 (`pgx`) and gorm (`gorm`); testcontainers through the `test` module's helpers.

**Spec:** `openspec/changes/consecutive-failure-hold/`. Read `proposal.md`, `design.md` (decisions 1–7), and the five delta specs under `specs/` (`security-policy`, `http-security-chain`, `security-state-stores`, `schema-migrations`, `expiry-sweeping`). Task numbers below are `tasks.md`'s.

## Global Constraints

- Test-first for every task (`.claude/rules/golang-tdd.md`). Each red step is run and seen to fail **for the intended reason**; a compile error is not a red step. A test that pins existing behaviour gets its red step by temporarily inverting the implementation, undone by editing the file back.
- Never run `git checkout --`, `git restore`, `git reset --hard`, `git stash` or `git clean`. The tree holds other agents' uncommitted work.
- Table tests follow the `table-test` skill:
  - an `assert` closure per case, with no `want` or `wantErr` fields;
  - `t.Context()`, never `context.Background()`.

  Examples are the exception, since they have no `t`.
- Test doubles come from the `use-mockgen` skill. `policy` tests already have `NewMockAttemptStore` (`policy/attempts_mock_test.go`). The new `FailureStreakStore` gets its mock from the existing `//go:generate` directive in `policy/attempts.go`, which covers every interface declared in that file.
- Heavy services come from the `use-testcontainers` skill, through the `test` module's existing PostgreSQL helpers (`migratedDB`, `emptied`).
- Library design (`.claude/rules/library-design.md`):
  - every new option's godoc names the default it replaces;
  - a wiring mistake fails at construction, with an error wrapping `policy.ErrConfig` (in `policy`) or the chain's configuration error (in `httpsec`);
  - every default has a test, as does at least one override.
- No production dependency is added to any module.
- Log records carry fixed text and the dependency's error type (`diag.Failure`). They never carry a dependency's error text or the submitted identifier.
- Identifiers are matched exactly, never folded. A string a PostgreSQL text column cannot hold (`storekit.Storable` false) is refused on write and reads as empty, exactly as the attempt store does today.
- Nothing cites, names or copies the predecessor reference under `.claude/.legacy/`.
- Do not edit anything under `openspec/`. Report where the code and the artifacts disagree.
- Every verification command named in a task is run, and its output is reported.

## Review Focus

1. **A cap lowered below an existing count.** A record with 70 consecutive failures, not held, under a new cap of 50, must become held on its next failure. That add must report that it set the hold, even though its count is not equal to the cap. This is why "set the hold" is returned by the store rather than inferred from `Failures == limit`. Pinned in Task 2.2 (suite case) and Task 4.6 (report).
2. **Out-of-order instants.** An add whose `at` is earlier than the stored newest failure must not move the newest failure backwards. The restart after inactivity is judged against the stored newest, not the late `at`. Pinned in Task 2.2.
3. **An unstorable identifier** (holding a NUL byte):
   - adding is refused with an error that does not echo the identifier;
   - reading returns an empty streak;
   - the policy's evaluation then reads the windowed count, which is also empty, so it allows.

   This matches `FailureCount`. Pinned in Task 2.2 and run by every backend in Task 3.2.
4. **A chain with a capped policy but no password login,** or with the same view given to both form login and Basic: construction succeeds. Pinned in Task 5.1.
5. **A reset racing a burst.** After `Reset`, an add starts again at one, not held, and a held identifier stays held only until its reset. A reset of an identifier with no streak is not an error. Pinned in Task 2.2.

## Dispatch map (main session)

| Wave | Dispatch | Tasks | Owns | Must not touch | Model | Reviewer |
|---|---|---|---|---|---|---|
| 1 | B1 | 1.1–1.2 | `httpsec/basic.go`, `httpsec/basic_test.go` | `policy/`, `test/`, every other `httpsec/` file | Sonnet: a known pattern copied from form login, with a reproduction test | Sonnet |
| 1 | S1 | 2.1–2.2 | `policy/streak.go` (new), `policy/attempts.go`, `policy/attempts_mock_test.go` (regenerated), `policy/streak_test.go` (new), `test/storetest/streak_suite.go` (new), `test/storetest/memory_test.go` | `httpsec/`, `policy/lockout*.go` | Opus: a contract other lanes compile against, with a race guarantee | Opus |
| 2 | D1 | 3.1–3.3 | `migrate/securitystate/20260926000000_security_state.sql`, `internal/pgschema/streaks.go` (new), `sqlstore/attempts.go`, `pgx/attempts.go`, `gorm/attempts.go`, `gorm/rows.go` (only if a row type is needed), `test/sqlstore/attempts_test.go`, `test/pgxstore/attempts_test.go`, `test/gormstore/attempts_test.go`, `test/migrate_securitystate_test.go`, `test/internal/storefix/ambients.go`, `test/crossbackend/streak_test.go` (new), the ambient wiring files in `test/sqlstore`, `test/pgxstore`, `test/gormstore` | `policy/`, `httpsec/` | Opus: one conditional upsert that must be atomic under concurrency, on three drivers | Opus |
| 2 | P1 | 4.1–4.4 | `policy/lockout.go`, `policy/lockout_error.go`, `policy/lockout_observer.go`, `policy/lockout_cap_test.go` (new), `policy/lockout_config_test.go` | `httpsec/`, `test/`, `policy/streak.go`, `policy/attempts.go` | Opus: security-critical refusal logic written for the first time | Opus |
| 3 | P2 | 4.5–4.7 | `policy/lockout.go`, `policy/lockout_observer.go`, `policy/lockout_cap_test.go`, `policy/lockout_observer_test.go`, `policy/example_test.go`, `policy/doc.go` | `httpsec/`, `test/` | Opus: concurrency, and exact once-only reporting | Opus |
| 4 | H1 | 5.1–5.4 | `policy/engine.go`, `policy/attempt_views.go` (new), `policy/engine_test.go`, `httpsec/lockout_wiring.go` (new), `httpsec/lockout_wiring_test.go` (new), `httpsec/held_test.go` (new), the one call in the chain's assembly (`httpsec/chain.go` `build`), `httpsec/options.go` (godoc only), `test/httpsecconformance/hold_scenarios.go` (new), the `Scenarios()` list in `test/httpsecconformance/scenarios.go` | `policy/lockout*.go`, `policy/streak.go` | Opus: an interface `httpsec` compiles against, and a construction guard a mistake would silently disarm | Opus |
| 4 | X1 | 6.1 | `test/expirytasks_test.go` | everything else | Sonnet: scenarios in an existing test file | Sonnet |
| 5 | main session | 7.1 | — | — | — | — |
| 5 | review | 7.2 | — | — | — | Opus |

Why these waves:
- B1 and S1 share no file and no API, so they run together.
- D1 implements the contract S1 defines, and P1 calls it, so both wait for S1. They share no file, so they run together.
- P2 extends the view and the evaluation that P1 writes, so it follows P1 in lane P.
- H1 asks the policy for its view and refusal, which P1 and P2 finish. X1 needs P2's purge. H1 and X1 share no file.

---

### Task 1.1: A successful Basic authentication clears failures (reproduce first)

**Files:**
- Modify: `httpsec/basic.go` (the success path after `b.authn.Authenticate`, before the stateless phase)
- Test: `httpsec/basic_test.go`

**Interfaces:**
- Consumes: `basicAuth.attempts policy.AttemptStore`, `basicAuth.log *slog.Logger`, and the existing constant `msgAttemptsNotReset` (`httpsec/login.go`).
- Produces: nothing new. Basic success now calls `attempts.Reset(ctx, username)`.

- [ ] **Step 1: Write the reproduction test.** It is `TestBasicSuccessClearsFailures` in `httpsec/basic_test.go`. Use the package's existing Basic harness (find it with gopls: the helper `basic_test.go` uses to build a chain with `EnableBasicAuth`). The test has four prior failures for `ada` in the mocked store, a request with the correct password, and an expectation of `Reset`:

```go
func TestBasicSuccessClearsFailures(t *testing.T) {
	t.Parallel()

	h := newBasicHarness(t) // the existing harness; it wires a MockAttemptStore as Attempts
	h.expectAuthenticated(testPrincipal())
	h.attempts.EXPECT().Reset(gomock.Any(), testSubject).Return(nil).Times(1)

	rec := h.serve(basicRequest(t, testSubject, testPassword))

	assert.Equal(t, http.StatusOK, rec.Code)
}
```

- [ ] **Step 2: Run it and see it fail.**

Run: `go test -count=1 -run 'TestBasicSuccessClearsFailures' ./httpsec/`
Expected: FAIL with `missing call(s) to *httpsec_test.MockAttemptStore.Reset(is anything, is equal to ada (string))`.
If it PASSES, stop and report to the main session. Design decision 6's claim was wrong, so the decision and the `http-security-chain` delta's Basic change are to be removed (`defect-claims.md`).

- [ ] **Step 3: Implement.** In `basic.go`, after `Authenticate` succeeds and before the stateless phase:

```go
	// A proven password supersedes the guesses before it, as at the login
	// form: a Basic client's typos must not add up to a lock its owner keeps
	// hitting with the right password.
	if err := b.attempts.Reset(ctx, username); err != nil {
		b.log.LogAttrs(ctx, slog.LevelError, msgAttemptsNotReset,
			diag.Failure("attempt-store", err)...)
	}
```

- [ ] **Step 4: Run it and see it pass,** together with the whole Basic suite. Existing Basic tests whose mocked store now receives an unexpected `Reset` get the expectation added: a successful Basic request now resets.

Run: `go test -count=1 -run 'TestBasic' ./httpsec/`
Expected: PASS.

### Task 1.2: A failed clearing on Basic success is logged and the request succeeds

**Files:**
- Test: `httpsec/basic_test.go`

- [ ] **Step 1: Write the test** `TestBasicSuccessClearingFails`. The store's `Reset` returns `errors.New("db: column secret_hint=hunter2")`. Capture the logger with the package's existing capture handler (the one the password-change clearing test uses). Assert that:
  - the response is 200;
  - exactly one error record is written, with message `msgAttemptsNotReset`;
  - its `error_type` attribute is `*errors.errorString`;
  - the record contains neither `hunter2` nor `ada`.
- [ ] **Step 2: Red.** Temporarily make the success path return the `Reset` error. The test fails with the request refused, at `assert.Equal(t, http.StatusOK, rec.Code)`. Edit it back.
- [ ] **Step 3: Run the package and the conformance suite.**

Run: `go test -race -count=1 ./httpsec/` and `cd test && go test -count=1 ./...`
Expected: PASS.

---

### Task 2.1: The streak contract and the in-memory streak

**Files:**
- Create: `policy/streak.go`
- Modify: `policy/attempts.go` (add the streak map to `MemoryAttemptStore`, implement the contract, and clear the streak in `Reset`)
- Regenerate: `policy/attempts_mock_test.go` (`go generate ./policy/`). The directive in `attempts.go` is `-source=attempts.go`, so declare the interface in `attempts.go`, not `streak.go`. `streak.go` holds the record type and the sentinel.
- Test: `policy/streak_test.go`

**Interfaces:**
- Produces, in `policy/streak.go`:

```go
// FailureStreak is an identifier's consecutive failures: how many there have
// been since it was last cleared, the newest of them, and when it became held.
type FailureStreak struct {
	Failures int
	Newest   time.Time
	HeldAt   time.Time // zero while not held
}

// Held reports whether the streak has reached a cap and is held.
func (s FailureStreak) Held() bool { return !s.HeldAt.IsZero() }

// ErrAccountHeld matches the refusal of an identifier held by the
// consecutive-failure cap, alongside ErrAccountLocked.
var ErrAccountHeld = errors.New("policy: account held until its failures are cleared")
```

- Produces, in `policy/attempts.go`:

```go
// FailureStreakStore is the optional half of AttemptStore that keeps each
// identifier's consecutive failures, for a policy configured with
// WithLockoutCap. A store that implements it clears the streak, hold
// included, in Reset, together with the failures Reset already clears.
type FailureStreakStore interface {
	// AddStreakFailure adds one failure at at to username's streak, in one
	// atomic write, and returns the streak after it. A streak that is not held
	// and whose newest failure is at or before since restarts at one. The
	// write that brings the count to limit or above, on a streak not yet held,
	// sets HeldAt to at and reports setHold true; no later write moves HeldAt.
	// Newest never moves backwards.
	AddStreakFailure(ctx context.Context, username string, at, since time.Time, limit int) (streak FailureStreak, setHold bool, err error)

	// FailureStreak reads username's streak. One that is not held and whose
	// newest failure is at or before since reads as the zero FailureStreak.
	FailureStreak(ctx context.Context, username string, since time.Time) (FailureStreak, error)

	// DeleteStreaksBefore removes every streak that is not held and whose
	// newest failure is strictly before retainSince, and reports how many
	// went. A zero retainSince is refused with ErrRetainSinceRequired.
	DeleteStreaksBefore(ctx context.Context, retainSince time.Time) (int, error)
}
```

- [ ] **Step 1: Write the failing test** in `policy/streak_test.go` (package `policy_test`). Write a table `TestMemoryAttemptStoreStreak` whose cases each build `policy.NewMemoryAttemptStore()`, assert it is a `policy.FailureStreakStore` with `require.Implements`, and check one behaviour. Start with three cases: "counts from one", "a write reaching the limit sets the hold once", and "Reset clears the streak and the hold".

```go
func TestMemoryAttemptStoreStreak(t *testing.T) {
	t.Parallel()

	at := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	since := at.Add(-30 * 24 * time.Hour)

	type testCase struct {
		name   string
		assert func(t *testing.T, ctx context.Context, s policy.FailureStreakStore)
	}

	cases := []testCase{
		{
			name: "counts from one",
			assert: func(t *testing.T, ctx context.Context, s policy.FailureStreakStore) {
				got, set, err := s.AddStreakFailure(ctx, "ada", at, since, 3)
				require.NoError(t, err)
				assert.Equal(t, policy.FailureStreak{Failures: 1, Newest: at}, got)
				assert.False(t, set)
			},
		},
		{
			name: "a write reaching the limit sets the hold once",
			assert: func(t *testing.T, ctx context.Context, s policy.FailureStreakStore) {
				var sets int
				for i := range 4 {
					got, set, err := s.AddStreakFailure(ctx, "ada", at.Add(time.Duration(i)*time.Second), since, 3)
					require.NoError(t, err)
					if set {
						sets++
						assert.Equal(t, 3, got.Failures)
					}
				}
				got, err := s.FailureStreak(ctx, "ada", since)
				require.NoError(t, err)
				assert.Equal(t, 1, sets)
				assert.Equal(t, 4, got.Failures)
				assert.Equal(t, at.Add(2*time.Second), got.HeldAt)
			},
		},
		{
			name: "Reset clears the streak and the hold",
			assert: func(t *testing.T, ctx context.Context, s policy.FailureStreakStore) {
				for range 3 {
					_, _, err := s.AddStreakFailure(ctx, "ada", at, since, 3)
					require.NoError(t, err)
				}
				require.NoError(t, s.(policy.AttemptStore).Reset(ctx, "ada"))
				got, err := s.FailureStreak(ctx, "ada", since)
				require.NoError(t, err)
				assert.Equal(t, policy.FailureStreak{}, got)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, ok := any(policy.NewMemoryAttemptStore()).(policy.FailureStreakStore)
			require.True(t, ok, "the memory store implements FailureStreakStore")
			tc.assert(t, t.Context(), s)
		})
	}
}
```

- [ ] **Step 2: Add stubs so the test compiles.** Add the interface, the type and the sentinel, plus memory methods that return `FailureStreak{}, false, nil`, `FailureStreak{}, nil` and `0, nil`. Run:

Run: `go test -count=1 -run 'TestMemoryAttemptStoreStreak' ./policy/`
Expected: FAIL on behaviour, for example `expected: policy.FailureStreak{Failures:1, ...} actual: policy.FailureStreak{Failures:0, ...}`.

- [ ] **Step 3: Implement the memory streak.** Add `streaks map[string]FailureStreak` to `MemoryAttemptStore`, initialised in `NewMemoryAttemptStore`. All methods hold `s.mu`.

```go
func (s *MemoryAttemptStore) AddStreakFailure(
	_ context.Context, username string, at, since time.Time, limit int,
) (FailureStreak, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cur := s.streaks[username]
	if !cur.Held() && !cur.Newest.After(since) {
		cur.Failures = 0
	}
	cur.Failures++
	if at.After(cur.Newest) {
		cur.Newest = at
	}
	set := false
	if !cur.Held() && cur.Failures >= limit {
		cur.HeldAt, set = at, true
	}
	s.streaks[username] = cur

	return cur, set, nil
}

func (s *MemoryAttemptStore) FailureStreak(_ context.Context, username string, since time.Time) (FailureStreak, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cur := s.streaks[username]
	if !cur.Held() && !cur.Newest.After(since) {
		return FailureStreak{}, nil
	}

	return cur, nil
}

func (s *MemoryAttemptStore) DeleteStreaksBefore(_ context.Context, retainSince time.Time) (int, error) {
	if retainSince.IsZero() {
		return 0, ErrRetainSinceRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var n int
	for u, cur := range s.streaks {
		if !cur.Held() && cur.Newest.Before(retainSince) {
			delete(s.streaks, u)
			n++
		}
	}

	return n, nil
}
```

`Reset` also does `delete(s.streaks, username)`. Add `var _ FailureStreakStore = (*MemoryAttemptStore)(nil)`.

Update the `MemoryAttemptStore` godoc: it can delete inactive streaks, but it is still no `AttemptReaper`. Then regenerate the mocks with `go generate ./policy/`.

- [ ] **Step 4: Run it and see it pass.**

Run: `go test -race -count=1 ./policy/`
Expected: PASS.

### Task 2.2: The streak conformance suite, run against the memory store

**Files:**
- Create: `test/storetest/streak_suite.go`
- Modify: `test/storetest/memory_test.go`

**Interfaces:**
- Consumes: `policy.FailureStreakStore`, `policy.AttemptStore`, `policy.FailureStreak`, `policy.ErrRetainSinceRequired`.
- Produces:

```go
// RunFailureStreakSuite checks a store that is both a policy.AttemptStore and
// a policy.FailureStreakStore against the contract the lockout cap relies on.
// newStore is called once per case and must return an empty store.
func RunFailureStreakSuite(t *testing.T, newStore func(t *testing.T) StreakStore)

// StreakStore is what the suite drives.
type StreakStore interface {
	policy.AttemptStore
	policy.FailureStreakStore
}

// RunFailureStreakRace adds n failures at once from a streak of start, with
// the given limit, and requires the count to be exact and the hold set once.
func RunFailureStreakRace(t *testing.T, newStore func(t *testing.T) StreakStore)
```

- [ ] **Step 1: Write the suite.** It uses the `suiteCase` form of `suite.go` (`name`, `assert func(t, ctx, s, clk)`). Use `suiteStart` as the base instant, a limit of 5, and a retention cutoff `since := suiteStart.Add(-30 * 24 * time.Hour)`. Cases:
  1. **counts from one:** one add gives `{Failures: 1, Newest: at}`, with the hold not set.
  2. **advances by one per add:** three adds give 3.
  3. **restarts after the cutoff:** four adds at `since.Add(-time.Hour)`, then one add at `suiteStart` with cutoff `since`, gives 1 and is not held.
  4. **reads as empty after the cutoff:** two adds at `since.Add(-time.Hour)`; `FailureStreak(ctx, u, since)` returns `FailureStreak{}`.
  5. **the add reaching the limit sets the hold once:** six adds; exactly one returns `setHold`, and it is the fifth. `HeldAt` equals the fifth's `at`, and the count is 6.
  6. **a held streak never restarts or reads empty:** five adds at `since.Add(-time.Hour)` (held). The read with cutoff `since` is held with 5. An add at `suiteStart` gives 6, still held, and `HeldAt` is unchanged.
  7. **a streak above a lowered limit is held by its next add** (Review Focus 1): seven adds with limit 100 (not held), then one add with limit 5. That add returns `setHold` true, with 8 failures.
  8. **newest never moves backwards** (Review Focus 2): an add at `suiteStart`, then one at `suiteStart.Add(-time.Minute)`, gives `Newest == suiteStart` and a count of 2.
  9. **Reset clears the streak, the hold and the log:**
     - five adds (held), plus `RecordFailure` at `suiteStart`;
     - then `Reset`;
     - afterwards the read is empty, `FailureCount` is 0, and the next add gives 1, not held (Review Focus 5).
  10. **Reset of an identifier with no streak is not an error.**
  11. **identifiers are exact:** adds for `Ada` and `ada ` leave `ada` empty.
  12. **an unstorable identifier** (`"ada\x00"`):
      - the add is refused with an error whose text does not contain the identifier, or it is counted as given;
      - the read is empty or holds what was added, and never another identifier's streak (as the attempt suite's NUL case).
  13. **purge refuses a zero cutoff:** `DeleteStreaksBefore(ctx, time.Time{})` returns `ErrRetainSinceRequired` and deletes nothing.
  14. **purge keeps holds and recent streaks:**
      - `old` has two adds at `since.Add(-time.Hour)`; `held` has five adds at `since.Add(-time.Hour)`; `recent` has one add at `suiteStart`;
      - `DeleteStreaksBefore(ctx, since)` returns 1;
      - `held` is still held, and `recent` still reads 1.

  `RunFailureStreakRace`:
  - seed a streak of 90 with limit 100;
  - start 20 goroutines behind a barrier (a closed channel), each calling `AddStreakFailure(ctx, "ada", suiteStart, since, 100)`;
  - collect the `setHold` flags;
  - require 110 failures, held, and exactly one `true`.
- [ ] **Step 2: Wire the memory store** in `test/storetest/memory_test.go`:

```go
func TestMemoryFailureStreak(t *testing.T) {
	t.Parallel()

	newStore := func(*testing.T) storetest.StreakStore { return policy.NewMemoryAttemptStore() }
	storetest.RunFailureStreakSuite(t, newStore)
	storetest.RunFailureStreakRace(t, newStore)
}
```

- [ ] **Step 3: Red.** Temporarily make the memory store never restart (remove the cutoff check in `AddStreakFailure`). Cases 3 and 4 fail with `expected: 1 actual: 5`. Then temporarily make the hold check `cur.Failures == limit`. Case 7 fails, because `setHold` is false. Edit both back.

Run: `cd test && go test -race -count=1 -run 'TestMemoryFailureStreak' ./storetest/...`
Expected: FAIL under each inversion, PASS when restored.

---

### Task 3.1: The streak table and its SQL

**Files:**
- Modify: `migrate/securitystate/20260926000000_security_state.sql` (after `login_attempts`, plus its drop in the down section)
- Create: `internal/pgschema/streaks.go`
- Test: `test/migrate_securitystate_test.go`

**Interfaces:**
- Produces:

```sql
CREATE TABLE login_failure_streaks (
    id                uuid PRIMARY KEY,
    username          text NOT NULL UNIQUE,
    failures          integer NOT NULL,
    newest_failure_at timestamptz NOT NULL,
    held_at           timestamptz
);
-- The sweep deletes inactive streaks that are not held, by time alone.
CREATE INDEX login_failure_streaks_inactive ON login_failure_streaks (newest_failure_at) WHERE held_at IS NULL;
```

and `DROP TABLE IF EXISTS login_failure_streaks;` in the down migration, before `login_attempts`.

```go
package pgschema

const (
	// StreakAdd adds one failure to a streak, atomically: $1 id for a new row,
	// $2 username, $3 at, $4 since (the retention cutoff), $5 limit. A streak
	// not held whose newest failure is at or before $4 restarts at one; the
	// write that brings it to $5 or more sets held_at to $3, once. The row
	// lock taken by prev serialises concurrent adds, so set_hold is true for
	// exactly one of them. Returns failures, newest_failure_at, held_at,
	// set_hold.
	StreakAdd = `WITH prev AS (
    SELECT held_at FROM login_failure_streaks WHERE username = $2 FOR UPDATE
), next AS (
    INSERT INTO login_failure_streaks AS s (id, username, failures, newest_failure_at, held_at)
    VALUES ($1, $2, 1, $3, CASE WHEN 1 >= $5::integer THEN $3::timestamptz END)
    ON CONFLICT (username) DO UPDATE SET
        failures = CASE WHEN s.held_at IS NULL AND s.newest_failure_at <= $4 THEN 1 ELSE s.failures + 1 END,
        newest_failure_at = GREATEST(s.newest_failure_at, $3),
        held_at = COALESCE(s.held_at, CASE
            WHEN (CASE WHEN s.held_at IS NULL AND s.newest_failure_at <= $4 THEN 1 ELSE s.failures + 1 END) >= $5::integer
            THEN $3::timestamptz END)
    RETURNING s.failures, s.newest_failure_at, s.held_at
)
SELECT next.failures, next.newest_failure_at, next.held_at,
       next.held_at IS NOT NULL AND NOT EXISTS (SELECT 1 FROM prev WHERE prev.held_at IS NOT NULL)
FROM next`

	// StreakRead reads username $1's streak; the caller treats a row not held
	// whose newest failure is at or before the cutoff as empty.
	StreakRead = `SELECT failures, newest_failure_at, held_at FROM login_failure_streaks WHERE username = $1`

	// AttemptAndStreakDeleteByUsername clears username $1's failures and
	// streak in one statement.
	AttemptAndStreakDeleteByUsername = `WITH a AS (DELETE FROM login_attempts WHERE username = $1)
DELETE FROM login_failure_streaks WHERE username = $1`

	// StreakDeleteBefore removes every streak not held whose newest failure is
	// strictly before $1.
	StreakDeleteBefore = `DELETE FROM login_failure_streaks WHERE held_at IS NULL AND newest_failure_at < $1`
)
```

- [ ] **Step 1: Write the failing migration tests.** In `test/migrate_securitystate_test.go`:
  - add `login_failure_streaks` to `securityStateTables`, and rename the "thirteen" case to "fourteen";
  - add a case for the spec scenario "Consecutive failure counts":
    - `username` has a unique constraint (query `pg_indexes` for a unique index on `(username)`);
    - `held_at` is nullable with no default (query `information_schema.columns`: `is_nullable = 'YES'`, `column_default IS NULL`).
- [ ] **Step 2: Run it and see it fail.**

Run: `cd test && go test -count=1 -run 'TestSecurityState' .`
Expected: FAIL, with `login_failure_streaks` missing from the table list.

- [ ] **Step 3: Add the table, its index and its drop, and `internal/pgschema/streaks.go`.** Run it again and see it pass.

### Task 3.2: The three durable implementations, run by the suite

**Files:**
- Modify: `sqlstore/attempts.go`, `pgx/attempts.go`, `gorm/attempts.go`
- Modify: `test/sqlstore/attempts_test.go`, `test/pgxstore/attempts_test.go`, `test/gormstore/attempts_test.go`

**Interfaces:**
- Consumes: `pgschema.StreakAdd`, `pgschema.StreakRead`, `pgschema.AttemptAndStreakDeleteByUsername`, `pgschema.StreakDeleteBefore`; each package's `config.conn`, `exec`, `queryRow` (gorm: `q.Raw(...).Row()` and `q.Exec`), `failed`, `s.c.ids.NewID()`; `storekit.CheckStorable`, `storekit.Storable`, `storekit.Time`.
- Produces: `var _ policy.FailureStreakStore = (*AttemptStore)(nil)` in each package.

- [ ] **Step 1: Wire the suite first.** In each adapter test, empty both tables and run both suite functions:

```go
func TestFailureStreakStore(t *testing.T) {
	t.Parallel()

	db := migratedDB(t).DB
	newStore := func(t *testing.T) storetest.StreakStore {
		return newAttemptStore(t, emptied(t, emptied(t, db, "login_attempts"), "login_failure_streaks"))
	}
	t.Run("sqlstore", func(t *testing.T) {
		storetest.RunFailureStreakSuite(t, newStore)
		storetest.RunFailureStreakRace(t, newStore)
	})
}
```

(If `emptied` does not compose that way, call it twice on `db` and pass the result. Check its signature with gopls. Use `"pgx"` and `"gorm"` for the other two packages.)

- [ ] **Step 2: Add compiling stubs** that return zero values. Run the suite and see it fail on behaviour.

Run: `cd test && go test -count=1 -run 'TestFailureStreakStore' ./sqlstore/ ./pgxstore/ ./gormstore/`
Expected: FAIL, for example `expected: 1 actual: 0` in "counts from one", on each backend.

- [ ] **Step 3: Implement for `sqlstore`.** `pgx` is the same with its own `queryRow`, and `gorm` uses `q.Raw(pgschema.StreakAdd, ...).Row().Scan(...)`:

```go
func (s *AttemptStore) AddStreakFailure(
	ctx context.Context, username string, at, since time.Time, limit int,
) (policy.FailureStreak, bool, error) {
	const op = "add to login failure streak"

	if err := storekit.CheckStorable(storekit.Text("username", username)); err != nil {
		return policy.FailureStreak{}, false, failed(op, err)
	}
	rowID, err := s.c.ids.NewID()
	if err != nil {
		return policy.FailureStreak{}, false, failed(op, err)
	}

	var (
		got    policy.FailureStreak
		heldAt sql.NullTime
		set    bool
	)
	err = s.c.queryRow(ctx, op, pgschema.StreakAdd,
		[]any{rowID, username, storekit.Time(at), storekit.Time(since), limit},
		&got.Failures, &got.Newest, &heldAt, &set)
	if err != nil {
		return policy.FailureStreak{}, false, err
	}
	got.Newest = got.Newest.UTC()
	if heldAt.Valid {
		got.HeldAt = heldAt.Time.UTC()
	}

	return got, set, nil
}

func (s *AttemptStore) FailureStreak(ctx context.Context, username string, since time.Time) (policy.FailureStreak, error) {
	if !storekit.Storable(username) {
		return policy.FailureStreak{}, nil
	}

	var (
		got    policy.FailureStreak
		heldAt sql.NullTime
	)
	err := s.c.queryRow(ctx, "read login failure streak", pgschema.StreakRead,
		[]any{username}, &got.Failures, &got.Newest, &heldAt)
	if errors.Is(err, sql.ErrNoRows) {
		return policy.FailureStreak{}, nil
	}
	if err != nil {
		return policy.FailureStreak{}, err
	}
	got.Newest = got.Newest.UTC()
	if heldAt.Valid {
		got.HeldAt = heldAt.Time.UTC()
	}
	if !got.Held() && !got.Newest.After(storekit.Time(since)) {
		return policy.FailureStreak{}, nil
	}

	return got, nil
}

func (s *AttemptStore) DeleteStreaksBefore(ctx context.Context, retainSince time.Time) (int, error) {
	if retainSince.IsZero() {
		return 0, policy.ErrRetainSinceRequired
	}

	n, err := s.c.exec(ctx, "purge login failure streaks", pgschema.StreakDeleteBefore, storekit.Time(retainSince))

	return int(n), err
}
```

Check how `queryRow` reports no rows in each package before relying on `sql.ErrNoRows`: read `sqlstore/stmt.go:80`, `pgx/stmt.go:103` and `gorm`'s `queryRow`, and use what they return. `pgx` returns `pgx.ErrNoRows` unless the helper maps it.

`Reset` in all three switches to `pgschema.AttemptAndStreakDeleteByUsername`. In gorm, replace `deleteWhere[loginAttemptRow]` with `q.Exec(pgschema.AttemptAndStreakDeleteByUsername, username)`, wrapped with `failed`.

- [ ] **Step 4: Run it and see it pass** on every backend, including the race.

Run: `cd test && go test -race -count=1 ./...`
Expected: PASS (Docker required; if unavailable, say so and stop).

### Task 3.3: Cross-backend and ambient coverage

**Files:**
- Create: `test/crossbackend/streak_test.go`
- Modify: `test/internal/storefix/ambients.go` (add `FailureStreakAmbient`), and the ambient wiring in `test/sqlstore`, `test/pgxstore`, `test/gormstore` (find the existing `RunAmbientTx` call sites with grep in those directories, and add the streak store beside the session one)

- [ ] **Step 1: Write the cross-backend test.** Hold `ada` through the `sqlstore` store with five adds and limit 5. Then read it through the `pgx` store and the `gorm` store on the same database. Both return held, with 5 failures and equal `HeldAt`. Follow the structure of `test/crossbackend/crossbackend_test.go` for opening the three stores on one database.
- [ ] **Step 2: Write the ambient fixture:**

```go
// FailureStreakAmbient is the ambient suite's view of the streak half of an
// attempt store: record i is a streak for an identifier of its own.
func FailureStreakAmbient[S interface {
	policy.FailureStreakStore
}]() storetest.Ambient[S] {
	return storetest.Ambient[S]{
		Write: func(ctx context.Context, s S, i int) error {
			_, _, err := s.AddStreakFailure(ctx, fmt.Sprintf("ambient-%d", i), time.Now(), time.Now().Add(-time.Hour), 100)
			return err
		},
		Present: func(t *testing.T, raw *sql.DB, i int) bool {
			return Exists(t, raw, `SELECT EXISTS (SELECT 1 FROM login_failure_streaks WHERE username = $1)`,
				fmt.Sprintf("ambient-%d", i))
		},
	}
}
```

Check `storetest.Ambient`'s fields with gopls. If `Refuse` and `Refusal` are required, use an add with an unstorable identifier, refused with the store's storability error. Wire it for each backend beside the existing ambient runs.
- [ ] **Step 3: Red.** Temporarily make `sqlstore`'s `AddStreakFailure` use `execOutsideTx`, or a connection from `s.c.base`, instead of `conn`. The ambient case "rolled back" fails, because the row is present after rollback. Edit it back.

Run: `cd test && go test -count=1 ./crossbackend/ ./sqlstore/ ./pgxstore/ ./gormstore/`
Expected: FAIL under the inversion, PASS when restored.

---

### Task 4.1: The cap and retention options and their configuration errors

**Files:**
- Modify: `policy/lockout.go` (fields, options, constants, validation)
- Test: `policy/lockout_config_test.go` (`TestNewAccountLockoutPolicy` table)

**Interfaces:**
- Consumes: `FailureStreakStore` (Task 2.1).
- Produces:

```go
// NISTLockoutCap is the consecutive-failure limit NIST SP 800-63B-4 §3.2.2
// sets as an upper bound: pass it to WithLockoutCap to hold an identifier at
// that limit.
const NISTLockoutCap = 100

// defaultLockoutCapRetention is how long a consecutive count below the cap
// lives after its newest failure.
const defaultLockoutCapRetention = 30 * 24 * time.Hour

func WithLockoutCap(n int) LockoutOption              // sets p.cap, p.setCap
func WithLockoutCapRetention(d time.Duration) LockoutOption // sets p.retention, p.setRetention
func (p *AccountLockoutPolicy) Cap() int              // 0 when no cap
func (p *AccountLockoutPolicy) CapRetention() time.Duration
```

New fields: `cap int`, `retention time.Duration`, `setCap`, `setRetention bool`, and `streaks FailureStreakStore` (set at construction when there is a cap).

- [ ] **Step 1: Write the failing table cases** in `TestNewAccountLockoutPolicy`:
  - "no cap by default": `Cap() == 0`.
  - "a cap takes the default retention": `WithLockoutCap(NISTLockoutCap)` gives `Cap() == 100` and `CapRetention() == 30*24*time.Hour`.
  - "a consumer retention": `WithLockoutCap(100), WithLockoutCapRetention(7*24*time.Hour)` gives 7 days.
  - "a cap above NIST's limit is accepted": `WithLockoutCap(150)` is no error.
  - "a cap with a store that keeps no streaks is refused": `WithAttemptStore(NewMockAttemptStore(ctrl))` plus `WithLockoutCap(100)` gives `ErrorIs(err, policy.ErrConfig)` and `ErrorContains(err, "WithLockoutCap")`.
  - "a cap not above the threshold is refused": `WithLockoutCap(5)` with the default threshold of 5 gives `ErrConfig`.
  - "a retention without a cap is refused": `WithLockoutCapRetention(time.Hour)` gives `ErrConfig`, naming `WithLockoutCapRetention`.
  - "a retention of zero is refused": `WithLockoutCap(100), WithLockoutCapRetention(0)` gives `ErrConfig`.
  - "a retention shorter than the window is refused": `WithLockoutCap(100), WithLockoutCapRetention(time.Hour)` against the default 24-hour window gives `ErrConfig`.
  - "a cap of zero is refused": `WithLockoutCap(0)` gives `ErrConfig`.
- [ ] **Step 2: Add the options as no-ops** that compile, plus `Cap()` returning 0. Run:

Run: `go test -count=1 -run 'TestNewAccountLockoutPolicy' ./policy/`
Expected: FAIL in each new case, for example `expected: 100 actual: 0` and `An error is expected but got nil`.

- [ ] **Step 3: Implement.** The options set the fields and flags. After the existing validation in `NewAccountLockoutPolicy`:

```go
	if p.setRetention && !p.setCap {
		return nil, fmt.Errorf("%w: WithLockoutCapRetention has no cap to retain counts for: "+
			"pass WithLockoutCap too, or drop it", ErrConfig)
	}
	if p.setCap {
		if err := p.validateCap(); err != nil {
			return nil, err
		}
	}
```

with:

```go
func (p *AccountLockoutPolicy) validateCap() error {
	if p.cap <= p.threshold {
		return fmt.Errorf("%w: WithLockoutCap must be above the threshold, got cap %d and threshold %d: "+
			"the first lock would already be a hold", ErrConfig, p.cap, p.threshold)
	}
	if p.retention <= 0 {
		return fmt.Errorf("%w: WithLockoutCapRetention must be positive, got %s", ErrConfig, p.retention)
	}
	if p.retention < p.window {
		return fmt.Errorf("%w: WithLockoutCapRetention %s is shorter than the lockout window %s: "+
			"a count would expire while the window still counts its failures", ErrConfig, p.retention, p.window)
	}
	streaks, ok := p.store.(FailureStreakStore)
	if !ok {
		return fmt.Errorf("%w: WithLockoutCap needs an attempt store that keeps consecutive failures "+
			"(policy.FailureStreakStore); %T does not", ErrConfig, p.store)
	}
	p.streaks = streaks

	return nil
}
```

The constructor's defaults set `retention: defaultLockoutCapRetention`. Check the cap-of-zero case: `WithLockoutCap(0)` is caught by `cap <= threshold`. The message must say that the cap must be above the threshold. That is acceptable, because the error names `WithLockoutCap`.

- [ ] **Step 4: Run it and see it pass.**

### Task 4.2: The view advances the streak, before the log

**Files:**
- Modify: `policy/lockout_observer.go` (`observedAttempts` becomes the view whenever there is an observer **or** a cap), `policy/lockout.go` (construction picks the view)
- Test: `policy/lockout_cap_test.go` (new)

**Interfaces:**
- Produces: `Attempts()` returns `&observedAttempts{p: p}` when `p.observer != nil || p.cap > 0`, and otherwise the store itself. The view's `RecordFailure` with a cap:

```go
	if p.streaks != nil {
		if _, _, err := p.streaks.AddStreakFailure(ctx, username, at, at.Add(-p.retention), p.cap); err != nil {
			return err
		}
	}
	if err := p.store.RecordFailure(ctx, username, at); err != nil {
		return err
	}
	if p.observer == nil {
		return nil
	}
	// ... the existing count and report, unchanged
```

The mock for a store that is both an attempt store and a streak store is a test-local interface. Declare it in `lockout_cap_test.go` with its own directive, per `use-mockgen`:

```go
//go:generate mockgen -source=lockout_cap_test.go -package=policy_test -destination=streakattempts_mock_test.go -typed -mock_names=streakAttemptStore=MockStreakAttemptStore
type streakAttemptStore interface {
	policy.AttemptStore
	policy.FailureStreakStore
}
```

- [ ] **Step 1: Write the failing tests** in `TestLockoutCapView` (table):
  - **"without a cap the view never touches the streak":** a policy without a cap over `MockStreakAttemptStore`, with no observer. `Attempts()` is the store itself (`assert.Same`), and one `RecordFailure` expects exactly `RecordFailure` and nothing else.
  - **"with a cap the streak is written before the log":**
    - a policy with `WithLockoutCap(100)` and a fake clock at `T`;
    - `gomock.InOrder` with `AddStreakFailure(ctx, "ada", T, T.Add(-30*24*time.Hour), 100)` returning a streak of 1, then `RecordFailure(ctx, "ada", T)`;
    - the call is `p.RecordFailure(ctx, "ada")`.
  - **"a failed streak write is returned and the log is not written":** `AddStreakFailure` returns `errStoreDown`; `RecordFailure` on the store is never called; and `errors.Is(err, errStoreDown)`.
  - **"a failed log write after the streak is returned":** `AddStreakFailure` succeeds, `RecordFailure` returns `errStoreDown`, and the error matches.
- [ ] **Step 2: Run it and see it fail.**

Run: `go generate ./policy/ && go test -count=1 -run 'TestLockoutCapView' ./policy/`
Expected: FAIL with `missing call(s) to *policy_test.MockStreakAttemptStore.AddStreakFailure(...)`.

- [ ] **Step 3: Implement as above,** then run and see it pass. The existing observer tests stay green: with no cap, `p.streaks` is nil.

### Task 4.3: Evaluation refuses a held identifier first

**Files:**
- Modify: `policy/lockout.go` (`Evaluate`), `policy/lockout_error.go` (`held` field, `Is`, text)
- Test: `policy/lockout_cap_test.go` (`TestLockoutCapEvaluate`), `policy/lockout_error_test.go`

**Interfaces:**
- Produces:

```go
// in LockoutError: held reports a refusal by the consecutive-failure cap.
type LockoutError struct {
	Wait time.Duration

	failures int
	window   time.Duration
	held     bool
}

func (e *LockoutError) Is(target error) bool {
	return target == ErrAccountLocked || (e.held && target == ErrAccountHeld) //nolint:errorlint // identity
}
```

`Error()` for a held refusal: `fmt.Sprintf("%s: held after %d consecutive failures", accountLockedText, e.failures)`.

In `Evaluate`, right after `now` is fixed:

```go
	if p.streaks != nil {
		streak, err := p.streaks.FailureStreak(ctx, in.Username, now.Add(-p.retention))
		if err != nil {
			return storeDenied(err)
		}
		if streak.Held() {
			return Decision{Outcome: Deny, Reason: &LockoutError{failures: streak.Failures, held: true}}
		}
	}
```

- [ ] **Step 1: Write the failing table** `TestLockoutCapEvaluate`, over a real `policy.NewMemoryAttemptStore()`. Each case seeds failures through `p.Attempts().RecordFailure(ctx, u, at)` at instants built from a fake clock, then advances the clock and evaluates. The cases are the spec scenarios:
  - **"No cap by default":** 20 failures per day for 5 days, the newest 2h ago; allowed.
  - **"Cap reached across days":** cap 100; 20 per day on each of five days, the newest 3 days ago; denied, `ErrorIs(ErrAccountLocked)` and `ErrorIs(ErrAccountHeld)`, and `Wait == 0`.
  - **"Consumer cap":** cap 20; 20 failures over two days; denied as held.
  - **"Below the cap":** cap 100; 99 failures over five days, the newest 2 days ago; allowed.
  - **"Unknown identifiers are held alike":** cap 20; 20 failures each for `ada` and `nobody`. Both are denied, with equal `Error()` text and both matching `ErrAccountHeld`.
  - **"A windowed lock is not a hold":** cap 100; seven failures now; denied, `ErrorIs(ErrAccountLocked)`, `NotErrorIs(ErrAccountHeld)`, with a wait of 120s.
  - **"Unreadable hold":** over `MockStreakAttemptStore`, `FailureStreak` returns `errStoreDown`. The decision is `Deny`, the reason matches `ErrPolicyDenied` and `errStoreDown`, and `FailureCount` is never called.
  - **"A hold outlives every window":** cap 100; held 90 days ago (100 failures 90 days ago); evaluating now is denied as held.
  - **"The correct password does not lift a hold":** held `ada`; Evaluate is denied. Assert that nothing in `Evaluate` writes, using a mock that expects only `FailureStreak`.

  Seeding 100 failures 90 days ago: the add's cutoff is `at.Add(-retention)` for each `at`, so consecutive adds 90 days ago count up. That is correct.
- [ ] **Step 2: Run it and see it fail.**

Run: `go test -count=1 -run 'TestLockoutCapEvaluate' ./policy/`
Expected: FAIL. "Cap reached across days" is allowed, because no hold is evaluated yet.

- [ ] **Step 3: Implement as above,** then run and see it pass, together with `go test -count=1 -run 'TestAccountLockoutPolicyLockoutError' ./policy/`, plus a new case there: "a held refusal matches the hold and carries no wait".

### Task 4.4: Retention and release

**Files:**
- Test: `policy/lockout_cap_test.go` (`TestLockoutCapRetention`)
- Modify: `policy/lockout.go` (godoc of `Reset`, only if the tests need no code change; the code path already goes through the view and the store's `Reset`)

- [ ] **Step 1: Write the table** over the memory store and a fake clock:
  - **"Inactive count restarts":** cap 100; 99 failures, the newest 31 days ago; one more now. Allowed, and `FailureStreak` reads `Failures == 1`. Read it through a type assertion of the policy's store to `policy.FailureStreakStore`, with cutoff `now - 30d`.
  - **"Consumer retention":** cap 100, retention 7 days; 99 failures, the newest 8 days ago; one more now. Allowed.
  - **"A hold does not expire":** cap 100; held 31 days ago. Denied as held.
  - **"Reset unlocks":** held `ada`, also with 100 failures in the window. `p.Reset(ctx, "ada")`, then Evaluate is allowed.
- [ ] **Step 2: Red.** These pin behaviour Tasks 2.1 and 4.3 already give.
  - Temporarily pass `time.Time{}` as the cutoff in the view's `AddStreakFailure`, so a streak never restarts. "Inactive count restarts" fails with `expected: 1 actual: 100`, and the evaluation denies.
  - Temporarily remove the streak deletion from the memory store's `Reset`. "Reset unlocks" fails, still held.

  Edit both back.

Run: `go test -count=1 -run 'TestLockoutCap' ./policy/`
Expected: FAIL under each inversion, PASS restored.

---

### Task 4.5: A burst across the cap through the policy

**Files:**
- Test: `policy/lockout_cap_test.go` (`TestLockoutCapBurst`)

- [ ] **Step 1: Write the test.**
  - Use cap 100 over the memory store, with an observer that appends reports under a mutex.
  - Seed 90 failures through the view.
  - Start 20 goroutines behind a closed-channel barrier, each calling `p.Attempts().RecordFailure(ctx, "ada", now)`.
  - Assert:
    - the streak reads 110 and is held;
    - exactly one report has kind `LockoutHeld` (Task 4.6 adds it; until then, assert on the store's `setHold` count through a wrapping test store).

  Order it after 4.6, or write the store-level half now and the report half in 4.6.
- [ ] **Step 2: Red.** Temporarily replace the memory store's add with a read-then-write that unlocks between the read and the write, a two-step add. Under `-race`, the hold is set more than once or the count is short. Edit it back.

Run: `go test -race -count=1 -run 'TestLockoutCapBurst' ./policy/`
Expected: FAIL under the inversion, PASS restored.

### Task 4.6: Hold and release reports, and the purge

**Files:**
- Modify: `policy/lockout_observer.go` (new kinds; the view uses `setHold`; `Reset` reads the streak first), `policy/lockout.go` (`PurgeExpired`)
- Test: `policy/lockout_observer_test.go`, `policy/lockout_cap_test.go`

**Interfaces:**
- Produces:

```go
const (
	// ... existing kinds
	// LockoutHeld reports the failure that made its identifier held by the
	// consecutive-failure cap: reported once, by the write that set the hold.
	LockoutHeld
	// LockoutReleased reports a reset that lifted a hold, in place of
	// LockoutCleared.
	LockoutReleased
)
```

`String()` returns `"held"` and `"released"`.

The view's `RecordFailure` with an observer: when the streak add returned `setHold`, report `LockoutHeld` with `Failures: streak.Failures`, and skip the windowed report for that write. Otherwise keep the existing windowed report.

The view's `Reset`: with a cap, read `p.streaks.FailureStreak(ctx, u, now.Add(-p.retention))` before the reset, alongside the windowed count. After a successful reset, a held streak reports `LockoutReleased` (with the streak's count); otherwise the existing `LockoutCleared` rule applies. A failed streak read is logged with `msgClearReportLost` and does not stop the reset.

`PurgeExpired`: after the attempt purge, when `p.streaks != nil`, add `p.streaks.DeleteStreaksBefore(ctx, now.Add(-p.retention))` to the removed count, wrapping its error the same way.

- [ ] **Step 1: Write the failing cases.**
  - In `TestLockoutObserver`:
    - "Held": cap 20, twenty failures; exactly one `LockoutHeld` report with 20, and no `LockoutLocked` or `LockoutAtCeiling` report for that twentieth write.
    - "Hold lifted": a held `ada` reset gives one `LockoutReleased`, and no `LockoutCleared`.
    - "a cap lowered below an existing count reports the hold" (Review Focus 1): build a store with 70 failures under cap 100 through one policy. A second policy with cap 50 over the same store records one more, and one `LockoutHeld` with 71 is reported.
  - In `TestLockoutCapPurge`, the spec scenario "Inactive counts are purged, holds are kept", over the memory store, which is an attempt store but not an `AttemptReaper`. The memory store cannot purge its log, so `PurgeExpired` returns `ErrReapUnsupported` before reaching the streaks. Run this case instead over a `MockStreakAttemptStore` that also implements `AttemptReaper`: declare `streakReaperStore` in the test file with a mock through the same directive. Assert that `DeleteStreaksBefore` is called with `now - 30d`, and that the total is the sum.
- [ ] **Step 2: Run them and see them fail.**

Run: `go generate ./policy/ && go test -race -count=1 -run 'TestLockoutObserver|TestLockoutCapPurge' ./policy/`
Expected: FAIL. There are no `LockoutHeld` reports yet, and `DeleteStreaksBefore` is never called.

- [ ] **Step 3: Implement as above.** Then complete Task 4.5's report assertion, and run the whole package with `-race`.

### Task 4.7: Godoc and the example

**Files:**
- Modify: `policy/lockout.go` (type doc, `WithLockoutCap`, `WithLockoutCapRetention`, `Reset`), `policy/doc.go`
- Test: `policy/example_test.go` (`ExampleWithLockoutCap`)

- [ ] **Step 1: Write the example.**

```go
func ExampleWithLockoutCap() {
	clk := clockwork.NewFakeClockAt(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	lockout, err := policy.NewAccountLockoutPolicy(
		policy.WithLockoutClock(clk),
		policy.WithLockoutCap(policy.NISTLockoutCap),
	)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	for range policy.NISTLockoutCap {
		_ = lockout.Attempts().RecordFailure(ctx, "ada", clk.Now())
		clk.Advance(2 * time.Hour)
	}

	d := lockout.Evaluate(ctx, &policy.Input{Username: "ada"})
	fmt.Println(d.Outcome, errors.Is(d.Reason, policy.ErrAccountHeld))

	_ = lockout.Reset(ctx, "ada")
	fmt.Println(lockout.Evaluate(ctx, &policy.Input{Username: "ada"}).Outcome)
	// Output:
	// Deny true
	// Allow
}
```

- [ ] **Step 2: Run it and see it fail before the godoc work,** if any piece is missing. Then write the godoc:
  - **`WithLockoutCap`:**
    - the default is none;
    - what holds an identifier, and what lifts a hold: the chain's password change, and `Reset` as the unlock. Time never lifts it, and neither does a correct password;
    - a cap above `NISTLockoutCap` is outside SP 800-63B-4 §3.2.2's limit;
    - the denial-of-service risk and its mitigations: recovery with codes, the per-source guard, and the waits making about 24 failures a day;
    - unknown identifiers' holds are never pruned;
    - it needs a `FailureStreakStore`, and with the chain the view must be what its logins record into.
  - **`WithLockoutCapRetention`:** the default is 30 days, a hold never expires, and the configuration errors.
  - **`Reset`:** it is the unlock for an administrator or support tool, and lifts a hold with the window.
  - **The type documentation:** the "There is no unlock call and no lock record" paragraph is rewritten to describe the streak record under a cap.
  - **`doc.go`:** one paragraph on the cap.

Run: `go test -count=1 -run Example ./policy/` and `go doc ./policy WithLockoutCap`
Expected: PASS, and the text shows.

---

### Task 5.1: The chain refuses a capped policy whose view it was not given

**Files:**
- Create: `policy/attempt_views.go`; Modify: `policy/engine.go` (`RequiredAttemptViews`); Test: `policy/engine_test.go`
- Create: `httpsec/lockout_wiring.go`; Modify: the chain's assembly (`build` in `httpsec/chain.go`: one call); Test: `httpsec/lockout_wiring_test.go`

**Interfaces:**
- Produces, in `policy`:

```go
// AttemptViewRequirer is implemented by a policy whose decisions depend on
// failures being recorded through a view it hands out.
type AttemptViewRequirer interface {
	// RequiredAttemptView returns the view and true when failures must be
	// recorded through it; false when any attempt store will do.
	RequiredAttemptView() (AttemptStore, bool)
}

// RequiredAttemptView reports the policy's view when a cap is configured.
func (p *AccountLockoutPolicy) RequiredAttemptView() (AttemptStore, bool) { return p.attempts, p.cap > 0 }

// RequiredAttemptView names a registered policy and the view it requires.
type RequiredAttemptView struct {
	Policy string
	View   AttemptStore
}

// RequiredAttemptViews reports, in registration order, every registered
// policy that requires failures to be recorded through its own view. It is
// meant for wiring time, like UnwiredFederatedAssurance.
func (e *Engine) RequiredAttemptViews() []RequiredAttemptView
```

- Produces, in `httpsec`: `func (c *config) checkAttemptViews() error`, called from `build` beside `wirePasswordChange`. For every form login and Basic interceptor, and every required view, the interceptor's `attempts` must satisfy `sameStore(attempts, view)`. Otherwise it returns `newConfigError("%s records failures into a store other than the account-lockout policy's view, but %s has a consecutive-failure cap that only its view enforces: give it lockout.Attempts()", field, policyName)`, where `field` is `"FormLoginDeps.Attempts"` or `"BasicAuthDeps.Attempts"`.

- [ ] **Step 1: Write the failing tests.**
  - `policy`: `TestRequiredAttemptViews` (table):
    - an engine with a capped lockout policy reports one entry whose `View` is `Same` as `p.Attempts()`;
    - an engine with an uncapped one reports nil;
    - an engine with none reports nil.
  - `httpsec`: `TestLockoutCapWiring` (table), with a capped real lockout policy over the memory store in the engine:
    - "Raw store with a cap": form login is given the memory store. The construction error contains `FormLoginDeps.Attempts`.
    - "View with a cap": both logins are given `lockout.Attempts()`. No error.
    - "Raw store without a cap": an uncapped policy, with Basic given the raw store. No error.
    - "no password login with a cap" (Review Focus 4): no error.
- [ ] **Step 2: Run them and see them fail.**

Run: `go test -count=1 -run 'TestRequiredAttemptViews' ./policy/ && go test -count=1 -run 'TestLockoutCapWiring' ./httpsec/`
Expected: FAIL. The method returns nil, and construction does not fail for the raw store.

- [ ] **Step 3: Implement,** then run them and see them pass, together with `go test -race -count=1 ./policy/ ./httpsec/`.

### Task 5.2: A held account is refused like any locked account

**Files:**
- Test: `httpsec/held_test.go` (new)

- [ ] **Step 1: Write the table** `TestHeld`:
  - a real capped policy (cap 20) over the memory store, given to the chain's engine and, as `lockout.Attempts()`, to both logins;
  - a decoy-counting authenticator, using the generated `MockDecoyAuthenticator` from `httpsec/decoyauthenticator_mock_test.go`;
  - each identifier is held by recording 20 failures through `lockout.Attempts()` before the requests.

  Cases:
  - "Held by default": a form login for `ada` with the correct password gets 401. The error matches `ErrAuthenticationFailed`, `policy.ErrAccountLocked` and `policy.ErrAccountHeld`, one decoy is spent, and `Authenticate` is never called.
  - "Held, disclosure chosen": with the chain's disclose-locks option, a Basic request for held `ada` gets 429, matches `ErrAccountHeld`, and has no `WWW-Authenticate` header.
  - "Unknown username held alike": held `ada` and held `nobody` give the same status, the same error text and one decoy each.
- [ ] **Step 2: Red.** Temporarily make the memory store's `AddStreakFailure` skip the username `nobody`, so it is never held. The alike case fails with `nobody` reaching the authenticator. Edit it back.

Run: `go test -count=1 -run 'TestHeld' ./httpsec/`
Expected: FAIL under the inversion, PASS restored.

### Task 5.3: Recovery and a password change release a hold (conformance)

**Files:**
- Create: `test/httpsecconformance/hold_scenarios.go`
- Modify: the `Scenarios()` list in `test/httpsecconformance/scenarios.go` (add `holdScenarios()`)

- [ ] **Step 1: Write the scenarios,** modelled on `recoveryAtTheCeilingSignsInAfterTheResolve` in `recovery_scenarios.go`:
  - **"a held account recovers and signs in with its new password":**
    - a capped policy (cap 20), with `ada` held through `lockout.Attempts()`;
    - first assert that a form login with the correct password is refused as held;
    - then complete a recovery with a saved code and an issued code, and resolve a password change on the recovery session;
    - then a form login with the new password succeeds.
  - **"a held account's password proof is refused":** a recovery with a saved code and `ada`'s password is refused, matching `policy.ErrAccountLocked`, and the password is not checked.
- [ ] **Step 2: Red.** Temporarily remove the streak deletion from the memory store's `Reset`. The first scenario fails at the final login, on every adapter, still held. Edit it back.

Run: `cd test && go test -count=1 ./...`
Expected: FAIL under the inversion, on net/http, Gin and Fiber; PASS restored.

### Task 5.4: Chain godoc

**Files:**
- Modify: `httpsec/options.go` (godoc only)

- [ ] **Step 1:** Update the godoc of `FormLoginDeps.Attempts` and `BasicAuthDeps.Attempts`: with a lockout policy that has a cap, `lockout.Attempts()` is required, and any other store fails construction. `EnableBasicAuth` states that a successful authentication clears the username's failures, as form login does.

Run: `go doc ./httpsec FormLoginDeps`, `go doc ./httpsec BasicAuthDeps`, `go doc ./httpsec EnableBasicAuth`
Expected: the text shows.

---

### Task 6.1: The login-attempt sweep keeps holds

**Files:**
- Modify: `test/expirytasks_test.go`

- [ ] **Step 1: Write the cases** for the three `expiry-sweeping` scenarios, against a durable store. Use the `sqlstore` attempt store on the test database. It is both an `AttemptReaper` and a `FailureStreakStore`, so `PurgeExpired` reaches the streaks. Run the policy's `LockoutExpiryTask` through an `expiry.Runner`, as the file's existing lockout case does:
  - **"A hold survives every sweep":** a cap of 100, and `ada` held 90 days ago (seed through the policy's view with the fake clock 90 days back, then advance). After the run, `ada` is still held.
  - **"A recent consecutive count survives":** 10 failures, the newest 29 days ago. After the run, the streak reads 10.
  - **"An inactive consecutive count is deleted":**
    - 10 failures, the newest 31 days ago;
    - after the run, the row is gone (query `login_failure_streaks` directly), and the next failure starts at 1.
- [ ] **Step 2: Red.** Temporarily change `pgschema.StreakDeleteBefore` to drop `held_at IS NULL`. The first case fails, because `ada` is no longer held. Edit it back.

Run: `cd test && go test -count=1 -run 'TestExpiry' .`
Expected: FAIL under the inversion, PASS restored.

---

### Task 7.1: Whole-branch checks (main session)

Run `go test -race -count=1 ./...` in every module (root, `test`, `ginsec`, `fibersec`, `gorm`, `pgx`, `redis`, `sweep`, `passkey/webauthn`), `go vet ./...` in each, `gofmt -l .` (empty) and `golangci-lint run` (root and `test`). Keep the output as evidence.

### Task 7.2: Whole-branch review

An Opus reviewer who wrote none of the code reviews against every requirement in the five delta specs and design decisions 1–7, and reports a requirement-to-test table. Every defect claimed has a failing test or is labelled `UNREPRODUCED`. Findings go back to fresh dispatches of the owning lane.
