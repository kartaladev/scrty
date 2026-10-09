# Lockout Honest Defaults Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the account lockout's options, documentation and observability say exactly what they do. The sliding lock is renamed, a fixed-duration configuration is documented and tested, the NIST claim is corrected, a password change clears failures, transitions can be observed, and unknown usernames are pinned.

**Architecture:**
- Everything stays inside the existing `policy.AccountLockoutPolicy` and the `httpsec` password-change gate. There is no port, store or schema change.
- Reports come from a recording view that the policy hands out (`Attempts()`), because the chain records failures straight into the store it is given.
- The gate clears failures through the attempt stores of the chain's password logins, handed over at assembly.

**Tech Stack:** Go 1.27; testify (`assert`/`require`); `go.uber.org/mock` typed mocks; `github.com/jonboulle/clockwork` fake clocks in tests; `log/slog`.

**Spec:** `openspec/changes/lockout-honest-defaults/`. Read `proposal.md`, `design.md` (decisions 1–6), `specs/security-policy/spec.md`, `specs/http-security-chain/spec.md` and `tasks.md`. Task numbers below are `tasks.md`'s.

## Global Constraints

- Test-first for every task (`.claude/rules/golang-tdd.md`). Each red step is run and seen to fail **for the intended reason**. A compile error is not a red step. A test that pins existing behaviour gets its red step by temporarily inverting the implementation. The inversion is undone by editing the file back.
- Never run `git checkout --`, `git restore`, `git reset --hard`, `git stash` or `git clean`. The tree holds other agents' uncommitted work.
- Table tests follow the `table-test` skill: an `assert` closure per case (no `want`/`wantErr` fields), and `t.Context()`, never `context.Background()`. Examples are the exception, since they have no `t`.
- Test doubles come from the `use-mockgen` skill. `policy` tests already have `NewMockAttemptStore` (`policy/attempts_mock_test.go`), and `httpsec` tests have `NewMockAttemptStore` in the `authHarness`.
- Library design (`.claude/rules/library-design.md`): every new option's godoc names the default it replaces, a wiring mistake fails at construction with an error wrapping `policy.ErrConfig`, and every default has a test, as does at least one override.
- No production dependency is added to the core module.
- Log records carry fixed text and the dependency's error type (`diag.Failure`), never a dependency's error text, and never the submitted identifier.
- Nothing cites, names or copies the predecessor reference under `.claude/.legacy/`.
- Do not edit anything under `openspec/`. Report where the code and the artifacts disagree.
- Every verification command named in a task must be run, and its output reported.

## Review Focus

1. **A username spelled differently at the password-change endpoint** (`ADA` versus `ada`): only the exact principal username is cleared, and failures under another spelling remain. Pinned in Task 5.2.
2. **An attempt store whose dynamic type is not comparable** (for example a struct value holding a slice) passed to both form login and Basic: deduplication must not panic. The store is treated as distinct and cleared once per registration. Pinned in Task 5.1.
3. **A store that records the failure but cannot then count it:** the failure stays recorded, `RecordFailure` returns nil, no report is sent, and one error record says the report was lost. Pinned in Task 4.2.
4. **A chain with the password-change gate but no form login and no Basic:** resolving clears nothing and does not fail. Pinned in Task 5.1.
5. **`Attempts()` called twice on one policy** (once for form login, once for Basic): it returns the same view, so the gate deduplicates it and a reset is reported once, not twice. Pinned in Tasks 4.1 and 5.1.

## Dispatch map (main session)

There are three lanes. A lane's dispatches run in order, and dispatches of different lanes run in parallel where the waves allow. After each dispatch, the main session runs its verification commands, then a fresh reviewer checks the diff.

| Wave | Dispatch | Tasks | Owns | Must not touch | Model | Reviewer |
|---|---|---|---|---|---|---|
| 1 | P1a | 1.1–1.3 | `policy/lockout.go`, `policy/lockout_test.go`, `policy/lockout_config_test.go`, `policy/lockout_error_test.go`, `httpsec/chain_login_guard_test.go`, `httpsec/recoverycomplete_test.go`, `test/expirytasks_test.go` | everything else | Sonnet: a rename the tests cover, plus godoc | Sonnet |
| 2 | P1b | 2.1–3.2 | `policy/lockout.go`, `policy/lockout_test.go`, `policy/lockout_error_test.go`, `policy/example_test.go` | `httpsec/`, `test/` | Sonnet: test pins and godoc whose text the plan gives | Sonnet |
| 2 | H1 | 5.1–5.4 | `httpsec/passwordchange.go`, `httpsec/passwordchange_test.go`, `test/httpsecconformance/recovery_scenarios.go` | `policy/`, `httpsec/options.go`, `test/httpsecconformance/scenarios.go` | Opus: first-time code that weakens a lockout, where a wrong identifier would pass the tests and still be wrong | Opus |
| 2 | C1 | 6.1 | `test/httpsecconformance/lockout_scenarios.go` (new), the `Scenarios()` list in `test/httpsecconformance/scenarios.go`, `httpsec/lockout_unknown_test.go` (new); `httpsec/login.go` and `httpsec/basic.go` for the temporary red-step inversion only, which must end byte-for-byte unchanged | `policy/`, every other `httpsec/` file | Sonnet: conformance cases in an existing suite | Sonnet |
| 3 | P2 | 4.1–4.4, and the `policy` half of 4.5 | `policy/lockout.go`, `policy/lockout_observer.go` (new), `policy/lockout_observer_test.go` (new), `policy/lockout_config_test.go`, `policy/example_test.go` | `httpsec/`, `test/` | Opus: concurrency, and an interface `httpsec` compiles against | Opus |
| 4 | H2 | the `httpsec` half of 4.5, and 5.5 | `httpsec/options.go` (godoc only), `httpsec/passwordchange.go` (godoc only), `httpsec/example_lockout_test.go` (new) | `policy/`, `test/` | Sonnet: godoc and an example whose code the plan gives | Sonnet |
| 5 | main session | 7.1 | — | — | — | — |
| 5 | review | 7.2 | — | — | — | Opus |

Why these waves:
- P1a goes first and alone, because the rename touches `httpsec` and `test` files that H1 and C1 also compile.
- P1b and P2 both edit `policy/lockout.go`, so they run one after the other.
- H2's example uses P2's `Attempts()` and `WithLockoutObserver`, so it comes after P2.

---

### Task 1.1: Rename `WithFixedLockout` to `WithSlidingLockout`

**Files:**
- Modify: `policy/lockout.go`: the `WithFixedLockout` function (line ≈233), the struct fields `fixed`, `fixedThreshold` and `fixedWindow` (line ≈113), the conflict list in `NewAccountLockoutPolicy` (line ≈279–294), and `Evaluate` (line ≈418)
- Modify (callers, via gopls): `policy/lockout_test.go`, `policy/lockout_config_test.go`, `policy/lockout_error_test.go`, `httpsec/chain_login_guard_test.go`, `httpsec/recoverycomplete_test.go`, `test/expirytasks_test.go`
- Test: `policy/lockout_config_test.go` (`TestNewAccountLockoutPolicy`)

**Interfaces:**
- Produces: `func WithSlidingLockout(threshold int, window time.Duration) LockoutOption`, with the same behaviour as today's `WithFixedLockout`.

- [ ] **Step 1: Rename the identifier with gopls (mechanical, covered by existing tests)**

```bash
G=$(command -v gopls || echo "$(go env GOPATH)/bin/gopls")
$G rename -w policy/lockout.go:233:6 WithSlidingLockout
grep -rn --include='*.go' 'WithFixedLockout' . --exclude-dir=.claude
```
Expected: the grep matches only comments and string literals. Rename any remaining code reference by hand, including in the `test` module, which gopls may not reach.

Rename the private fields in `policy/lockout.go` too: `fixed` becomes `sliding`, `fixedThreshold` becomes `slidingThreshold`, and `fixedWindow` becomes `slidingWindow`.

Run: `go test -count=1 ./policy/... ./httpsec/...`, and `cd test && go test -count=1 ./...`
Expected: PASS. Nothing has changed in behaviour.

- [ ] **Step 2: Write the failing test.** Add this case to `TestNewAccountLockoutPolicy`'s `cases`:

```go
{
	name: "a conflicting option names the sliding lock it conflicts with",
	opts: []policy.LockoutOption{
		policy.WithSlidingLockout(5, 15*time.Minute),
		policy.WithLockoutWait(time.Minute, time.Hour),
	},
	assert: func(t *testing.T, p *policy.AccountLockoutPolicy, err error) {
		refused(t, p, err)
		assert.ErrorContains(t, err, "WithSlidingLockout")
		assert.NotContains(t, err.Error(), "WithFixedLockout")
	},
},
```

- [ ] **Step 3: Run it to verify it fails**

Run: `go test -count=1 -run 'TestNewAccountLockoutPolicy/a_conflicting_option_names' ./policy/`
Expected: FAIL. The error still reads `WithFixedLockout sets its own threshold and window…`.

- [ ] **Step 4: Fix the message.** In `NewAccountLockoutPolicy`:

```go
return nil, fmt.Errorf(
	"%w: WithSlidingLockout sets its own threshold and window and has no wait or ceiling, so "+
		"combining it with %s would silently change what that option means",
	ErrConfig, strings.Join(conflicts, ", "))
```

- [ ] **Step 5: Run to verify it passes**

Run: `go test -count=1 ./policy/... ./httpsec/...` and `cd test && go test -count=1 ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add policy/ httpsec/chain_login_guard_test.go httpsec/recoverycomplete_test.go test/expirytasks_test.go
git commit -m "refactor(policy): name the sliding lock for what it does"
```

### Task 1.2: Pin that the sliding lock lifts when its oldest failure leaves the window

**Files:**
- Test: `policy/lockout_test.go` (`TestAccountLockoutPolicyEvaluates`)

- [ ] **Step 1: Write the tests.** Add these two cases:

```go
{
	// Failures spread across the window: only the oldest is outside it,
	// so four remain and the sliding lock has already lifted.
	name: "a sliding lock lifts as soon as its oldest failure leaves the window",
	opts: []policy.LockoutOption{policy.WithSlidingLockout(5, 15*time.Minute)},
	record: func(t *testing.T, store *policy.MemoryAttemptStore) {
		failuresAt(t, store, "ada",
			lockoutNow.Add(-15*time.Minute-time.Second),
			lockoutNow.Add(-14*time.Minute),
			lockoutNow.Add(-10*time.Minute),
			lockoutNow.Add(-5*time.Minute),
			lockoutNow.Add(-time.Minute))
	},
	assert: allows,
},
{
	name: "a sliding lock holds while its oldest failure is still inside the window",
	opts: []policy.LockoutOption{policy.WithSlidingLockout(5, 15*time.Minute)},
	record: func(t *testing.T, store *policy.MemoryAttemptStore) {
		failuresAt(t, store, "ada",
			lockoutNow.Add(-15*time.Minute+time.Second),
			lockoutNow.Add(-14*time.Minute),
			lockoutNow.Add(-10*time.Minute),
			lockoutNow.Add(-5*time.Minute),
			lockoutNow.Add(-time.Minute))
	},
	assert: denies,
},
```

- [ ] **Step 2: Red by inversion.** In `Evaluate`, temporarily change `now.Add(-p.window)` to `now.Add(-2 * p.window)`.

Run: `go test -count=1 -run 'TestAccountLockoutPolicyEvaluates/a_sliding_lock_lifts' ./policy/`
Expected: FAIL (`Deny` where `Allow` was expected). Then edit the line back.

- [ ] **Step 3: Run to verify it passes**

Run: `go test -count=1 -run 'TestAccountLockoutPolicyEvaluates' ./policy/`
Expected: PASS.

- [ ] **Step 4: Commit:** `git commit -am "test(policy): pin the sliding lock lifting with its oldest failure"`

### Task 1.3: Godoc of the sliding lock, and a refusal under it that carries no wait

**Files:**
- Modify: `policy/lockout.go`: the godoc of `WithSlidingLockout`; the type doc paragraph that mentions it; the `NewAccountLockoutPolicy` godoc; every other "fixed lock" mention, including the `PurgeExpired` godoc and the `LockoutError.Wait` comment in `policy/lockout_error.go`
- Test: `policy/lockout_error_test.go`: rename the case `under a fixed lock the refusal carries no wait`

- [ ] **Step 1: Rename the existing case** to `"under a sliding lock the refusal carries no wait"`. Its options already use `WithSlidingLockout` after Task 1.1.

- [ ] **Step 2: Red by inversion.** In `Evaluate`'s sliding branch, temporarily return `lockedDecision(count, p.window, p.window)`.

Run: `go test -count=1 -run 'TestAccountLockoutPolicyLockoutError' ./policy/`
Expected: FAIL (a wait of `15m0s` where 0 was expected). Then edit it back.

- [ ] **Step 3: Replace the option's godoc**

```go
// WithSlidingLockout replaces the escalating wait with a sliding lock: an
// identifier is refused while at least threshold of its failures fall inside
// the last window, however long ago its newest failure was, and is allowed
// again as soon as enough of them leave the window. The default is the
// escalating wait, with no sliding lock.
//
// It limits the failure rate, not how long a lock lasts. Failures bunched
// together lock for nearly the whole window; failures spread across it lock
// only until the oldest ages out, which can be seconds. A deployment that must
// hold a lock for a fixed duration sets equal waits instead (see
// WithLockoutWait).
//
// Know what it gives up: anyone who knows a username can keep its owner
// refused for as long as they keep failing, which the escalating wait exists
// to prevent.
//
// A threshold or window of zero or less is a configuration error, as for
// WithLockoutThreshold and WithLockoutWindow. Combining it with
// WithLockoutThreshold, WithLockoutWindow, WithLockoutWait or
// WithLockoutCeiling is a configuration error whatever the order, since each
// would mean something different, or nothing, under a sliding lock. A refusal
// under a sliding lock carries no wait.
```

In the `AccountLockoutPolicy` type doc, replace the two sentences beginning `WithFixedLockout replaces the escalating wait…` with:

```go
// WithSlidingLockout replaces the escalating wait with a sliding lock, which
// limits the failure rate within a window; WithLockoutWait with equal waits
// gives a lock of fixed duration instead.
```

In the `NewAccountLockoutPolicy` godoc, replace `WithFixedLockout(5, 15*time.Minute) restores the previous default instead: 5 failures per 15 minutes.` with `WithSlidingLockout replaces the escalating wait with a sliding lock.` Change `WithFixedLockout combined with` to `WithSlidingLockout combined with`.

Then run `grep -n -i 'fixed' policy/lockout.go policy/lockout_error.go`. Reword every remaining mention of a "fixed lock" to "sliding lock". Only Task 2.2's fixed-duration paragraph may say "fixed".

- [ ] **Step 4: Verify**

Run: `go test -count=1 ./policy/...` and `go doc ./policy WithSlidingLockout`
Expected: PASS, and the godoc above is printed.

- [ ] **Step 5: Commit:** `git commit -am "docs(policy): describe the sliding lock as a rate limit"`

### Task 2.1: Boundary tests for a fixed-duration lock

**Files:**
- Test: `policy/lockout_error_test.go` (`TestAccountLockoutPolicyLockoutError`) and `policy/lockout_test.go` (`TestAccountLockoutPolicyEvaluates`)

- [ ] **Step 1: Write the tests.** In `TestAccountLockoutPolicyLockoutError`'s `cases` (the `owing` helper exists there):

```go
{
	name:   "a flat fifteen-minute wait is owed one second before it ends",
	opts:   []policy.LockoutOption{policy.WithLockoutWait(15*time.Minute, 15*time.Minute)},
	record: failuresEndingAt("ada", 5, 15*time.Minute-time.Second),
	assert: owing(15*time.Minute,
		"policy: account locked after repeated failures: 5 failures within 24h0m0s"),
},
{
	name:   "a further failure owes the same flat wait, not a doubled one",
	opts:   []policy.LockoutOption{policy.WithLockoutWait(15*time.Minute, 15*time.Minute)},
	record: failuresEndingAt("ada", 6, 14*time.Minute),
	assert: owing(15*time.Minute,
		"policy: account locked after repeated failures: 6 failures within 24h0m0s"),
},
```

In `TestAccountLockoutPolicyEvaluates`:

```go
{
	// FailureCount counts strictly after its cutoff, so the lock is lifted
	// at the instant the fifteen minutes have passed.
	name:   "a flat fifteen-minute wait is served exactly at its end",
	opts:   []policy.LockoutOption{policy.WithLockoutWait(15*time.Minute, 15*time.Minute)},
	record: failuresEndingAt("ada", 5, 15*time.Minute),
	assert: allows,
},
{
	name:   "six failures under a flat wait are allowed once it ends",
	opts:   []policy.LockoutOption{policy.WithLockoutWait(15*time.Minute, 15*time.Minute)},
	record: failuresEndingAt("ada", 6, 15*time.Minute),
	assert: allows,
},
```

- [ ] **Step 2: Red by inversion.** In `waitFor`, temporarily replace `return p.longestWait` inside the loop with `return wait * 2`.

Run: `go test -count=1 -run 'TestAccountLockoutPolicyLockoutError/a_further_failure|TestAccountLockoutPolicyEvaluates/six_failures' ./policy/`
Expected: FAIL (a wait of `30m0s`, and `Deny` where `Allow` was expected). Edit it back.

**If "a flat fifteen-minute wait is served exactly at its end" fails on the unmodified code, stop and report it.** The spec scenario "Allowed when the duration has passed" would then be wrong, and the main session corrects the spec, not the test.

- [ ] **Step 3: Run to verify it passes**

Run: `go test -count=1 -run 'TestAccountLockoutPolicy' ./policy/`
Expected: PASS.

- [ ] **Step 4: Commit:** `git commit -am "test(policy): pin a lock of fixed duration at its boundary"`

### Task 2.2: Document the fixed-duration configuration

**Files:**
- Modify: the `WithLockoutWait` godoc in `policy/lockout.go`, and `policy/doc.go` (one paragraph in the lockout section, if it has one; otherwise the type doc)
- Test: `policy/example_test.go` (add an import of `time`)

- [ ] **Step 1: Write the example, which fails until it compiles and prints.** Add:

```go
// A lock of fixed duration: once five failures fall in the day, the
// identifier is refused for exactly fifteen minutes after its newest one.
func ExampleWithLockoutWait_fixedDuration() {
	lockout, err := policy.NewAccountLockoutPolicy(
		policy.WithLockoutWait(15*time.Minute, 15*time.Minute),
	)
	if err != nil {
		fmt.Println(err)

		return
	}

	fmt.Println(lockout.Threshold(), lockout.Window())
	// Output: 5 24h0m0s
}
```

Run: `go test -count=1 -run 'ExampleWithLockoutWait_fixedDuration' ./policy/`. To see a red step, first write `// Output: 5 15m0s` and watch it fail on the output diff, then correct it.

- [ ] **Step 2: Append to the `WithLockoutWait` godoc**

```go
// Equal waits make a lock of fixed duration. WithLockoutWait(15*time.Minute,
// 15*time.Minute) refuses an identifier that has reached the threshold for
// exactly 15 minutes after its newest failure, and lets it try again at the
// instant they have passed. Refused attempts are not recorded, so the lock
// runs from the failure that reached the threshold. Unlike the CIS benchmark's
// lockout, the count is not cleared when the lock ends: the failures stay in
// the window, so each further failure locks again for the full duration, one
// guess per duration rather than a fresh threshold's worth. This is the
// configuration for an audit that asks for a minimum lock duration;
// WithSlidingLockout does not provide one.
```

Do not mention PCI DSS.

- [ ] **Step 3: Verify**

Run: `go test -count=1 -run Example ./policy/` and `go doc ./policy WithLockoutWait`
Expected: PASS, and the paragraph is printed.

- [ ] **Step 4: Commit:** `git commit -am "docs(policy): present equal waits as a lock of fixed duration"`

### Task 3.1: Pin that the ceiling counts only the window

**Files:**
- Test: `policy/lockout_test.go` (`TestAccountLockoutPolicyEvaluates`)

- [ ] **Step 1: Write the test**

```go
{
	// 24 failures a day is what the default waits let a patient guesser
	// make. Five days of it is 120 failures, but the ceiling counts only
	// the window, so it never refuses.
	name: "failures outside the window do not count toward the ceiling",
	record: func(t *testing.T, store *policy.MemoryAttemptStore) {
		for day := range 5 {
			for i := range 24 {
				failuresAt(t, store, "ada", lockoutNow.Add(
					-2*time.Hour-time.Duration(day)*24*time.Hour-time.Duration(i)*time.Minute))
			}
		}
	},
	assert: allows,
},
```

- [ ] **Step 2: Red by inversion.** In `Evaluate`, just before `if count >= p.ceiling`, temporarily add:

```go
if total, _ := p.store.FailureCount(ctx, in.Username, time.Unix(0, 0)); total >= p.ceiling {
	return lockedDecision(total, p.window, 0)
}
```

Run: `go test -count=1 -run 'TestAccountLockoutPolicyEvaluates/failures_outside_the_window' ./policy/`
Expected: FAIL (`Deny`). Remove the lines.

- [ ] **Step 3: Run to verify it passes**, with the same command. Expected: PASS.
- [ ] **Step 4: Commit:** `git commit -am "test(policy): pin that the ceiling counts only the window"`

### Task 3.2: Correct the NIST wording

**Files:**
- Modify: `policy/lockout.go`: the comments on `defaultLockoutWindow`, `defaultLockoutCeiling`, the `AccountLockoutPolicy` type doc, `WithLockoutCeiling` and `NewAccountLockoutPolicy`

This is documentation only, so there is no red step (`golang-tdd.md`, "Where this does not apply").

- [ ] **Step 1: Replace the constant comments**

```go
	// defaultLockoutWindow is how far back failures are counted. A day bounds
	// what the store holds while keeping a slow, steady guesser's failures in
	// view; a successful authentication clears them sooner, through Reset.
	// Failures older than the window no longer count toward anything, the
	// ceiling included.
	defaultLockoutWindow = 24 * time.Hour
```

```go
	// defaultLockoutCeiling is how many failures inside the window refuse an
	// identifier outright. It borrows the number NIST SP 800-63B-4 §3.2.2
	// uses, but it is not that section's cap: NIST counts consecutive failures
	// in total and disables the authenticator until it is bound again, while
	// this ceiling counts only the window and lifts as failures age out. With
	// the default waits a guesser who respects them makes about 24 guesses a
	// day, so the ceiling bounds bursts of concurrent requests, not a patient
	// guesser's total.
	defaultLockoutCeiling = 100
```

- [ ] **Step 2: In the type doc**, replace `At 100 failures in the window, the cap NIST SP 800-63B-4 §3.2.2 sets, it is refused however long it has waited, until failures leave the window or a successful authentication clears them.` with:

```go
// At 100 failures in the window it is refused however long it has waited,
// until failures leave the window or a successful authentication clears them.
// That ceiling limits the guessing rate, about 24 guesses a day under the
// default waits, not the total. It is not NIST SP 800-63B-4 §3.2.2's cap on
// consecutive failures, which disables the authenticator until it is bound
// again; this policy never disables anything.
```

- [ ] **Step 3: In `WithLockoutCeiling`**, replace `The default is 100, the cap on consecutive failed attempts NIST SP 800-63B-4 §3.2.2 sets.` with `The default is 100.` Replace `A ceiling above 100 is allowed, but departs from NIST's cap, and a consumer who sets one owns that departure.` with:

```go
// The ceiling counts failures inside the window, which age out; it is not a
// cap on consecutive failures in total and never disables the authenticator
// (see AccountLockoutPolicy). A ceiling above 100 is allowed.
```

- [ ] **Step 4: In the `NewAccountLockoutPolicy` godoc**, replace `a ceiling of 100 failures, NIST SP 800-63B's cap (WithLockoutCeiling)` with `a ceiling of 100 failures in the window (WithLockoutCeiling)`.

- [ ] **Step 5: Verify**

Run: `grep -n "NIST" policy/lockout.go`
Expected: every remaining line either cites the 30-second-to-1-hour example range, or states that the ceiling is *not* NIST's cap.

Run: `go doc -all ./policy | grep -n -A3 -i ceiling`, and `go vet ./policy/` (clean).

- [ ] **Step 6: Commit:** `git commit -am "docs(policy): stop calling the windowed ceiling NIST's cap"`

### Task 4.1: The report type, the observer and logger options, and the policy's recording view

**Files:**
- Create: `policy/lockout_observer.go`
- Modify: `policy/lockout.go`: add struct fields, construction, and route `RecordFailure`/`Reset` through the view
- Test: `policy/lockout_observer_test.go` (create), `policy/lockout_config_test.go`

**Interfaces:**
- Produces (exact names; later tasks and H2 use them):

```go
type LockoutReportKind int

const (
	LockoutLocked    LockoutReportKind = iota + 1 // String(): "locked"
	LockoutAtCeiling                              // String(): "at-ceiling"
	LockoutCleared                                // String(): "cleared"
)

func (k LockoutReportKind) String() string

type LockoutReport struct {
	Identifier string    // as submitted, never folded
	Kind       LockoutReportKind
	Failures   int       // failures in the window: after the failure, or cleared by the reset
	At         time.Time // the failure's instant, or the policy clock's at the reset
}

type LockoutObserver func(ctx context.Context, r LockoutReport)

func WithLockoutObserver(o LockoutObserver) LockoutOption // nil: configuration error
func WithLockoutLogger(l *slog.Logger) LockoutOption      // default slog.Default(); nil ignored
func (p *AccountLockoutPolicy) Attempts() AttemptStore    // same value on every call
```

- [ ] **Step 1: Scaffold the types so the test compiles.** In `policy/lockout_observer.go`, write the declarations above. Give `observedAttempts` (holding `p *AccountLockoutPolicy`) the methods `RecordFailure`, `Reset` and `FailureCount`, each forwarding to `p.store` and, for this scaffold only, also calling `p.store.FailureCount` in `RecordFailure`.

Add these fields to `AccountLockoutPolicy`: `observer LockoutObserver`, `setObserver bool`, `logger *slog.Logger` and `attempts AttemptStore`. In `NewAccountLockoutPolicy`, set `logger: slog.Default()`, and as the last step before `return p, nil` add `p.attempts = &observedAttempts{p: p}`. `Attempts()` returns `p.attempts`.

- [ ] **Step 2: Write the failing tests.** In `policy/lockout_observer_test.go`:

```go
// TestLockoutObserverDefaults pins that a policy with no observer adds
// nothing to the store's work: its view records and nothing else.
func TestLockoutObserverDefaults(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	store := NewMockAttemptStore(ctrl)
	store.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil).Times(1)

	p := lockoutWith(t, policy.WithAttemptStore(store))

	require.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", lockoutNow))
	assert.Equal(t, p.Attempts(), p.Attempts(),
		"two calls must hand out the same view, so the chain can deduplicate it")
}
```

In `TestNewAccountLockoutPolicy`'s `cases`:

```go
{
	name:   "a nil lockout observer is refused",
	opts:   []policy.LockoutOption{policy.WithLockoutObserver(nil)},
	assert: refused,
},
{
	name: "a nil lockout logger is ignored",
	opts: []policy.LockoutOption{policy.WithLockoutLogger(nil)},
	assert: func(t *testing.T, p *policy.AccountLockoutPolicy, err error) {
		require.NoError(t, err)
		assert.NotNil(t, p)
	},
},
```

- [ ] **Step 3: Run to verify they fail**

Run: `go test -count=1 -run 'TestLockoutObserverDefaults|TestNewAccountLockoutPolicy/a_nil_lockout' ./policy/`
Expected: FAIL. The mock reports an unexpected `FailureCount` call, and the nil observer is accepted.

- [ ] **Step 4: Implement.** In construction:

```go
if p.setObserver && p.observer == nil {
	return nil, fmt.Errorf("%w: lockout observer must not be nil: a consumer who passed "+
		"one meant to be told, and would hear nothing", ErrConfig)
}

p.attempts = p.store
if p.observer != nil {
	p.attempts = &observedAttempts{p: p}
}
```

The options:

```go
func WithLockoutObserver(o LockoutObserver) LockoutOption {
	return func(p *AccountLockoutPolicy) {
		p.observer = o
		p.setObserver = true
	}
}

func WithLockoutLogger(l *slog.Logger) LockoutOption {
	return func(p *AccountLockoutPolicy) {
		if l != nil {
			p.logger = l
		}
	}
}
```

Change `RecordFailure` and `Reset` on the policy to call `p.attempts.RecordFailure(ctx, username, p.clock.Now())` and `p.attempts.Reset(ctx, username)`, keeping their `diag.Wrap`. An administrator's `Reset` is then reported too.

- [ ] **Step 5: Run to verify it passes**

Run: `go test -count=1 ./policy/...`
Expected: PASS.

- [ ] **Step 6: Commit:** `git add policy/ && git commit -m "feat(policy): a recording view and an opt-in lockout observer"`

### Task 4.2: Report every recorded failure that leaves the identifier locked

**Files:**
- Modify: `policy/lockout_observer.go` (`observedAttempts.RecordFailure`)
- Test: `policy/lockout_observer_test.go`

- [ ] **Step 1: Write the failing table test**

```go
// reportLog collects what an observer is told, safe for concurrent reports.
type reportLog struct {
	mu  sync.Mutex
	got []policy.LockoutReport
}

func (l *reportLog) observe(_ context.Context, r policy.LockoutReport) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.got = append(l.got, r)
}

func (l *reportLog) all() []policy.LockoutReport {
	l.mu.Lock()
	defer l.mu.Unlock()

	return slices.Clone(l.got)
}

func TestLockoutObserver(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []policy.LockoutOption
		store  func(t *testing.T) policy.AttemptStore // nil: a fresh in-memory store
		before func(t *testing.T, store policy.AttemptStore)
		act    func(t *testing.T, p *policy.AccountLockoutPolicy) error
		assert func(t *testing.T, reports []policy.LockoutReport, err error, logs string)
	}

	record := func(id string) func(*testing.T, *policy.AccountLockoutPolicy) error {
		return func(t *testing.T, p *policy.AccountLockoutPolicy) error {
			return p.Attempts().RecordFailure(t.Context(), id, lockoutNow)
		}
	}
	prior := func(id string, n int) func(*testing.T, policy.AttemptStore) {
		return func(t *testing.T, s policy.AttemptStore) {
			for i := range n {
				require.NoError(t, s.RecordFailure(t.Context(), id, lockoutNow.Add(-time.Duration(i+1)*time.Second)))
			}
		}
	}

	cases := []testCase{
		{
			name:   "four failures report nothing",
			before: prior("ada", 3),
			act:    record("ada"),
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				assert.Empty(t, r)
			},
		},
		{
			name:   "the fifth failure reports the identifier locked",
			before: prior("ada", 4),
			act:    record("ada"),
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []policy.LockoutReport{
					{Identifier: "ada", Kind: policy.LockoutLocked, Failures: 5, At: lockoutNow},
				}, r)
			},
		},
		{
			name:   "each further locking failure is reported",
			before: prior("ada", 5),
			act:    record("ada"),
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				assert.Equal(t, []policy.LockoutReport{
					{Identifier: "ada", Kind: policy.LockoutLocked, Failures: 6, At: lockoutNow},
				}, r)
			},
		},
		{
			name:   "the hundredth failure reports the ceiling",
			before: prior("ada", 99),
			act:    record("ada"),
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				require.Len(t, r, 1)
				assert.Equal(t, policy.LockoutAtCeiling, r[0].Kind)
				assert.Equal(t, 100, r[0].Failures)
			},
		},
		{
			name:   "under a sliding lock a locking failure is locked, never at the ceiling",
			opts:   []policy.LockoutOption{policy.WithSlidingLockout(5, 15*time.Minute)},
			before: prior("ada", 104),
			act:    record("ada"),
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				require.Len(t, r, 1)
				assert.Equal(t, policy.LockoutLocked, r[0].Kind)
			},
		},
		{
			name:   "an unknown identifier is reported exactly like a known one",
			before: func(t *testing.T, s policy.AttemptStore) { prior("ada", 4)(t, s); prior("nobody", 4)(t, s) },
			act: func(t *testing.T, p *policy.AccountLockoutPolicy) error {
				return errors.Join(record("ada")(t, p), record("nobody")(t, p))
			},
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.NoError(t, err)
				require.Len(t, r, 2)
				r[1].Identifier = r[0].Identifier
				assert.Equal(t, r[0], r[1], "the reports differ in something other than the identifier")
			},
		},
		{
			name: "a failure the store could not record is not reported",
			store: func(t *testing.T) policy.AttemptStore {
				s := NewMockAttemptStore(gomock.NewController(t))
				s.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(errAttemptStoreDown)

				return s
			},
			act: record("ada"),
			assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
				require.ErrorIs(t, err, errAttemptStoreDown)
				assert.Empty(t, r)
			},
		},
		{
			// Review Focus 3.
			name: "a failure recorded but not countable loses only its report",
			store: func(t *testing.T) policy.AttemptStore {
				s := NewMockAttemptStore(gomock.NewController(t))
				s.EXPECT().RecordFailure(gomock.Any(), "ada", lockoutNow).Return(nil)
				s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(0, errAttemptStoreDown)

				return s
			},
			act: record("ada"),
			assert: func(t *testing.T, r []policy.LockoutReport, err error, logs string) {
				require.NoError(t, err, "the failure is recorded, so recording succeeded")
				assert.Empty(t, r)
				assert.Equal(t, 1, strings.Count(logs, "policy: a lockout report was lost"))
				assert.NotContains(t, logs, "ada")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var store policy.AttemptStore = policy.NewMemoryAttemptStore()
			if tc.store != nil {
				store = tc.store(t)
			}
			if tc.before != nil {
				tc.before(t, store)
			}

			var logs bytes.Buffer
			got := &reportLog{}
			p := lockoutWith(t, append([]policy.LockoutOption{
				policy.WithAttemptStore(store),
				policy.WithLockoutObserver(got.observe),
				policy.WithLockoutLogger(slog.New(slog.NewTextHandler(&logs, nil))),
			}, tc.opts...)...)

			err := tc.act(t, p)
			tc.assert(t, got.all(), err, logs.String())
		})
	}
}
```

Add a concurrency test:

```go
// TestLockoutObserverReportsEveryConcurrentLockingFailure pins why reports
// are per failure: a burst whose failures all read a count past the
// threshold would lose a crossing report, and must lose none of these.
func TestLockoutObserverReportsEveryConcurrentLockingFailure(t *testing.T) {
	t.Parallel()

	store := policy.NewMemoryAttemptStore()
	failuresEndingAt("ada", 5, time.Minute)(t, store)

	got := &reportLog{}
	p := lockoutWith(t, policy.WithAttemptStore(store), policy.WithLockoutObserver(got.observe))

	const burst = 32
	var wg sync.WaitGroup
	for range burst {
		wg.Go(func() {
			assert.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", lockoutNow))
		})
	}
	wg.Wait()

	reports := got.all()
	assert.Len(t, reports, burst, "a burst of locking failures lost reports")
	for _, r := range reports {
		assert.Equal(t, policy.LockoutLocked, r.Kind)
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test -race -count=1 -run 'TestLockoutObserver' ./policy/`
Expected: FAIL. The scaffold reports nothing (`[]` where one report was expected).

- [ ] **Step 3: Implement**

```go
// msgReportLost is the record for a failure that was recorded but could not
// be counted afterwards: the lockout is intact, and only its report is gone.
const msgReportLost = "policy: a lockout report was lost: the attempt store recorded the failure but could not count it"

func (o *observedAttempts) RecordFailure(ctx context.Context, username string, at time.Time) error {
	p := o.p
	if err := p.store.RecordFailure(ctx, username, at); err != nil {
		return err
	}

	count, err := p.store.FailureCount(ctx, username, at.Add(-p.window))
	if err != nil {
		p.logger.LogAttrs(ctx, slog.LevelError, msgReportLost, diag.Failure("attempt-store", err)...)

		return nil
	}

	switch {
	case !p.sliding && count >= p.ceiling:
		p.report(ctx, LockoutReport{Identifier: username, Kind: LockoutAtCeiling, Failures: count, At: at})
	case count >= p.threshold:
		p.report(ctx, LockoutReport{Identifier: username, Kind: LockoutLocked, Failures: count, At: at})
	}

	return nil
}
```

`p.report(ctx, r)` calls `p.observer(ctx, r)`. Task 4.4 adds panic recovery to it.

- [ ] **Step 4: Second red, for the reason the design gives.** Temporarily change the `Locked` case to `case count == p.threshold:` (detecting crossings).

Run the concurrency test.
Expected: FAIL (0 reports where 32 were expected). Edit it back.

- [ ] **Step 5: Run to verify it passes**

Run: `go test -race -count=1 -run 'TestLockoutObserver' ./policy/`
Expected: PASS.

- [ ] **Step 6: Commit:** `git commit -am "feat(policy): report every recorded failure that leaves an identifier locked"`

### Task 4.3: Report a clearing that removed failures

**Files:**
- Modify: `policy/lockout_observer.go` (`observedAttempts.Reset`)
- Test: `policy/lockout_observer_test.go` (add cases to `TestLockoutObserver`)

- [ ] **Step 1: Write the failing cases**

```go
{
	name:   "clearing an identifier with failures reports it cleared",
	before: prior("ada", 3),
	act:    func(t *testing.T, p *policy.AccountLockoutPolicy) error { return p.Attempts().Reset(t.Context(), "ada") },
	assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
		require.NoError(t, err)
		assert.Equal(t, []policy.LockoutReport{
			{Identifier: "ada", Kind: policy.LockoutCleared, Failures: 3, At: lockoutNow},
		}, r)
	},
},
{
	name:   "an administrator's reset through the policy is reported too",
	before: prior("ada", 3),
	act:    func(t *testing.T, p *policy.AccountLockoutPolicy) error { return p.Reset(t.Context(), "ada") },
	assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
		require.NoError(t, err)
		require.Len(t, r, 1)
		assert.Equal(t, policy.LockoutCleared, r[0].Kind)
	},
},
{
	name: "clearing nothing is not reported",
	act:  func(t *testing.T, p *policy.AccountLockoutPolicy) error { return p.Attempts().Reset(t.Context(), "ada") },
	assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
		require.NoError(t, err)
		assert.Empty(t, r)
	},
},
{
	name: "a reset the store refused is not reported",
	store: func(t *testing.T) policy.AttemptStore {
		s := NewMockAttemptStore(gomock.NewController(t))
		s.EXPECT().FailureCount(gomock.Any(), "ada", gomock.Any()).Return(2, nil)
		s.EXPECT().Reset(gomock.Any(), "ada").Return(errAttemptStoreDown)

		return s
	},
	act: func(t *testing.T, p *policy.AccountLockoutPolicy) error { return p.Attempts().Reset(t.Context(), "ada") },
	assert: func(t *testing.T, r []policy.LockoutReport, err error, _ string) {
		require.ErrorIs(t, err, errAttemptStoreDown)
		assert.Empty(t, r)
	},
},
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test -count=1 -run 'TestLockoutObserver/clearing|TestLockoutObserver/an_administrator' ./policy/`
Expected: FAIL (no `Cleared` report).

- [ ] **Step 3: Implement**

```go
func (o *observedAttempts) Reset(ctx context.Context, username string) error {
	p := o.p
	now := p.clock.Now()

	// Read first, so a report can say what the reset removed. A count that
	// cannot be read does not stop the reset: clearing is what the caller
	// asked for, and only the report depends on the count.
	count, countErr := p.store.FailureCount(ctx, username, now.Add(-p.window))

	if err := p.store.Reset(ctx, username); err != nil {
		return err
	}

	if countErr == nil && count > 0 {
		p.report(ctx, LockoutReport{Identifier: username, Kind: LockoutCleared, Failures: count, At: now})
	}

	return nil
}
```

- [ ] **Step 4: Run to verify it passes:** `go test -race -count=1 -run 'TestLockoutObserver' ./policy/`. Expected: PASS.
- [ ] **Step 5: Commit:** `git commit -am "feat(policy): report a clearing that removed failures"`

### Task 4.4: A panicking observer changes nothing

**Files:**
- Modify: `policy/lockout_observer.go` (`report`)
- Test: `policy/lockout_observer_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestLockoutObserverPanicChangesNothing(t *testing.T) {
	t.Parallel()

	store := policy.NewMemoryAttemptStore()
	failuresEndingAt("ada", 4, time.Second)(t, store)

	var logs bytes.Buffer
	p := lockoutWith(t,
		policy.WithAttemptStore(store),
		policy.WithLockoutObserver(func(context.Context, policy.LockoutReport) { panic("observer bug") }),
		policy.WithLockoutLogger(slog.New(slog.NewTextHandler(&logs, nil))),
	)

	require.NotPanics(t, func() {
		assert.NoError(t, p.Attempts().RecordFailure(t.Context(), "ada", lockoutNow))
	})
	assert.Equal(t, 1, strings.Count(logs.String(), "policy: the lockout observer panicked"))
	assert.NotContains(t, logs.String(), "ada", "the record must not carry the submitted identifier")
}
```

- [ ] **Step 2: Run to verify it fails:** `go test -count=1 -run 'TestLockoutObserverPanicChangesNothing' ./policy/`. Expected: FAIL (`func panicked`).

- [ ] **Step 3: Implement**

```go
// msgObserverPanicked is the record for an observer that panicked. The
// lockout outcome is the store's and the policy's, never the observer's.
const msgObserverPanicked = "policy: the lockout observer panicked; the lockout outcome is unchanged"

func (p *AccountLockoutPolicy) report(ctx context.Context, r LockoutReport) {
	defer func() {
		if recover() != nil {
			p.logger.LogAttrs(ctx, slog.LevelError, msgObserverPanicked, slog.String("kind", r.Kind.String()))
		}
	}()

	p.observer(ctx, r)
}
```

- [ ] **Step 4: Run to verify it passes:** `go test -race -count=1 ./policy/...`. Expected: PASS.
- [ ] **Step 5: Commit:** `git commit -am "feat(policy): an observer that panics cannot change a lockout outcome"`

### Task 4.5: Document the reports (`policy` half in P2, `httpsec` half in H2)

**Files:**
- Modify (P2): godoc in `policy/lockout_observer.go`; `policy/example_test.go`
- Modify (H2): the godoc of `FormLoginDeps.Attempts` and `BasicAuthDeps.Attempts` in `httpsec/options.go`
- Create (H2): `httpsec/example_lockout_test.go`

- [ ] **Step 1 (P2): Write the example**

```go
// Reports go to the consumer's observer; the policy's view records them, so
// the chain is handed lockout.Attempts() rather than the bare store.
func ExampleWithLockoutObserver() {
	lockout, err := policy.NewAccountLockoutPolicy(
		policy.WithLockoutObserver(func(_ context.Context, r policy.LockoutReport) {
			fmt.Println(r.Identifier, r.Kind, r.Failures)
		}),
	)
	if err != nil {
		fmt.Println(err)

		return
	}

	ctx := context.Background()
	for range 5 {
		_ = lockout.RecordFailure(ctx, "ada")
	}
	_ = lockout.Reset(ctx, "ada")

	// Output:
	// ada locked 5
	// ada cleared 5
}
```

Run: `go test -count=1 -run ExampleWithLockoutObserver ./policy/`. Red: first write `ada locked 4` and see the diff, then correct it.

- [ ] **Step 2 (P2): Godoc**
  - On `LockoutObserver`: it is called synchronously after the store write, with no return value. It sees only what goes through `Attempts()`, so a store handed to the chain directly is never reported. A panic is recovered and logged through `WithLockoutLogger`. It is told of every locking failure, not only the first, so a burst loses no report.
  - On `WithLockoutObserver`: "The default is none: nothing is reported."
  - On `WithLockoutLogger`: "The default is slog.Default. A nil logger is ignored."
  - On `Attempts()`: it returns the same value on every call, and is the store to hand to `httpsec.FormLoginDeps.Attempts` and `httpsec.BasicAuthDeps.Attempts`.
  - On `LockoutCleared`: a reset racing a failure may report a stale count.

  Verify: `go doc ./policy LockoutObserver`, `go doc ./policy AccountLockoutPolicy.Attempts`.

- [ ] **Step 3 (H2): Replace the `httpsec` godoc.** On `FormLoginDeps.Attempts`:

```go
	// Attempts is where a failed login is recorded and a successful one clears
	// what came before. Supply the account-lockout policy's own view,
	// lockout.Attempts(): it records into the store the policy reads, and it
	// is what reports lockout transitions to an observer the policy was given.
	// A bare store the policy also reads locks just the same, but nothing
	// recorded through it is reported. A failure recorded in one store and
	// counted in another locks nothing.
	Attempts policy.AttemptStore
```

Give `BasicAuthDeps.Attempts` the same paragraph, ending as it does today with the sentence about a password guessed over Basic counting towards the same lockout.

- [ ] **Step 4 (H2): The example** in `httpsec/example_lockout_test.go`. It builds no chain request, so it has no `// Output:` and is compiled only:

```go
package httpsec_test

import (
	"context"
	"log/slog"

	"github.com/kartaladev/scrty/httpsec"
	"github.com/kartaladev/scrty/policy"
)

// Form login and Basic record through the lockout policy's view, so its
// observer hears about every failure that locks an identifier.
func ExampleFormLoginDeps_lockoutReports() {
	lockout, err := policy.NewAccountLockoutPolicy(
		policy.WithLockoutObserver(func(ctx context.Context, r policy.LockoutReport) {
			slog.InfoContext(ctx, "lockout", "kind", r.Kind.String(), "failures", r.Failures)
		}),
	)
	if err != nil {
		panic(err)
	}

	deps := httpsec.FormLoginDeps{Attempts: lockout.Attempts()}
	basic := httpsec.BasicAuthDeps{Attempts: lockout.Attempts()}
	_, _ = deps, basic
}
```

If the linters reject an example without output, keep it, and follow the pattern of `httpsec/example_expiry_test.go`.

Verify: `go test -count=1 -run Example ./httpsec/`, `go doc ./httpsec FormLoginDeps`, `go doc ./httpsec BasicAuthDeps`.

- [ ] **Step 5: Commit** each half in its own dispatch: `docs(policy): lockout reports and the recording view`, and `docs(httpsec): wire the lockout policy's view into login`.

### Task 5.1: Hand the gate the chain's password-login attempt stores

**Files:**
- Modify: `httpsec/passwordchange.go` (gate fields, `wirePasswordChange`, new helpers)
- Test: `httpsec/passwordchange_test.go` (new `TestChangePasswordEndpointClearsLockoutFailures`)

**Interfaces:**
- Consumes: `formLogin.attempts`, `basicAuth.attempts` (both `policy.AttemptStore`), `c.logger`, and `eachInterceptor` (`httpsec/options.go:253`).
- Produces: the gate fields `attempts []policy.AttemptStore` and `log *slog.Logger`.

- [ ] **Step 1: Write the failing table test.** It follows `TestChangePasswordEndpoint`: its `resolvingSession` wiring, `changes`/`refuses` functions, and `serve`.

```go
// TestChangePasswordEndpointClearsLockoutFailures pins that a password the
// caller has just changed is not held to guesses made at the old one.
func TestChangePasswordEndpointClearsLockoutFailures(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		options func(t *testing.T, h *authHarness, other policy.AttemptStore) []httpsec.Option
		expect  func(h *authHarness, other *MockAttemptStore)
		change  httpsec.ChangePasswordFunc
		request func(ctx context.Context) *http.Request
		assert  func(t *testing.T, h *authHarness, s served)
	}

	changes := func(ex *httpsec.Exchange) error {
		ex.Writer.WriteHeader(http.StatusNoContent)

		return nil
	}
	refuses := func(*httpsec.Exchange) error { return errChangeRefused }
	post := func(ctx context.Context) *http.Request { return changePasswordRequest(ctx, http.MethodPost, true) }
	succeeded := func(t *testing.T, _ *authHarness, s served) {
		require.NoError(t, s.err)
		assert.Equal(t, http.StatusNoContent, s.rec.Code)
	}
	login := func(_ *testing.T, h *authHarness, _ policy.AttemptStore) []httpsec.Option {
		return []httpsec.Option{httpsec.EnableFormLogin(h.formLoginDeps())}
	}

	cases := []testCase{
		{
			name:    "a successful change clears the principal's username in the login store",
			options: login,
			expect:  func(h *authHarness, _ *MockAttemptStore) { h.attempts.EXPECT().Reset(gomock.Any(), testSubject).Return(nil).Times(1) },
			change:  changes, request: post, assert: succeeded,
		},
		{
			name: "a distinct Basic store is cleared too",
			options: func(_ *testing.T, h *authHarness, other policy.AttemptStore) []httpsec.Option {
				return []httpsec.Option{
					httpsec.EnableFormLogin(h.formLoginDeps()),
					httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: h.authn, Attempts: other}),
				}
			},
			expect: func(h *authHarness, other *MockAttemptStore) {
				h.attempts.EXPECT().Reset(gomock.Any(), testSubject).Return(nil).Times(1)
				other.EXPECT().Reset(gomock.Any(), testSubject).Return(nil).Times(1)
			},
			change: changes, request: post, assert: succeeded,
		},
		{
			name: "a store shared by form login and Basic is cleared once",
			options: func(_ *testing.T, h *authHarness, _ policy.AttemptStore) []httpsec.Option {
				return []httpsec.Option{httpsec.EnableFormLogin(h.formLoginDeps()), httpsec.EnableBasicAuth(h.basicAuthDeps())}
			},
			expect: func(h *authHarness, _ *MockAttemptStore) { h.attempts.EXPECT().Reset(gomock.Any(), testSubject).Return(nil).Times(1) },
			change: changes, request: post, assert: succeeded,
		},
		{
			// Review Focus 4.
			name:    "a chain with no password login clears nothing and does not fail",
			options: func(*testing.T, *authHarness, policy.AttemptStore) []httpsec.Option { return nil },
			expect:  func(*authHarness, *MockAttemptStore) {},
			change:  changes, request: post, assert: succeeded,
		},
		{
			// Review Focus 2: a value whose dynamic type holds a slice cannot be
			// compared with ==, so it is treated as distinct, never as a panic.
			name: "an attempt store of an uncomparable type is cleared without panicking",
			options: func(_ *testing.T, h *authHarness, _ policy.AttemptStore) []httpsec.Option {
				s := uncomparableStore{AttemptStore: h.attempts, tags: []string{"x"}}
				d := h.formLoginDeps()
				d.Attempts = s

				return []httpsec.Option{
					httpsec.EnableFormLogin(d),
					httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: h.authn, Attempts: s}),
				}
			},
			expect: func(h *authHarness, _ *MockAttemptStore) { h.attempts.EXPECT().Reset(gomock.Any(), testSubject).Return(nil).Times(2) },
			change: changes, request: post, assert: succeeded,
		},
		{
			name:    "a refused change clears nothing",
			options: login,
			expect:  func(*authHarness, *MockAttemptStore) {},
			change:  refuses, request: post,
			assert: func(t *testing.T, _ *authHarness, s served) { require.ErrorIs(t, s.err, errChangeRefused) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newAuthHarness(t)
			h.expectVerified()
			h.store.EXPECT().Load(gomock.Any(), testJTI).Return(owingPasswordChange(), nil).AnyTimes()
			h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(storedUser(), nil).AnyTimes()
			h.expectSaved(&savedSessions{}, nil)

			other := NewMockAttemptStore(gomock.NewController(t))
			tc.expect(h, other)

			opts := append([]httpsec.Option{
				httpsec.WithLogger(h.logger()),
				httpsec.EnableBearerToken(h.bearerTokenDeps()),
				httpsec.EnablePasswordChangeGate(h.sessions,
					httpsec.WithChangePasswordEndpoint(testChangePasswordPath, tc.change)),
			}, tc.options(t, h, other)...)

			chain, err := httpsec.New(opts...)
			require.NoError(t, err)

			tc.assert(t, h, serve(t, chain, tc.request(t.Context())))
		})
	}
}

// uncomparableStore is an attempt store whose dynamic type cannot be compared
// with ==, as a consumer's struct value holding a slice cannot.
type uncomparableStore struct {
	policy.AttemptStore
	tags []string
}
```

If `h.expectSaved` or `expectVerified` must be called differently for a refused change, follow `TestChangePasswordEndpoint`'s `refuses` case.

- [ ] **Step 2: Run to verify it fails**

Run: `go test -count=1 -run 'TestChangePasswordEndpointClearsLockoutFailures' ./httpsec/`
Expected: FAIL with `missing call(s) to *MockAttemptStore.Reset`.

- [ ] **Step 3: Implement the handover**

```go
// in passwordChangeGate:
	// attempts are the stores the chain's password logins record failures
	// into, each once, handed over at assembly. A successful change clears
	// the caller's username in each. Empty on a chain with no password login.
	attempts []policy.AttemptStore
	log      *slog.Logger
```

```go
func (c *config) wirePasswordChange() {
	stores := c.passwordAttemptStores()

	_ = eachInterceptor(c, func(g *passwordChangeGate) error {
		g.logoutPath = c.logoutPath
		g.attempts = stores
		g.log = c.logger

		return nil
	})
}

// passwordAttemptStores is every attempt store the chain's password logins
// record into, each once: form login's and Basic's, which a consumer usually
// wires to the same store.
func (c *config) passwordAttemptStores() []policy.AttemptStore {
	var stores []policy.AttemptStore
	add := func(s policy.AttemptStore) {
		if nilcheck.IsNil(s) {
			return
		}
		for _, have := range stores {
			if sameStore(have, s) {
				return
			}
		}
		stores = append(stores, s)
	}

	_ = eachInterceptor(c, func(l *formLogin) error { add(l.attempts); return nil })
	_ = eachInterceptor(c, func(b *basicAuth) error { add(b.attempts); return nil })

	return stores
}

// sameStore reports whether a and b are one store. Comparing interfaces
// panics on a dynamic type that cannot be compared, so such a store is never
// treated as the same as another; it is cleared once per login that holds it.
func sameStore(a, b policy.AttemptStore) bool {
	ta := reflect.TypeOf(a)

	return ta == reflect.TypeOf(b) && ta.Comparable() && a == b
}
```

Task 5.2 adds the clearing call itself. For this task's green step, also add the minimal call in `resolve`, right after `g.change(ex)` succeeds: `g.clearFailures(ex)`, with `clearFailures` as in Task 5.2 Step 3.

- [ ] **Step 4: Run to verify it passes**

Run: `go test -count=1 -run 'TestChangePasswordEndpoint' ./httpsec/`
Expected: PASS, including the existing `TestChangePasswordEndpoint` cases. They wire no form login, so nothing is cleared.

- [ ] **Step 5: Commit:** `git commit -am "feat(httpsec): the password-change gate learns the chain's attempt stores"`

### Task 5.2: Clear on the function's success, on an uncancellable context

**Files:**
- Modify: `httpsec/passwordchange.go` (`resolve`, `clearFailures`)
- Test: `httpsec/passwordchange_test.go`

> **As implemented:** the test harness's `serve` builds the exchange on `t.Context()` and ignores the request's context, so a `withCancel` request never reaches the gate and the case below passes without the fix. The hang-up case therefore runs through a `serveHangingUp` helper that builds the exchange itself on a cancellable context carrying its cancel function. The fixture named `storedPrincipal()` below is `testPrincipal()` in the code.

- [ ] **Step 1: Write the failing cases** in `TestChangePasswordEndpointClearsLockoutFailures`. The hang-up case cancels the request's own context from inside the consumer's function, through a cancel function carried on that context:

```go
// cancelKey carries a request's cancel function, so a test's change function
// can hang the client up mid-request.
type cancelKey struct{}

func withCancel(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)

	return context.WithValue(ctx, cancelKey{}, cancel), cancel
}
```

```go
{
	name:    "a client that hangs up after changing its password is still cleared",
	options: login,
	expect: func(h *authHarness, _ *MockAttemptStore) {
		h.attempts.EXPECT().Reset(gomock.Any(), testSubject).
			DoAndReturn(func(ctx context.Context, _ string) error {
				if ctx.Err() != nil {
					return fmt.Errorf("cleared on a cancelled context: %w", ctx.Err())
				}

				return nil
			}).Times(1)
	},
	change: func(ex *httpsec.Exchange) error {
		if cancel, ok := ex.Context().Value(cancelKey{}).(context.CancelFunc); ok {
			cancel()
		}
		ex.Writer.WriteHeader(http.StatusNoContent)

		return nil
	},
	request: func(ctx context.Context) *http.Request {
		ctx, _ = withCancel(ctx) //nolint:govet // the change function cancels it

		return changePasswordRequest(ctx, http.MethodPost, true)
	},
	assert: func(t *testing.T, h *authHarness, s served) {
		require.NoError(t, s.err)
		for _, r := range h.logs.records() {
			assert.NotEqual(t, "httpsec: lockout failures could not be cleared after a password change", r.Message,
				"the clearing ran on the client's cancelled context")
		}
	},
},
{
	// Review Focus 1: the store matches exactly, so only the principal's own
	// spelling is cleared.
	name:    "only the principal's exact username is cleared",
	options: login,
	expect: func(h *authHarness, _ *MockAttemptStore) {
		h.attempts.EXPECT().Reset(gomock.Any(), "ada").Return(nil).Times(1)
	},
	change: changes, request: post, assert: succeeded,
},
```

If an adapter or interceptor upstream of the gate reads `ex.Context()` through a derived context so that the value is not found, carry the cancel function through a variable captured in the case instead. The assertion stays the same.

- [ ] **Step 2: Run to verify it fails.** With Task 5.1's minimal `clearFailures` using `ex.Context()`, the hang-up case fails with `cleared on a cancelled context`.

Run: `go test -count=1 -run 'TestChangePasswordEndpointClearsLockoutFailures/a_client_that_hangs_up' ./httpsec/`
Expected: FAIL.

- [ ] **Step 3: Implement**

```go
// msgFailuresNotCleared is the record for a store that could not clear the
// failures a password change superseded. The change stands; only the
// bookkeeping failed.
const msgFailuresNotCleared = "httpsec: lockout failures could not be cleared after a password change"

// clearFailures clears the caller's lockout failures in every password-login
// store, once their password has changed: the failures were guesses at a
// password that no longer exists, and keeping them only locks out the user
// who has just proved they hold the account.
//
// The username is the principal's, which the bearer step loaded the user by,
// so it is the identifier this user signs in with. Only that exact string is
// cleared; failures recorded under another spelling stay until they leave
// the window, as they do after a successful login.
//
// The client's cancellation is not passed on: a client that hangs up after
// changing its password must still be cleared.
func (g *passwordChangeGate) clearFailures(ex *Exchange) {
	p, ok := identity.PrincipalFromContext(ex.Context())
	if !ok || p.Username == "" {
		return
	}

	ctx := context.WithoutCancel(ex.Context())
	for _, store := range g.attempts {
		if err := store.Reset(ctx, p.Username); err != nil {
			g.log.LogAttrs(ex.Context(), slog.LevelError, msgFailuresNotCleared,
				diag.Failure("attempt-store", err)...)
		}
	}
}
```

In `resolve`, call it immediately after `g.change(ex)` returns nil, before `adoptResolution` and `Save`.

- [ ] **Step 4: Write an end-to-end red case for "New password is not held to old failures".** It uses a real lockout policy over a memory store, in a new test function in `passwordchange_test.go`:

```go
func TestChangePasswordEndpointLetsTheNewPasswordIn(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	store := policy.NewMemoryAttemptStore()
	now := time.Now()
	for i := range 7 {
		require.NoError(t, store.RecordFailure(t.Context(), testSubject, now.Add(-time.Duration(i)*time.Second)))
	}

	lockout, err := policy.NewAccountLockoutPolicy(policy.WithAttemptStore(store))
	require.NoError(t, err)
	engine, err := policy.NewEngine(lockout)
	require.NoError(t, err)

	h.expectVerified()
	h.store.EXPECT().Load(gomock.Any(), testJTI).Return(owingPasswordChange(), nil).AnyTimes()
	h.users.EXPECT().LoadByUsername(gomock.Any(), testSubject).Return(storedUser(), nil).AnyTimes()
	h.expectSaved(&savedSessions{}, nil)
	h.expectAuthenticated(storedPrincipal())
	h.expectSessionOpened("a-new-token")

	login := h.formLoginDeps()
	login.Attempts = store

	chain, err := httpsec.New(
		httpsec.WithLogger(h.logger()),
		httpsec.WithPolicyEngine(engine),
		httpsec.EnableBearerToken(h.bearerTokenDeps()),
		httpsec.EnableFormLogin(login),
		httpsec.EnablePasswordChangeGate(h.sessions,
			httpsec.WithChangePasswordEndpoint(testChangePasswordPath, func(ex *httpsec.Exchange) error {
				ex.Writer.WriteHeader(http.StatusNoContent)

				return nil
			})),
	)
	require.NoError(t, err)

	require.NoError(t, serve(t, chain, changePasswordRequest(t.Context(), http.MethodPost, true)).err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, httpsec.DefaultLoginPath,
		strings.NewReader("username="+testSubject+"&password=the-new-one"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	got := serve(t, chain, req)

	require.NoError(t, got.err, "the new password was refused for guesses at the old one")
}
```

Adapt to the harness's real helper names: `expectAuthenticated`, `expectSessionOpened` (`login_test.go:70–88`) and the principal fixture used beside `storedUser()`. Red: comment out the `g.clearFailures(ex)` call and see the login refused with `policy.ErrAccountLocked`. Restore it.

- [ ] **Step 5: Run to verify it passes:** `go test -race -count=1 -run 'TestChangePasswordEndpoint' ./httpsec/`. Expected: PASS.
- [ ] **Step 6: Commit:** `git commit -am "feat(httpsec): a password change clears the caller's lockout failures"`

### Task 5.3: A failed clearing is logged, and the response stands

**Files:**
- Test: `httpsec/passwordchange_test.go`

- [ ] **Step 1: Write the case**

```go
{
	name:    "a clearing that fails is logged and the consumer's response stands",
	options: login,
	expect: func(h *authHarness, _ *MockAttemptStore) {
		h.attempts.EXPECT().Reset(gomock.Any(), testSubject).Return(errors.New("db: column secret_hint=hunter2")).Times(1)
	},
	change: changes, request: post,
	assert: func(t *testing.T, h *authHarness, s served) {
		succeeded(t, h, s)
		var found int
		for _, r := range h.logs.records() {
			if r.Message == "httpsec: lockout failures could not be cleared after a password change" {
				found++
			}
		}
		assert.Equal(t, 1, found)
		for _, r := range h.logs.records() {
			r.Attrs(func(a slog.Attr) bool {
				assert.NotContains(t, a.Value.String(), "hunter2", "a store's error text reached the log")
				return true
			})
		}
	},
},
```

- [ ] **Step 2: Red by inversion.** Temporarily make `clearFailures` return the error into `resolve` (`return err`), and see `s.err` non-nil. Restore it.

Run: `go test -count=1 -run 'TestChangePasswordEndpointClearsLockoutFailures/a_clearing_that_fails' ./httpsec/`

- [ ] **Step 3: Run to verify it passes**, with the same command. Expected: PASS.
- [ ] **Step 4: Commit:** `git commit -am "test(httpsec): a failed clearing leaves the password change standing"`

### Task 5.4: A recovered account at the ceiling signs in with its new password (conformance)

**Files:**
- Modify: `test/httpsecconformance/recovery_scenarios.go`: add a scenario, and add it to `recoveryScenarios()`

- [ ] **Step 1: Write the scenario.** Model it on `recoveryPasswordRouteReachesFullSession` (line ≈442). Use `Steps`, because it is a conversation:

```go
// recoveryAtTheCeilingSignsInAfterTheResolve pins spec http-security-chain
// "Recovered account at the ceiling": a password change on a recovery-pending
// session clears the lockout failures, so the new password is let in.
func recoveryAtTheCeilingSignsInAfterTheResolve() Scenario {
	return Scenario{
		Name: "a recovered account at the lockout ceiling signs in after resolving a password change",
		Build: func(t *testing.T) ChainSpec {
			t.Helper()

			fx, sessions := newRecoveryFixture(t)
			ctx := t.Context()

			s, err := sessions.Create(ctx, UserID, session.WithFirstFactor(factor.Recovery))
			require.NoError(t, err)
			sessions.MarkRecoveryPending(s, 15*time.Minute, fx.Clock.Now())
			require.NoError(t, sessions.Save(ctx, s))

			attempts := policy.NewMemoryAttemptStore()
			now := time.Now()
			for i := range 100 {
				require.NoError(t, attempts.RecordFailure(ctx, Username, now.Add(-time.Duration(i)*time.Second)))
			}

			lockout, err := policy.NewAccountLockoutPolicy(policy.WithAttemptStore(attempts))
			require.NoError(t, err)
			engine, err := policy.NewEngine(lockout)
			require.NoError(t, err)

			effects := &Effects{Sessions: sessions, Recovery: fx, SessionID: s.ID, Attempts: attempts}

			return ChainSpec{
				Options: []httpsec.Option{
					httpsec.WithPolicyEngine(engine),
					httpsec.EnableBearerToken(httpsec.BearerTokenDeps{
						Verifier: fixtureTokens{}, Sessions: sessions, Users: fixtureUsers{},
					}),
					httpsec.EnableFormLogin(httpsec.FormLoginDeps{
						Authenticator: &fixtureAuthenticator{calls: &effects.authCalls},
						Sessions:      sessions,
						Tokens:        fixtureTokens{},
						Attempts:      attempts,
					}),
					httpsec.EnablePasswordChangeGate(sessions,
						httpsec.WithChangePasswordEndpoint(recoveryResolvePath, noopChangePassword)),
				},
				Effects: effects,
			}
		},
		Steps: func(t *testing.T, spec ChainSpec, send func(RequestSpec) Result) {
			resolve := authenticatedRequest(http.MethodPost, recoveryResolvePath)(spec)
			resolve.Header["Content-Type"] = "application/x-www-form-urlencoded"
			resolve.Body = url.Values{"password": {Password}}.Encode()
			require.NoError(t, send(resolve).Refusal)

			res := send(formBody("username=" + Username + "&password=" + Password))
			require.NoError(t, res.Refusal, "the new password was refused for guesses at the old one")
			assert.Equal(t, http.StatusOK, res.Status)
		},
	}
}
```

Add it to the slice that `recoveryScenarios()` returns. If `Effects.authCalls` is unexported and the field set differs, follow `newEffects` in `scenarios.go`. If `policy.NewEngine`'s signature differs, follow `lockedAccountIsRefused`'s use of it.

- [ ] **Step 2: Red.** Before Task 5.2 lands, or with `g.clearFailures(ex)` commented out, run `cd test && go test -count=1 -run 'Conformance' ./...`. Expected: FAIL. The login refusal is `policy.ErrAccountLocked`. Restore it.

- [ ] **Step 3: Verify:** `cd test && go test -count=1 ./...`. Expected: PASS on every adapter.
- [ ] **Step 4: Commit:** `git add test/httpsecconformance/recovery_scenarios.go && git commit -m "test(conformance): a recovered account at the ceiling signs in after the resolve"`

### Task 5.5: Document the clearing (H2)

**Files:**
- Modify: `httpsec/passwordchange.go` (`ChangePasswordFunc` godoc), `httpsec/options.go` (`EnablePasswordChangeGate` godoc)

This is documentation only, so there is no red step.

- [ ] **Step 1: Append to the `ChangePasswordFunc` godoc**

```go
// When it succeeds, the chain clears the caller's lockout failures in the
// attempt stores of its form login and Basic authentication, under the
// principal's username exactly as stored: guesses at the old password protect
// nothing once it has changed. Failures recorded under another spelling of
// the username stay until they leave the lockout window. A consumer who
// changes passwords outside the chain clears them with
// policy.AccountLockoutPolicy.Reset.
```

- [ ] **Step 2: Add one sentence to `EnablePasswordChangeGate`:** "A successful resolve also clears the caller's lockout failures (see ChangePasswordFunc); there is no option to keep them, since they were guesses at a password that no longer exists."

- [ ] **Step 3: Verify:** `go doc ./httpsec ChangePasswordFunc`, `go doc ./httpsec EnablePasswordChangeGate`, `go vet ./httpsec/`.
- [ ] **Step 4: Commit:** `git commit -am "docs(httpsec): a password change clears lockout failures"`

### Task 6.1: Unknown usernames lock exactly like known ones

**Files:**
- Create: `test/httpsecconformance/lockout_scenarios.go`
- Modify: `test/httpsecconformance/scenarios.go`: add `lockoutScenarios()` to the `slices.Concat` in `Scenarios()`
- Create: `httpsec/lockout_unknown_test.go`

- [ ] **Step 1: Write the conformance scenario**

```go
package httpsecconformance

// lockoutScenarios is every lockout behaviour that must be identical on every
// adapter.
func lockoutScenarios() []Scenario {
	return []Scenario{unknownAndKnownUsernamesLockAlike()}
}

// unknownAndKnownUsernamesLockAlike pins spec http-security-chain "Unknown and
// known look alike under lock": a lock reveals nothing about whether the
// username names an account.
func unknownAndKnownUsernamesLockAlike() Scenario {
	return Scenario{
		Name: "an unknown username is locked exactly like a known one",
		Build: func(t *testing.T) ChainSpec {
			effects := newEffects(t)

			lockout, err := policy.NewAccountLockoutPolicy(policy.WithAttemptStore(effects.Attempts))
			require.NoError(t, err)
			engine, err := policy.NewEngine(lockout)
			require.NoError(t, err)

			return ChainSpec{
				Options: append(formLoginOptions(effects), httpsec.WithPolicyEngine(engine)),
				Effects: effects,
			}
		},
		Steps: func(t *testing.T, _ ChainSpec, send func(RequestSpec) Result) {
			sixth := map[string]Result{}
			for _, user := range []string{Username, "nobody"} {
				for range 5 {
					res := send(formBody("username=" + user + "&password=wrong"))
					require.ErrorIs(t, res.Refusal, authenticate.ErrAuthenticationFailed)
				}
				sixth[user] = send(formBody("username=" + user + "&password=wrong"))
			}

			known, unknown := sixth[Username], sixth["nobody"]
			assert.Equal(t, known.Status, unknown.Status)
			assert.Equal(t, http.StatusUnauthorized, unknown.Status)
			require.ErrorIs(t, known.Refusal, policy.ErrAccountLocked)
			require.ErrorIs(t, unknown.Refusal, policy.ErrAccountLocked)
			assert.Equal(t, known.Refusal.Error(), unknown.Refusal.Error())
			assert.Equal(t, 10, known.Effects.AuthenticatorCalls(),
				"the sixth request of each was refused before any password was checked")
		},
	}
}
```

Add the imports the file needs (`testing`, `net/http`, testify, `authenticate`, `httpsec`, `policy`). Register it with `slices.Concat(oidcScenarios(), …, passkeyScenarios(), lockoutScenarios())`.

- [ ] **Step 2: Write the `httpsec` test for Basic and for the decoy**

```go
package httpsec_test

// TestUnknownUsernameLock pins that Basic, and the decoy password work, treat
// a username with no account exactly as one with an account under lock.
func TestUnknownUsernameLock(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name   string
		opts   []httpsec.Option
		send   func(ctx context.Context, user string) *http.Request
		assert func(t *testing.T, known, unknown served)
	}

	basic := func(ctx context.Context, user string) *http.Request {
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/records", nil)
		req.SetBasicAuth(user, "wrong")

		return req
	}

	cases := []testCase{
		{
			name: "over Basic, both are refused alike",
			send: basic,
			assert: func(t *testing.T, known, unknown served) {
				assert.Equal(t, known.rec.Code, unknown.rec.Code)
				assert.Equal(t, known.err.Error(), unknown.err.Error())
				assert.Equal(t, known.rec.Header().Get("WWW-Authenticate"), unknown.rec.Header().Get("WWW-Authenticate"))
			},
		},
		{
			name: "over Basic with locks disclosed, both are answered 429",
			opts: []httpsec.Option{httpsec.WithLockDisclosure()},
			send: basic,
			assert: func(t *testing.T, known, unknown served) {
				assert.Equal(t, http.StatusTooManyRequests, httpsec.StatusForError(known.err))
				assert.Equal(t, http.StatusTooManyRequests, httpsec.StatusForError(unknown.err))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := policy.NewMemoryAttemptStore()
			now := time.Now()
			for _, user := range []string{"ada", "nobody"} {
				for i := range 5 {
					require.NoError(t, store.RecordFailure(t.Context(), user, now.Add(-time.Duration(i)*time.Second)))
				}
			}
			lockout, err := policy.NewAccountLockoutPolicy(policy.WithAttemptStore(store))
			require.NoError(t, err)
			engine, err := policy.NewEngine(lockout)
			require.NoError(t, err)

			chain, err := httpsec.New(append([]httpsec.Option{
				httpsec.WithPolicyEngine(engine),
				httpsec.EnableBasicAuth(httpsec.BasicAuthDeps{Authenticator: lockDecoyAuthenticatorFor(t, 2), Attempts: store}),
			}, tc.opts...)...)
			require.NoError(t, err)

			tc.assert(t, serve(t, chain, tc.send(t.Context(), "ada")), serve(t, chain, tc.send(t.Context(), "nobody")))
		})
	}
}
```

For the decoy count, reuse the approach of `lockDecoyAuthenticator` (`httpsec/recoverycomplete_test.go:1012`): a manager over the password provider with strict mocks, where `Match` is expected exactly `decoys` times. Write a local `lockDecoyAuthenticatorFor(t, decoys)` in this new file. Do not edit `recoverycomplete_test.go`, which belongs to P1a. With locks concealed, two decoys (one per identifier) prove equal password work. With locks disclosed, the test passes `lockDecoyAuthenticatorFor(t, 0)`. Thread the count through as a `decoys int` field on `testCase`.

- [ ] **Step 3: Red by inversion.** In `httpsec/login.go`'s `recordFailure` and in the Basic recording at `httpsec/basic.go:177`, temporarily skip recording when `username == "nobody"`. Pre-recorded failures cover the `httpsec` test, so for that test temporarily pre-record only for `ada` instead. Run:
  - `cd test && go test -count=1 ./...`
  - `go test -count=1 -run TestUnknownUsernameLock ./httpsec/`

  Expected: FAIL (status or error differs between `ada` and `nobody`). Edit everything back. C1 holds `login.go` and `basic.go` only for this inversion. Confirm with `git diff --stat httpsec/login.go httpsec/basic.go` (empty) and report it.

- [ ] **Step 4: Verify:** `cd test && go test -count=1 ./...` and `go test -count=1 -run TestUnknownUsernameLock ./httpsec/`. Expected: PASS.
- [ ] **Step 5: Commit:** `git add test/httpsecconformance/ httpsec/lockout_unknown_test.go && git commit -m "test: an unknown username is locked exactly like a known one"`

### Task 7.1: Whole-branch checks (main session)

- [ ] **Step 1:** In each module, run `go test -race -count=1 ./...`: root, `test`, `ginsec`, `fibersec`, `gorm`, `pgx`, `redis`, `sweep`, `passkey/webauthn`.
- [ ] **Step 2:** `go vet ./...` (every module), `gofmt -l .` (empty output) and `golangci-lint run ./...`.
- [ ] **Step 3:** Keep the output as evidence. Any failure goes back to the lane that owns the file.

### Task 7.2: Whole-branch review

- [ ] **Step 1:** Dispatch a fresh Opus reviewer that wrote none of the code. It checks the branch diff against every requirement in `specs/security-policy/spec.md` and `specs/http-security-chain/spec.md` of this change, design decisions 1–6, and this plan's Review Focus. It reports and edits nothing. Each claimed defect either has a failing test or is labelled `UNREPRODUCED`.
- [ ] **Step 2:** Findings go to a fresh dispatch of the owning lane. Re-run 7.1 afterwards.
