# Login Source Throttling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session never writes code (`.claude/rules/subagent-delegation.md`). Every task below is carried out by a dispatched subagent, and the main session verifies and reviews it.

**Goal:** Bound password spraying per source, replace the hard account lock with an escalating wait, make a locked account's login refusal indistinguishable from a wrong password, and count every login failure even when the client disconnects.

**Architecture:**
- **Source guard.** Form login and Basic share one `password-login` source guard, built through `resolveSourceGuard` like every other guarded flow. It is checked before pre-authentication.
- **Escalating wait.** `policy.AccountLockoutPolicy` computes the wait with two `FailureCount` queries, so the `AttemptStore` port is unchanged. A fixed lock remains available as an option.
- **Undisclosed lock.** On a lock, the endpoints spend a decoy password verification through the new `authenticate.DecoyVerifier`, and refuse with an error joining the authentication failure to the lock reason, which the status table answers with 401. A consumer who opts to disclose locks gets the lock reason alone, which the status table now answers with 429 instead of 423.

**Tech Stack:** Go 1.27. testify, `go.uber.org/mock` (typed), and the `jonboulle/clockwork` fake clock in tests.

**Spec:** `openspec/changes/login-source-throttling/`. It holds `proposal.md`, `design.md` (decisions 1–4), the delta specs `specs/security-policy/spec.md`, `specs/authentication/spec.md`, `specs/http-security-chain/spec.md` and `specs/http-error-propagation/spec.md`, and `tasks.md`. Task numbers below (1.1, 2.2, …) are `tasks.md`'s.

## Global Constraints

- **Test-first for every task.** Write the failing test, run it, and confirm it fails **for the intended reason**; a compile error is not a red step. Then implement and refactor (`.claude/rules/golang-tdd.md`). Where a new identifier is needed, stub it first so the red step is a behavioural failure.
- **Tests and mocks.** Tables follow the `table-test` skill: an `assert` closure per case, and `t.Context()`. Mocks come from `use-mockgen`. `httpsec` already has a typed `MockAttemptStore` (`attemptstore_mock_test.go`), and `authenticate` has `MockEncoder` and `MockUserLoader`.
- **Library design.** Every option names the default it replaces. Wiring mistakes fail at construction: `policy.ErrConfig`, or an `httpsec` configuration error naming the option.
- **Defect claims.** Decision 4 is `UNREPRODUCED`. If 1.1 passes on unchanged code, 1.2 is not done.
- **Exact values:**

  | Setting | Value |
  |---|---|
  | threshold | `5` |
  | window | `24 * time.Hour` |
  | first wait | `30 * time.Second` |
  | longest wait | `time.Hour` |
  | ceiling | `100` |
  | login guard flow and namespace | `"password-login"` |
  | login guard limit | `50` per `15 * time.Minute` |
  | account-locked status (disclosed) | `http.StatusTooManyRequests` (429) |
  | joined lock refusal status (default) | `http.StatusUnauthorized` (401) |

- **Option names:** `WithLockoutWait`, `WithLockoutCeiling`, `WithFixedLockout`, `WithLoginLimiter`, `WithBasicAuthLimiter`, `WithLockDisclosure`, and the interface `authenticate.DecoyVerifier`.
- **Predecessor.** No citing or copying it (`.claude/rules/legacy-reference.md`).
- **Git.** No git command that discards work. Subagents do not commit; the main session commits after each verified, reviewed dispatch.
- **Every task's verification also includes** an empty `gofmt -l` for the touched packages, and `go vet ./...`.

## Review Focus

1. **The wait boundary.** The newest failure is exactly `wait` old. Because `FailureCount` counts strictly after `since`, the attempt is allowed. Test: Task 2.2, case "newest exactly at the wait".
2. **A wait whose exponent overflows.** With 70 failures, `30s · 2^65` overflows `time.Duration`. The wait must cap at the longest wait, not wrap negative or to zero. Test: Task 2.2, case "huge exponent caps".
3. **A store failure on the second query.** If the first count succeeds and the wait query errors, the policy must deny with the store's error, never allow. Test: Task 2.2, case "wait query fails".
4. **A malformed Basic header from a throttled source.** It is refused with `WWW-Authenticate`, and the guard is not consulted. Test: Task 4.1, case "malformed header skips the guard". The header is refused before the source check, so a bad header spends nothing.
5. **A lock under the disclosing option from Basic.** The response is 429 and must not carry `WWW-Authenticate`, which belongs to 401. Test: Task 4.2, case "disclosed Basic lock has no challenge".

---

## Execution: lanes, dispatches and models

| Dispatch | Tasks | Owns | Must not touch | Model | Why |
|---|---|---|---|---|---|
| H1 | 1.1, 1.2 | `httpsec/login.go`, `httpsec/basic.go`, `httpsec/login_test.go`, `httpsec/basic_test.go` | `policy/`, `authenticate/` | Sonnet | A red step and a one-line fix, matching an existing pattern |
| P1 | 2.1–2.4 | `policy/lockout.go`, `policy/lockout_error.go` (new), `policy/lockout_test.go`, `policy/lockout_config_test.go`, `policy/store_failure_test.go`, `httpsec/returned_errors_test.go`, `httpsec/recoverycomplete_test.go` | everything else in `httpsec` | Opus | Security-critical refusal logic written for the first time |
| A1 | 3.1, 3.2 | `authenticate/decoy.go` (new), `authenticate/password.go`, `authenticate/manager.go`, `authenticate/decoy_test.go` (new) | `httpsec/`, `policy/` | Sonnet | A small port with a stated contract and an existing reference-hash path |
| H2 | 4.1–4.3 | `httpsec/login.go`, `httpsec/basic.go`, `httpsec/options.go`, `httpsec/throttle.go`, `httpsec/chain.go`, `httpsec/doc.go`, `httpsec/status.go`, `httpsec/status_test.go`, `httpsec/login_test.go`, `httpsec/basic_test.go`, `httpsec/chain_login_guard_test.go` (new), the lock-status assertion in `httpsec/recoverycomplete_test.go`, `test/httpsecconformance/scenarios.go` | `policy/`, `authenticate/`, and `httpsec/returned_errors_test.go` | Opus | Changes the order of refusals on the login path; a mistake would pass tests and still leak |

**Order:**
- H1, P1 and A1 start together.
- H2 starts after H1, P1 and A1 are verified and reviewed: it edits the lock-status assertion in `recoverycomplete_test.go`, which P1 also edits.
- H2 edits `httpsec/options.go` and `httpsec/throttle.go`, which the `limiter-key-bounds` change (another session, branch `feat/limiter-key-bounds`) also edits. Before H2 starts, the main session tells that session, and whichever change lands those files first is the base the other rebases on.
- 5.1 and 5.2 belong to the main session.

P1 and H2 get Opus reviewers. H1 and A1 get Sonnet reviewers.

---

### Task 1.1: Red step for recording on an uncancellable context (`UNREPRODUCED`)

**Files:** Modify `httpsec/login_test.go` and `httpsec/basic_test.go`.

- [ ] **Step 1: Write the failing tests.** Build form login, and Basic, with `EnableFormLogin` / `EnableBasicAuth`, an authenticator mock returning `authenticate.ErrAuthenticationFailed`, and a `MockAttemptStore`. The store expects `RecordFailure` and returns `ctx.Err()`, capturing the context.

```go
func TestFormLogin_RecordsFailureOnUncancellableContext(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := NewMockAttemptStore(ctrl)
	var recordedCtx context.Context
	store.EXPECT().RecordFailure(gomock.Any(), "ada", gomock.Any()).
		DoAndReturn(func(ctx context.Context, _ string, _ time.Time) error {
			recordedCtx = ctx
			return ctx.Err()
		})
	ctx, cancel := context.WithCancel(t.Context())
	authn := NewMockAuthenticator(ctrl)
	authn.EXPECT().Authenticate(gomock.Any(), gomock.Any()).
		DoAndReturn(func(context.Context, identity.Credentials) (*authenticate.Authentication, error) {
			cancel() // the client hangs up after sending its guess
			return nil, authenticate.ErrAuthenticationFailed
		})
	chain := newLoginChain(t, authn, store) // the existing login-test helper, or a new one built with EnableFormLogin
	serveLogin(t, chain, ctx, "ada", "wrong")
	require.NotNil(t, recordedCtx)
	assert.NoError(t, recordedCtx.Err(), "the failure must be recorded on a context the client cannot cancel")
}
```

Write the same test for Basic, with an `Authorization: Basic` header.

- [ ] **Step 2: Run.** `go test -run 'Test(FormLogin|BasicAuth)_RecordsFailureOnUncancellableContext' -count=1 ./httpsec/`
  - If the claim holds: FAIL with `context canceled`. Report the output.
  - If it PASSES, report that. 1.2 is skipped, and the main session removes decision 4.

### Task 1.2: Record on `context.WithoutCancel` (only if 1.1 failed)

**Files:** Modify `httpsec/login.go` (`recordFailure`) and `httpsec/basic.go` (the failure branch of `Intercept`).

- [ ] **Step 1: Minimal fix.**

```go
// login.go recordFailure
// The client's cancellation is not passed on: a client that hangs up after
// sending its guess must still be charged for it, and an attempt store that
// honours cancellation would otherwise drop the failure.
if err := l.attempts.RecordFailure(context.WithoutCancel(ctx), username, now); err != nil {
```

In `basic.go`, make the same change at its `b.attempts.RecordFailure(...)` call. `Reset` stays on `ctx`.

- [ ] **Step 2: Verify.** 1.1's command passes, and `go test -race -count=1 ./httpsec/...` passes.

### Task 2.1: New lockout options and construction rules

**Files:** Modify `policy/lockout.go` and `policy/lockout_config_test.go` (table `TestNewAccountLockoutPolicy`).

**Interfaces — produces:**

```go
func WithLockoutWait(first, longest time.Duration) LockoutOption
func WithLockoutCeiling(n int) LockoutOption
func WithFixedLockout(threshold int, window time.Duration) LockoutOption
```

New fields on `AccountLockoutPolicy`:
- `firstWait` and `longestWait time.Duration`;
- `ceiling int`;
- `fixed bool`;
- `setThreshold`, `setWindow`, `setWait` and `setCeiling bool`, so a conflict with `WithFixedLockout` can be detected.

New constants:
- `defaultLockoutWindow = 24 * time.Hour`;
- `defaultLockoutFirstWait = 30 * time.Second`;
- `defaultLockoutLongestWait = time.Hour`;
- `defaultLockoutCeiling = 100`.

- [ ] **Step 1: Failing table cases.** Each error case asserts `errors.Is(err, policy.ErrConfig)`:
  - "first wait zero": `WithLockoutWait(0, time.Hour)`;
  - "longest shorter than first": `WithLockoutWait(time.Minute, time.Second)`;
  - "ceiling equals threshold": `WithLockoutCeiling(5)`;
  - "ceiling below a consumer threshold": `WithLockoutThreshold(10), WithLockoutCeiling(8)`;
  - "fixed with wait": `WithFixedLockout(5, 15*time.Minute), WithLockoutWait(time.Second, time.Minute)`;
  - "fixed with threshold": `WithFixedLockout(5, 15*time.Minute), WithLockoutThreshold(3)`;
  - "fixed with zero window": `WithFixedLockout(5, 0)`;
  - "defaults": no options. Check `p.Window() == 24*time.Hour` and `p.Threshold() == 5`. Update `TestAccountLockoutPolicyDefaults` likewise;
  - "ceiling above 100 allowed": `WithLockoutCeiling(150)`, which succeeds.
- [ ] **Step 2: Run.** `go test -run 'TestNewAccountLockoutPolicy|TestAccountLockoutPolicyDefaults' -count=1 ./policy/`, after stubbing the three options so they set nothing. Expected: FAIL. The error cases construct, and the default window is 15 minutes.
- [ ] **Step 3: Implement.** Options set their fields and `set*` flags. Under `WithFixedLockout(n, d)`, `fixed = true`, `threshold = n`, `window = d`. Validation in `NewAccountLockoutPolicy`, after the existing threshold and window checks:

```go
if p.fixed && (p.setThreshold || p.setWindow || p.setWait || p.setCeiling) {
	return nil, fmt.Errorf("%w: WithFixedLockout sets its own threshold and window and has no wait "+
		"or ceiling, so combining it with another lockout option would silently change that option's meaning", ErrConfig)
}
if !p.fixed {
	if p.firstWait <= 0 { /* ErrConfig: first wait must be positive */ }
	if p.longestWait < p.firstWait { /* ErrConfig */ }
	if p.ceiling <= p.threshold { /* ErrConfig: the ceiling must be above the threshold */ }
}
```

- [ ] **Step 4: Verify.** Step 2's command passes, and `go test -race -count=1 ./policy/...` passes, except evaluation tests whose semantics change in 2.2. Note them in the report rather than editing them here.

### Task 2.2: Evaluate the escalating wait and the ceiling

**Files:** Modify `policy/lockout.go` (`Evaluate`), `policy/lockout_test.go` (`TestAccountLockoutPolicyEvaluates`), `policy/store_failure_test.go`, `httpsec/returned_errors_test.go` and `httpsec/recoverycomplete_test.go`.

- [ ] **Step 1: Failing table cases** in `TestAccountLockoutPolicyEvaluates`. Use the in-memory store and failures recorded at given offsets before `now` (`in.Now` = `epoch`).

| case | failures (offsets before now) | options | expect |
|---|---|---|---|
| at the threshold | 5, newest 10s | default | deny, `ErrAccountLocked` |
| first wait | 5, newest 29s | default | deny |
| first wait served | 5, newest 31s | default | allow |
| newest exactly at the wait | 5, newest 30s | default | allow |
| doubled wait | 7, newest 100s | default | deny |
| doubled wait served | 7, newest 121s | default | allow |
| longest wait | 20 within 24h, newest 61m | default | allow |
| huge exponent caps | 70 within 24h, newest 59m | default | deny |
| huge exponent served | 70 within 24h, newest 61m | default | allow |
| one hundred failures | 100 within 24h, newest 2h | default | deny |
| consumer ceiling | 20, newest 2h | `WithLockoutCeiling(20)` | deny |
| consumer threshold | 3, newest 10s | `WithLockoutThreshold(3)` | deny |
| below threshold | 4, newest 1s | default | allow |
| failures older than the window | 10, all 25h ago | default | allow |

For "wait query fails", use a store double (the existing pattern in `store_failure_test.go`) whose first `FailureCount` returns 7 and whose second returns an error. Expect a deny with a reason matching `ErrPolicyDenied` that wraps the store error, and not `ErrAccountLocked`.

Also update the existing scenarios ("Reset on success", "Store failure") so their failure timing matches the new semantics, keeping their intent. Update the `httpsec` tests that build `policy.NewAccountLockoutPolicy()` and expect a lock after N failures, so that the newest failure is inside the wait, or construct them with `WithFixedLockout(5, 15*time.Minute)` where the test is about the chain rather than the policy.

- [ ] **Step 2: Run.** `go test -race -run TestAccountLockoutPolicyEvaluates -count=1 ./policy/`. Expected: FAIL. "first wait served" is denied by the hard lock, and "one hundred failures" is still a hard lock without the ceiling logic.
- [ ] **Step 3: Implement.**

```go
func (p *AccountLockoutPolicy) waitFor(n int) time.Duration {
	steps := n - p.threshold
	// Doubling past the longest wait in a loop rather than with a shift keeps
	// a large failure count from overflowing time.Duration into a short wait.
	wait := p.firstWait
	for range steps {
		if wait >= p.longestWait/2 {
			return p.longestWait
		}
		wait *= 2
	}
	return min(wait, p.longestWait)
}

// In Evaluate, after counting n over the window:
if p.fixed {
	if n >= p.threshold { return lockedDecision(n, p.window, 0) }
	return Decision{}
}
if n >= p.ceiling { return lockedDecision(n, p.window, 0) }
if n < p.threshold { return Decision{} }
wait := p.waitFor(n)
recent, err := p.store.FailureCount(ctx, in.Username, now.Add(-wait))
if err != nil { return storeDenied(err) } // the same diag.Wrap path as the first count
if recent > 0 { return lockedDecision(n, p.window, wait) }
return Decision{}
```

`lockedDecision` builds the 2.4 error. Until 2.4 lands, it keeps returning `fmt.Errorf("%w: ...", ErrAccountLocked, ...)`. Extract the existing store-failure decision into `storeDenied(err)`, so both queries share it.

- [ ] **Step 4: Verify.** `go test -race -count=1 ./policy/... ./httpsec/...` passes.

### Task 2.3: The fixed lock

**Files:** Modify `policy/lockout_test.go`.

- [ ] **Step 1: Failing cases** in `TestAccountLockoutPolicyEvaluates`:
  - "fixed lock": `WithFixedLockout(5, 15*time.Minute)`, five failures, newest 10 minutes ago, expects deny;
  - "fixed lock aged out": five failures, newest 16 minutes ago, expects allow;
  - "fixed lock ignores ceiling": `WithFixedLockout(200, 24*time.Hour)` with 150 failures, expects allow.
- [ ] **Step 2: Run.** It fails if 2.2's `fixed` branch is missing or wrong. If 2.2 already made these pass, invert the `fixed` branch temporarily, see them fail, restore it, and report both runs.
- [ ] **Step 3: Verify.** `go test -race -run TestAccountLockout -count=1 ./policy/` passes.

### Task 2.4: `LockoutError` and godoc

**Files:** Create `policy/lockout_error.go`. Modify `policy/lockout.go` and `policy/lockout_test.go`.

**Interfaces — produces:**

```go
// LockoutError is the reason an AccountLockoutPolicy denies a locked identifier.
// It matches ErrAccountLocked. Wait is the escalated wait the identifier owes,
// an upper bound on what remains; it is zero at the ceiling and under a fixed
// lock, where no wait would lift the lock.
type LockoutError struct {
	Wait     time.Duration
	failures int
	window   time.Duration
}

func (e *LockoutError) Error() string // "policy: account locked after repeated failures: <n> failures within <window>"
func (e *LockoutError) Is(target error) bool { return target == ErrAccountLocked }
```

- [ ] **Step 1: Failing cases.** In "doubled wait", `var le *policy.LockoutError` with `errors.As(d.Reason, &le)` and `le.Wait == 120*time.Second`. In "one hundred failures" and "fixed lock", `le.Wait == 0`. Also check `errors.Is(d.Reason, policy.ErrAccountLocked)`.
- [ ] **Step 2: Run.** `go test -run TestAccountLockoutPolicyEvaluates -count=1 ./policy/`. Expected: FAIL, because `errors.As` finds no `*LockoutError`.
- [ ] **Step 3: Implement.** `lockedDecision(n, window, wait)` returns `Decision{Outcome: Deny, Reason: &LockoutError{Wait: wait, failures: n, window: window}}`. Rewrite the godoc of `AccountLockoutPolicy`, `NewAccountLockoutPolicy` and each option so it covers:
  - the escalating default;
  - each default value;
  - the NIST cap, with a ceiling above 100 named as a departure;
  - that `WithFixedLockout(5, 15*time.Minute)` restores the hard lock;
  - that attempts refused during a wait are not recorded, so an attacker cannot extend the wait without guessing.
- [ ] **Step 4: Verify.** `go test -race -count=1 ./policy/...` passes, and `go doc ./policy LockoutError` and `go doc ./policy AccountLockoutPolicy` read correctly.

### Task 3.1: `DecoyVerifier` and the password provider

**Files:** Create `authenticate/decoy.go` and `authenticate/decoy_test.go`. Modify `authenticate/password.go`.

**Interfaces — produces:**

```go
// DecoyVerifier spends the password work a real verification would, on a
// refusal made before any password was checked. It reports nothing about the
// outcome; handled says only whether creds are of a kind it verifies, so a
// Manager can find the right delegate without calling Authenticate.
type DecoyVerifier interface {
	VerifyDecoy(ctx context.Context, creds identity.Credentials) (handled bool)
}
```

- [ ] **Step 1: Failing test `TestPasswordAuthenticator_VerifyDecoy`** (table):
  - "username and password": a `MockEncoder`, set to expect `Encode(referencePassword)` once at construction and `Match("guess", referenceHash)` once at the decoy, and a `MockUserLoader` with **no** expectations (so a call fails the test). Then `NewUsernamePasswordAuthenticator(users, WithPasswordEncoder(enc))`, assert it implements `DecoyVerifier`, and assert that `VerifyDecoy(t.Context(), identity.NewUsernamePassword("ada", []byte("guess")))` returns `true`.
  - "other credentials": `VerifyDecoy` with `authenticate.NewBearerToken("x")` returns `false`, and `Match` is not called.
- [ ] **Step 2: Run.** `go test -race -run TestPasswordAuthenticator_VerifyDecoy -count=1 ./authenticate/`. Expected: FAIL. The type assertion fails, or, after a stub returning false, `Match` is never called.
- [ ] **Step 3: Implement.**

```go
func (a *passwordAuthenticator) VerifyDecoy(_ context.Context, c identity.Credentials) bool {
	creds, ok := c.(*identity.UsernamePassword)
	if !ok {
		return false
	}
	// Deliberately unused: the verification is the point, not its verdict.
	// The user is not loaded, so a slow store cannot tell this refusal from a
	// real one either.
	_ = a.enc.Match(string(creds.Password), a.reference)
	return true
}

var _ DecoyVerifier = (*passwordAuthenticator)(nil)
```

- [ ] **Step 4: Verify.** Step 2's command passes, and `go test -race -count=1 ./authenticate/...` passes.

### Task 3.2: `Manager.VerifyDecoy`

**Files:** Modify `authenticate/manager.go` and `authenticate/decoy_test.go`.

- [ ] **Step 1: Failing test `TestManager_VerifyDecoy`** (table). Delegates are test types implementing `Authenticator`, optionally `DecoyVerifier`, and recording calls:
  - "manager delegates": the delegates are [bearer (no decoy), decoyA (handles bearer only), decoyB (handles username and password)]. `VerifyDecoy(usernamePassword)` returns true, decoyB was called once, and decoyA was offered and declined.
  - "no provider offers it": only non-decoy delegates. It returns false.
  - "first handler wins": two delegates both handle username and password. Only the first is called.
- [ ] **Step 2: Run.** `go test -race -run TestManager_VerifyDecoy -count=1 ./authenticate/`, after a stub returning false. Expected: FAIL.
- [ ] **Step 3: Implement.**

```go
// VerifyDecoy offers creds to each delegate that can spend a decoy
// verification, in order, and stops at the first that handles them.
func (m *Manager) VerifyDecoy(ctx context.Context, c identity.Credentials) bool {
	for _, d := range m.delegates {
		if v, ok := d.(DecoyVerifier); ok && v.VerifyDecoy(ctx, c) {
			return true
		}
	}
	return false
}

var _ DecoyVerifier = (*Manager)(nil)
```

- [ ] **Step 4: Verify.** Step 2's command passes, `go test -race -count=1 ./authenticate/...` passes, and `go doc ./authenticate DecoyVerifier` reads correctly.

### Task 4.1: The `password-login` guard

**Files:**
- Modify `httpsec/options.go`: `LoginOption` `WithLoginLimiter` and `BasicAuthOption` `WithBasicAuthLimiter`, with the `limiter` field on each endpoint's option state.
- Modify `httpsec/throttle.go` or `httpsec/chain.go`: build the guard at `build`, after the keyer.
- Modify `httpsec/login.go` and `httpsec/basic.go`: the `guard sourceGuard` field, check, and record.
- Create `httpsec/chain_login_guard_test.go`.

**Interfaces:**
- Consumes: `c.resolveSourceGuard(option, flow string, limiter ratelimit.Limiter, limit int, window time.Duration, logInterval time.Duration) (sourceGuard, error)`.
- Produces:
  - `const passwordLoginFlow = "password-login"`;
  - `defaultPasswordLoginLimit = 50`;
  - `defaultPasswordLoginWindow = 15 * time.Minute`;
  - `func WithLoginLimiter(l ratelimit.Limiter) LoginOption`;
  - `func WithBasicAuthLimiter(l ratelimit.Limiter) BasicAuthOption`.

- [ ] **Step 1: Failing tests** in `chain_login_guard_test.go`. Requests go through the chain with `httptest` and a set client address, following the existing chain rate-limit tests (`chain_ratelimit_test.go`). The cases:
  - "spraying": 50 wrong-password form logins for `user1` to `user50` from `203.0.113.7`, then one for `user51`. Its status is 401 and its error matches `ratelimit.ErrThrottled`. The authenticator mock and the policy engine's pre-authentication see no 51st call.
  - "form and Basic share": 30 failed form logins and 20 failed Basic attempts from one source, then a form login, which is throttled.
  - "successes spend nothing": 100 successful logins and 49 failed ones, then another failed one, which is not throttled.
  - "locked refusals count": a lockout policy built with `WithFixedLockout(1, time.Hour)` and one prior failure for `ada`. Then 50 form logins for `ada` (each refused as locked), then a login as `bob`, which is throttled.
  - "consumer limiter": `WithLoginLimiter(memLimiter(10, 15*time.Minute))`. After 10 form failures the eleventh is throttled, and Basic from the same source is not.
  - "factory namespace": a recording factory. With both endpoints enabled it receives exactly one `NewLimiter("password-login", 50, 15*time.Minute)`.
  - "unattributable": empty client address. Refused as `ErrSourceUnattributable`, and the authenticator is not called.
  - "throttled Basic challenged": the response carries `WWW-Authenticate: Basic realm="Restricted"`.
  - "malformed header skips the guard": a throttled source sends `Authorization: Basic !!!`. The result is 401 with `WWW-Authenticate`, and the limiter mock sees no `Exceeded` call.
  - "nil limiter": `WithLoginLimiter(nil)` and `WithBasicAuthLimiter((*ratelimit.MemoryLimiter)(nil))` each fail `httpsec.New` with an error naming the option.
- [ ] **Step 2: Run.** `go test -race -run 'TestChain_PasswordLogin' -count=1 ./httpsec/`, after stubbing the two options. Expected: FAIL, because the 51st login reaches the authenticator.
- [ ] **Step 3: Implement.**
  - At `build`, after `c.keyer` is set and if form login or Basic is enabled, build the default guard once with `c.resolveSourceGuard("EnableFormLogin/EnableBasicAuth", passwordLoginFlow, nil, defaultPasswordLoginLimit, defaultPasswordLoginWindow, c.refusalInterval)`.
  - An endpoint given its own limiter builds its own guard over it, with the same flow name, under its own option name.
  - Hand each endpoint its guard, and register every built guard with the chain's flush list as the other flows' guards are.
  - In both `Intercept`s, after the credentials are read:

```go
src, err := l.guard.Check(ctx, ex.Request.ClientIP())
if err != nil {
	return err // Basic: b.challenge(ex) first
}
```

  - On an authentication failure, call `l.guard.RecordFailure(ctx, src)` next to the attempt-store record. On a pre-authentication deny matching `policy.ErrAccountLocked`, call `l.guard.RecordFailure(ctx, src)` before refusing.
- [ ] **Step 4: Verify.** Step 2's command passes, `go test -race -count=1 ./httpsec/...` passes, and `go test -race ./...` passes in `ginsec/` and `fibersec/`.

### Task 4.2: The undisclosed lock response

**Files:** Modify `httpsec/login.go`, `httpsec/basic.go`, `httpsec/options.go` (`WithLockDisclosure`, the `discloseLocks bool` config field), the `build` warning (`chain.go` or `options.go`) and `httpsec/status.go:65` (the account-locked row). Test in `httpsec/chain_login_guard_test.go` and `httpsec/status_test.go`; follow the lock status in `httpsec/login_test.go:427`, `httpsec/basic_test.go:177`, `httpsec/recoverycomplete_test.go:209` and `test/httpsecconformance/scenarios.go:644`.

**Interfaces:**
- Consumes: `authenticate.DecoyVerifier` (3.1) and `policy.ErrAccountLocked`.
- Produces: `func WithLockDisclosure() Option`.

- [ ] **Step 0: Status row, red first.** In `httpsec/status_test.go`, change the case `{name: "account locked", err: policy.ErrAccountLocked, want: 423}` to `want: 429`, and add `{name: "concealed account lock", err: errors.Join(authenticate.ErrAuthenticationFailed, policy.ErrAccountLocked), want: 401}`. Run `go test -race -run 'TestStatusForError' -count=1 ./httpsec/`. Expected: FAIL, `expected: 429 actual: 423` on "account locked"; the concealed case already passes, which pins the row order. Then move the row in `httpsec/status.go` beside `policy.ErrTooManySessions`:

```go
	{policy.ErrAccountLocked, http.StatusTooManyRequests},
	{policy.ErrTooManySessions, http.StatusTooManyRequests},
```

  with a comment that an account lock is a client that sent too many failed attempts in a span (RFC 6585 §4), not a WebDAV resource lock (RFC 4918 §11.3). Update the four assertions listed under **Files** from `http.StatusLocked` to `http.StatusTooManyRequests`. Run `go test -race -run 'TestStatusForError|TestFormLogin|TestBasicAuth|TestRecoveryComplete' -count=1 ./httpsec/` and `go test -race -count=1 ./...` in `test/`: PASS.
- [ ] **Step 1: Failing table `TestChain_LockResponse`.** Use a policy engine with a lockout policy that denies `ada` (`WithFixedLockout(1, time.Hour)` and one failure), and an authenticator that is either an `authenticate.Manager` over a password provider with a `MockEncoder`, or a mock implementing only `Authenticator`. The cases:
  - "default response": a form login for `ada` returns an error where `errors.Is(err, authenticate.ErrAuthenticationFailed)` and `errors.Is(err, policy.ErrAccountLocked)` both hold, and `httpsec.StatusForError(err) == 401`.
  - "equal password work": with the password provider, `Match(password, referenceHash)` is called exactly once and `LoadByUsername` is never called.
  - "Basic default": 401 with `WWW-Authenticate`.
  - "disclosure chosen": `WithLockDisclosure()`. `StatusForError(err) == 429`, `errors.Is(err, authenticate.ErrAuthenticationFailed)` is false, and `Match` is not called.
  - "disclosed Basic lock has no challenge": Basic with `WithLockDisclosure()` returns 429, and the response has no `WWW-Authenticate` header.
  - "authenticator without a decoy": the mock-only authenticator, with a recording logger. `httpsec.New` writes exactly one WARN containing "timing". With `WithLockDisclosure()` it writes none.
  - "other denies unchanged": a pre-authentication deny without `ErrAccountLocked`, such as a store failure, still returns the policy reason, with no decoy and no join.
- [ ] **Step 2: Run.** `go test -race -run 'TestChain_LockResponse' -count=1 ./httpsec/`, after stubbing `WithLockDisclosure`. Expected: FAIL. "default response" gets 429 from the bare lock reason (Step 0 already moved the row), and no `Match` call happens.
- [ ] **Step 3: Implement.** A helper shared by both endpoints:

```go
// refuseLocked answers a pre-authentication lock. Unless the consumer chose to
// disclose locks, it spends the same password work a real check would and
// refuses as a failed authentication, so neither the status nor the timing
// says the account exists and is locked; the lock stays reachable through
// errors.Is for the consumer's own handler.
func refuseLocked(ctx context.Context, authn authenticate.Authenticator, disclose bool,
	creds identity.Credentials, reason error) error {
	if disclose {
		return reason
	}
	if v, ok := authn.(authenticate.DecoyVerifier); ok {
		_ = v.VerifyDecoy(ctx, creds)
	}
	return errors.Join(authenticate.ErrAuthenticationFailed, reason)
}
```

  - In each `Intercept`, when `refusePreAuthentication` returns an error matching `policy.ErrAccountLocked`, record the source failure (4.1), then return `refuseLocked(...)`.
  - Basic calls `b.challenge(ex)` only when the result is not disclosed.
  - The WARN at `build`: if form login or Basic is enabled, `!c.discloseLocks`, and the endpoint's authenticator is not a `DecoyVerifier`, write one `c.logger.Warn("httpsec: lock refusals may be told apart from wrong passwords by their timing, because the login authenticator offers no decoy verification", slog.String("option", "EnableFormLogin"))`. Write it once per endpoint.
- [ ] **Step 4: Verify.** Step 2's command passes, and `go test -race -count=1 ./httpsec/...` passes.

### Task 4.3: Godoc and package documentation

**Files:** Modify `httpsec/options.go` and `httpsec/doc.go`.

- [ ] **Step 1:** Write godoc for:
  - `WithLoginLimiter` and `WithBasicAuthLimiter`: the default (one shared `password-login` limiter from the chain's factory, 50 per 15 minutes) and the nil refusal;
  - `WithLockDisclosure`: the default (401, with decoy work), the disclosed status (429, and that a consumer needing 423 maps `policy.ErrAccountLocked` in their own handler), what the option gives up, and that a consumer handler can still see the lock through `errors.Is`;
  - `EnableFormLogin` and `EnableBasicAuth`: the new order of steps.

  In `doc.go`, list `password-login` among the limiter sites.
- [ ] **Step 2:** `go doc ./httpsec WithLockDisclosure`, `go doc ./httpsec WithLoginLimiter` and `go vet ./...` are all clean.

### Task 5.1: Whole-workspace gate (main session)

- [ ] For every module in `go.work`, run `go build ./... && go vet ./... && go test -race -count=1 ./...`, with Docker running for the store and Redis conformance runs.
- [ ] `gofmt -l .` is empty, and `golangci-lint run ./...` is clean.

### Task 5.2: Whole-branch review (main session dispatches an Opus reviewer)

- [ ] The reviewer reads the three spec deltas and design decisions 1–4, and checks the full diff against every requirement and scenario. It reports findings with failing tests, or labels them `UNREPRODUCED`, and edits nothing.
- [ ] The main session removes decision 4 if 1.1 passed, folds the findings into fresh dispatches, and ticks the tasks.
