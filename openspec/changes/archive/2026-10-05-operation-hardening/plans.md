# Operation Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session never writes code (`.claude/rules/subagent-delegation.md`): every task is carried out by a dispatched subagent, and the main session verifies, reviews and commits.

**Goal:** Delete expired security state through its owners' purge operations, manually or on a gocron schedule, without ever freeing rate-limit, issuance or lockout quota; and fold in two faults the reviews found (a one-time manager's default store on the wrong clock; a second `EnableMFA` accepted).

**Architecture:**
- **`expiry`** (core, standard library only): `Task{Name, Interval, Run}`, a sequential `Runner` that isolates failures and panics, honours cancellation and per-task timeouts, refuses overlapping runs of one task, and reports every `Result`.
- **Task constructors** live with each owner and wrap the owner's purge, so the cutoff never leaves the owner. Owners that build one-time managers internally (`passkey.Manager`, `httpsec.Chain` for MFA challenges and recovery) expose `ExpiryTasks()`.
- **`sweep`** (nested module): one gocron job per task, `sweep:<task>`, singleton reschedule mode, no default cadence, no boot-time sweep unless asked, optional distributed locker.
- **Follow-ups (group 7):** `onetime.NewManager` builds its default store on the manager's clock; `httpsec.EnableMFA` refuses a second registration.

**Tech Stack:** Go 1.27; gocron v2 ≥ v2.22.0 and clockwork v0.5.0 (`sweep` only); testify, typed `go.uber.org/mock`, `go.uber.org/goleak`, `testing/synctest`, testcontainers via the `test` module's helpers.

**Spec:** `openspec/changes/operation-hardening/` — `proposal.md`, `design.md` (decisions 1–8, Risks, References), `specs/expiry-sweeping/spec.md`, `specs/time-source/spec.md`, `specs/http-security-chain/spec.md`, and `tasks.md`. Groups 1–6 are done (their steps are ticked); group 7 is open. Task numbers below (1.1, 2.3, …) are `tasks.md`'s.

## Global Constraints

- **Test-first for every task** (`.claude/rules/golang-tdd.md`): failing test, run it, confirm it fails **for the intended reason** (stub new identifiers first; a compile error is not a red step), implement, refactor (consider `/simplify`).
- **Tables** follow the `table-test` skill (assert closures, `t.Context()`); **mocks** follow `use-mockgen` (typed, `//go:generate`, never in production builds); **PostgreSQL** comes from the `test` module's existing testcontainers helpers (`use-testcontainers`).
- **Library design** (`.claude/rules/library-design.md`): every option's godoc names its default; wiring mistakes fail at construction; a default with no override says why.
- **No retention window anywhere:** no `Task` field, runner option, sweeper option or constructor parameter accepts a window, cutoff or `time.Time`. A cutoff is always the owner's.
- **No constructor sets `Interval`.** Built-in task names are stable contract: `sessions`, `one-time-tokens:<purpose>`, `magiclink-tokens`, `login-attempts`, `ratelimit`, `oidc-flows`, `oidc-handoffs`, `passkey-registration-challenges`, `passkey-login-challenges`, `mfa-challenges:<method>`, `recovery-issued-codes`, `recovery-finish-tokens`, `recovery-cancel-tokens`.
- **Purge-unsupported** from any built-in task matches `errors.Is(err, expiry.ErrPurgeUnsupported)` and the owner's own sentinel; it is never `Removed: 0, Err: nil`.
- **Core module gains no dependency.** `expiry` imports the standard library and `pkg/clock` only. gocron and clockwork appear only in `sweep/go.mod`.
- **gocron:** pin `github.com/go-co-op/gocron/v2 v2.22.0` (or later); never use `WithLimitConcurrentJobs` (issue #959); always name jobs (`WithName`), since the name is the lock key.
- **Predecessor:** never read into or cite it in code, comments or artifacts (`.claude/rules/legacy-reference.md`); `.claude/.legacy` is not present in this worktree and must not be copied in.
- **Git:** subagents run no git commands; the main session commits after each verified, reviewed dispatch.
- **Every task's verification also includes** `gofmt -l` empty for touched packages and `go vet ./...`.

## Review Focus

1. **A task that returns a removed count with an error.** `Run` returns `(3, dbErr)`. The result must carry the error and must not be logged at DEBUG as success; `Removed` keeps 3. Test: Task 1.2, row "partial count with error is a failure".
2. **A `Run` that blocks past the run timeout and ignores its context.** The runner cannot interrupt it (stated limit); it must not start a goroutine to "time it out", and the next task still runs after it returns. Test: Task 1.2, row "purge ignoring its deadline still returns and the next task runs", plus the goleak check in 1.3.
3. **`RunTask` racing `RunOnce` on the same task.** The second caller gets `Skipped` with `ErrTaskBusy`, and the busy mark is released even when the first run panics. Test: Task 1.3, rows "busy under concurrent RunTask" and "busy mark released after a panic".
4. **A chain with nothing enabled that owns one-time state.** `(*httpsec.Chain).ExpiryTasks()` returns an empty, non-nil slice, and a consumer passing it with no other task gets `ErrNoTasks` from `NewRunner` rather than a silent no-op runner. Test: Task 3.3, row "nothing enabled gives no tasks".
5. **Shutdown while a run is in progress.** `Shutdown` returns after the running job finishes (bounded by gocron's stop timeout); no further run starts; goleak passes. Test: Task 4.3, row "shutdown during a run".

6. **A one-time manager given a clock behind the system clock and no store.** The default store would treat live tokens as expired, and a purge could delete a token the manager still honours. Test: Task 7.1, row "a clock behind the system clock keeps a live token".
7. **A chain given `EnableMFA` then `EnableMFA` again with no methods in common.** It must fail construction naming MFA, whatever prefixes or methods the second carries. Test: Task 7.2, row "MFA enabled twice".

---

## Execution: lanes, dispatches and models

| Dispatch | Tasks | Owns | Must not touch | Model | Why |
|---|---|---|---|---|---|
| E1 | 1.1–1.3 | `expiry/` (new) | everything else | Opus | Concurrency (busy marks, synctest), panic isolation, cancellation ordering; an interface every other lane compiles against |
| C1 | 2.1–2.4 | `session/expiry*.go`, `onetime/expiry*.go`, `magiclink/` (purge + task), `policy/expiry*.go` and their tests | `oidc/`, `passkey/`, `httpsec/`, `recovery/`, `ratelimit/`, `sweep/`, `test/` | Sonnet | Thin constructors over existing purges against a stated contract |
| C2 | 2.5 | `test/expirytasks_test.go` (new) | everything else | Sonnet | Conformance-style test against existing helpers |
| O1 | 3.1–3.4 | `oidc/` (purges + tasks), `passkey/` (ExpiryTasks), `recovery/` (ExpiryTasks), `httpsec/` (Chain.ExpiryTasks, docs) and their tests | `session/`, `onetime/`, `magiclink/`, `policy/`, `ratelimit/`, `sweep/` | Opus | Touches several packages and the chain's assembly; a task over the wrong manager would pass tests and still sweep nothing |
| S1 | 4.1–4.3 | `sweep/` (new module), `go.work`, `layout_test.go`, `.github/workflows/ci.yml` if it lists modules | everything in the core packages | Opus | Scheduler concurrency, lifecycle and goroutine-leak guarantees |
| R1 | 5.1 | `ratelimit/memory*.go` (Prune's return), `ratelimit/expiry*.go` and tests | everything else | Sonnet | Small change on a stated contract — **only after `limiter-key-bounds` is on main and this branch is rebased** |

| F1 | 7.1 | `onetime/manager.go`, `onetime/options.go`, `onetime/*_test.go`, `recovery/*_test.go`, and any constructor the gopls sweep finds outside `httpsec/` | `httpsec/`, `sweep/`, `expiry/` | Sonnet | A default fixed on a stated rule, with the scenario as its red test |
| F2 | 7.2 | `httpsec/options.go` (EnableMFA), `httpsec/expiry.go`, `httpsec/*_test.go` | `onetime/`, `recovery/`, `sweep/` | Sonnet | A construction refusal on the pattern `afa793d` set for form login and Basic |

As run, lane C1 was split into C1a (2.1, 2.2, 2.4) and C1b (2.3), because 2.3 and lane O1 consume `onetime.ExpiryTaskNamed`, which 2.2 creates; R1 ran in the first wave, since the branch had already been rebased onto `limiter-key-bounds`.

**Order:**
- F1 and F2 run in parallel, unless F1's sweep finds a constructor in `httpsec/`, which then moves to F2 or runs after it. 7.3 and 7.4 follow both.
- E1 first. Then C1, O1 and S1 run in parallel (disjoint files); C2 after C1.
- R1 after the rebase onto `limiter-key-bounds`.
- Each dispatch is verified by the main session, then reviewed by a fresh reviewer (Opus for E1, O1, S1; Sonnet for C1, C2, R1) before the lane's next dispatch.
- 6.1 and 6.2 are the main session's gate and the whole-branch review.

---

### Task 1.1: `expiry` types and construction

**Files:**
- Create: `expiry/doc.go`, `expiry/expiry.go` (Task, Result, Report, sentinels), `expiry/runner.go` (Runner, options, NewRunner)
- Test: `expiry/runner_construct_test.go`

**Interfaces:**
- Produces:

```go
package expiry

type Task struct {
	Name     string
	Interval time.Duration
	Run      func(ctx context.Context) (removed int, err error)
}

type Result struct {
	Task    string
	Removed int
	Skipped bool
	Err     error
	Elapsed time.Duration
}

type Report struct{ Results []Result }

var (
	ErrNoTasks           = errors.New("expiry: a runner needs at least one task")
	ErrInvalidTask       = errors.New("expiry: invalid task")
	ErrDuplicateTask     = errors.New("expiry: duplicate task name")
	ErrUnknownTask       = errors.New("expiry: unknown task")
	ErrTaskBusy          = errors.New("expiry: task already running")
	ErrTaskPanicked      = errors.New("expiry: task panicked")
	ErrPurgeUnsupported  = errors.New("expiry: the owner's store cannot purge")
	ErrInvalidOption     = errors.New("expiry: invalid option")
)

type Option func(*Runner) error
func WithRunTimeout(d time.Duration) Option      // default 0: no deadline beyond ctx
func WithObserver(fn func(Result)) Option         // default none
func WithLogger(l *slog.Logger) Option            // default slog.Default()
func WithClock(c clock.Clock) Option              // default clock.System()

func NewRunner(tasks []Task, opts ...Option) (*Runner, error)
func (r *Runner) Tasks() []Task
```

- [x] **Step 1: Failing table `TestNewRunner`.** Rows: "no tasks" → `ErrNoTasks`; "empty name" → `ErrInvalidTask`; "nil Run named audit" → `ErrInvalidTask` and the message contains `audit`; "negative interval" → `ErrInvalidTask`; "two tasks named sessions" → `ErrDuplicateTask` with `sessions` in the message; "negative run timeout" → `ErrInvalidOption`; "nil observer", "nil logger", "nil clock (typed nil included)" → `ErrInvalidOption`; "valid" → no error and `Tasks()` returns equal copies (mutating the returned slice does not change a later `Tasks()`).
- [x] **Step 2: Run** `go test -race -run 'TestNewRunner' -count=1 ./expiry/` against stubs that return `&Runner{}, nil`. Expected: FAIL on every refusal row ("An error is expected but got nil").
- [x] **Step 3: Implement** validation in `NewRunner` in the order above, each error wrapping its sentinel with `fmt.Errorf("%w: ...", ErrX)` naming the task. Use `internal/nilcheck.IsNil` for typed-nil options.
- [x] **Step 4: Verify** Step 2 passes; `go doc ./expiry` shows defaults on every option.

### Task 1.2: Running tasks

**Files:**
- Modify: `expiry/runner.go`
- Test: `expiry/runner_run_test.go`

**Interfaces:**
- Produces: `func (r *Runner) RunOnce(ctx context.Context) (Report, error)`, `func (r *Runner) RunTask(ctx context.Context, name string) (Result, error)`.

- [x] **Step 1: Failing table `TestRunner_RunOnce`** with fake tasks built by a helper `fakeTask(name string, removed int, err error)`; a panicking task `panicTask(name, value any)`; a cancelling task that cancels the run's context. Rows:
  - "failing task among healthy ones": `a`(1), `b`(dbErr), `c`(2) → three results, `a.Removed==1`, `c.Removed==2`, `errors.Is(b.Err, dbErr)`, returned error `errors.Is(err, dbErr)`.
  - "panicking task": `b` panics with `"nil store"` → `errors.Is(b.Err, ErrTaskPanicked)`, message contains `nil store`, `c` ran.
  - "cancelled between tasks": `a` cancels ctx → `b` and `c` `Skipped` with `errors.Is(Err, context.Canceled)`.
  - "partial count with error is a failure" (Review Focus 1): `(3, dbErr)` → `Removed==3`, `Err` set, ERROR logged.
  - "consumer run timeout": with `WithRunTimeout(30*time.Second)` each task's ctx has a deadline ≤ start+30s (task records `ctx.Deadline()`).
  - "purge ignoring its deadline still returns and the next task runs" (Review Focus 2): inside `synctest.Test`, a task that `time.Sleep`s past a 1s timeout without reading ctx; the next task runs after it.
  - `TestRunner_RunTask`: "unknown task" → `ErrUnknownTask`, no task ran; "named task" → only that task ran.
- [x] **Step 2: Run** `go test -race -run 'TestRunner' -count=1 ./expiry/`. Expected: FAIL (stubs return an empty report).
- [x] **Step 3: Implement.**

```go
func (r *Runner) runOne(ctx context.Context, t Task) (res Result) {
	res.Task = t.Name
	if err := ctx.Err(); err != nil {
		res.Skipped, res.Err = true, err
		return res
	}
	start := r.clock.Now()
	defer func() {
		if v := recover(); v != nil {
			res.Err = fmt.Errorf("%w: %s: %v", ErrTaskPanicked, t.Name, v)
		}
		res.Elapsed = r.clock.Now().Sub(start)
	}()
	runCtx, cancel := ctx, context.CancelFunc(func() {})
	if r.timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, r.timeout)
	}
	defer cancel()
	res.Removed, res.Err = t.Run(runCtx)
	return res
}
```

  `RunOnce` loops in declared order, calls `report(res)` (Task 1.3) after each, collects results, and returns `errors.Join` of non-nil `Err` of non-skipped and skipped-by-cancel results alike.
- [x] **Step 4: Verify** Step 2 passes.

### Task 1.3: Overlap, reporting, documentation

**Files:**
- Modify: `expiry/runner.go`, `expiry/doc.go`
- Test: `expiry/runner_busy_test.go`, `expiry/runner_report_test.go`, `expiry/main_test.go` (`goleak.VerifyTestMain`)

- [x] **Step 1: Failing tests.**
  - `TestRunner_Busy` (inside `synctest.Test`): a task blocking on a channel; `go r.RunTask(ctx,"sessions")`; `synctest.Wait()`; a second `RunTask` → `Skipped`, `errors.Is(Err, ErrTaskBusy)`; release; the first returns normally. Row "busy mark released after a panic" (Review Focus 3): a panicking run, then a second `RunTask` of the same task runs.
  - `TestRunner_Reporting`: observer receives `Result{Task:"sessions", Removed:3}`; a recording `slog` handler sees DEBUG with `removed=3` on success and an ERROR naming the task and error on failure; the observer is called after the log record (record order in a shared slice).
  - `TestMain` with `goleak.VerifyTestMain(m)`.
- [x] **Step 2: Run** `go test -race -count=1 ./expiry/...`. Expected: FAIL (no busy tracking; no observer calls).
- [x] **Step 3: Implement** a `sync.Mutex`-guarded `map[string]bool` of running tasks, set before `runOne` and cleared in a `defer` (so panics release it); `report(res)` logs then calls the observer. Package godoc: what a task is, the no-window rule, manual vs scheduled use, the two stated limits, a non-blocking observer example:

```go
results := make(chan expiry.Result, 64)
runner, _ := expiry.NewRunner(tasks, expiry.WithObserver(func(r expiry.Result) {
	select {
	case results <- r:
	default: // never block a sweep on a slow consumer
	}
}))
```
- [x] **Step 4: Verify** `go test -race -count=1 ./expiry/...`, `go doc ./expiry`.

### Task 2.1: Sessions task

**Files:** Create `session/expiry.go`; test `session/expiry_test.go`.

**Interfaces:** Consumes `expiry.Task`. Produces `func ExpiryTask(s Store) expiry.Task` (name `sessions`).

- [x] **Step 1: Failing table `TestExpiryTask`** over `session.NewMemoryStore` with a fake clock: two expired, one live → `Removed==2`, the live one still loads; a mock `Store` whose `DeleteExpired` errors → the error propagates; `Name=="sessions"`, `Interval==0`.
- [x] **Step 2: Run** `go test -race -run 'TestExpiryTask' -count=1 ./session/` against a stub returning a zero Task. Expected: FAIL.
- [x] **Step 3: Implement**

```go
// ExpiryTask deletes expired sessions through s. It sets no interval, and
// accepts no cutoff: expiry is the store's own rule.
func ExpiryTask(s Store) expiry.Task {
	return expiry.Task{Name: "sessions", Run: s.DeleteExpired}
}
```
- [x] **Step 4: Verify** Step 2 passes.

### Task 2.2: Generic one-time task

**Files:** Create `onetime/expiry.go`; test `onetime/expiry_test.go`.

**Interfaces:** Produces `func ExpiryTask(m *Manager) expiry.Task` (name `one-time-tokens:` + `m.Purpose()`).

- [x] **Step 1: Failing table `TestExpiryTask`:**
  - "issued count unchanged": purpose `email-change`, TTL 15m, window 1h; a token issued 30m ago; run → `IssuedCount` for the subject unchanged and the token not deleted.
  - "separate purposes stay separate": managers for `magic-link` and `email-change` over one memory store, both with tokens past expiry and window; run only the `email-change` task → only those removed.
  - "store cannot purge": a store without `Reaper` (wrap memory store in a struct exposing only `Store`) → `errors.Is(err, expiry.ErrPurgeUnsupported)` and `errors.Is(err, onetime.ErrReapUnsupported)`.
  - Name and zero interval.
  - Prove the quota row: temporarily make the task purge with the TTL as cutoff (call the store's `DeleteExpiredBefore(ctx, purpose, now-TTL)` directly), see "issued count unchanged" fail, restore.
- [x] **Step 2: Run** `go test -race -run 'TestExpiryTask' -count=1 ./onetime/`. Expected: FAIL.
- [x] **Step 3: Implement**

```go
func ExpiryTask(m *Manager) expiry.Task {
	return expiry.Task{
		Name: "one-time-tokens:" + m.Purpose(),
		Run: func(ctx context.Context) (int, error) {
			n, err := m.PurgeExpired(ctx)
			if errors.Is(err, ErrReapUnsupported) {
				return n, errors.Join(err, expiry.ErrPurgeUnsupported)
			}
			return n, err
		},
	}
}
```

  Export a small helper for other packages to reuse the join: `func ExpiryTaskNamed(name string, m *Manager) expiry.Task` (same body, chosen name) — used by magiclink, passkey, recovery and httpsec.
- [x] **Step 4: Verify** Step 2 passes.

### Task 2.3: Magic-link purge and task

**Files:** Modify `magiclink/manager.go` (add `PurgeExpired`); create `magiclink/expiry.go`; tests `magiclink/expiry_test.go`.

**Interfaces:** Consumes `onetime.ExpiryTaskNamed`. Produces `func (m *Manager) PurgeExpired(ctx context.Context) (int, error)`, `func ExpiryTask(m *Manager) expiry.Task` (name `magiclink-tokens`).

- [x] **Step 1: Failing table:** with token lifetime 15m and issuance window 1h, a token for `carol` issued 30m ago is not deleted and her issued count is unchanged; a token issued 2h ago (expired, past window) is deleted; name `magiclink-tokens`, zero interval.
- [x] **Step 2: Run** `go test -race -run 'TestExpiryTask|TestManager_PurgeExpired' -count=1 ./magiclink/`. Expected: FAIL.
- [x] **Step 3: Implement** `PurgeExpired` delegating to the wrapped `*onetime.Manager` field; `ExpiryTask(m)` builds the task with the magic-link name and the purge-unsupported join (reuse the join logic, not a copy of it: `onetime.ExpiryTaskNamed` takes a manager, so give `magiclink` an unexported accessor to its tokens manager and call `onetime.ExpiryTaskNamed("magiclink-tokens", m.tokens)`).
- [x] **Step 4: Verify** Step 2 passes.

### Task 2.4: Login-attempt task

**Files:** Create `policy/expiry.go`; test `policy/expiry_test.go`.

**Interfaces:** Produces `func LockoutExpiryTask(p *AccountLockoutPolicy) expiry.Task` (name `login-attempts`).

- [x] **Step 1: Failing table** with a purge-capable attempt store (`sqlstore` is not available here; use a small in-test store implementing `AttemptStore` and `AttemptReaper` over a slice, or an existing test helper in `policy`): window 15m (`WithLockoutWindow`), failures for `ada` at −5m and −20m → only the −20m one removed and `FailureCount(since=now−15m)` unchanged; window 1h and a −30m failure → kept; the default `MemoryAttemptStore` → `errors.Is(err, expiry.ErrPurgeUnsupported)` and `errors.Is(err, policy.ErrReapUnsupported)`, never `(0, nil)`.
- [x] **Step 2: Run** `go test -race -run 'TestLockoutExpiryTask' -count=1 ./policy/`. Expected: FAIL.
- [x] **Step 3: Implement** wrapping `p.PurgeExpired`, joining `expiry.ErrPurgeUnsupported` when `errors.Is(err, ErrReapUnsupported)`.
- [x] **Step 4: Verify** Step 2 passes.

### Task 2.5: Durable adapters

**Files:** Create `test/expirytasks_test.go`.

- [x] **Step 1: Write `TestExpiryTasks`**, a table over the three adapters (`sqlstore`, `pgx`, `gorm`) using the `test` module's PostgreSQL helper: seed an expired and a live session, a one-time token past expiry and window plus one inside its window, login failures inside and outside a 15m window, and one API key with a past `expires_at`, an OIDC link, an MFA enrolment and a signing key. Run `session.ExpiryTask`, `onetime.ExpiryTask`, `policy.LockoutExpiryTask` through an `expiry.Runner`. Assert expired rows gone, live rows present, and the API key, OIDC link, MFA enrolment and signing key untouched (count rows directly).
- [x] **Step 2: Run** `cd test && go test -race -run 'TestExpiryTasks' -count=1 ./...` against a deliberately broken variant (session task replaced by a task that deletes every session via the adapter's DB handle) to see the "live session present" assertion fail; restore.
- [x] **Step 3: Verify** the run passes with Docker up.

### Task 3.1: OIDC purges and tasks

**Files:** Modify `oidc/manager.go` (`PurgeExpiredFlows`), `oidc/handoff.go` (or wherever `HandoffManager` lives: `PurgeExpired`); create `oidc/expiry.go`; test `oidc/expiry_test.go`.

**Interfaces:** Produces `func (m *Manager) PurgeExpiredFlows(ctx context.Context) (int, error)`, `func (h *HandoffManager) PurgeExpired(ctx context.Context) (int, error)`, `func FlowExpiryTask(m *Manager) expiry.Task` (`oidc-flows`), `func HandoffExpiryTask(h *HandoffManager) expiry.Task` (`oidc-handoffs`).

- [x] **Step 1: Failing table** with memory flow and handoff stores and a fake `clock.Clock`: an expired and a live flow → one removed; an expired and a live handoff → one removed; a store returning an error → propagated; names and zero intervals.
- [x] **Step 2: Run** `go test -race -run 'TestExpiryTask|PurgeExpired' -count=1 ./oidc/`. Expected: FAIL.
- [x] **Step 3: Implement** `return m.flows.DeleteExpired(ctx, m.clock.Now())` and the handoff equivalent; godoc says the cutoff is the owner's own now and that nothing counts expired flows or handoffs.
- [x] **Step 4: Verify** Step 2 passes.

### Task 3.2: Passkey ceremony tasks

**Files:** Create `passkey/expiry.go`; test `passkey/expiry_test.go`.

**Interfaces:** Consumes `onetime.ExpiryTaskNamed`. Produces `func (m *Manager) ExpiryTasks() []expiry.Task` → `passkey-registration-challenges`, `passkey-login-challenges`.

- [x] **Step 1: Failing test `TestManager_ExpiryTasks`:** build a manager over a memory challenge store (`Deps.Challenges`) with a fake clock; `BeginLogin` twice (unauthenticated, as a stranger would); advance past TTL and issuance window; run the login task → both removed; a fresh `BeginLogin` inside its window survives a run; the two names in order; zero intervals; a challenge store without `Reaper` → shared sentinel.
- [x] **Step 2: Run** `go test -race -run 'TestManager_ExpiryTasks' -count=1 ./passkey/`. Expected: FAIL.
- [x] **Step 3: Implement** over the manager's `registration` and `login` one-time managers (fields of `passkey.Manager`) with `onetime.ExpiryTaskNamed`.
- [x] **Step 4: Verify** Step 2 passes.

### Task 3.3: Chain-owned tasks (MFA challenges, recovery)

**Files:** Create `recovery/expiry.go` (`(*Recoverer).ExpiryTasks()`), `httpsec/expiry.go` (`(*Chain).ExpiryTasks()`); tests `recovery/expiry_test.go`, `httpsec/expiry_test.go`.

**Interfaces:** Produces `func (r *Recoverer) ExpiryTasks() []expiry.Task` (`recovery-issued-codes` when issued codes are enabled, `recovery-finish-tokens` and `recovery-cancel-tokens` when holds are enabled) and `func (c *Chain) ExpiryTasks() []expiry.Task` (each enabled MFA method's `mfa-challenges:<method>`, then the chain-built recoverer's tasks).

- [x] **Step 1: Failing tests.**
  - `TestRecoverer_ExpiryTasks`: issued codes only → one task; holds enabled → finish and cancel tasks; an expired issued code removed, a live one kept.
  - `TestChain_ExpiryTasks`: MFA with the passkey challenge method and no recovery → exactly `[mfa-challenges:passkey]`; TOTP alone keeps no pending challenge → no MFA task; MFA plus recovery with holds → MFA task then the three recovery tasks; "nothing enabled gives no tasks" (Review Focus 4) → `len==0`, non-nil, and `expiry.NewRunner(tasks)` fails with `ErrNoTasks`.
- [x] **Step 2: Run** `go test -race -run 'TestChain_ExpiryTasks|TestRecoverer_ExpiryTasks' -count=1 ./httpsec/ ./recovery/`. Expected: FAIL.
- [x] **Step 3: Implement** with `onetime.ExpiryTaskNamed` over `r.issued`, `r.finishTokens`, `r.cancelTokens` (nil-checked) and the chain's MFA interceptor `challenges` map, iterated in the methods' configured order (not map order).
- [x] **Step 4: Verify** Step 2 passes.

### Task 3.4: Documentation

- [x] **Step 1:** godoc for every new method/constructor: its task name(s), that it sets no interval, and what it never deletes; `httpsec` and `passkey` package docs point to `ExpiryTasks`. Example in `httpsec/example_expiry_test.go` wiring `chain.ExpiryTasks()` and `session.ExpiryTask` into `expiry.NewRunner` (compiles; `// Output:` omitted).
- [x] **Step 2: Verify** `go doc ./httpsec Chain.ExpiryTasks`, `go doc ./passkey Manager.ExpiryTasks`, `go vet ./...`, `go test -run Example -count=1 ./httpsec/`.

### Task 4.1: The `sweep` module

**Files:** Create `sweep/go.mod` (module `github.com/kartaladev/scrty/sweep`, `go 1.27`, require core, gocron v2.22.0, clockwork v0.5.0, goleak for tests), `sweep/doc.go`; modify `go.work` (`use ./sweep`), `layout_test.go` (a `TestCoreDependencies` row pinning gocron, already on `layout_guard_test.go`'s integration list as `github.com/go-co-op/gocron`; clockwork cannot be listed, because the core requires it for its own tests, and the existing production ban keeps it out of core builds), `.github/workflows/ci.yml` only if it enumerates modules (the Makefile derives them from `go list -m`).

- [x] **Step 1: Failing guard row:** add a temporary import of gocron in a core file and see `go test -run 'TestModuleLayout|TestCoreDependencies|TestConsumerModuleGraph' -count=1 .` fail naming it; remove the import.
- [x] **Step 2: Verify** `go test -run 'TestModuleLayout|TestCoreDependencies|TestConsumerModuleGraph' -count=1 .`, `cd sweep && go build ./... && go mod tidy && git diff --exit-code go.mod go.sum` (the main session runs the git check).

### Task 4.2: Scheduling

**Files:** Create `sweep/sweeper.go`; tests `sweep/sweeper_test.go`, `sweep/main_test.go` (goleak).

**Interfaces:**

```go
func New(r *expiry.Runner, opts ...Option) (*Sweeper, error)
func WithDefaultInterval(d time.Duration) Option
func WithRunImmediately() Option
func WithDistributedLocker(l gocron.Locker) Option
func WithClock(c clockwork.Clock) Option // default clockwork.NewRealClock()
var ErrNoInterval, ErrAlreadyStarted, ErrAlreadyShutdown, ErrInvalidOption error
```

- [x] **Step 1: Failing tests** with `clockwork.NewFakeClock()`, tasks counting runs on channels, and the probe pattern (`Start`, `fc.BlockUntilContext(ctx, n)`, `fc.Advance(d)`, then wait on the channel):
  - "consumer default interval": default 10m, two tasks without interval; advance 10m → each ran once.
  - "task interval": `login-attempts` 1m, default 10m; advance 1m three times → it ran 3 times, others 0.
  - "no interval anywhere": no default, a task without interval → `ErrNoInterval` naming it.
  - "no boot-time sweep by default": start, then `BlockUntilContext` → no run before the first advance.
  - "run immediately": `WithRunImmediately()` → each task runs once at start.
  - "slow run skips ticks": a task blocking until released; advance two intervals; release; wait → exactly one run, and after one more interval exactly two (no back-to-back queued runs).
  - "distributed lock consulted": a fake `gocron.Locker` recording keys → `sweep:sessions` requested before the run.
  - "nil options": nil locker, nil clock, non-positive default interval → `ErrInvalidOption`.
- [x] **Step 2: Run** `cd sweep && go test -race -count=1 ./...`. Expected: FAIL.
- [x] **Step 3: Implement.** `New` validates, builds `gocron.NewScheduler(gocron.WithClock(c), [gocron.WithDistributedLocker(l)], gocron.WithStopTimeout(...))`, and records per-task intervals; `Start` registers, per task:

```go
_, err := s.sched.NewJob(
	gocron.DurationJob(interval),
	gocron.NewTask(func(ctx context.Context) { _, _ = s.runner.RunTask(ctx, name) }),
	gocron.WithName("sweep:"+name),
	gocron.WithSingletonMode(gocron.LimitModeReschedule),
	gocron.WithContext(runCtx),
	startAt..., // gocron.WithStartAt(gocron.WithStartImmediately()) when asked
)
```

  The runner already logs and observes results, so job errors need no gocron listener; add `AfterLockError` logging so a failing locker is visible.
- [x] **Step 4: Verify** Step 2 passes three times in a row (`-count=3`).

### Task 4.3: Lifecycle

- [x] **Step 1: Failing tests:** built-never-started then `Shutdown` → no goroutine left (`goleak.VerifyNone` in that test); second `Start` → `ErrAlreadyStarted`; `Start` after `Shutdown` → `ErrAlreadyShutdown`; `Shutdown` twice → nil; "shutdown stops runs": started, shut down, advance several intervals → no run; "shutdown during a run" (Review Focus 5): a run blocked, `Shutdown` in a goroutine, release, `Shutdown` returns, no further run, goleak clean; "partial start": a job registration failure (e.g. a locker or interval forced invalid through an unexported test seam) → sweeper shut down and `Start` again → `ErrAlreadyShutdown`.
- [x] **Step 2: Run** `cd sweep && go test -race -count=1 ./...`. Expected: FAIL.
- [x] **Step 3: Implement** a state field (`new`, `started`, `shutdown`) under a mutex; `Shutdown` calls gocron's `Shutdown` once; a failed `Start` calls it before returning. Godoc: every replica sweeps without a lock; the lock tests prove consultation, not serialisation; run the first sweep manually in a maintenance window.
- [x] **Step 4: Verify** `cd sweep && go test -race -count=3 ./...`, `go doc ./sweep`.

### Task 5.1: The in-memory rate-limiter task (after the rebase)

**Files:** Modify `ratelimit/memory.go` (or the shard file `limiter-key-bounds` introduced) so `Prune() int` returns the keys its shards removed; create `ratelimit/expiry.go`; tests `ratelimit/expiry_test.go`.

- [x] **Step 1: Failing tests:** a quiet limiter with 3 expired keys → `Prune()==3` and the task reports `Removed==3`; a key with its newest stamp inside the window survives and is still counted (prove by temporarily removing every key in prune and seeing the row fail); two limiters as tasks renamed `ratelimit:apikey` and `ratelimit:magic-link` run in one runner and report under those names; name `ratelimit`, zero interval.
- [x] **Step 2: Run** `go test -race -run 'TestExpiryTask|TestMemoryLimiter_Prune' -count=1 ./ratelimit/`. Expected: FAIL.
- [x] **Step 3: Implement** `Prune` summing per-shard removals; `ExpiryTask(l)` returns `expiry.Task{Name: "ratelimit", Run: func(context.Context) (int, error) { return l.Prune(), nil }}`. Update every `Prune()` caller found with gopls references.
- [x] **Step 4: Verify** `go test -race -count=1 ./ratelimit/... ./httpsec/...`.

### Task 6.1: Whole-workspace gate (main session)

- [x] `make check`-equivalent across every module in `go.work` with Docker up: build, vet, `go test -race -count=1 ./...`, `gofmt -l` empty, `golangci-lint run ./...` clean, and `govulncheck ./...` in `sweep`.

### Task 6.2: Whole-branch review (main session dispatches an Opus reviewer)

- [x] Review against every requirement and scenario of `specs/expiry-sweeping/spec.md` and design decisions 1–6, producing a requirement → test map; no open finding.

### Task 7.1: A one-time manager's default store follows its clock

**Files:**
- Modify: `onetime/manager.go` (`NewManager`, ~line 73), `onetime/options.go` (`WithStore` ~54, `WithClock` ~83: godoc and a `storeSet` mark)
- Test: `onetime/manager_clock_test.go` (new), `recovery/expiry_test.go` (or the recovery test file that builds a recoverer with a fake clock)

**Interfaces:**
- Consumes: `onetime.NewMemoryStore(opts ...MemoryStoreOption)`, `onetime.WithMemoryStoreClock(clock.Clock)` (`onetime/memory.go:43-52`).
- Produces: no new exported API. Behaviour: when no `WithStore` was given, `m.store` is `NewMemoryStore(WithMemoryStoreClock(m.clock))`, built after the options run and after the clock is validated.

- [ ] **Step 1: Failing table `TestNewManager_DefaultStoreFollowsClock`** (assert closures, `t.Context()`), with a `clockwork.NewFakeClockAt` start:
  - "a clock ahead of the system clock purges what it expired": start = system now + 365 days; `NewManager("email-change", WithClock(fc), WithTTL(15*time.Minute), WithIssuanceWindow(time.Hour))`, no store; `token, _, err := m.Issue(ctx, "carol")`; `fc.Advance(2*time.Hour)`; `n, err := m.PurgeExpired(ctx)` → `NoError`, `n == 1`.
  - "a clock behind the system clock keeps a live token" (Review Focus 6): start = system now − 365 days; TTL 15m, window 10m; issue; `fc.Advance(12*time.Minute)` (past the window, so the window gate no longer protects it, but inside the TTL, so it is live); `PurgeExpired` → `n == 0`, and the token still checks as valid (`m.Check(ctx, token, "")` → no error).
  - "an explicit store keeps its own clock": `WithStore(NewMemoryStore())` (system clock) with the ahead clock; same steps → `n == 0`, which pins that a consumer's store is never replaced.
- [ ] **Step 2: Run** `go test -race -run 'TestNewManager_DefaultStoreFollowsClock' -count=1 ./onetime/`. Expected: FAIL on the first two rows ("expected: 1 actual: 0"; the behind row fails because the token is purged or reads as expired).
- [ ] **Step 3: Implement.** In `options.go`:

```go
func WithStore(s Store) Option { return func(m *Manager) { m.store, m.storeSet = s, true } }
```

  In `NewManager`, start with `store: nil` and after the clock's nil check:

```go
if !m.storeSet {
	m.store = NewMemoryStore(WithMemoryStoreClock(m.clock))
}
```

  A `WithStore(nil)` keeps being refused by the existing nil check. Godoc: `WithClock` says the default store reads the same clock; `WithStore` says a consumer's store keeps its own clock.
- [ ] **Step 4: Run** Step 2's command → PASS; then `go test -race -count=1 ./onetime/...`.
- [ ] **Step 5: Recovery row.** In the recovery tests, add a row building a recoverer with a fake clock ahead of the system clock and NO `WithIssuedCodeStore`; issue a code through `Start`, advance past expiry and window, run `recovery-issued-codes` from `(*Recoverer).ExpiryTasks()` → `Removed == 1`. It passes now; prove it bites by temporarily reverting Step 3 and seeing it fail, then restore. Remove any test workaround that injected a clocked store only because of this fault (the O1 dispatch added such stores in `recovery` and `httpsec` expiry tests), keeping the ones that test the injected-store path itself.
- [ ] **Step 6: Sweep.** With gopls (`gopls references` on `clock.System` and on each `NewMemory*`/default-store constructor), list every constructor that builds a time-keeping default dependency without passing its own clock. For each: fix test-first in the same way, or report why it is unaffected (its default reads no time, or it already passes the clock). Report the list. A hit inside `httpsec/` is reported, not fixed, because lane F2 owns that package.
- [ ] **Step 7: Verify** `go test -race -count=1 ./onetime/... ./recovery/... ./passkey/... ./httpsec/...`, `go vet ./...`, `gofmt -l onetime recovery`, `golangci-lint run ./onetime/... ./recovery/...`.

### Task 7.2: A second `EnableMFA` is refused

**Files:**
- Modify: `httpsec/options.go` (`EnableMFA`, ~line 1480), `httpsec/expiry.go` (`Chain.ExpiryTasks` godoc)
- Test: a new `httpsec/mfa_twice_test.go` beside `httpsec/login_twice_test.go` (`TestChain_LoginEnabledTwice`), and `httpsec/expiry_test.go`

**Interfaces:**
- Consumes: `eachInterceptor(c, func(*mfaInterceptor) error)` and `newConfigError(format, args...)`, as `EnableFormLogin` uses them (commit `afa793d`); `ChallengeError.Methods []MFAMethod` (`httpsec/errors.go:90`).
- Produces: no new API. Behaviour: `httpsec.New(..., EnableMFA(a...), EnableMFA(b...))` returns a configuration error naming `EnableMFA`.

- [ ] **Step 1: Prove the fault first.** Test `TestChain_TwoEnableMFAOfferOnlyTheLast` (temporary name; it becomes the refusal row): a chain with form login, a policy challenging MFA, `EnableMFA([a])` on one prefix and `EnableMFA([b])` on another, both usable by the user. Log in; `errors.As` the refusal into `*ChallengeError`; assert `Methods` holds both `a` and `b`. Run `go test -race -run 'TestChain_TwoEnableMFAOfferOnlyTheLast' -count=1 ./httpsec/`. Expected: FAIL, with one configuration's method missing (as run: the second configuration's was dropped). Record the output. If it passes instead, record that the claim in design decision 8(b) was wrong (the main session corrects the design), and continue: the refusal stands on the wiring rule alone.
- [ ] **Step 2: Failing refusal row "MFA enabled twice"** (Review Focus 7) in the chain's construction-refusal table: `EnableMFA` given twice, with different prefixes and disjoint methods → `errors.Is(err, httpsec.ErrConfig)`, and the message contains `EnableMFA`. Replace Step 1's test with this row. Run it → FAIL ("An error is expected but got nil").
- [ ] **Step 3: Implement**, at the top of `EnableMFA`'s returned func, before `c.enable`:

```go
if err := eachInterceptor(c, func(*mfaInterceptor) error {
	return newConfigError("%s was given twice; one chain offers one set of second-factor methods, so give every method to one EnableMFA", option)
}); err != nil {
	return err
}
```

  Godoc on `EnableMFA`: a chain has one MFA configuration, and a second `EnableMFA` is refused whatever prefix or methods it carries.
- [ ] **Step 4: Run** the row → PASS.
- [ ] **Step 5: Expiry tasks.** In `TestChain_ExpiryTasks`, the rows "every EnableMFA contributes its challenge tasks", "a challenge begun through the first EnableMFA is swept by its task" and "two EnableMFA sharing a method name give tasks the runner refuses" now fail at construction. Replace them with: "several challenge methods of one EnableMFA contribute their tasks in order", and a single end-to-end row beginning a challenge through that `EnableMFA`. In `Chain.ExpiryTasks`'s godoc, drop the sentence about two configurations sharing a method name, and say "for each challenge method given to EnableMFA, in the order given". The walk over every registered MFA interceptor stays.
- [ ] **Step 6: Verify** `go test -race -count=1 ./httpsec/...`, `go test -run Example -count=1 ./httpsec/`, `go vet ./httpsec/...`, `gofmt -l httpsec`, `golangci-lint run ./httpsec/...`.

### Task 7.3: Whole-workspace gate (main session)

- [ ] For every module in `go list -m` (root, `fibersec`, `ginsec`, `gorm`, `passkey/webauthn`, `pgx`, `redis`, `sweep`, `test`), with Docker up: `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...`, `golangci-lint run ./...`; `gofmt -l` empty over the tracked Go files. A failure in a package the follow-ups did not touch is rerun in isolation on this branch and on `main` before it is classified.
- [ ] `openspec validate operation-hardening --strict`.

### Task 7.4: Whole-branch review (main session dispatches an Opus reviewer)

- [ ] Review `git diff main...HEAD` against every requirement and scenario of the three delta specs (`expiry-sweeping`, `time-source`, `http-security-chain`) and design decisions 1–8, producing a requirement → test map, with findings labelled REPRODUCED or UNREPRODUCED. No open finding.
