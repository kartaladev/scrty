# Tasks

Every task is test-first: write the failing test, run it and see it fail for the intended reason (a
compile error is not a red step), make it pass, then refactor (consider `/simplify`). Tables follow
the project's `table-test` skill; test doubles come from `use-mockgen`; durable adapters are
exercised through the existing store conformance suites and testcontainers helpers. Each task says
how it is verified. Names in parentheses are the spec requirements and design decisions covered.

Ownership and order:
- Group 1 (`expiry`) comes first: every other group compiles against it.
- Groups 2, 3 and 4 then run in parallel: group 2 owns `session`, `onetime`, `magiclink`, `policy`;
  group 3 owns `oidc`, `passkey`, `httpsec`; group 4 owns the new `sweep` module, `go.work` and
  the layout guard.
- Group 5 (`ratelimit`) waits until `limiter-key-bounds` has landed on main and this branch is
  rebased onto it.

## 1. The expiry runner (decisions 1–5; "One task's failure does not affect other tasks", "Runs honour cancellation and deadlines", "Sweeps can run manually", "Each run is reported", "Wiring mistakes fail at construction")

- [x] 1.1 Package `expiry`, standard library only: `Task`, `Result`, `Report`, the sentinels (`ErrNoTasks`, `ErrInvalidTask`, `ErrDuplicateTask`, `ErrUnknownTask`, `ErrTaskBusy`, `ErrTaskPanicked`, `ErrPurgeUnsupported`, `ErrInvalidOption`) and `NewRunner` with `WithRunTimeout`, `WithObserver`, `WithLogger`, `WithClock(clock.Clock)`. Construction refuses no tasks, an empty name, a nil `Run`, duplicate names (naming the task), a negative interval or run timeout, and nil option values. Covers "Empty runner", "Duplicate names", "Missing purge operation". Verify with `go test -race -run 'TestNewRunner' -count=1 ./expiry/`
- [x] 1.2 `RunOnce` and `RunTask`: sequential on the caller's goroutine, in declared order; error and panic isolation (panic value kept in `ErrTaskPanicked`); context checked before each task with unreached tasks `Skipped` carrying `ctx.Err()`; per-task deadline under `WithRunTimeout`; `RunOnce` returns the report and `errors.Join` of task errors; unknown name is `ErrUnknownTask` with nothing run; `Tasks()` returns copies. Covers "Failing task among healthy ones", "Panicking task", "Cancelled between tasks", "Consumer run timeout", "Consumer's own scheduler", "Unknown task". Verify with `go test -race -run 'TestRunner' -count=1 ./expiry/`
- [x] 1.3 Overlap and reporting: a task already running in this runner is skipped with `ErrTaskBusy`, proved with `testing/synctest`; results carry name, removed, skipped, error and elapsed measured on the runner's clock; DEBUG on success, ERROR on failure, then the observer synchronously, for every run. A `goleak` check after runs with failing, panicking and cancelled tasks. Package godoc covers the no-retention-window rule, the stated limits (a purge ignoring its context; first large delete) and a non-blocking observer example. Covers "Overlapping runs of one task", "Observer sees counts", "Default logging", "No goroutine left behind". Verify with `go test -race -count=1 ./expiry/...` and `go doc ./expiry`

## 2. Task constructors over the core owners (decisions 2, 5; "Expired security state is deleted through its owners", "A sweep never frees rate-limit or lockout quota")

- [x] 2.1 `session.ExpiryTask(s session.Store)` named `sessions`, interval unset, wrapping `DeleteExpired`. Tests: two expired and one live session, only the expired deleted; the store's error propagates; stable name; no interval. Covers "Expired and live sessions". Verify with `go test -race -run 'TestExpiryTask' -count=1 ./session/`
- [x] 2.2 `onetime.ExpiryTask(m *onetime.Manager)` named `one-time-tokens:<purpose>`, wrapping `PurgeExpired`; a store without `Reaper` fails with an error matching both `onetime.ErrReapUnsupported` and `expiry.ErrPurgeUnsupported`. Tests: the issued count for a subject is unchanged by a run (seen to fail against a variant using the TTL as cutoff); separate purposes stay separate. Covers "Separate purposes stay separate", "Store without purge support" (one-time). Verify with `go test -race -run 'TestExpiryTask' -count=1 ./onetime/`
- [x] 2.3 `(*magiclink.Manager).PurgeExpired(ctx)` delegating to its one-time manager, and `magiclink.ExpiryTask(m)` named `magiclink-tokens`. Tests: the 15-minute-lifetime, 1-hour-window token issued 30 minutes ago is kept and the issued count for `carol` is unchanged; an expired token past its window is deleted. Covers "Expired token still counted for issuance". Verify with `go test -race -run 'TestExpiryTask|TestManager_PurgeExpired' -count=1 ./magiclink/`
- [x] 2.4 `policy.LockoutExpiryTask(p *policy.AccountLockoutPolicy)` named `login-attempts`, wrapping `PurgeExpired`; purge-unsupported matches `expiry.ErrPurgeUnsupported` and `policy.ErrReapUnsupported`, never zero removed. Tests use explicit windows (15 minutes; consumer 1 hour) so they hold whatever the default window is. Covers "Recent login failures survive", "Consumer-configured window is respected", "Store without purge support". Verify with `go test -race -run 'TestLockoutExpiryTask' -count=1 ./policy/`
- [x] 2.5 Durable adapters: a test in the `test` module running the session, one-time and login-attempt tasks against `sqlstore`, `pgx` and `gorm` over PostgreSQL (existing testcontainers helpers), proving live rows survive and expired rows go. Covers "Durable records untouched" for the tables those adapters hold (API keys, OIDC links, MFA enrolments, signing keys untouched). Verify with `cd test && go test -race -run 'TestExpiryTasks' -count=1 ./...`

## 3. Task constructors over OIDC and the components the library builds (decision 2; "Expired security state is deleted through its owners")

- [x] 3.1 `(*oidc.Manager).PurgeExpiredFlows(ctx)` and `(*oidc.HandoffManager).PurgeExpired(ctx)`, each deleting rows expired before its own clock's now, plus `oidc.FlowExpiryTask(m)` (`oidc-flows`) and `oidc.HandoffExpiryTask(h)` (`oidc-handoffs`). Tests with the memory stores and a fake clock: expired rows go, live rows stay, store errors propagate. Verify with `go test -race -run 'TestExpiryTask|PurgeExpired' -count=1 ./oidc/`
- [x] 3.2 `(*passkey.Manager).ExpiryTasks() []expiry.Task`: `passkey-registration-challenges` and `passkey-login-challenges`, over the one-time managers it builds; purge-unsupported matches the shared sentinel. Covers "Unauthenticated ceremony state is swept". Verify with `go test -race -run 'TestManager_ExpiryTasks' -count=1 ./passkey/`
- [x] 3.3 `(*httpsec.Chain).ExpiryTasks() []expiry.Task`: `mfa-challenges:<method>` for each enabled MFA method's challenge manager, and `recovery-issued-codes`, `recovery-finish-tokens`, `recovery-cancel-tokens` from the recoverer the chain builds, each only when enabled (recovery exposes the tasks through `(*recovery.Recoverer).ExpiryTasks()`). Covers "Only enabled components contribute tasks". Verify with `go test -race -run 'TestChain_ExpiryTasks|TestRecoverer_ExpiryTasks' -count=1 ./httpsec/ ./recovery/`
- [x] 3.4 Godoc on every new method and constructor states its name, that it sets no interval, and what it never deletes; `httpsec` and `passkey` package docs point to the expiry tasks. Verify with `go doc ./httpsec Chain.ExpiryTasks`, `go doc ./passkey Manager.ExpiryTasks` and `go vet ./...`

## 4. The scheduled sweeper (decision 6; "Sweeps can run on a schedule", "The scheduled sweeper starts and stops cleanly")

- [x] 4.1 Nested module `github.com/kartaladev/scrty/sweep` requiring gocron v2 at v2.22.0 or later and clockwork v0.5.0; added to `go.work`, the layout guard's integration-module list and the CI matrix; the core module gains no dependency. Verify with `go test -run 'TestLayout' -count=1 .` in the root module and `cd sweep && go build ./...`
- [x] 4.2 `sweep.New(r, opts...)` with `WithDefaultInterval`, `WithRunImmediately`, `WithDistributedLocker(gocron.Locker)`, `WithClock(clockwork.Clock)`: one job per task named `sweep:<task>`, `LimitModeReschedule`, no `WithLimitConcurrentJobs`; `ErrNoInterval` naming the task; refusals of nil options. Fake-clock tests: per-task interval, default interval, no boot-time sweep by default, run-immediately, a slow run skipping ticks (asserted after release), locker consulted with the job name. Covers "Consumer default interval", "Task interval", "No interval anywhere", "No boot-time sweep by default", "Consumer asks for a boot-time sweep", "Slow run skips ticks", "Distributed lock consulted". Verify with `cd sweep && go test -race -count=1 ./...`
- [x] 4.3 Lifecycle: `Start`, idempotent `Shutdown`, `ErrAlreadyStarted`, `ErrAlreadyShutdown`, a partial `Start` leaving the sweeper shut down; `goleak` for built-never-started and started-then-shut-down; no run after `Shutdown` returns. Godoc: no lock means every replica sweeps; what the lock tests do not prove; the first manual sweep. Covers "Built and never started", "Shutdown stops runs", "Restart refused". Verify with `cd sweep && go test -race -count=1 ./...` and `go doc ./sweep`

## 5. The in-memory rate limiter task (decision 2; after `limiter-key-bounds` lands)

- [x] 5.1 `(*ratelimit.MemoryLimiter).Prune()` returns the number of keys removed, and `ratelimit.ExpiryTask(l)` named `ratelimit`, interval unset. Tests: a quiet limiter's expired keys are removed and counted; a key whose newest stamp is inside the window survives and its count is unchanged (seen to fail against a variant that removes every key); two limiters renamed `ratelimit:apikey` and `ratelimit:magic-link` both run under their own names. Covers "Consumer renames a built-in task". Verify with `go test -race -run 'TestExpiryTask|TestMemoryLimiter_Prune' -count=1 ./ratelimit/`

## 6. Integration

- [x] 6.1 Whole-workspace gate: `go build ./...`, `go vet ./...` and `go test -race -count=1 ./...` in every module of `go.work` (Docker running), `gofmt -l .` empty, and `golangci-lint run ./...` clean in every module. Verify by every command's output.
- [x] 6.2 Whole-branch review against every requirement and scenario of `specs/expiry-sweeping/spec.md` and design decisions 1–6. Verify by the review reporting no open finding.
