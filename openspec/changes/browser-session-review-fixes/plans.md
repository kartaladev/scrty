# Browser Session Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reproduce each of the six review findings on PR #160 with a failing test, then fix it.

**Architecture:**
- Four lanes own disjoint files, and each runs in its own git worktree off `feat/browser-session`
  HEAD. Lanes A, B and D share the `httpsec` package, so a half-edited file in one would break
  the others' builds.
- The main session integrates the lanes' diffs, writes the CHANGELOG (task 7.1) and runs the gate.

**Tech Stack:** Go 1.27, `httpsec`, `session`, testify, `go.uber.org/mock` (mockgen, `-typed`),
testcontainers (store conformance).

**Spec:** `openspec/changes/browser-session-review-fixes/`: `design.md` decisions 1–6 and the
Failure modes table, and the deltas `specs/browser-session/spec.md`, `specs/sessions/spec.md` and
`specs/sender-constrained-tokens/spec.md`. Executors read the design and the scenarios their tasks
cover.

## Global Constraints

- **Red first, as reproduction** (`golang-tdd.md`, `defect-claims.md`). Write the test and run it
  on the unmodified code. See it fail for the claimed reason (the wrong value, the admitted
  request, the panic, the race), and record the failing output. If it passes instead, stop: report
  that the claim is unreproduced and do not make the fix.
- No production change beyond what the lane's tasks name. No edits under `openspec/`.
- No git command that discards work (`checkout --`, `restore`, `reset --hard`, `stash`, `clean`),
  and no commits. Leave changes uncommitted in the lane's worktree.
- Table tests follow `.claude/skills/table-test/SKILL.md` (`assert` closure, `t.Context()`): add
  rows to existing tables for the same SUT call. Mocks follow `.claude/skills/use-mockgen/SKILL.md`.
  Durable stores follow `.claude/skills/use-testcontainers/SKILL.md`.
- The godoc of every changed option or port names its default and what it refuses
  (`library-design.md`).
- Errors are refusals with the existing sentinels: `ErrCrossSiteRequest`, `ErrConfig`,
  `ErrAuthenticationRequired`. No new exported identifiers.

## Review Focus

1. **A CSRF refusal whose tree holds only nil entries beside the sentinel.** Expected: refused as a
   cross-site request, not as a dependency failure. Task 1 asserts this with the
   `{ErrAuthenticationRequired, nil}` row.
2. **An `Unwrap() error` that returns a typed nil.** It must not panic either. Task 1 adds a row
   where a single-wrap error unwraps to a typed nil.
3. **A prefix spelled `__Host-` followed by nothing (`__Host-`).** It must still be refused as an
   invalid name, as today. Task 2 keeps the existing invalid-name rows passing.
4. **A role switch called twice from two goroutines while the handler returns.** Expected: the
   switches are serialized; the return waits for the one holding the run's lock; the other either
   completes before the return or is refused with `ErrConfig`, or gives up when its context ends.
   Task 6 covers the queued and cancelled case.
5. **The lock order of a logout racing a switch, with the handler's return.** Expected: no deadlock, and
   the existing "Logout during a role switch" scenario still holds. Task 6.3 includes that test.

---

## Dispatches

| Lane | Tasks | Owns | Model |
|---|---|---|---|
| A — httpsec refusals | 1.1–1.2, 2.1–2.2, 3.1–3.2 | `httpsec/session_cookie.go`, `httpsec/dpop.go`, `httpsec/session_cookie_test.go`, `httpsec/session_cookie_options_test.go`, a new `httpsec/session_cookie_bound_continuation_test.go` | Opus: security refusal logic and typed-nil error walking |
| B — delivery quoting | 4.1–4.2 | `httpsec/session_delivery.go`, `httpsec/session_delivery_port_test.go` | Sonnet: one comparison with a stated test |
| C — session mark | 5.1–5.3 | `session/sessions.go`, `session/reuse.go`, `session/session.go`, `session/store.go`, `session/rotate_copy_test.go` | Sonnet: a pin beside existing pins, test-first |
| D — handler-return lock | 6.1–6.3 | `httpsec/chain.go`, `httpsec/role_switch.go`, `httpsec/role_switch_test.go` (or a new `httpsec/role_switch_run_end_test.go`) | Opus: a lock across goroutines and a barrier test |

Each lane is a single dispatch of no more than six tasks. All four run in parallel, each in its own
worktree. Reviewers use the same model as the lane: Opus for A and D, Sonnet for B and C. One
whole-branch review on Opus runs before the gate, because the change has security-critical
refusals.

**Scoped verification** (`test-scope.md`), run from the lane's worktree root:

```sh
# Lanes A, B, D: httpsec and its dependents
go test -race -count=1 ./httpsec/...
(cd test && go test -race -count=1 ./httpsecconformance/...)
go vet ./httpsec/... && gofmt -l httpsec
# Lane C: session and its dependents
go list -f '{{.ImportPath}} {{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}' ./... \
  | awk '/github.com\/kartaladev\/scrty\/session( |$)/{print $1}'   # in-module dependents
go test -race -count=1 ./session/... <those dependents>
(cd test && go test -race -count=1 ./storetest/... ./crossbackend/...)   # needs Docker
go vet ./session/... && gofmt -l session
```

---

### Task 1: CSRF refusal fails closed (tasks 1.1–1.2, lane A)

**Files:** Modify `httpsec/session_cookie.go` (`csrfAnswer` :281, `otherCauses` :309). Test
`httpsec/session_cookie_test.go`, in the table that holds the `authRequiredTokens()` /
`outageTokens()` rows (uses near :556, :577). Those are now `NewMockCSRFTokens` helpers.

- [ ] **Step 1: Red.** Add these rows, each with a `NewMockCSRFTokens` whose `Token` returns
  `"t", nil` `.AnyTimes()` and whose `Verify` returns the error named:
  - `"a CSRF refusal holding a nil entry is still a refusal"`: a test type `joinedWith struct{ errs []error }` whose `Unwrap() []error` returns `{httpsec.ErrAuthenticationRequired, nil}`;
  - `"a CSRF refusal holding a typed nil is still a refusal"`: `{httpsec.ErrAuthenticationRequired, (*typedNilErr)(nil)}`, where `*typedNilErr` has pointer-receiver `Error` and `Unwrap() error`;
  - `"a CSRF refusal wrapping a typed nil is still a refusal"`: a single-wrap error around `ErrAuthenticationRequired` that holds a typed-nil cause.

  Each row asserts:
  - `errors.Is(err, httpsec.ErrCrossSiteRequest)` and `403`;
  - the handler did not run;
  - `f.limiter.recorded()` is empty;
  - no `Set-Cookie`;
  - no panic, i.e. the test completes.
- [ ] **Step 2: Run** `go test -run 'TestSessionCookie_<table>' -count=1 ./httpsec/`. Expected:
  FAIL, either the nil-entry row admitted (200 and the handler ran) or the typed-nil row panicked.
  Record the output.
- [ ] **Step 3: Green.**
  - `otherCauses(err error, budget *int) ([]error, bool)` skips a nil entry and a typed-nil value,
    meaning `reflect.ValueOf(e).Kind() == reflect.Pointer && IsNil()`, as `internal/errwalk`
    defines it, and never calls a method on either.
  - `csrfAnswer` returns `ErrCrossSiteRequest` when `errors.Join(causes...)` is nil.
- [ ] **Step 4: Run** the table, then the outage row. Expected: PASS, and the outage row still
  fails as the dependency failure.

### Task 2: Canonical prefixes (tasks 2.1–2.2, lane A)

**Files:** Modify `httpsec/session_cookie.go` (`checkAttributes` around :595–616, `hasPrefixFold`
callers, and the godoc of `WithSessionCookieName`). Test `httpsec/session_cookie_options_test.go`,
`TestSessionCookie_Attributes` (:20).

- [ ] **Step 1: Red.** Add rows `__host-app` (no domain), `__HOST-app` (no domain) and
  `__secure-app` with `WithSessionCookieDomain("example.com")`. Assert `errors.Is(err,
  httpsec.ErrConfig)` and that the message contains `__Host-` or `__Secure-` respectively.
- [ ] **Step 2: Run** → FAIL, because the chain builds.
- [ ] **Step 3: Green.** Exact `strings.HasPrefix` for acceptance. A name that matches a prefix
  only under `strings.EqualFold` gets a configuration error naming the canonical spelling.
- [ ] **Step 4: Run** the whole `TestSessionCookie_Attributes` table → PASS. The existing
  `__Host-app`, `__Secure-scrty-session` and Domain-with-`__Host-` rows are unchanged.

### Task 3: Bound session refused at continuation (tasks 3.1–3.2, lane A)

**Files:** Modify `httpsec/dpop.go` (`credentialDelivery.continuingProof` :986). Create
`httpsec/session_cookie_bound_continuation_test.go`.

**Interfaces:** Consumes the cookie-chain fixtures of `session_cookie_test.go` (read-only), plus a
consumer `Authenticator` registered on the chain (as `httpsec` tests already do for API keys) that
publishes a session created with `session.WithKeyBinding(...)` (DPoP `jkt`).

- [ ] **Step 1: Red.** Table `TestSessionCookie_BoundSessionNotContinued` with rows for:
  - second-factor verification (`/mfa/challenge/totp` with a valid code);
  - re-authentication with the right password;
  - renewal.

  Each asserts:
  - `errors.Is(err, httpsec.ErrAuthenticationRequired)` and `401`;
  - the session is still loadable and not superseded (`RotatedStrictly` and `SupersededAt` zero);
  - the code is not spent (the same code then verifies on a token chain, or the challenge store
    still holds it).
- [ ] **Step 2: Run** → FAIL. Each row proceeds or rotates.
- [ ] **Step 3: Green.** On a cookie chain (`d.cookie != nil`), return `ErrAuthenticationRequired`
  when `s.KeyBinding != (session.KeyBinding{})`, and nil otherwise.
- [ ] **Step 4: Run** the new table and the cookie-chain "Invalid proof ignored" rows → PASS.

### Task 4: Quoted delivery refused (tasks 4.1–4.2, lane B)

**Files:** Modify `httpsec/session_delivery.go` (`sameCookie` :547, and the godoc of
`SessionDelivery` :582). Test `httpsec/session_delivery_port_test.go`.

- [ ] **Step 1: Red.** A row where a `NewMockSessionDelivery` `Deliver` `DoAndReturn` sets the
  chain's cookie unchanged except `Quoted: true`, then returns `"", nil`. Assert:
  - the sign-in fails as an issuing failure, with the same assertion the existing
    altered-attribute row uses;
  - no session `Set-Cookie`;
  - the created session is ended (its load fails).
- [ ] **Step 2: Run** → FAIL. The sign-in succeeds with a quoted `Set-Cookie`.
- [ ] **Step 3: Green.** `sameCookie` adds `a.Quoted == b.Quoted`. Add "or whether its value is
  quoted" to the godoc's list of attributes the delivery must not change.
- [ ] **Step 4: Run** the delivery-port tests → PASS.

### Task 5: `MFAAtFirstFactor` pinned (tasks 5.1–5.3, lane C)

**Files:** Modify `session/sessions.go` (strict rotation, beside :1026/:1033), `session/reuse.go`
(`successorFromCaller`, beside :787/:790), and the godoc at `session/session.go:138`,
`session/sessions.go:785-795` and `session/store.go:337`. Test `session/rotate_copy_test.go`.

- [ ] **Step 1: Red.** Table `TestRotate_KeepsSecondFactorAtLoginMark` with rows:
  - `"strict rotation ignores a copy that sets the mark"`: created without `WithSecondFactorAtLogin`, copy `MFAAtFirstFactor = true`, `Rotate` → the stored successor's mark is false;
  - `"caller-built grace rotation ignores a copy that clears the mark"`: created with `WithSecondFactorAtLogin()`, copy mark false, `RotateWithGrace(..., WithSuccessorFromCaller(loaded))` → true;
  - `"strict rotation carries the mark"`: unchanged copy → true;
  - `"grace rotation carries the mark"`: unchanged copy → true.

  Read each successor back from the store with `Load`.
- [ ] **Step 2: Run** `go test -run TestRotate_KeepsSecondFactorAtLoginMark -count=1 ./session/`
  → the first two rows FAIL.
- [ ] **Step 3: Green.** Add `next.MFAAtFirstFactor = stored.MFAAtFirstFactor` in
  `successorFromCaller`, and the same on the strict path. Reword the three godoc places to "taken
  from the stored record".
- [ ] **Step 4: Run** the table → PASS. Then run `(cd test && go test -race -count=1 ./storetest/...)`.
  The session suite rotates marked sessions against memory, pgx, sql and gorm, and passes. If the
  suite has no row that rotates a marked session, add one in `test/storetest/session_suite.go`.
  This file is owned by lane C only for this purpose.

### Task 6: Handler-return lock for role switch (tasks 6.1–6.3, lane D, revised)

**Files:** Modify `httpsec/chain.go`: `chainRun` (:396), `runTerminal` (:679, the innermost step
that calls the terminal), and the run's end (`run.end()` from the first dispatch). Modify
`httpsec/role_switch.go` (`rotateForSwitch` and the godoc of `SwitchActiveRole`). Test
`httpsec/role_switch_run_end_test.go`.

**Interfaces:**
- `chainRun` holds `lock chan struct{}` (capacity 1) and `handled bool`, which is written only
  while the lock is held. The `done atomic.Bool` stays for the lock-free readers.
- The lock methods:
  - `func (r *chainRun) acquire(ctx context.Context) error` blocks until the lock is taken or
    `ctx` ends; in the second case it returns `ctx.Err()`.
  - `func (r *chainRun) acquireAlways()` blocks without a context.
  - `func (r *chainRun) release()` releases the lock.
- `runTerminal`: after `next(ex)` returns, call `run.acquireAlways()`, set `run.handled = true`,
  then `run.release()`. The run is the one whose terminal this is. Do it in a `defer`, so a panic
  or `Goexit` still sets it.
- `rotateForSwitch`:
  - Call `src.run.acquire(ctx)` and return its error, storing nothing.
  - Then take `src.mu`.
  - If `src.run.handled || src.run.done.Load()`, refuse with `ErrConfig` as today.
  - Hold both locks through the rotation and the cookie write.

- [ ] **Step 1: Red.** Starting from lane D's current tree:
  - Extend `TestSwitchActiveRole_RunEndWaitsForSwitch`:
    - Register `httpsec.RegisterInterceptor(InterceptorFunc{...}, httpsec.OrderSessionTouch)`
      that, after `next`, records `ex.Session.ID`, reads `ex.Context()`, and calls
      `ex.Writer.SetHeader("X-After", "1")`.
    - Snapshot `rec.Header().Values("Set-Cookie")` in the run goroutine right after the run
      returns, and assert on that snapshot.
    - Assert the interceptor recorded the successor's ID.
    - Under `-race`, the current lane code must fail with a race report, or with the interceptor
      seeing the old ID.
  - Add `TestSwitchActiveRole_AfterHandlerReturned`: an interceptor after `next` calls
    `SwitchActiveRole`. Assert `ErrConfig` and that nothing is stored. It fails now, because the
    switch is accepted.
  - Add `TestSwitchActiveRole_QueuedSwitchGivesUp`: the first switch is held in the rotation, and
    a second switch with a cancelled context is queued behind it. Assert `context.Canceled` within
    a timeout, nothing stored by the second switch, and the first switch completing. It fails now,
    because the wait ignores its context.
  - Every wait is bounded by `select` with a timeout, so a failure never hangs.
- [ ] **Step 2: Run** `go test -race -count=1 -run 'TestSwitchActiveRole' ./httpsec/` and record
  the failures.
- [ ] **Step 3: Green** per the Interfaces block. Replace the first dispatch's `sync.Mutex` with
  the one-slot lock. Godoc of `SwitchActiveRole`:
  - the handler's return waits for a switch in progress;
  - a switch after the handler returned is refused;
  - a queued switch gives up when its context ends;
  - the rotation is bounded by the store's own timeouts, not by the request context, which
    `net/http` cancels only after the chain returns.
- [ ] **Step 4: Run** `go test -race -count=20 -run 'TestSwitchActiveRole|RoleSwitch|TestChain_SwitchActiveRole|TestWithSwitchableRoles|TestSessionCookie_LogoutRacesRoleSwitch' ./httpsec/`.
  Then run the nested-chain tests (`-run 'Nested|Assemble'`), the ginsec and fibersec module
  suites, and the lane's scoped verification. Expected: PASS, with no race and no hang.

### Task 7: CHANGELOG (task 7.1, main session)

- [ ] Under `[Unreleased]`:
  - In **Changed**, reword the `__Host-` rule entry to say the prefixes are canonical-spelling only.
  - In **Fixed**, add:
    - the CSRF fail-closed fix;
    - quoted delivery refused;
    - `MFAAtFirstFactor` kept at rotation;
    - the role switch waiting for its request's end;
    - a key-bound session refused at continuation on a cookie chain.

### Task 8: Gate (task 8.1, main session)

- [ ] Integrate the four lanes' diffs into the `feat/browser-session` worktree, and run the scoped
  commands above for `httpsec` and `session`.
- [ ] Whole-branch review on Opus against the three delta specs and the Failure modes table.
- [ ] `make check` and `make spec-check`. Read the output; both must pass after the last edit.
- [ ] Commit per lane, with messages naming the guaranteed behaviour. Push to update PR #160.
