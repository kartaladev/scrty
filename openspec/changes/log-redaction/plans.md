# Log Redaction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session never writes code: every task is dispatched to a subagent under `.claude/rules/subagent-delegation.md`, and the subagent reports; it never commits and never edits anything under `openspec/`.

**Goal:** No library log record and no error the library returns carries a consumer dependency's error text or a typed username, while operators still see what failed and consumers still match errors by identity.

**Architecture:** A small `internal/diag` package gives log sites a fixed-reason attribute set and gives return sites a fixed-text error that unwraps to the library sentinel and the cause. Every audited site moves onto it, one package at a time, each proven by a test whose dependency quotes an address and a user reference.

**Tech Stack:** Go 1.27; the core module `github.com/kartaladev/scrty` (`internal/diag` new; `httpsec`, `authenticate`, `magiclink`, `notify`, `oidc`, `ratelimit`, `onetime`, `apikey`, `signingkey`, `policy`); the `test` module for framework conformance; `log/slog`; uber-go/mock (`mockgen --typed`).

**Spec:** `openspec/changes/log-redaction/`: `proposal.md`, `design.md` (decisions 1–7), `specs/{diagnostic-redaction,authentication,email-notification,http-error-propagation}/spec.md`, `tasks.md`. Plan task numbers are `tasks.md` numbers.

## Global Constraints

- Test-first on every task: write the test, run it, see it fail **for the intended reason** (a compile error is not a red step), implement, see it pass (`.claude/rules/golang-tdd.md`).
- Every site is a defect claim found by reading (`.claude/rules/defect-claims.md`): its reproduction runs against the unchanged site first. A site whose test passes unchanged is reported and dropped.
- The fixtures every reproduction uses: a dependency error whose text is `store: Key (username)=(alice@example.com) for user u-123`, and assertions that no captured record and no `err.Error()` contains `alice@example.com` or `u-123`.
- Table tests use the `table-test` skill's `assert` closure form and `t.Context()`; mocks come from the `use-mockgen` skill.
- Kept on purpose, never removed: the throttled `source` address, the opaque user reference in MFA and policy records, the `email_domain` in identity-linking records, the protocol-failure text of token verification, discovery, key sets and the token endpoint.
- The consumer's own refusal checks, guards, authorizers, rule sets and policies' reasons are returned unchanged.
- Statuses from `httpsec.StatusForError` do not change for any error this plan touches.
- Nothing is copied from, or cites, the read-only reference.
- Verification a subagent runs before reporting: the task's focused `go test -run ... -count=1`, then `go test -count=1 ./<pkg>/`, `go vet ./<pkg>/`, `gofmt -l <pkg>` (empty).

## Review Focus

1. **A dependency error wrapped several levels deep** (`fmt.Errorf("x: %w", fmt.Errorf("y: %w", storeErr))`). The record still carries only the fixed reason and the outermost type; `errors.Is` still finds the store's error. Test added to task 1.1.
2. **A context cancellation from the dependency.** The record says `cancelled=true`, so an operator can tell a hang-up from an outage. Test added to task 1.1.
3. **A dependency error that is exactly a library sentinel** (a store returning `session.ErrSessionNotFound` bare). It passes through unchanged, so existing matching and statuses hold. Test added to task 1.1, and a row in task 6.1.
4. **A consumer refusal check whose error text itself contains an address.** It is returned byte for byte; the library does not rewrite the consumer's words. Test added to task 6.1.
5. **The opt-in username with sampling.** Two different usernames refused for the same reason in one window still produce one record (the username is not part of the sampling key). Test added to task 2.1.

---

## File Structure

| File | Responsibility | Tasks |
|---|---|---|
| `internal/diag/diag.go` (new) | `Failure`, `Fault`, `Wrap` | 1.1 |
| `internal/diag/diag_test.go` (new) | helper tables | 1.1 |
| `httpsec/mfaenrol.go` | `enrolmentFault`/`refusedAs` onto `diag` | 1.2 |
| `authenticate/password.go`, `authenticate/options.go` (or where password options live) | username off by default; `WithUsernameInRefusalLogs`; loader failure record | 2.1, 2.2 |
| `httpsec/login.go`, `basic.go`, `sessiontouch.go`, `oidc_callback.go`, `throttle.go` | log sites | 3.1 |
| `notify/smtp.go`, `notify/queued.go` | failure records | 4.1 |
| `magiclink/manager.go` | failure records | 4.2 |
| `ratelimit/guard.go` | limiter-failure records | 4.3 |
| `oidc/callback.go`, `oidc/handoff.go` | failure records | 5.1 |
| `onetime/manager.go`, `apikey/manager.go`, `signingkey/rotate.go` | store-failure records | 5.2 |
| `policy/mfarequirement.go`, `policy/lockout.go`, `policy/concurrent.go`, `policy/mfa.go` | record and reasons | 5.3 |
| `httpsec/logincomplete.go`, `bearer.go`, `mfaverify.go`, `logout.go`, `oidc_authorize.go`, `oidc_callback.go`, `oidc_backchannel.go` | returned errors | 6.1 |
| `test/httpsecconformance/redaction_scenarios.go` (new), `scenarios.go` | adapter scenario | 6.2 |
| godoc across the packages above | consumer-detail note, deliberate fields | 7.1 |

## Dispatch Lanes (for the main session)

| Lane | Tasks | Owns | Must not touch | Model | Why |
|---|---|---|---|---|---|
| A | 1.1 | `internal/diag/` | everything else | Opus | the primitive every other lane compiles against; its unwrap contract decides every status |
| B1 | 1.2, 3.1 | `httpsec/mfaenrol.go` (fault only), `login.go`, `basic.go`, `sessiontouch.go`, `oidc_callback.go` (log site), `throttle.go`, their tests | other packages | Sonnet | applying a stated pattern to listed sites |
| B2 | 6.1, 6.2 | the `httpsec` return sites listed in 6.1, `test/httpsecconformance/redaction_scenarios.go` + list | other packages | Opus | a public error contract across many paths; a wrong wrap passes tests and changes a status |
| C | 2.1, 2.2 | `authenticate/` | everything else | Sonnet | one option and one record, well specified |
| D | 4.1–4.3 | `notify/`, `magiclink/`, `ratelimit/` | everything else | Sonnet | a stated pattern over listed sites |
| E | 5.1–5.3 | `oidc/`, `onetime/`, `apikey/`, `signingkey/`, `policy/` | everything else | Sonnet (5.3 on Opus) | a stated pattern; 5.3 changes public policy reasons |

A runs first. Then B1, C, D and E run **in parallel** (no shared files). B2 runs after B1 (same package) and after E (it asserts statuses of policy reasons E rewraps). 7.1 is the last dispatch of each lane's package, folded into that lane's final dispatch; 7.2 is the main session's final gate. After each dispatch the main session runs its verification, then a fresh reviewer checks the diff.

---

### Task 1.1: `internal/diag`

**Files:** Create `internal/diag/diag.go`, `internal/diag/diag_test.go`.

**Interfaces:** Produces:

```go
package diag

// Failure returns the attributes a log record carries for a failed
// dependency: a fixed reason, the error's Go type, and cancelled=true when
// the error is a context cancellation or deadline. Never the error's text.
func Failure(reason string, err error) []slog.Attr

// Fault is an error whose text is fixed library text and which unwraps to the
// library sentinels it stands for and to the dependency's error.
type Fault struct { /* unexported fields */ }
func (f *Fault) Error() string
func (f *Fault) Unwrap() []error

// Wrap returns nil for nil, err itself when err is exactly one of kinds, and
// otherwise a *Fault with text, kinds and err.
func Wrap(err error, text string, kinds ...error) error
```

- [ ] **Step 1: Write the failing test.**

```go
func TestFailure(t *testing.T) {
	t.Parallel()

	storeErr := errors.New("store: Key (username)=(alice@example.com) for user u-123")

	cases := []struct {
		name   string
		err    error
		assert func(t *testing.T, attrs []slog.Attr)
	}{
		{name: "plain dependency error", err: storeErr, assert: func(t *testing.T, attrs []slog.Attr) {
			rendered := fmt.Sprint(attrs)
			assert.NotContains(t, rendered, "alice@example.com")
			assert.NotContains(t, rendered, "u-123")
			assert.Contains(t, rendered, "reason=attempt-store")
			assert.Contains(t, rendered, "error_type=*errors.errorString")
		}},
		// Review Focus 1
		{name: "wrapped twice", err: fmt.Errorf("x: %w", fmt.Errorf("y: %w", storeErr)),
			assert: func(t *testing.T, attrs []slog.Attr) {
				assert.NotContains(t, fmt.Sprint(attrs), "alice@example.com")
				assert.Contains(t, fmt.Sprint(attrs), "error_type=*fmt.wrapError")
			}},
		// Review Focus 2
		{name: "cancelled", err: fmt.Errorf("store: %w", context.Canceled),
			assert: func(t *testing.T, attrs []slog.Attr) {
				assert.Contains(t, fmt.Sprint(attrs), "cancelled=true")
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.assert(t, diag.Failure("attempt-store", tc.err))
		})
	}
}
```

`TestWrap`: a table asserting, for `Wrap(storeErr, "httpsec: the session could not be saved", session.ErrSessionNotFound)`, that `Error()` is exactly the given text, `errors.Is` finds both `storeErr` and the sentinel, `errors.As` finds a typed cause (use a small `*pgLikeError` struct); `Wrap(nil, …)` is nil; and (Review Focus 3) `Wrap(session.ErrSessionNotFound, "…", session.ErrSessionNotFound)` returns the sentinel itself (`assert.Same` on the error value, or `==`).
- [ ] **Step 2: Run to verify it fails** against stubs returning nil. `go test -run 'TestFailure|TestFault|TestWrap' -count=1 ./internal/diag/`. Expected: FAIL on every assertion, not on compilation.
- [ ] **Step 3: Implement.**

```go
func Failure(reason string, err error) []slog.Attr {
	attrs := []slog.Attr{
		slog.String("reason", reason),
		slog.String("error_type", fmt.Sprintf("%T", err)),
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		attrs = append(attrs, slog.Bool("cancelled", true))
	}
	return attrs
}

type Fault struct {
	text  string
	kinds []error
	cause error
}

func (f *Fault) Error() string   { return f.text }
func (f *Fault) Unwrap() []error { return append(append([]error(nil), f.kinds...), f.cause) }

func Wrap(err error, text string, kinds ...error) error {
	if err == nil {
		return nil
	}
	for _, k := range kinds {
		if err == k { //nolint:errorlint // identity: a bare sentinel carries no dependency text
			return err
		}
	}
	return &Fault{text: text, kinds: kinds, cause: err}
}
```

Package godoc: the rule (design decision 1), and that a consumer keeps detail by logging inside their own dependency.
- [ ] **Step 4: Run to verify it passes.** Then `go vet ./internal/diag/`.
- [ ] **Step 5: Report.**

### Task 1.2: The enrolment path uses `diag`

**Files:** Modify `httpsec/mfaenrol.go`.

- [ ] **Step 1:** Replace `enrolmentFault` with `*diag.Fault` and `refusedAs(kind, err)` with `diag.Wrap(err, kind.Error(), kind)`; keep each site's existing fixed text and reason word (`reasonNotBegun`, etc.) by passing them to `diag.Wrap`/`diag.Failure`. Where a site logged `slog.String("reason", …)` directly, use `diag.Failure`.
- [ ] **Step 2:** `go test -run 'TestEnrolment' -count=1 ./httpsec/` — unchanged and green (a refactor under existing tests; its red step is those tests' own history). `go vet ./httpsec/`.

### Task 2.1: No typed usernames by default

**Files:** Modify `authenticate/password.go` (the `refuse` helper and its callers) and the password options file; Test `authenticate/password_refusal_test.go` (new).

**Interfaces:** Produces `func WithUsernameInRefusalLogs() PasswordOption`.

- [ ] **Step 1: Write the reproduction.** `TestPasswordRefusalRecords`: a capturing slog handler through `WithPasswordAuthenticatorLogger`, interval zero. Rows: an unknown username `alice@example.com` → no record contains it; a known user with a wrong password → no record contains the username; with `WithUsernameInRefusalLogs()` → the record contains `alice@example.com`; Review Focus 5: with the option and the default one-minute interval, `alice` and `bob` refused for the same reason → one record.
- [ ] **Step 2: Run on unchanged code.** Expected: the default rows FAIL (the username is written). Record `REPRODUCED`. If they pass, stop and report.
- [ ] **Step 3: Implement.** `refuse` writes `slog.String("username", u)` only when the option is set; the option's godoc: "WithUsernameInRefusalLogs writes the submitted username in refusal records, which by default carry the reason only. Users type email addresses, and sometimes passwords, into the username field, and every unknown username then reaches the log."
- [ ] **Step 4: Run to verify it passes.** `go test -run TestPasswordRefusalRecords -count=1 ./authenticate/ && go test -count=1 ./authenticate/`.
- [ ] **Step 5: Report.**

### Task 2.2: The user loader failure record

**Files:** Modify `authenticate/password.go`; Test `authenticate/password_refusal_test.go`.

- [ ] **Step 1: Write the reproduction.** `TestPasswordLoaderFailureRecord`: a user loader (mock) returning the fixture error; the record contains neither value, and carries `reason=user-loader` and `error_type`.
- [ ] **Step 2: Run on unchanged code.** Expected: FAIL (the error text is written).
- [ ] **Step 3: Implement** with `diag.Failure("user-loader", err)` in place of the error attribute.
- [ ] **Step 4: Run to verify it passes.**
- [ ] **Step 5: Report.**

### Task 3.1: `httpsec` log sites

**Files:** Modify `httpsec/login.go` (`recordFailure`, `resetFailures`), `basic.go` (attempt store), `sessiontouch.go`, `oidc_callback.go` (handoff issue record), `throttle.go` (both limiter records, keeping `source` and `flow`); Test `httpsec/failure_records_test.go` (new).

- [ ] **Step 1: Write the reproduction.** `TestHTTPSecFailureRecords`, one row per site, each driving the chain so the dependency (attempt store, session store, handoff issuer, limiter) returns the fixture error, with the chain's logger set to a capturing handler. Each row asserts the record exists, contains neither value, carries its `reason` (`attempt-store`, `session-store`, `handoff-issue`, `limiter`) and `error_type`, and for the limiter rows still carries `flow` (and `source` where it did).
- [ ] **Step 2: Run on unchanged code.** Expected: every row FAILS on the address. Record `REPRODUCED`.
- [ ] **Step 3: Implement.** At each site replace `slog.String("error", err.Error())` with `diag.Failure("<reason>", err)...`, e.g.:

```go
	if err := l.attempts.RecordFailure(ctx, username, now); err != nil {
		l.log.LogAttrs(ctx, slog.LevelError, msgAttemptNotRecorded,
			diag.Failure("attempt-store", err)...)
	}
```

For the sampled limiter record in `throttle.go`, pass `slog.String("flow", flow)` followed by `diag.Failure("limiter", err)...` to `logSampled`.
- [ ] **Step 4: Run to verify it passes.** `go test -run TestHTTPSecFailureRecords -count=1 ./httpsec/ && go test -count=1 ./httpsec/`.
- [ ] **Step 5: Report.**

### Task 4.1: Sender failure records

**Files:** Modify `notify/smtp.go` (the delivery-failure record), `notify/queued.go` (inner-sender failure and recovered panic); Test `notify/failure_records_test.go` (new).

- [ ] **Step 1: Write the reproduction.** `TestSenderFailureRecords` with a capturing logger: an SMTP server (the package's existing fake SMTP test server, or `test.RunTestSMTP` only if the package's tests already use it — core tests must not import `test`) rejecting `RCPT TO` with `550 5.1.1 <alice@example.com>: Recipient address rejected`; a queued sender whose inner sender returns the fixture error; a queued sender whose inner sender panics with a value quoting the address. Each asserts no record contains the address and the record carries a `reason` naming the stage (`rcpt`, `send`, `panic`) and `error_type` (for the panic, the value's type).
- [ ] **Step 2: Run on unchanged code.** Expected: FAIL.
- [ ] **Step 3: Implement** with `diag.Failure`; for the panic, log `slog.String("reason", "panic")` and `slog.String("value_type", fmt.Sprintf("%T", v))`.
- [ ] **Step 4: Run to verify it passes.** `go test -run TestSenderFailureRecords -count=1 ./notify/ && go test -count=1 ./notify/`.
- [ ] **Step 5: Report.**

### Task 4.2: Magic-link failure records

**Files:** Modify `magiclink/manager.go` (issued-count, issue, send, resolver, user-loader records); Test `magiclink/failure_records_test.go` (new).

- [ ] **Step 1: Write the reproduction.** `TestMagicLinkFailureRecords`, one row per dependency returning the fixture error, capturing logger; assert neither value and the `reason` (`token-count`, `token-issue`, `sender`, `resolver`, `user-loader`).
- [ ] **Step 2: Run on unchanged code.** Expected: FAIL.
- [ ] **Step 3: Implement** with `diag.Failure`.
- [ ] **Step 4: Run to verify it passes.** `go test -run TestMagicLinkFailureRecords -count=1 ./magiclink/ && go test -count=1 ./magiclink/`.
- [ ] **Step 5: Report.**

### Task 4.3: Rate-limiter failure records

**Files:** Modify `ratelimit/guard.go`; Test `ratelimit/failure_records_test.go` (new).

- [ ] **Step 1: Write the reproduction.** `TestGuardFailureRecords`: a limiter whose error names the key `magic-link|203.0.113.7` and the fixture address; the limiter-failure record carries `flow`, `reason=limiter`, `error_type`, and neither the key text nor the address; a throttled source still writes its record with `source`.
- [ ] **Step 2: Run on unchanged code.** Expected: FAIL on the limiter row.
- [ ] **Step 3: Implement** with `diag.Failure("limiter", err)`.
- [ ] **Step 4: Run to verify it passes.** `go test -run TestGuardFailureRecords -count=1 ./ratelimit/ && go test -count=1 ./ratelimit/`.
- [ ] **Step 5: Report.**

### Task 5.1: OIDC failure records

**Files:** Modify `oidc/callback.go` (flow-store completion record), `oidc/handoff.go` (user-loader record at redemption); Test `oidc/failure_records_test.go` (new).

- [ ] **Step 1: Write the reproduction.** `TestCallbackFailureRecords` (a flow store whose `Complete` returns an error quoting the handle, the state and the fixture address) and `TestHandoffFailureRecords` (a user loader returning the fixture error, which the current value scrubbing misses because the username is not among its values). Assert neither value, nor the handle or state, in any record.
- [ ] **Step 2: Run on unchanged code.** Expected: FAIL.
- [ ] **Step 3: Implement** with `diag.Failure("flow-store", err)` and `diag.Failure("user-loader", err)`. Leave `oidc/broker.go`'s `redact` untouched.
- [ ] **Step 4: Run to verify it passes.** `go test -run 'TestCallbackFailureRecords|TestHandoffFailureRecords' -count=1 ./oidc/ && go test -count=1 ./oidc/`.
- [ ] **Step 5: Report.**

### Task 5.2: Store failure records in `onetime`, `apikey`, `signingkey`

**Files:** Modify `onetime/manager.go`, `apikey/manager.go`, `signingkey/rotate.go`; Test one `failure_records_test.go` per package.

- [ ] **Step 1: Write the reproduction.** One table per package with its store returning the fixture error; assert neither value in any record, the public identifier (`token_id`, `key_id`) still present where it was, and `reason=token-store` / `key-store` / `signing-key-store`.
- [ ] **Step 2: Run on unchanged code.** Expected: FAIL in each.
- [ ] **Step 3: Implement** with `diag.Failure`.
- [ ] **Step 4: Run to verify it passes.** `go test -run 'Test.*StoreFailureRecords' -count=1 ./onetime/ ./apikey/ ./signingkey/`.
- [ ] **Step 5: Report.**

### Task 5.3: Policy records and reasons

**Files:** Modify `policy/mfarequirement.go` (lookup-failure record; reasons around lines 317 and 354), `policy/lockout.go` (reason around line 217), `policy/concurrent.go` (reason around line 132), `policy/mfa.go` (reason around line 324); Test `policy/store_failure_test.go` (new).

- [ ] **Step 1: Write the reproduction.** `TestPolicyStoreFailureReasons`, one row per policy whose store or lookup returns the fixture error: the decision's `Reason` text contains neither value; `errors.Is(d.Reason, <the policy's sentinel>)` and `errors.Is(d.Reason, storeErr)` both hold; the MFA requirement policy's record keeps `user` (deliberate) but not the error text.
- [ ] **Step 2: Run on unchanged code.** Expected: FAIL on the text.
- [ ] **Step 3: Implement** each reason as `diag.Wrap(err, "<policy>: <fixed text>", <sentinel>)`, keeping the text each reason uses today up to the `%w`; the record with `diag.Failure("enrolment-lookup", err)`.
- [ ] **Step 4: Run to verify it passes.** `go test -run TestPolicyStoreFailureReasons -count=1 ./policy/ && go test -count=1 ./policy/`.
- [ ] **Step 5: Report.**

### Task 6.1: Returned errors on the HTTP paths

**Files:** Modify `httpsec/logincomplete.go`, `bearer.go`, `mfaverify.go`, `logout.go`, `oidc_authorize.go`, `oidc_callback.go`, `oidc_backchannel.go`; Test `httpsec/returned_errors_test.go` (new).

**Interfaces:** Consumes `diag.Wrap`.

- [ ] **Step 1: Write the reproduction.** `TestReturnedErrorsCarryFixedText`, one row per path, each with a chain whose consumer error handler records `err.Error()` and the status `StatusForError(err)`, and the dependency returning the fixture error:
  - login: session create, session save, token generation;
  - bearer: the per-request save;
  - verify: the TOTP store read (through a failing enrolment store), rotation, token generation;
  - logout: session delete;
  - OIDC: authorize's flow begin, the callback's flow abort and handoff issue, back-channel logout's link lookup and session delete.
  Each asserts neither value in the text, `errors.Is(err, storeErr)`, and the status equal to the one the unchanged code produces (compute it once against a bare `storeErr` and pin it per row). Review Focus 3: a store returning `session.ErrSessionNotFound` bare → returned unchanged. Review Focus 4: a consumer magic-link refusal check returning `errors.New("terms not accepted for alice@example.com")` → returned byte for byte.
- [ ] **Step 2: Run on unchanged code.** Expected: FAIL on the text in every path row; the two Review Focus rows pass (they pin what must not change). Record `REPRODUCED`.
- [ ] **Step 3: Implement.** At each return site, `return diag.Wrap(err, "httpsec: <what failed>", <the library sentinel the path already maps to, if any>)`, e.g. in `logincomplete.go`:

```go
	s, err := d.sessions.Create(ctx, principal.ID, createOpts...)
	if err != nil {
		return diag.Wrap(err, "httpsec: the session could not be created")
	}
```

  Do not wrap errors from the consumer's own checks, guards, authorizers, rule sets or policy reasons.
- [ ] **Step 4: Run to verify it passes.** `go test -run TestReturnedErrorsCarryFixedText -count=1 ./httpsec/ && go test -race -count=1 ./httpsec/`.
- [ ] **Step 5: Report.**

### Task 6.2: Conformance

**Files:** Create `test/httpsecconformance/redaction_scenarios.go`; Modify `test/httpsecconformance/scenarios.go` (append to the list).

- [ ] **Step 1: Write the scenario** "a store failure's text stays out of the refusal": form login with a session store whose `Create` returns the fixture error. Assert the status is the one net/http gives, identical on every adapter, and the refusal error's text contains neither value (for gin, read it from the recorded `c.Errors`; for fiber, from the error returned to the error handler).
- [ ] **Step 2: See it fail** against the unchanged login path by temporarily reverting its wrap (edit back), then restore.
- [ ] **Step 3: Run.** `cd test && go test -run TestConformance -count=1 .`. Expected: PASS on net/http, gin and fiber.
- [ ] **Step 4: Report.**

### Task 7.1: Documentation

**Files:** godoc in each package touched above.

- [ ] **Step 1:** In each component that logs a dependency failure, add to its constructor's or logger option's godoc: "Records of a failed dependency carry a fixed reason and the error's type, never its text; log inside your own implementation for full detail." Name the deliberate fields where they are logged: `ratelimit` (source address), `mfa` and `policy` (user reference), `oidc` (email domain; protocol-failure text), `httpsec` bearer (token verification text).
- [ ] **Step 2:** `go doc` each package; `go vet ./...`.

### Task 7.2: Final gate and whole-branch review (main session)

- [ ] **Step 1:** In each of `.`, `ginsec`, `fibersec`, `test`: `go test -race -count=1 ./...`, `go vet ./...`, `gofmt -l .` (empty, ignoring `.claude/`), `golangci-lint run ./...` (0 issues).
- [ ] **Step 2:** `rg --glob '!.claude' --glob '!*_test.go' -n 'err(or)?\.Error\(\)' .` — every remaining hit is either library-controlled text, a deliberate exception from design decision 6, or outside a log record and returned error; list any other in the review.
- [ ] **Step 3:** Dispatch a fresh reviewer against every requirement in `specs/`, `design.md` decisions 1–7 and this plan's Review Focus. Every defect it claims needs a failing test, or is labelled `UNREPRODUCED`. Resolve its findings before archive.
