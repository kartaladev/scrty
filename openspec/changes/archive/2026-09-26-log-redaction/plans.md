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
3. **A dependency error that is exactly a library sentinel** (a store returning `session.ErrSessionNotFound` bare). It passes through unchanged, so existing matching and statuses hold. Test added to task 1.1, a row in task 6.1, and a row in each of tasks 5.4–5.7 for every sentinel the package's dependency may return bare (design decision 8), and, in every fixture row, an assertion that the wrapped error matches no sentinel it did not match before: the bare sentinels pass through by identity and are never passed to `diag.Wrap` as kinds.
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
| `httpsec/login.go`, `basic.go`, `sessiontouch.go`, `oidc_callback.go`, `bearer.go`, `logout.go`, `throttle.go` | log sites | 3.1 |
| `notify/smtp.go`, `notify/queued.go` | failure records | 4.1 |
| `magiclink/manager.go` | failure records | 4.2 |
| `ratelimit/guard.go` | limiter-failure records | 4.3 |
| `oidc/callback.go`, `oidc/handoff.go` | failure records | 5.1 |
| `onetime/manager.go`, `apikey/manager.go`, `signingkey/rotate.go` | store-failure records | 5.2 |
| `policy/mfarequirement.go`, `policy/lockout.go`, `policy/concurrent.go`, `policy/mfa.go` | record and reasons | 5.3 |
| `policy/lockout.go`, `ratelimit/guard.go`, `notify/smtp.go`, `token/verifier.go`; `*/returned_errors_test.go` | returned errors of the smaller managers | 5.4 |
| `session/manager.go`, `session/encrypted.go`; `session/returned_errors_test.go` | returned errors | 5.5 |
| `mfa/totp.go`, `mfa/enroller.go`, `mfa/reset.go`; `mfa/returned_errors_test.go` | returned errors | 5.6 |
| `onetime/manager.go`, `apikey/manager.go`, `signingkey/manager.go`, `oidc/authorize.go`, `oidc/callback.go`, `oidc/handoff.go`, `oidc/passwordclaim.go` (encoder probe), `authenticate/password.go`, `authenticate/jwt.go`; `*/returned_errors_test.go` | returned errors | 5.7 |
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
| F1 | 5.4 | `policy/lockout.go`, `ratelimit/guard.go`, `notify/smtp.go`, `token/verifier.go`, their `returned_errors_test.go` | everything else | Sonnet | six sites, one pattern, sentinels named |
| F2 | 5.5 | `session/` | everything else | Opus | an interface every other package calls; a wrap that drops a bare sentinel's identity passes local tests and changes statuses elsewhere |
| F3 | 5.6 | `mfa/` | everything else | Opus | eighteen sites across the enrolment state machine; bare sentinels (`ErrNotEnrolled`, code refusals) must pass through |
| G | 5.8, 6.1 rows | `authorize/privilege.go`, `authorize/returned_errors_test.go`, the two new rows in `httpsec/returned_errors_test.go` | everything else | Sonnet | one site, a stated pattern; found by the 6.1 review |
| F4 | 5.7 | `onetime/`, `apikey/`, `signingkey/`, `oidc/` (not the broker's scrubbing), `authenticate/` | everything else | Sonnet | a stated pattern over listed sites |

A runs first. Then B1, C, D and E run **in parallel** (no shared files). F1–F4 were added after E's review (design decision 8); they run **in parallel** with each other once E and D are clean, since they own the same packages. B2 runs after B1 (same package), after E (it asserts statuses of policy reasons E rewraps) and after F2 (its rows assert the text of session errors that F2 now wraps). Each F dispatch runs the whole core module's tests and reports, without fixing, any failure in a package it does not own. 7.1 is the last dispatch of each lane's package, folded into that lane's final dispatch; 7.2 is the main session's final gate. After each dispatch the main session runs its verification, then a fresh reviewer checks the diff.

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

**Files:** Modify `httpsec/login.go` (`recordFailure`, `resetFailures`), `basic.go` (attempt store), `sessiontouch.go`, `oidc_callback.go` (handoff issue record), `bearer.go` (unreadable-session record), `logout.go` (end-session step record), `throttle.go` (both limiter records, keeping `source` and `flow`); Test `httpsec/failure_records_test.go` (new).

- [ ] **Step 1: Write the reproduction.** `TestHTTPSecFailureRecords`, one row per site, each driving the chain so the dependency (attempt store, session store, handoff issuer, limiter) returns the fixture error, with the chain's logger set to a capturing handler. Each row asserts the record exists, contains neither value, carries its `reason` (`attempt-store`, `session-store`, `handoff-issue`, `end-session`, `limiter`) exactly once and `error_type`, no record repeats a key, and the limiter rows still carry `flow`. One row drives a source over its limit and asserts the throttle record's `source` is the client address.
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

**Files:** Modify `magiclink/manager.go` (issued-count, issue, send, resolver, user-loader and binding-nonce random-source records); Test `magiclink/failure_records_test.go` (new).

- [ ] **Step 1: Write the reproduction.** `TestMagicLinkFailureRecords`, one row per dependency returning the fixture error, capturing logger; assert neither value and the `reason` (`token-count`, `token-issue`, `sender`, `resolver`, `user-loader`, and `random-source` for a `WithRandom` reader that fails).
- [ ] **Step 2: Run on unchanged code.** Expected: FAIL.
- [ ] **Step 3: Implement** with `diag.Failure`.
- [ ] **Step 4: Run to verify it passes.** `go test -run TestMagicLinkFailureRecords -count=1 ./magiclink/ && go test -count=1 ./magiclink/`.
- [ ] **Step 5: Report.**

### Task 4.3: Rate-limiter failure records

**Files:** Modify `ratelimit/guard.go`; Test `ratelimit/failure_records_test.go` (new).

- [ ] **Step 1: Write the reproduction.** `TestGuardFailureRecords`: a limiter whose error names the key `magic-link|203.0.113.7` and the fixture address; the limiter-failure records, from `Check` and from `RecordFailure`, carry `flow`, `reason=limiter`, `error_type`, and neither the key text nor the address; a throttled source still writes its record with `source`.
- [ ] **Step 2: Run on unchanged code.** Expected: FAIL on the limiter row.
- [ ] **Step 3: Implement** with `diag.Failure("limiter", err)`.
- [ ] **Step 4: Run to verify it passes.** `go test -run TestGuardFailureRecords -count=1 ./ratelimit/ && go test -count=1 ./ratelimit/`.
- [ ] **Step 5: Report.**

### Task 5.1: OIDC failure records

**Files:** Modify `oidc/callback.go` (flow-store completion record), `oidc/handoff.go` (user-loader, store-find and store-consume records at redemption); Test `oidc/failure_records_test.go` (new).

- [ ] **Step 1: Write the reproduction.** `TestCallbackFailureRecords` (a flow store whose `Complete` returns an error quoting the handle, the state and the fixture address) and `TestHandoffFailureRecords` (rows: a user loader, a store `Find` and a store `Consume` returning the fixture error; the current value scrubbing misses the username, which is not among its values, and turns `u-123` into `[redacted]23`). Each record names `reason` once. Assert neither value, nor the handle or state, in any record.
- [ ] **Step 2: Run on unchanged code.** Expected: FAIL.
- [ ] **Step 3: Implement** with `diag.Failure("flow-store", err)`, `diag.Failure("user-loader", err)` and `diag.Failure("handoff-store", err)`. Leave `oidc/broker.go`'s `redact` untouched.
- [ ] **Step 4: Run to verify it passes.** `go test -run 'TestCallbackFailureRecords|TestHandoffFailureRecords' -count=1 ./oidc/ && go test -count=1 ./oidc/`.
- [ ] **Step 5: Report.**

### Task 5.2: Store failure records in `onetime`, `apikey`, `signingkey`

**Files:** Modify `onetime/manager.go`, `apikey/manager.go`, `signingkey/rotate.go`; Test one `failure_records_test.go` per package.

- [ ] **Step 1: Write the reproduction.** One table per package with its store returning the fixture error; assert neither value in any record, the public identifier (`token_id`, `key_id`) still present where it was, and `reason=token-store` / `key-store` / `signing-key-store`, with `error_type` naming the store's own error rather than the library's wrapping. `signingkey` also gets a row for a stored key that cannot be decoded: `reason=key-decode`, the key's `kid`, no key bytes.
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

### Task 5.4: Errors the smaller managers return

**Files:** Modify `policy/lockout.go` (`RecordFailure`, `Reset`, `PurgeExpired`), `ratelimit/guard.go` (`Check`), `notify/smtp.go` (the dial in `send`, and every exchange stage `exchange` returns: greeting, EHLO, STARTTLS, AUTH, MAIL, RCPT, DATA), `token/verifier.go` (the key-source call in `Verify`), `token/generator.go` (the signer's failure in `Generate`); Test `returned_errors_test.go` in each of the four packages (new).

**Interfaces:** Consumes `diag.Wrap(err error, text string, kinds ...error) error`. Produces no new API; each method's returned error text changes, its identity does not.

- [ ] **Step 1: Write the reproduction.** One table per package; each row calls the exported method with the dependency failing, and asserts on the returned error:

```go
var errFixture = errors.New("store: Key (username)=(alice@example.com) for user u-123")

func TestLockoutReturnedErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		call   func(ctx context.Context, p *policy.AccountLockoutPolicy) error
		assert func(t *testing.T, err error)
	}{
		{
			name: "recording a failure the store cannot write",
			call: func(ctx context.Context, p *policy.AccountLockoutPolicy) error {
				return p.RecordFailure(ctx, "alice@example.com")
			},
			assert: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "alice@example.com")
				assert.NotContains(t, err.Error(), "u-123")
				assert.ErrorIs(t, err, errFixture)
			},
		},
		// Reset, PurgeExpired: the same shape.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newLockoutWithFailingStore(t, errFixture) // typed mockgen store, every method returning errFixture
			tc.assert(t, tc.call(t.Context(), p))
		})
	}
}
```

  The `ratelimit` table also asserts `errors.Is(err, ratelimit.ErrThrottled)`; the `token` table asserts every sentinel `Verify` matched before for a key-source failure. `notify` drives `SMTPSender.Send` with a dialer (`DialFunc`) failing with the fixture, and with the scripted server rejecting each stage with a reply quoting the fixture values (`550 5.1.1 <alice@example.com>: Recipient address rejected, user u-123`).
- [ ] **Step 2: Run on unchanged code.** `go test -run 'Test.*ReturnedErrors' -count=1 ./policy/ ./ratelimit/ ./notify/ ./token/`. Expected: FAIL on `should not contain "alice@example.com"` in every row. A row that passes is reported and dropped.
- [ ] **Step 3: Implement.** Each site becomes `diag.Wrap`, keeping its text up to the `%w`, e.g.:

```go
	if err := p.store.RecordFailure(ctx, username, p.now()); err != nil {
		return diag.Wrap(err, "policy: record a failed attempt")
	}
```

  `ratelimit` keeps its sentinel as a kind: `diag.Wrap(err, "ratelimit: throttled: the limiter could not be consulted", ErrThrottled)`, with the text chosen so it still reads as the throttle refusal it was. Godoc of each method says a dependency's error comes back with fixed text and matches by identity.
- [ ] **Step 4: Run to verify it passes.** The same command, then `go test -race -count=1 ./policy/ ./ratelimit/ ./notify/ ./token/ ./httpsec/` (httpsec matches these by identity).
- [ ] **Step 5: Report.**

### Task 5.5: Errors `session` returns

**Files:** Modify `session/manager.go` (`Create`, `Load`, `Touch`, `Save`, `Delete`, `DeleteByUser`, `CountActiveByUser`, `DeleteExpired`, `DeleteByExternalSession`, `DeleteByUserAndExternalIssuer`, `Rotate`), `session/encrypted.go` (every method passing the inner store's or the cipher's error); Test `session/returned_errors_test.go` (new).

**Interfaces:** Consumes `diag.Wrap`. Produces: each method's error matches the store's error and every session sentinel it matched before; a store returning a session sentinel bare (`ErrSessionNotFound`, and any other the package defines for stores to return — list them with gopls references on the package's exported errors) gets that same value back.

- [ ] **Step 1: Write the reproduction.** `TestSessionReturnedErrors`, one row per method, over a typed mockgen `Store` (and a failing `Cipher` for the encrypted-store rows) returning the fixture. Assert: text contains neither value; `errors.Is(err, errFixture)`. Add one row per session sentinel a store may return bare, asserting `assert.Same`-style identity (`err == session.ErrSessionNotFound`) and unchanged text. Every row also asserts the text carries no session identifier: `Session.ID` is the bearer credential, and `http-error-propagation` forbids a session handle in a refusal's text (the encrypted store's Seal, Open and invalid-envelope errors formatted it in).
- [ ] **Step 2: Run on unchanged code.** `go test -run TestSessionReturnedErrors -count=1 ./session/`. Expected: the fixture rows FAIL on the text; the bare-sentinel rows pass (they pin what must not change).
- [ ] **Step 3: Implement.** A package-level helper keeps the kinds in one place:

```go
// storeFailed hides a store's text behind fixed library text. A sentinel the
// store returned bare comes back as itself; anything else is wrapped with no
// kinds, since a kind would make every outage match that sentinel.
func storeFailed(err error, text string) error {
	for _, bare := range []error{ErrSessionNotFound, ErrSessionExpired, ErrSessionUnreadable} {
		if err == bare { //nolint:errorlint // identity: only a bare sentinel carries no store text
			return err
		}
	}

	return diag.Wrap(err, text)
}
```

  and each method returns `storeFailed(err, "session: the session could not be loaded")` and so on. Replace godoc saying "the store's own error" with "the store's error, behind fixed text, still matching by identity".
- [ ] **Step 4: Run to verify it passes**, then `go test -race -count=1 ./...` in the core module. Report, without fixing, any failure outside `session/` (for example a test asserting a session error's old text).
- [ ] **Step 5: Report.**

### Task 5.6: Errors `mfa` returns

**Files:** Modify `mfa/totp.go` (`Verify`, `Enrolled`, `BeginEnrolment`/`BeginEnrolmentGeneration`, `ConfirmEnrolment`, `RemoveEnrolment`), `mfa/enroller.go` (`ProveDevice`, `CompleteEnrolment`, `RedeemEmailCode`), `mfa/reset.go` (`ResetEnrolment`'s remover, revoker, loader, contact and sender); Test `mfa/returned_errors_test.go` (new).

**Interfaces:** Consumes `diag.Wrap`. `VoidEmailCode` is unchanged: it passes the method's own contract error (design decision 8).

- [ ] **Step 1: Write the reproduction.** `TestMFAReturnedErrors`, one row per method and dependency, in the shape of Task 5.4's table, over typed mockgen `EnrolmentStore`, `DeviceProofStore`, `EnrolmentRemover`, `SessionRevoker`, `identity.UserLoader` and `notify.Sender` doubles returning the fixture. Plus one row per `mfa` sentinel a store may return bare (`ErrNotEnrolled` and the others the store contracts name), asserting identity and unchanged text.
- [ ] **Step 2: Run on unchanged code.** `go test -run TestMFAReturnedErrors -count=1 ./mfa/`. Expected: fixture rows FAIL on the text.
- [ ] **Step 3: Implement** with one helper per store contract, as in Task 5.5, returning that contract's bare sentinels by identity and wrapping everything else with no kinds; fixed texts in the package's words (`"mfa: the enrolment could not be read"`, `"mfa: reset could not remove the enrolment"`, ...). Update godoc that says "a store failure is returned as itself".
- [ ] **Step 4: Run to verify it passes**, then `go test -race -count=1 ./mfa/ ./httpsec/ ./policy/`.
- [ ] **Step 5: Report.**

### Task 5.7: Errors the remaining managers return

**Files:** Modify `onetime/manager.go` (`Issue`, `IssuedCount`, `PurgeExpired`), `apikey/manager.go` (`Issue`, `List`, `Revoke`, `Rotate`), `signingkey/manager.go` (construction's `LoadAll` and `Store`), `oidc/authorize.go` (flow begin), `oidc/callback.go` (`completeFlow`, for `Callback`, which keeps `ErrFlowUnspent` joined, and `AbortFlow`), `oidc/handoff.go` (`Issue`), `oidc/passwordclaim.go` (the encoder probe `NewBroker` runs), `authenticate/password.go` (reference-hash probe; its credential cleanup cannot fail and is left alone), `authenticate/jwt.go` (credential cleanup); Test `returned_errors_test.go` per package (new).

**Interfaces:** Consumes `diag.Wrap`. Unchanged: `oidc` broker scrubbing (`broker.go` `redact`, `provision.go`), `authenticate.Manager.Authenticate` (the consumer's authenticator's error), the JWT verifier's joined error (a stated exception).

- [ ] **Step 1: Write the reproduction.** One table per package, in the shape of Task 5.4's, one row per method listed, with the dependency failing with the fixture. `apikey.Rotate`'s revoke-failure row asserts the key identifiers are still in the text and the fixture is not. `oidc.Callback`'s row asserts `errors.Is(err, oidc.ErrFlowUnspent)` still holds. Bare-sentinel rows for each store's not-found sentinel.
- [ ] **Step 2: Run on unchanged code.** `go test -run 'Test.*ReturnedErrors' -count=1 ./onetime/ ./apikey/ ./signingkey/ ./oidc/ ./authenticate/`. Expected: FAIL on the text in every fixture row.
- [ ] **Step 3: Implement** with `diag.Wrap`, keeping each text up to the `%w` and, for `apikey.Rotate`, formatting the identifiers into the fixed text before wrapping:

```go
	return diag.Wrap(err, fmt.Sprintf("apikey: rotated key %s was issued but %s could not be revoked", newID, oldID))
```

- [ ] **Step 4: Run to verify it passes**, then `go test -race -count=1` over the five packages and `./httpsec/`.
- [ ] **Step 5: Report.**

### Task 5.8: Errors `authorize` returns

**Files:** Modify `authorize/privilege.go` (the `RoleLoader` failure in the privilege lookup); Test `authorize/returned_errors_test.go` (new), and two rows in `httpsec/returned_errors_test.go`.

**Interfaces:** Consumes `diag.Wrap`. The consumer's own authorizers are unchanged (decision 5).

- [ ] **Step 1: Write the reproduction.** `TestAuthorizeReturnedErrors`: a `PrivilegeAuthorizer` over a `RoleLoader` failing with the fixture; the returned error's text contains neither value, `errors.Is(err, errFixture)` holds, and it matches no `authorize` sentinel it did not match before. In `TestReturnedErrorsCarryFixedText`, a `ResourcePrivileges` guard over that authorizer: status 500 as at HEAD, no fixture text; and a login whose lockout policy's attempt store fails: text free of the fixture, `errors.Is` finds the fixture and `policy.ErrPolicyDenied`, status 403.
- [ ] **Step 2: Run on unchanged code.** `go test -run TestAuthorizeReturnedErrors -count=1 ./authorize/`. Expected: FAIL on `should not contain "alice@example.com"` (the text reads `authorize: load privileges for role "editor": store: ...`). The attempt-store row passes already (task 5.3 fixed it at the policy) and is kept as the scenario's HTTP-level pin.
- [ ] **Step 3: Implement.**

```go
	if err != nil {
		return diag.Wrap(err, "authorize: the role's privileges could not be loaded")
	}
```

- [ ] **Step 4: Run to verify it passes**, then `go test -race -count=1 ./authorize/ ./httpsec/`.
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

### Task 7.3: Lint guard

**Files:** Modify `.golangci.yml` (root, and the nested modules' configs if they have their own); annotate `httpsec/bearer.go`, `httpsec/oidc_backchannel.go`, `oidc/callback.go`, `oidc/keycache.go`, `oidc/broker.go`, `oidc/mirror.go`, `oidc/provision.go`; replace sentinel-text uses in `httpsec/mfaenrol.go` and `session/encrypted.go` with constants.

- [ ] **Step 1:** Add `forbidigo` with `analyze-types: true` and patterns `^error\.Error$` and `^slog\.Any$`, excluding `internal/diag`, `_test\.go` and the `test` module. Run `golangci-lint run ./...` and record every hit.
- [ ] **Step 2:** Annotate each stated exception with `//nolint:forbidigo // <the exception and why>`; rewrite each sentinel-text use to a constant. Anything else flagged is a finding: report it rather than annotating it.
- [ ] **Step 3:** Show the rule works: add `slog.Any("error", err)` to a non-exempt package, see it flagged, remove it.
- [ ] **Step 4:** `golangci-lint run ./...` in every module: 0 issues; `go test -count=1 ./...` green.

### Task 7.2: Final gate and whole-branch review (main session)

- [ ] **Step 1:** In each of `.`, `ginsec`, `fibersec`, `test`: `go test -race -count=1 ./...`, `go vet ./...`, `gofmt -l .` (empty, ignoring `.claude/`), `golangci-lint run ./...` (0 issues).
- [ ] **Step 2:** `rg --glob '!.claude' --glob '!*_test.go' -n 'err(or)?\.Error\(\)' .` — every remaining hit is either library-controlled text, a deliberate exception from design decision 6, or outside a log record and returned error; list any other in the review.
- [ ] **Step 3:** Dispatch a fresh reviewer against every requirement in `specs/`, `design.md` decisions 1–7 and this plan's Review Focus. Every defect it claims needs a failing test, or is labelled `UNREPRODUCED`. Resolve its findings before archive.
