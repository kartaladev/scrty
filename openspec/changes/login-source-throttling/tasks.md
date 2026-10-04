# Tasks

Every task is test-first: write the failing test, run it and see it fail for the intended reason (a
compile error is not a red step), make it pass, then refactor. Tables follow the project's
`table-test` skill. Test doubles come from `use-mockgen`; `httpsec` already has a typed
`MockAttemptStore`. Each task says how it is verified. A signature or default change owns every
caller and test it breaks across the workspace, so the workspace compiles and passes at the end of
every group. Names in parentheses are the spec requirements and design decisions the task covers.

Ownership:
- Group 2 changes `policy`, plus the `httpsec` tests that build a lockout policy (`returned_errors_test.go`, `recoverycomplete_test.go`).
- Group 3 changes `authenticate`.
- Groups 1 and 4 change `httpsec` login and Basic, and run in that order.
- Group 4 also changes `httpsec/status.go` and the tests that assert a lock's status, among them `recoverycomplete_test.go` (also group 2's) and `test/httpsecconformance/scenarios.go`.
- Groups 1, 2 and 3 may run in parallel. Group 4 needs groups 2 and 3.
- Task 4.4 also changes `recovery` (its error conversion), and task 4.5 also changes `authenticate` (`Manager.OffersDecoy`), both after groups 1–3 have landed.

## 1. Failures recorded on an uncancellable context (decision 4; http-security-chain "Login failures are counted even when the client disconnects")

- [x] 1.1 Red step for the `UNREPRODUCED` claim. Add `TestFormLogin_RecordsFailureOnUncancellableContext` and `TestBasicAuth_RecordsFailureOnUncancellableContext`, each using a `MockAttemptStore` whose `RecordFailure` returns `ctx.Err()` and a request context cancelled before recording, on the unchanged code. Record the failing output, or report that they pass. Verify with `go test -run 'Test(FormLogin|BasicAuth)_RecordsFailureOnUncancellableContext' -count=1 ./httpsec/`
- [x] 1.2 Only if 1.1 failed: record login and Basic failures on `context.WithoutCancel(ctx)`, and keep `Reset` on the request's context. If 1.1 passed, report it, and the main session removes decision 4 and this group. Verify with 1.1 passing and `go test -race -count=1 ./httpsec/...`

## 2. Escalating wait in the lockout policy (decision 2; security-policy MODIFIED "Accounts lock after repeated failures", "A locked account waits, and the wait escalates", "An account at the ceiling is refused until its failures age out", "A fixed lock is available as an option", "An account-locked refusal states the wait it owes")

- [x] 2.1 New options `WithLockoutWait(first, longest time.Duration)`, `WithLockoutCeiling(n int)` and `WithFixedLockout(threshold int, window time.Duration)`. The default window becomes 24 hours. Construction refuses with `ErrConfig`:
  - a non-positive threshold, window or first wait;
  - a longest wait shorter than the first;
  - a ceiling not above the threshold;
  - `WithFixedLockout` combined with any threshold, window, wait or ceiling option.

  `Window()` reports the effective window. Covers scenarios "Zero window", "Ceiling not above the threshold" and "Fixed lock with a wait option". Verify with `go test -race -run 'TestNewAccountLockoutPolicy|TestLockoutConfig' -count=1 ./policy/`
- [x] 2.2 Evaluate the escalating wait and the ceiling with `FailureCount`: one query below the threshold, and a second for the wait at or above it. Strictly-after semantics, so a failure exactly `wait` old no longer counts. Driven by the fake clock and the in-memory store. Update the existing lockout tests and the `httpsec` tests that build a default policy to the new semantics, keeping their intent. Covers scenarios "At the threshold", "Reset on success", "Store failure", "Consumer threshold", "First wait", "First wait served", "Doubled wait", "Longest wait", "One hundred failures" and "Consumer ceiling". Verify with `go test -race -count=1 ./policy/... ./httpsec/...`
- [x] 2.3 The fixed lock: with `WithFixedLockout`, deny at the threshold in the window regardless of the newest failure's age. Covers scenario "Fixed lock". Verify with `go test -race -run 'TestAccountLockout' -count=1 ./policy/`
- [x] 2.4 `*policy.LockoutError{Wait time.Duration}`, which `errors.Is` matches to `ErrAccountLocked` and which keeps the fixed text rule. It carries the escalated wait, and zero at the ceiling and under a fixed lock. Godoc on the policy and every option states its default, the NIST cap, and that `WithFixedLockout(5, 15*time.Minute)` restores the established behaviour. Covers scenarios "Wait carried" and "Ceiling carries none". Verify with `go test -race -count=1 ./policy/...` and `go doc ./policy AccountLockoutPolicy`

## 3. Decoy verification (decision 3; authentication "A refusal made before checking a password can cost the same password work")

- [x] 3.1 `authenticate.DecoyVerifier`, and `VerifyDecoy` on the username-and-password provider. It verifies the presented password against the reference hash through the configured encoder, never calls the user loader, reports nothing about the outcome, and returns `handled` true only for username-and-password credentials. Use the mockgen `Encoder` and `UserLoader` doubles. Covers scenario "Decoy through the password provider". Verify with `go test -race -run 'TestPasswordAuthenticator_VerifyDecoy' -count=1 ./authenticate/`
- [x] 3.2 `Manager.VerifyDecoy` offers the credentials to each delegate implementing `DecoyVerifier` in order, stops at the first that reports `handled`, and reports `false` when none does. Covers scenarios "Manager delegates" and "No provider offers it". Godoc on both. Verify with `go test -race -run 'TestManager_VerifyDecoy' -count=1 ./authenticate/` and `go doc ./authenticate DecoyVerifier`

## 4. The login guard and lock response in the chain (decisions 1, 3; http-error-propagation MODIFIED "One public table maps refusals to a status"; http-security-chain MODIFIED "Form login authenticates, applies policy and opens a session", MODIFIED "HTTP Basic authentication is stateless", "Password login is throttled per source", "A locked account's login refusal looks like a wrong password by default")

- [x] 4.1 One `password-login` source guard, built through `resolveSourceGuard` at the default 50 per 15 minutes and shared by form login and Basic.
  - It is checked after the credentials are read and before pre-authentication.
  - Authentication failures and account-locked refusals are recorded against the source.
  - A throttled Basic refusal carries `WWW-Authenticate`.
  - `WithLoginLimiter` and `WithBasicAuthLimiter` give an endpoint its own limiter; a nil value, typed nil included, is a configuration error naming the option.
  - The guard's sampler is flushed with the chain's.
  - Covers scenarios "Spraying one password across accounts", "Form and Basic share the allowance", "Successes spend nothing", "Locked refusals count", "Consumer limiter", "Factory namespace", "Unattributable source" and "Throttled source still challenged".

  Verify with `go test -race -run 'TestChain_PasswordLogin|TestBasicAuth|TestFormLogin' -count=1 ./httpsec/`
- [x] 4.2 The undisclosed lock response.
  - On a pre-authentication deny matching `ErrAccountLocked`, both endpoints call the authenticator's `VerifyDecoy` when it implements `DecoyVerifier`, and refuse with `errors.Join(authenticate.ErrAuthenticationFailed, reason)`. Basic sets its challenge header.
  - The status table's account-locked row moves from 423 to 429 (`httpsec/status.go`), and every test asserting 423 for a lock follows it: `status_test.go`, `login_test.go`, `basic_test.go`, `recoverycomplete_test.go` and `test/httpsecconformance/scenarios.go`. Covers http-error-propagation scenarios "Disclosed account lock" and "Concealed account lock".
  - `WithLockDisclosure()` refuses with the reason alone, mapped to 429, runs no decoy, and for Basic sets no challenge header.
  - `build` writes one WARN when locks are not disclosed and the login authenticator offers no decoy.
  - Covers scenarios "Locked account is not probed", "Default response", "Equal password work", "Disclosure chosen", "Disclosed Basic lock" and "Authenticator without a decoy".

  Verify with `go test -race -run 'TestChain_LockResponse|TestFormLogin|TestBasicAuth|TestStatusForError|TestRecoveryComplete' -count=1 ./httpsec/` and `go test -race -count=1 ./...` in `test`
- [x] 4.3 Godoc and package documentation:
  - `WithLoginLimiter`, `WithBasicAuthLimiter` and `WithLockDisclosure` state their defaults, the `password-login` namespace and the sharing between endpoints;
  - `EnableFormLogin` and `EnableBasicAuth` describe the new order of steps;
  - the `httpsec` package documentation lists the login guard among the limiter sites.

  Verify with `go doc ./httpsec WithLockDisclosure` and `go vet ./...`

- [x] 4.4 Account recovery's password proof conceals a lock (decision 3; account-recovery MODIFIED "A recovery needs two proofs of different kinds").
  - `checkPassword` refuses a lock as login does: unless locks are disclosed, it spends the decoy and returns the joined error.
  - `recovery` keeps the check's error beneath `ErrRefused` when converting an authentication failure, so `errors.Is(err, policy.ErrAccountLocked)` still holds and the status is 401.
  - With `WithLockDisclosure()` the recovery is refused with the lock alone (429) and no decoy runs.
  - Covers scenarios "Locked account" and "Locked account with locks disclosed".

  Verify with `go test -race -run 'TestRecoveryComplete|TestRecover' -count=1 ./httpsec/ ./recovery/`
- [x] 4.5 Review fixes for group 4.
  - `Manager.OffersDecoy() bool`, true when any delegate offers a decoy (nested managers asked in turn), and the build warning consults it. Covers authentication scenario "No provider offers it" and http-security-chain scenario "Authenticator without a decoy".
  - Basic sets `WWW-Authenticate` on every refusal the status table answers 401, including a stateless-phase challenge and a 401 pre-authentication refusal.
  - A Basic row for "Locked refusals count", seen to fail when the Basic lock branch does not record against the source.
  - Rewrap the over-long godoc lines in `httpsec/doc.go` and `WithRefusalLogInterval`.

  Verify with `go test -race -count=1 ./authenticate/... ./httpsec/...`

- [x] 4.6 After rebasing onto `limiter-key-bounds`: the `password-login` guard's IPv6 aggregate. Tests: with the default factory the chain asks for `password-login-ipv6-aggregate` at 200 per 15 minutes; addresses rotating across /64s inside one /56 exhaust it; a consumer limiter given through `WithLoginLimiter` that reports a policy gets an aggregate sized from it; one that reports none gets no aggregate and one construction warning naming the option, and with an explicit `WithIPv6Aggregate` construction fails. Godoc of `WithLoginLimiter` and `WithBasicAuthLimiter` states this. Verify with `go test -race -run 'TestChain_PasswordLogin' -count=1 ./httpsec/` and `go doc ./httpsec WithLoginLimiter`

- [x] 4.7 An endpoint given its own limiter runs under its own flow (`password-login:form`, `password-login:basic`), so its guard and IPv6 aggregate share nothing with the other endpoint. Red first: a conflict-checking factory in the httpsec tests (refusing one namespace with two policies, as the Redis factory does) makes `WithLoginLimiter(10/min)` plus a default Basic fail construction on the unchanged code; equal own limiters on both endpoints get separate aggregate buckets. Update the godoc of both options, the 4.6 rows' expected namespaces, and the WARN/refusal assertions. Covers http-security-chain scenario "Own limiter under a shared factory". Verify with `go test -race -run 'TestChain_PasswordLogin' -count=1 ./httpsec/`

## 5. Integration

- [ ] 5.1 Whole-workspace gate. Verify with:
  - `go build ./...`, `go vet ./...` and `go test -race -count=1 ./...` in every module of `go.work` (with Docker for the store and Redis conformance runs), plus `go test -race ./...` in `ginsec` and `fibersec`;
  - `gofmt -l .` empty;
  - `golangci-lint run ./...` clean.
- [ ] 5.2 Whole-branch review against every requirement in this change's spec deltas and design decisions 1–4. Verify by the review reporting no open finding.
