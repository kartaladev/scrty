# Request Input and Log Flush Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session never writes code: every task is dispatched to a subagent under `.claude/rules/subagent-delegation.md`, and the subagent reports; it never commits and never edits anything under `openspec/`.

**Goal:** No library credential read accepts the URL query on any adapter, every adapter reads a form field with the same precedence, and one `Chain.FlushRefusalLogs` call reports every suppressed log count the chain can reach.

**Architecture:** The verify endpoint reads `code` through the body-only reader the enrolment endpoints already use, moved to a shared file. fibersec's `FormValue` reads the posted form before the query. The OIDC components and the policy engine gain a flush; the chain walks its registrations through an unexported flusher interface and flushes the engine.

**Tech Stack:** Go 1.27; the core module `github.com/kartaladev/scrty` (`httpsec`, `oidc`, `policy`, `mfa`, `ratelimit`, `authenticate`, `pkg/logsample`); the nested modules `fibersec` (fiber v3), `ginsec` and `test` (framework conformance); uber-go/mock (`mockgen --typed`).

**Spec:** `openspec/changes/request-input-and-log-flush/`: `proposal.md`, `design.md` (decisions 1–5), `specs/{multi-factor-auth,framework-adapters,http-security-chain,oidc-login}/spec.md`, `tasks.md`. Plan task numbers are `tasks.md` numbers.

## Global Constraints

- Test-first on every task: write the test, run it, see it fail **for the intended reason** (a compile error is not a red step), implement, see it pass (`.claude/rules/golang-tdd.md`).
- Table tests use the `table-test` skill's `assert` closure form and `t.Context()`; mocks come from the `use-mockgen` skill.
- Defect claims (`.claude/rules/defect-claims.md`): tasks 1.1 and 2.1 start with the reproduction of an `UNREPRODUCED` claim. If it passes on unchanged code, stop and report; do not implement the decision.
- Library design: every changed default is named in godoc; nothing is accepted and silently degraded.
- Core module tests never import the `test` module.
- Never log a presented code.
- Nothing is copied from, or cites, the read-only reference.
- Verification a subagent runs before reporting: the task's focused `go test -run ... -count=1`, then `go test -count=1 ./<pkg>/`, `go vet ./<pkg>/`, `gofmt -l <pkg>` (empty).

## Review Focus

1. **A code in both body and query on fiber.** The body wins after 2.1, and the verify endpoint never reads the query at all after 1.1. Test added to task 1.2 (the conformance scenario runs a wrong body code plus a valid query code on every adapter and expects `ErrInvalidCode`).
2. **A locked-out user posting an unreadable body.** The throttle's check still runs first, so the answer is the throttle refusal, not 400. Test added to task 1.1.
3. **A policy registered for two phases.** `Engine.FlushRefusalLogs` flushes it once, from `asked`, not once per phase. Test added to task 4.1.
4. **A component shared by two chains.** The chain builds every source guard itself, so the shared case is a consumer component given to two chains — an authenticator behind form login on one chain and Basic on another, or one limiter behind two chains' guards. Both chains flushing reports the pending count once. Test added to task 4.2 (rows "a limiter shared by two chains" and "an authenticator shared by two chains").
5. **An OIDC chain with `WithCallbackSuccess` and no handoff manager.** The flush skips the nil handoff manager without panicking. Test added to task 4.2.

---

## File Structure

| File | Responsibility | Tasks |
|---|---|---|
| `httpsec/postedfield.go` (new) | `postedField`, `declaresForm`, the body limit, moved from `mfaenrol.go` | 1.1 |
| `httpsec/mfaenrol.go` | calls the moved helper | 1.1 |
| `httpsec/mfaverify.go` | reads `code` through `postedField`; the flusher (its throttle) | 1.1, 4.2 |
| `httpsec/mfaverify_bodyonly_test.go` (new) | table for 1.1 | 1.1 |
| `httpsec/options.go` | `EnableMFA` godoc | 1.3 |
| `test/httpsecconformance/request_scenarios.go` (new), `scenarios.go` | verify-in-query and form-precedence scenarios | 1.2, 2.1 |
| `fibersec/exchange.go` | `FormValue` precedence | 2.1 |
| `httpsec/exchange.go` | `Request.FormValue` godoc | 2.1 |
| `oidc/handoff.go`, `oidc/broker.go`, `oidc/manager.go` | `FlushRefusalLogs() error` | 3.1, 3.2 |
| `oidc/flush_test.go` (new) | tables for 3.1, 3.2 | 3.1, 3.2 |
| `policy/engine.go`, `policy/engine_test.go` | `(*Engine).FlushRefusalLogs()` | 4.1 |
| `httpsec/throttle.go` | `Flush()` on the `sourceGuard` seam | 4.2 |
| `httpsec/chain.go` | `FlushRefusalLogs` walks flushers; godoc | 4.2, 4.3 |
| `httpsec/apikey.go`, `magiclink.go`, `oidc.go`, `login.go`, `basic.go`, `mfaenrol.go` | each implements the unexported `refusalLogFlusher` | 4.2 |
| `httpsec/flush_test.go` (new) | table for 4.2 | 4.2 |

## Dispatch Lanes (for the main session)

| Lane | Tasks | Owns | Must not touch | Model | Why |
|---|---|---|---|---|---|
| A1 | 1.1–1.3 | `httpsec/postedfield.go`, `mfaverify.go` (read path), `mfaenrol.go` (call site), `options.go` (`EnableMFA` godoc), their tests, `test/httpsecconformance/request_scenarios.go` + the list in `scenarios.go` | `fibersec/`, `oidc/`, `policy/`, `httpsec/chain.go`, `throttle.go` | Opus | credential read on a security endpoint; the throttle's order must not move |
| A2 | 2.1 | `fibersec/exchange.go`, `httpsec/exchange.go` (godoc), `test/httpsecconformance/request_scenarios.go` | everything else | Sonnet | a single adapter method against a stated precedence, pinned by conformance |
| B | 3.1–3.2, 4.1 | `oidc/`, `policy/engine.go` + test | `httpsec/`, `fibersec/` | Sonnet | option plumbing over existing samplers; well specified |
| C | 4.2–4.3 | `httpsec/chain.go`, `throttle.go`, the flusher methods in `apikey.go`, `magiclink.go`, `oidc.go`, `login.go`, `basic.go`, `mfaenrol.go`, `mfaverify.go`, `httpsec/flush_test.go` | `oidc/`, `policy/`, `fibersec/` | Opus | an interface other lanes' types satisfy; touches several interceptors |

A1 and B run **in parallel** (no shared files). A2 runs after A1 (both edit `request_scenarios.go`). C runs after A1 and B (it calls `oidc` and `policy` flushes, and edits `mfaverify.go` after A1). After each dispatch the main session runs its verification, then a fresh reviewer checks the diff. Task 5.1 is the main session's; 5.2 is the final gate.

---

### Task 1.1: The verify endpoint reads its code from the body only

**Files:** Create `httpsec/postedfield.go`; Modify `httpsec/mfaenrol.go` (remove `postedField`, `declaresForm` and the body-limit constant, now in the new file), `httpsec/mfaverify.go:156`; Test `httpsec/mfaverify_bodyonly_test.go`.

**Interfaces:**
- Consumes: `postedField(r Request, name string) (string, error)` as it exists in `mfaenrol.go` today, unchanged.
- Produces: the same helper at package level in `postedfield.go`, used by the verify and enrolment endpoints.

- [ ] **Step 1: Write the reproduction (the `UNREPRODUCED` claim).** In `mfaverify_bodyonly_test.go`, `TestVerifyReadsBodyOnly` with the existing verify test harness (see `mfaverify_test.go` for how a pending session and a TOTP code are built). A table:

```go
type testCase struct {
	name    string
	request func(t *testing.T, code string) httpsec.Request // builds the POST to /mfa/totp
	assert  func(t *testing.T, err error, pending bool, failures int)
}
cases := []testCase{
	{name: "a valid code in the query only", request: queryOnly, assert: missingUncounted},
	{name: "a wrong code in the body and a valid one in the query", request: wrongBodyValidQuery,
		assert: func(t *testing.T, err error, pending bool, failures int) {
			require.ErrorIs(t, err, mfa.ErrInvalidCode)
			assert.True(t, pending)
			assert.Equal(t, 1, failures)
		}},
	{name: "multipart", request: multipart, assert: missingUncounted},
	{name: "JSON", request: jsonBody, assert: missingUncounted},
	{name: "empty body", request: emptyBody, assert: missingUncounted},
	{name: "no code field", request: otherField, assert: missingUncounted},
	{name: "a body that does not parse", request: brokenForm, assert: missingUncounted},
	{name: "a body over the limit", request: oversized,
		assert: func(t *testing.T, err error, pending bool, failures int) {
			require.ErrorIs(t, err, httpsec.ErrRequestTooLarge)
			assert.Equal(t, 0, failures)
		}},
	{name: "a valid URL-encoded code", request: formBody,
		assert: func(t *testing.T, err error, pending bool, failures int) {
			require.NoError(t, err)
			assert.False(t, pending)
		}},
}
// missingUncounted: require.ErrorIs(err, httpsec.ErrCredentialsMissing);
// assert.True(pending); assert.Equal(0, failures).
// failures is read from a counting limiter passed through WithMFAVerifyLimiter
// (or the existing throttle option; check go doc ./httpsec EnableMFA).
```

Add the Review Focus 2 row: a user already locked out by the throttle posts an empty body → the throttle's refusal (`mfa.ErrVerifyThrottled`), not 400.

- [ ] **Step 2: Run on unchanged code.** `go test -run TestVerifyReadsBodyOnly -count=1 ./httpsec/`. Expected: "a valid code in the query only" FAILS because it verifies (`err` nil), and "a wrong code in the body and a valid one in the query" FAILS on fiber-like precedence only if the harness adapter prefers the query; on net/http it already passes. The multipart, JSON, empty and no-field rows fail with `ErrInvalidCode` and one failure counted. **This reproduces the claim; record it.** If the query-only row passes, stop and report.
- [ ] **Step 3: Move the helper.** Cut `postedField`, `declaresForm` and the body-limit constant from `mfaenrol.go` into `postedfield.go` unchanged, with a package comment line saying every library credential read that takes a form field goes through it. Run `go test -count=1 -run 'TestEnrolment' ./httpsec/`: PASS.
- [ ] **Step 4: Implement.** In `mfaverify.go`:

```go
	if err := i.throttle.Check(ctx, user); err != nil {
		return err
	}

	code, err := postedField(ex.Request, "code")
	if err != nil {
		return err // 400 or 413; not a guess, so not recorded
	}

	if err := i.method.Verify(ctx, user, code); err != nil {
		i.throttle.RecordFailure(ctx, user)

		return err
	}
```

Update the numbered comment above `verify` (step 4 now reads the code from the body first).
- [ ] **Step 5: Run.** `go test -run 'TestVerifyReadsBodyOnly|TestMFAVerify' -count=1 ./httpsec/ && go test -count=1 ./httpsec/`. Expected: PASS. Any existing verify test that posted the code another way is fixed to post a URL-encoded body.
- [ ] **Step 6: Report**, with the reproduction output labelled `REPRODUCED`.

### Task 1.2: Conformance: a code in the verify query is refused on every adapter

**Files:** Create `test/httpsecconformance/request_scenarios.go`; Modify `test/httpsecconformance/scenarios.go` (append `requestScenarios()...` to the list `Run` iterates).

- [ ] **Step 1: Write the scenarios** in the existing `Scenario` shape (see `enrolment_scenarios.go` for a pending-MFA session built directly): "a verify code in the query is not read" (valid code only in the query → the missing-credentials status, 400, and the session still MFA pending), and Review Focus 1, "the verify body code wins over the query" (wrong code in the body, valid in the query → 401 invalid code).
- [ ] **Step 2: See them fail.** Temporarily revert step 4 of task 1.1 (edit back `FormValue("code")`), run `cd test && go test -run TestConformance -count=1 .`: expect the first scenario to fail on all three adapters (200), and the second to fail on fiber. Restore by editing.
- [ ] **Step 3: Run.** `cd test && go test -run TestConformance -count=1 .`. Expected: PASS on net/http, gin and fiber.
- [ ] **Step 4: Report.**

### Task 1.3: Godoc on `EnableMFA`

**Files:** Modify `httpsec/options.go` (or wherever `EnableMFA` is declared; `go doc ./httpsec EnableMFA` locates it).

- [ ] **Step 1:** Add a paragraph: "The verify endpoint reads only the `code` field of an `application/x-www-form-urlencoded` POST body. A code in the URL query is never read, because a URL reaches access logs, proxy logs and the Referer header. A body that carries no code, is not such a form, or does not parse is refused with ErrCredentialsMissing (400) and is not counted against the verification throttle. This is a limit, not a default: there is no option to read another encoding."
- [ ] **Step 2:** `go doc ./httpsec EnableMFA` shows it; `go vet ./...` clean.

### Task 2.1: fiber reads a form field with net/http's precedence

**Files:** Modify `fibersec/exchange.go` (`FormValue`, and its comment), `httpsec/exchange.go` (`Request.FormValue` godoc); Modify `test/httpsecconformance/request_scenarios.go`.

- [ ] **Step 1: Write the reproduction (the `UNREPRODUCED` claim).** Three scenarios in `request_scenarios.go`, each registering a consumer interceptor that answers 200 with the value `ex.Request.FormValue("x")` returned:
  - "a form field in body and query" (URL-encoded body `x=body`, query `x=query`) → body `body`;
  - "a form field in the query only" (body without `x`, query `x=query`) → `query`;
  - "a form field in a multipart body" (multipart `x=body`, query `x=query`) → `body`.
- [ ] **Step 2: Run on unchanged code.** `cd test && go test -run TestConformance -count=1 .`. Expected: the first and third FAIL on fiber only, answering `query`. **Record it as `REPRODUCED`.** If fiber already answers `body`, stop and report.
- [ ] **Step 3: Implement.**

```go
// FormValue reads a submitted field with the precedence every adapter shares:
// the posted form first — URL-encoded, then multipart, parsed under the app's
// own BodyLimit — and the URL query only when the body does not carry it. It
// deliberately does not call fiber's own FormValue, which searches the query
// first.
func (r request) FormValue(name string) string {
	if v := r.c.Request().PostArgs().Peek(name); v != nil {
		return string(v)
	}

	if form, err := r.c.MultipartForm(); err == nil {
		if vs := form.Value[name]; len(vs) > 0 {
			return vs[0]
		}
	}

	return string(r.c.Request().URI().QueryArgs().Peek(name))
}
```

(Confirm the fiber v3 accessors with `go doc github.com/gofiber/fiber/v3 Ctx` from inside `fibersec/`; adjust names if they differ, keeping the order.) Update `httpsec.Request.FormValue`'s godoc: "Every adapter the library provides looks in the posted form first and falls back to the URL query. The library's own credential reads never use FormValue; they read the body."
- [ ] **Step 4: Run.** `cd test && go test -run TestConformance -count=1 . && cd ../fibersec && go test -count=1 ./...`. Expected: PASS.
- [ ] **Step 5: Report.**

### Task 3.1: `HandoffManager` and `Broker` flush their refusal logs

**Files:** Modify `oidc/handoff.go`, `oidc/broker.go`; Test `oidc/flush_test.go`.

**Interfaces:** Produces `func (h *HandoffManager) FlushRefusalLogs() error` and `func (b *Broker) FlushRefusalLogs() error`.

- [ ] **Step 1: Write the failing test.** `TestHandoffManagerFlushRefusalLogs` and `TestBrokerFlushRefusalLogs`, each a table over a component built with a capturing slog handler (the reporter writes a summary record; see `reportSuppressed` in each file for its message and attributes):
  - three refusals of one reason within a window, then a flush → one summary record carrying a suppressed count of 2;
  - a flush with nothing pending → no summary record;
  - a refusal after the flush → written (the key was forgotten).
  Trigger refusals the way the existing tests do (a redemption of an unknown code for the handoff manager; a refused provisioning for the broker).
- [ ] **Step 2: Run to verify it fails.** Add stubs `func (h *HandoffManager) FlushRefusalLogs() error { return nil }` (and the broker's) so it compiles. `go test -run 'TestHandoffManagerFlushRefusalLogs|TestBrokerFlushRefusalLogs' -count=1 ./oidc/`. Expected: FAIL, no summary record.
- [ ] **Step 3: Implement.**

```go
// FlushRefusalLogs reports every refusal record the handoff manager's sampler
// has suppressed but not yet counted, then forgets every key. It returns no
// error; the signature matches the other components' flushes. Call it at
// shutdown, or let the chain call it (httpsec.Chain.FlushRefusalLogs).
func (h *HandoffManager) FlushRefusalLogs() error {
	h.sampler.Flush()

	return nil
}
```

The broker's is the same over `b.sampler`.
- [ ] **Step 4: Run to verify it passes.** Then `go test -count=1 ./oidc/`.
- [ ] **Step 5: Report.**

### Task 3.2: `Manager` flushes itself and its broker

**Files:** Modify `oidc/manager.go`; Test `oidc/flush_test.go`.

**Interfaces:** Produces `func (m *Manager) FlushRefusalLogs() error`.

- [ ] **Step 1: Write the failing test.** `TestManagerFlushRefusalLogs`: a manager with suppressed refusals of its own reports them on flush; a manager built with a `*Broker` that has suppressed refusals reports the broker's too; a manager built with a consumer `IdentityBroker` that has no flush flushes without error.
- [ ] **Step 2: Run to verify it fails** against a stub returning nil.
- [ ] **Step 3: Implement.**

```go
func (m *Manager) FlushRefusalLogs() error {
	m.sampler.Flush()

	if f, ok := m.broker.(interface{ FlushRefusalLogs() error }); ok {
		return f.FlushRefusalLogs()
	}

	return nil
}
```

Godoc names the broker behaviour.
- [ ] **Step 4: Run.** `go test -run TestManagerFlushRefusalLogs -count=1 ./oidc/ && go test -count=1 ./oidc/`.
- [ ] **Step 5: Report.**

### Task 4.1: The policy engine flushes its policies

**Files:** Modify `policy/engine.go`; Test `policy/engine_test.go`.

**Interfaces:** Produces `func (e *Engine) FlushRefusalLogs()`.

- [ ] **Step 1: Write the failing test.** `TestEngineFlushRefusalLogs`, a table with a recording `RefusalLogFlusher` double (a `MockPolicy` plus a flush counter, or a small typed mock via `use-mockgen` for an interface combining `Policy` and `RefusalLogFlusher`):
  - two flushable policies → each flushed once;
  - a policy without a flush → skipped, no panic;
  - Review Focus 3: a flushable policy registered for two phases → flushed once;
  - a flushable policy added after a first flush → flushed by the next.
- [ ] **Step 2: Run to verify it fails** against an empty method.
- [ ] **Step 3: Implement** over `e.asked`, which already holds each policy once:

```go
// FlushRefusalLogs asks every registered policy that keeps a refusal-log
// sampler to report what it has suppressed. A policy registered for several
// phases is flushed once. It is safe to call at shutdown while requests are
// still evaluated, since each policy's flush is.
func (e *Engine) FlushRefusalLogs() {
	for _, p := range e.asked {
		if f, ok := p.(RefusalLogFlusher); ok {
			_ = f.FlushRefusalLogs() // documented never to fail
		}
	}
}
```

- [ ] **Step 4: Run.** `go test -run TestEngineFlushRefusalLogs -count=1 ./policy/ && go test -count=1 ./policy/`.
- [ ] **Step 5: Report.**

### Task 4.2: One chain flush reaches every sampler it holds

**Files:** Modify `httpsec/throttle.go` (seam), `httpsec/chain.go` (`FlushRefusalLogs`), and add a `flushRefusalLogs()` method to `apiKeyInterceptor`, `magicLinkInterceptor`, `oidcInterceptor`, `formLogin`, `basicAuth`, `mfaInterceptor`, `enrolmentInterceptor`; Test `httpsec/flush_test.go`.

**Interfaces:**
- Consumes: `(*oidc.Manager).FlushRefusalLogs`, `(*oidc.HandoffManager).FlushRefusalLogs` (3.1–3.2), `(*policy.Engine).FlushRefusalLogs` (4.1), `(*mfa.VerifyThrottle).FlushRefusalLogs`, `(*ratelimit.SourceGuard).Flush`, `authenticate.RefusalLogFlusher`.
- Produces, unexported:

```go
// refusalLogFlusher is implemented by an interceptor that holds a component
// keeping its own refusal-log sampler.
type refusalLogFlusher interface{ flushRefusalLogs() }
```

- [ ] **Step 1: Write the failing test.** `TestFlushRefusalLogsReachesComponents`: one chain per row, each component configured with a one-hour log interval and a counting reporter (or a capturing slog handler), refusals driven through the chain until each has suppressed at least one record, then a single `chain.FlushRefusalLogs()`:
  - the verification throttle (wrong codes past the first);
  - a chain-built magic-link source guard (throttled source);
  - a source guard built over a consumer-supplied limiter (`WithMagicLinkLimiter`, `WithHandoffLimiter` or `WithAPIKeyLimiter`; there is no option to supply a guard itself), and Review Focus 4: a component shared by two chains, both flushed → the pending count reported once;
  - the password authenticator of form login;
  - a second-factor policy on the engine (the lockout policy keeps no sampler);
  - the OIDC manager and handoff manager;
  - Review Focus 5: an OIDC chain with `WithCallbackSuccess` and no handoff manager → no panic.
  Each row asserts its component's reporter received its pending count.
- [ ] **Step 2: Run to verify it fails.** `go test -run TestFlushRefusalLogsReachesComponents -count=1 ./httpsec/`. Expected: FAIL on every row except the enrolment path (already flushed).
- [ ] **Step 3: Implement.**
  - `throttle.go`: add `Flush()` to the `sourceGuard` interface (the real guard has it; the compile-time assertion keeps them in step).
  - Each interceptor:

```go
func (i *magicLinkInterceptor) flushRefusalLogs() {
	if i.guard != nil {
		i.guard.Flush()
	}
}

func (i *oidcInterceptor) flushRefusalLogs() {
	if i.guard != nil {
		i.guard.Flush()
	}
	if i.manager != nil {
		_ = i.manager.FlushRefusalLogs()
	}
	if i.handoffs != nil {
		_ = i.handoffs.FlushRefusalLogs()
	}
}

func (i *mfaInterceptor) flushRefusalLogs() {
	if i.throttle != nil {
		_ = i.throttle.FlushRefusalLogs()
	}
}

func (l *formLogin) flushRefusalLogs() {
	if f, ok := l.authn.(authenticate.RefusalLogFlusher); ok {
		_ = f.FlushRefusalLogs()
	}
}
// apiKeyInterceptor: its guard, as magic link. basicAuth: its authn, as form
// login. enrolmentInterceptor: i.sampler.Flush(), moving today's special case.
```

  - `chain.go`:

```go
func (c *Chain) FlushRefusalLogs() {
	c.sampler.Flush()

	for _, r := range c.registrations {
		if f, ok := r.interceptor.(refusalLogFlusher); ok {
			f.flushRefusalLogs()
		}
	}

	if c.engine != nil {
		c.engine.FlushRefusalLogs()
	}
}
```

  Remove the old `*enrolmentInterceptor` type switch.
- [ ] **Step 4: Run.** `go test -run TestFlushRefusalLogsReachesComponents -count=1 ./httpsec/ && go test -race -count=1 ./httpsec/`. Expected: PASS.
- [ ] **Step 5: Report.**

### Task 4.3: `FlushRefusalLogs` godoc

**Files:** Modify `httpsec/chain.go`.

- [ ] **Step 1:** Replace the godoc with one that lists, in order, what the call reaches (design decision 3's list), states that a flush reports pending counts and forgets keys so repeating it or flushing a component directly as well is harmless, and names what is not reached: a component the consumer built but never gave the chain, and `signingkey.KeyManager`, which flushes when its background loops stop. Remove the claims the audit found false (that the throttle and guards have no flush; that the chain's sampler carries every built-in refusal).
- [ ] **Step 2:** `go doc ./httpsec Chain.FlushRefusalLogs` matches design decision 3; `go vet ./...` clean.

### Task 5.1: Delta order with `mfa-enrolment-path` (main session)

- [ ] **Step 1:** If `mfa-enrolment-path` has archived, rewrite this change's `multi-factor-auth` MODIFIED requirement from the promoted spec plus this change's sentence; otherwise confirm `mfa-enrolment-path`'s `design.md` records that its delta must carry this change's sentence. Then `openspec validate request-input-and-log-flush --strict`.

### Task 5.2: Final gate and whole-branch review (main session)

- [ ] **Step 1:** In each of `.`, `ginsec`, `fibersec`, `test`: `go test -race -count=1 ./...`, `go vet ./...`, `gofmt -l .` (empty, ignoring `.claude/`), `golangci-lint run ./...` (0 issues).
- [ ] **Step 2:** Dispatch a fresh reviewer against every requirement in `specs/`, `design.md` decisions 1–5 and this plan's Review Focus. Every defect it claims needs a failing test, or is labelled `UNREPRODUCED`. Resolve its findings before archive.
