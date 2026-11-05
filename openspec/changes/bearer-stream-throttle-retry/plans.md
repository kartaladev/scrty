# Bearer Stream Throttle Retry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session dispatches every task to a subagent and reviews it (`.claude/rules/subagent-delegation.md`).

**Goal:** A bearer stream throttled by a per-request policy retries wherever the same request unthrottled opens.

**Architecture:** A bearer records its credential when its resolution ends in the existing `*perRequestThrottle` mark, so `streamByCookie` judges the request as a bearer. Nothing else records earlier.

**Tech Stack:** Go 1.27; testify; the existing `httpsec` stream rigs and `test/httpsecconformance`.

**Spec:** `openspec/changes/bearer-stream-throttle-retry/` (`proposal.md`, `design.md` D1, `specs/session-signals/spec.md`, `tasks.md`).

## Global Constraints

- Test-first: a red run failing on an assertion (`.claude/rules/golang-tdd.md`). Tables follow the `table-test` skill.
- No other refusal records a credential. A throttled cookie stream stays 403 and is not counted.
- The record happens only for an error carrying `*perRequestThrottle`, found with `errors.As`.
- Never read or cite `.claude/.legacy`. Never edit `openspec/` from an implementer.

## Review Focus

1. A wrong or expired bearer. Expected: `bearerCredential` stays empty and the answer is unchanged. Task 1.2.
2. A consumer's cookie authenticator that calls `RecordPresentedToken`, throttled. Expected: judged by its `Authorization` header as today, so it stays a cookie. Task 1.2.
3. A throttle off the stream's path. Expected: no mark, so no record, and the policy's own error value. Task 1.2.
4. A stream throttled with `RetryableError` false. Expected: the chain's mapping, whichever order the record and the check run in. Task 1.1.
5. A throttled bearer whose `Authorization` differs from the verified credential, as with a DPoP scheme. Expected: the same answer as the unthrottled request. Task 1.1.

---

### Task 1.1: The rows

**Files:** Test: `httpsec/signals_throttle_test.go` (`TestSessionSignals_Caps_ThrottledCookie`, near its CORS wildcard rows).

- [ ] **Step 1:** Turn the row pinning 403 for a throttled bearer from a wildcard's origin into 200 with only a retry, `Throttled` counted once. Add rows for a session bearer and a signed bearer, from a wildcard's origin and from a credentialless named origin, each beside its unthrottled twin, which opens. Add `RetryableError` false: the chain's mapping.
- [ ] **Step 2:** Run `go test -run 'TestSessionSignals_Caps' -count=1 -race -v ./httpsec/`. Expected: FAIL with `expected: 200, actual: 403`.

### Task 1.2: The record

**Files:** Modify: `httpsec/signals_retry.go`, `httpsec/session_bearer.go`, `httpsec/bearer.go`.

**Interfaces:**
- Consumes: `*perRequestThrottle` (`httpsec/signals_retry.go`); `(*Exchange).RecordPresentedToken(tok string)`.
- Produces: `func (ex *Exchange) recordThrottledBearer(err error, presented string)`, which records `presented` only when `errors.As` finds the mark.

- [ ] **Step 1:** Add rows: a refused bearer leaves `bearerCredential` empty; a throttled cookie stream answers 403 with nothing counted; a consumer's cookie authenticator recording a token stays a cookie; a throttle off the stream's path records nothing.
- [ ] **Step 2:** Implement `recordThrottledBearer`, and call it on `resolver.resolve`'s error in both bearers, before returning that error.
- [ ] **Step 3:** Remove the comment in `answerRetryOnly` stating the old limit, keeping the rest of it.
- [ ] **Step 4:** Run `go test -count=1 -race ./httpsec/`. Expected: `ok`.

### Task 1.3: Conformance

**Files:** Modify: `test/httpsecconformance/signals_throttle_scenarios.go`.

- [ ] **Step 1:** Add `signals: a throttled bearer stream from a wildcard's origin is answered with a retry`, asserting 200, a body of only `retry:`, and `Throttled` of 1, and with the fix removed confirm `expected: 200, actual: 403` on all three adapters, then edit it back.
- [ ] **Step 2:** Run `go test -run 'TestConformance(NetHTTP|Gin|Fiber)/signals' -count=1 -race -parallel 4 -v .` in `test`. Expected: the row appears three times, each PASS.

### Task 1.4: The gate

- [ ] **Step 1:** Run `gofmt -l .`, `go vet ./...` and `golangci-lint run ./...` in the root and `test`, and `go test -race -count=1 ./...` in `httpsec/ginsec` and `httpsec/fibersec`. Expected: clean.
- [ ] **Step 2:** The main session reruns these, a reviewer checks the diff, and the main session commits `fix(httpsec): retry a throttled bearer stream wherever it would open`.
