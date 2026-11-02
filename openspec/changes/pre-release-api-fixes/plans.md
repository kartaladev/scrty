# Pre-Release API Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session dispatches every file-writing step to a subagent (`.claude/rules/subagent-delegation.md`), and runs the verification commands itself.

**Goal:** Land the library fixes that would be breaking changes, or broken promises, after `v0.1.0`: the `notify` worker replacement and `ErrConfig` wording, the token subject as user identifier, signing-key deletion, the passkey port trim, and the MFA confirmation race settled.

**Architecture:** Five independent dispatches over disjoint files, each test-first against the moved spec deltas, then one whole-branch review. The steps below moved from `release-readiness`'s plan (its tasks 6.1–9.2) on 2026-11-02, renumbered; only the numbering, the dispatch names and the commit steps are new.

**Tech Stack:** Go 1.27; `go.uber.org/goleak`; testcontainers PostgreSQL for the store conformance suites; gopls for the audit in 2.1.

**Spec:** `openspec/changes/pre-release-api-fixes/`:
- `proposal.md`;
- `design.md` (decisions 1 to 6);
- `specs/email-notification`, `specs/token-issuance`, `specs/authentication`, `specs/signing-keys`;
- `tasks.md`.

Plan task N.M is `tasks.md` task N.M.

## Global Constraints

- **Go checks are test-first** (`.claude/rules/golang-tdd.md`): see the failure for the intended reason, then make it pass. A compile error is not a red step: add a stub first where a port gains a method.
- **Table tests** use the `table-test` skill's `assert`-closure form with `t.Context()`. Mocks come from `use-mockgen`; PostgreSQL from `use-testcontainers`.
- **Defaults and overrides** (`.claude/rules/library-design.md`): the subject defaults to `Principal.ID` (`token.WithUsernameSubject()` and `authenticate.WithJWTUsernameSubject()` override it); key deletion is on by default (`signingkey.WithRetiredKeysKept()` overrides it). Each option's godoc names the default it replaces.
- **Defect claims** (`.claude/rules/defect-claims.md`): decision 6's race stays `UNREPRODUCED` until 4.2's test fails for the claimed reason.
- **Destructive git commands.** Agents never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and never edit `openspec/`.
- **Navigation** uses gopls, not text search, for references and callers (`.claude/rules/gopls-navigation.md`).
- **Verification commands**, from the repository root: `go test -race -count=1 ./...` per changed module, `make check`, `openspec validate pre-release-api-fixes --strict`.

## Review Focus

1. **A principal with an identifier but no username, behind the standalone JWT authenticator.**
   - Expected: authentication succeeds and `Principal.Username` is empty; nothing behind it panics or treats the empty name as a user.
   - Test: in task 2.2, "Valid token" asserts an empty `Username`; 2.1's audit names every reader that must cope.
2. **A token whose `sub` is a username presented to a default chain** (a consumer who switched the default on one side only).
   - Expected: refused with the authentication-required error, never resolved to another user.
   - Test: in task 2.2's chain table, "a token whose sub is not the session's user is refused".
3. **A key dated in the future by another replica's clock.**
   - Expected: unpublished but never deleted.
   - Test: in task 3.1, "Far-future key removed" asserts the key is still stored.
4. **A delete that fails at housekeeping.**
   - Expected: the key stays unpublished, the failure is reported, and the next run deletes it.
   - Test: in task 3.1, "Failed delete retried" with a store double whose `Delete` fails once.
5. **Several workers ending their goroutines at once.**
   - Expected: the pool returns to its configured size, and shutdown still drains without a leaked goroutine.
   - Test: in task 1.1, add a case with 2 workers whose first two deliveries both call `runtime.Goexit()`, then assert a third message is delivered and goleak reports nothing.

---

## Dispatch map (main session)

| Order | Dispatch | Tasks | Owns | Model, and why |
|---|---|---|---|---|
| 1 (parallel) | P1 | 1.1–1.2 | `notify/queued.go`, `notify/queued_test.go`, `notify/smtp_test.go`, `notify/notify.go` | Opus: worker replacement under races (decision 1) |
| 1 (parallel) | P2 | 2.1, then 2.2 | `token/generator.go` and its tests, `authenticate/jwt.go` and its tests, `httpsec/bearer.go` and its tests, and every caller of the subject on the bearer path that 2.1 names | Opus: a change to a public claim, a security contract that cannot change after the tag |
| 1 (parallel) | P3 | 3.1–3.2 | `token/signingkey` (`record.go`, the housekeeping files, their tests); `signingkey.go` in `store/sqlstore`, `store/pgxstore` and `store/gormstore`; `internal/pgschema/signingkeys.go`; `store/seal/signingkey.go` and its test; `test/storetest/signingkey_suite.go` and its callers | Opus: a port change across four stores and a decorator, with retry on failure |
| 1 (parallel) | P4 | 4.1 | `authenticate/passkey/store.go` and its tests and mocks; `passkey_credential.go` in the three SQL stores; `internal/pgschema/passkey.go`; `test/storetest/passkeycredential_suite.go` and `broken_passkey_test.go` | Sonnet: a mechanical removal. It shares packages with P3 but never a file, since P3 owns only the `signingkey*` files |
| 1 (parallel) | P5 | 4.2 | a new test file in `authenticate/mfa`, nothing else | Opus: a race reproduction whose outcome decides a contract change |
| 2 | main | 5.1–5.2 | — | Opus reviewer for 5.1, since P1–P3 are on the Opus list |

P2 and P3 both touch the `token` tree but never the same file: P2 owns `token/generator.go`, P3 only `token/signingkey`. Each dispatch gets a fresh reviewer that edits nothing, Opus for P1, P2, P3 and P5, Sonnet for P4.

**Starting point.** This change starts once `close-security-gaps` has landed, because both touch `token` and `httpsec/bearer.go`. If it must start earlier, P2 rebases onto it before review.

---

### Task 1.1–1.2: Pre-release fixes in `notify` (decisions 1, 2; dispatch P1)

**Files:** `notify/queued.go`, `notify/queued_test.go`, `notify/smtp_test.go`, `notify/notify.go`

**Interfaces:** no exported change. The worker loop gains a replacement path, and `ErrConfig`'s godoc gains one case.

- [ ] **Step 1 (1.1, red):** Write `TestQueuedSender_WrappedSenderEndsItsGoroutine` with `goleak`. Build a sender with 1 worker, wrapping a sender that calls `runtime.Goexit()` on its first message and records later ones. Send message A, wait until it is in flight, then send message B. Assert B is delivered within 5 s, and that `Shutdown` with a 5 s context returns nil. Fold in a second table case (Review Focus 5): 2 workers whose first two deliveries both call `runtime.Goexit()`; a third message is delivered within 5 s and goleak reports nothing after `Shutdown`.
- [ ] **Step 2:** `go test -race -run TestQueuedSender_WrappedSenderEndsItsGoroutine -count=1 ./notify/`. Expected: FAIL, because B is never delivered.
- [ ] **Step 3 (green):** In the worker, a deferred check sees a delivery that did not return normally. It logs that delivery as failed, the same way a recovered panic is logged, and starts a replacement worker under the same `WaitGroup` before the dying one is marked done, so the drained signal never closes early. Run Step 2 and the queued-sender suite with `-race -count=5`. Expected: PASS.
- [ ] **Step 4 (1.2):** Write `TestSMTPSender_NoSenderAddressIsAConfigError`: an `SMTPSender` built without `WithSMTPFrom` sends a `Message` with no `From`, and the error matches `notify.ErrConfig`. It passes today. Temporarily wrap a different error in `smtp.go`, watch the test fail, then edit it back.
- [ ] **Step 5:** `ErrConfig`'s godoc in `notify/notify.go` names the case: a send with no sender address on the message and no default sender. `rg -n 'ErrConfig' notify/*.go` shows no other non-constructor use the godoc misses.
- [ ] **Step 6:** `go test -race -count=1 ./notify/...`, `go vet ./notify/...`, `golangci-lint run ./notify/...`. Expected: PASS, 0 issues.
- [ ] **Step 7: commit** `fix(notify): replace a queued-sender worker whose delivery ends its goroutine`.

---

### Task 2.1–2.2: The token subject (decision 3; dispatch P2)

**Interfaces:**
- Produces: `func token.WithUsernameSubject() Option`, `func authenticate.WithJWTUsernameSubject() JWTOption`. The generator's default subject is `Principal.ID`.

- [ ] **Step 1 (2.1, audit):** with gopls, list every read of `identity.Principal.Username` reachable from `JWTAuthenticator.Authenticate`, and from a guard, policy or endpoint behind the chain's bearer interceptor (`httpsec/bearer.go`). Confirm that the chain builds its principal with `PrincipalFromDetails` from the reloaded user (`httpsec/resolve.go`). Report each reader, with whether it would see an empty username. Edit nothing. The main session records the outcome in decision 3.
- [ ] **Step 2 (2.2, red):** the table cases in `token`: "Default token" (`sub` `u-1`), "Consumer chooses the username as subject" (`sub` `alice`), "Empty subject" (`Generate` returns an error, `errors.Is(err, token.ErrConfig)` or the package's issuing error, and no token). In `authenticate`: "Valid token" (`Principal.ID` `u-1`, empty `Username`) and "Consumer reads the subject as a username". Run `go test -run 'Subject|ValidToken' -count=1 ./token/ ./authenticate/`. Expected: FAIL on the default and empty-subject cases.
- [ ] **Step 2b (2.2, red, chain):** in `httpsec`, write `TestBearer_SubjectIsTheSessionUser`, a table with three cases: "default token reloads by the session's user reference and keeps the username", "a token whose sub is not the session's user is refused with the authentication-required error", "the username option reloads by username". Expected: FAIL on the first two cases.
- [ ] **Step 3 (green):** in `httpsec/bearer.go`, choose `lookupBySessionUser()` under the default, checking that `sub` equals the session's user reference, and `lookupByUsername(sub)` under the username option. Then implement both options, each naming the default it replaces, with godoc saying the two must agree. Fix any reader 2.1 reported, as decision 3 then states. Run Step 2, then `go test ./token/... ./authenticate/... ./httpsec/...` and the `test` module. Expected: PASS.
- [ ] **Step 4: commit** `feat(token)!: the token subject is the user identifier by default`.

---

### Task 3.1–3.2: Signing-key retention (decision 4; dispatch P3)

**Interfaces:**
- Produces: `KeyStore.Delete(ctx context.Context, kids ...string) error`, idempotent, and `func signingkey.WithRetiredKeysKept() Option`.

- [ ] **Step 1 (3.1, red):** add `Delete` to the port as a stub returning nil in every store, so the tree compiles. Add to `test/storetest/signingkey_suite.go`: "deleted keys are not loaded", "deleting a missing key is not an error", "delete with no keys is a no-op". Add the five `signing-keys` scenarios as table cases on a clockwork fake. "Failed delete retried" uses a store double whose `Delete` fails once. Run them. Expected: FAIL on assertions.
- [ ] **Step 2 (3.2, green):** implement `Delete` in the memory store, `sqlstore`, `pgxstore`, `gormstore` (one statement, `kid` in the set) and the sealing decorator (forwards). Implement the housekeeping deletion of keys retired for age only, with report and retry. Run `go test -race ./token/signingkey/... ./store/seal/...` and the conformance suite in the `test` module against every store (Docker). Expected: PASS.
- [ ] **Step 3: commit** `feat(signingkey)!: housekeeping deletes keys retired for age`.

---

### Task 4.1: Remove the unused passkey store method (decision 5; dispatch P4)

- [ ] **Step 1:** remove `DeleteAwaitingSavedCodes` from `passkey.CredentialStore`, its three SQL implementations, `internal/pgschema/passkey.go`, the conformance suite and its broken-store variant. Regenerate the mocks with `go generate`. Run `go build ./...` and `go test ./...` in every module that changed, including the Docker suites. Expected: PASS. `rg DeleteAwaitingSavedCodes --glob '!openspec/**' --glob '!.claude/.legacy'` finds nothing.
- [ ] **Step 2: commit** `refactor(passkey)!: drop the unused DeleteAwaitingSavedCodes port method`.

### Task 4.2: Reproduce or drop the MFA confirmation race (decision 6; dispatch P5)

- [ ] **Step 1:** write `TestConfirmEnrolment_DeviceProofBetweenReadAndConfirm` in `authenticate/mfa`. A store double blocks `Confirm` until the test lands a device proof for the same enrolment through the device path. Assert that the enrolment's outcome reflects the device proof: confirmed once, with no second confirmation overwriting it. Run it under `-race -count=10`.
- [ ] **Step 2:** report the result and stop. If it passes, the main session records the claim as dropped. If it fails, the main session writes the fix's decision and a `multi-factor-auth` delta, and then plans the fix.

---

### Task 5.1–5.2: Integration gate (main session)

- [ ] **5.1:** dispatch a fresh Opus reviewer that edits nothing. It gets the four spec deltas, decisions 1–6, and `git diff main...HEAD`. Findings are labelled `REPRODUCED` (with a failing check) or `UNREPRODUCED`, and go back to the owning dispatch.
- [ ] **5.2:** run `make check` and `openspec validate pre-release-api-fixes --strict`, and keep the outputs.
