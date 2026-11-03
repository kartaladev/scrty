# Pre-Release API Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repository the main session dispatches every file-writing step to a subagent (`.claude/rules/subagent-delegation.md`), and runs the verification commands itself.

**Goal:** Land the library fixes that would be breaking changes, or broken promises, after `v0.1.0`: the `notify` worker replacement and `ErrConfig` wording, the token subject as user identifier on the generator, the authenticator and the chain, signing-key deletion, the passkey port trim, and the MFA confirmation race settled.

**Architecture:** Five lanes over disjoint files, each test-first against the spec deltas, then one whole-branch review. The token-subject lane runs as two sequential dispatches, because the chain consumes the `token.SubjectMode` the first one defines. The steps moved from `release-readiness`'s plan on 2026-11-02, and were revised on 2026-11-03 after the change was checked against `main`. That revision added task 2.3, the chain's subject option and build check, the in-memory passkey store, and the scenarios from the sweep.

**Tech Stack:** Go 1.27; `go.uber.org/goleak`; testcontainers PostgreSQL for the store conformance suites; gopls for the audit in 2.1 and for finding implementers.

**Spec:** `openspec/changes/pre-release-api-fixes/`:
- `proposal.md`;
- `design.md` (decisions 1 to 6);
- `specs/email-notification`, `specs/token-issuance`, `specs/authentication`, `specs/http-security-chain`, `specs/signing-keys`;
- `tasks.md`.

Plan task N.M is `tasks.md` task N.M.

## Global Constraints

- **Go checks are test-first** (`.claude/rules/golang-tdd.md`): see the failure for the intended reason, then make it pass. A compile error is not a red step: add a stub first where a port or interface gains a method.
- **Table tests** use the `table-test` skill's `assert`-closure form with `t.Context()`. Mocks come from `use-mockgen`; PostgreSQL from `use-testcontainers`.
- **Defaults and overrides** (`.claude/rules/library-design.md`):
  - the subject defaults to `Principal.ID`. `token.WithUsernameSubject()`, `authenticate.WithJWTUsernameSubject()` and `httpsec.WithBearerUsernameSubject()` override it, and each option's godoc names the other two;
  - key deletion is on by default, and `signingkey.WithRetiredKeysKept()` overrides it;
  - each option's godoc names the default it replaces.
- **Construction refuses a mismatch:** a chain with signed bearer tokens whose given token generator reports a different `token.SubjectMode` fails to build with a configuration error.
- **Defect claims** (`.claude/rules/defect-claims.md`): decision 6's race stays `UNREPRODUCED` until 4.2's test fails for the claimed reason.
- **Destructive git commands.** Agents never run `git checkout --`, `restore`, `reset --hard`, `stash` or `clean`, and never edit `openspec/`.
- **Navigation** uses gopls, not text search, for references, callers and implementers (`.claude/rules/gopls-navigation.md`).
- **Verification commands**, from the repository root: `go test -race -count=1 ./...` per changed module, `make check`, `openspec validate pre-release-api-fixes --strict`.

## Review Focus

1. **A principal with an identifier but no username, behind the standalone JWT authenticator.**
   - Expected: authentication succeeds and `Principal.Username` is empty; nothing behind it panics or treats the empty name as a user.
   - Test: in task 2.2, "Valid token" asserts an empty `Username`; 2.1's audit names every reader that must cope.
2. **A token whose `sub` is a username presented to a default chain** (a consumer who switched the default on one side only, past the build check, for example with a token issued by another service).
   - Expected: refused with the authentication-required error before any user reload, never resolved to another user.
   - Test: in task 2.3, "Subject is not the session's user", with a user loader double that fails the test if called.
3. **A key dated in the future by another replica's clock.**
   - Expected: unpublished but never deleted.
   - Test: in task 3.1, "Far-future key removed" asserts the key is still stored.
4. **A delete that fails at housekeeping, or that races another replica.**
   - Expected: a failure leaves the key unpublished, is reported, and the next run deletes it. A key another replica already deleted is no failure.
   - Test: in task 3.1, "Failed delete retried" with a store double whose `Delete` fails once, and "Replicas delete the same retired key" on two managers over one in-memory store.
5. **Several workers ending their goroutines at once.**
   - Expected: the pool returns to its configured size, and shutdown still drains without a leaked goroutine.
   - Test: in task 1.1, "Several workers end their goroutines".

---

## Dispatch map (main session)

| Order | Dispatch | Tasks | Owns | Model, and why |
|---|---|---|---|---|
| 1 (parallel) | P1 | 1.1–1.2 | `notify/queued.go`, `notify/queued_test.go`, `notify/smtp_test.go`, `notify/notify.go` | Opus: worker replacement under races (decision 1) |
| 1 (parallel) | P2a | 2.1, then 2.2 | `token/generator.go`, `token/claims.go`, `token/config.go` and their tests; `authenticate/jwt.go` and its tests; every other implementer of `token.Generator`, found with gopls: `authenticate/passkey/example_test.go`, `httpsec/example_enrolment_test.go`, `httpsec/tokengenerator_mock_test.go` (regenerated), `test/challenge_durable_test.go`, `test/httpsec_login_redis_test.go`, `test/httpsecconformance/scenarios.go` | Opus: a change to a public claim and to an interface other lanes compile against |
| 2 (after P2a) | P2b | 2.3 | `httpsec/bearer.go`, `httpsec/dpop.go` (beside `checkBindingGenerator`), the `httpsec` option and config files 2.1 names for the generator options, and their tests | Opus: refusal logic on the authentication path, and a build check every chain passes through |
| 1 (parallel) | P3 | 3.1–3.2 | `token/signingkey` (`record.go`, the housekeeping files, their tests); `signingkey.go` in `store/sqlstore`, `store/pgxstore` and `store/gormstore`; `internal/pgschema/signingkeys.go`; `store/seal/signingkey.go` and its test; `test/storetest/signingkey_suite.go` and its callers | Opus: a port change across four stores and a decorator, with retry on failure |
| 1 (parallel) | P4 | 4.1 | `authenticate/passkey/store.go` (the port and `MemoryCredentialStore`) and its tests and mocks; `passkey_credential.go` in the three SQL stores; `internal/pgschema/passkey.go`; `test/storetest/passkeycredential_suite.go` and `broken_passkey_test.go` | Sonnet: a mechanical removal. It shares packages with P2a and P3 but never a file |
| 1 (parallel) | P5 | 4.2 | a new test file in `authenticate/mfa`, nothing else | Opus: a race reproduction whose outcome decides a contract change |
| 3 | main | 5.1–5.2 | — | Opus reviewer for 5.1, since P1–P3 and P5 are on the Opus list |

P2a and P3 both touch the `token` tree but never the same file: P2a owns the `token` package files, and P3 only `token/signingkey`. P2a and P4 both touch `authenticate/passkey`, but P2a owns only `example_test.go`. P2b starts only when P2a's verification is green and its review is clean. Each dispatch gets a fresh reviewer that edits nothing: Opus for P1, P2a, P2b, P3 and P5, and Sonnet for P4.

**Starting point.** `close-security-gaps` was archived on 2026-11-03 (#45, #66). Its changes to `token` (`confirmation.go`) and `httpsec/bearer.go` (the `cnf` check) are on `main`, and every dispatch starts from it.

---

### Task 1.1–1.2: Pre-release fixes in `notify` (decisions 1, 2; dispatch P1)

**Files:** `notify/queued.go`, `notify/queued_test.go`, `notify/smtp_test.go`, `notify/notify.go`

**Interfaces:** no exported change. The worker loop gains a replacement path, and `ErrConfig`'s godoc gains one case.

- [ ] **Step 1 (1.1, red):** write `TestQueuedSender_WrappedSenderEndsItsGoroutine`, a table with `goleak`:
  - "Wrapped sender ends its goroutine": 1 worker, wrapping a sender that calls `runtime.Goexit()` on its first message and records later ones. Send message A, wait until it is in flight, then send B. Assert that B is delivered within 5 s, that the captured log has one failed-delivery record for A, and that `Shutdown` with a 5 s context returns nil.
  - "Several workers end their goroutines": 2 workers whose first two deliveries both call `runtime.Goexit()`. Assert that a third message is delivered within 5 s, that `Shutdown` returns nil, and that goleak reports nothing after it.
- [ ] **Step 2:** `go test -race -run TestQueuedSender_WrappedSenderEndsItsGoroutine -count=1 ./notify/`. Expected: FAIL, because the later message is never delivered.
- [ ] **Step 3 (green):** in the worker, a deferred check sees a delivery that did not return normally. It logs that delivery as failed, the same way a recovered panic is logged. Then it starts a replacement worker under the same `WaitGroup` before the dying one is marked done, so the drained signal never closes early. Run Step 2 and the queued-sender suite with `-race -count=5`. Expected: PASS.
- [ ] **Step 4 (1.2):** write `TestSMTPSender_NoSenderAddressIsAConfigError`. An `SMTPSender` built without `WithSMTPFrom`, over a dialler double that records dials, sends a `Message` with no `From`. Assert that the error matches `notify.ErrConfig` and that no dial happened. It passes today: temporarily wrap a different error at `notify/smtp.go:300`, watch the test fail, then edit it back.
- [ ] **Step 5:** `ErrConfig`'s godoc in `notify/notify.go` names the case: a send with no sender address on the message and no default sender. `rg -n 'ErrConfig' notify/*.go` shows no other non-constructor use the godoc misses.
- [ ] **Step 6:** `go test -race -count=1 ./notify/...`, `go vet ./notify/...`, `golangci-lint run ./notify/...`. Expected: PASS, 0 issues.
- [ ] **Step 7: commit** `fix(notify): replace a queued-sender worker whose delivery ends its goroutine`.

---

### Task 2.1–2.2: The token subject in `token` and `authenticate` (decision 3; dispatch P2a)

**Interfaces:**
- Produces, in `token`:
  - `type SubjectMode int`, with `SubjectUserID SubjectMode = iota` (the zero value, the default) and `SubjectUsername`;
  - on `Generator`: `SubjectMode() SubjectMode`, a required method;
  - `func WithUsernameSubject() Option`.
- Produces, in `authenticate`: `func WithJWTUsernameSubject() JWTOption`.
- Consumed by P2b: `token.SubjectMode`, and `Generator.SubjectMode()`.

- [ ] **Step 1 (2.1, audit):** with gopls, list:
  - every read of `identity.Principal.Username` reachable from `JWTAuthenticator.Authenticate`, and from a guard, policy or endpoint behind the chain's signed bearer (`httpsec/bearer.go`) or its session-reference bearer (`httpsec/session_bearer.go`);
  - every `httpsec` option or field through which the chain is given a `token.Generator`.

  Confirm that both chain paths build the principal with `PrincipalFromDetails` from the reloaded user (`httpsec/resolve.go`). Report each reader, with whether it would see an empty username, and the generator list for P2b. Edit nothing. The main session records the outcome in decision 3.
- [ ] **Step 2 (red, compile first):** add `SubjectMode()` to `token.Generator` and to every implementer P2a owns, each returning `SubjectUsername` (today's behaviour), and regenerate `httpsec/tokengenerator_mock_test.go` with `go generate`. `go build ./... && go vet ./...` in the root and `test` modules pass. Then write the table cases:
  - in `token`: "Default token" (`sub` `u-1`, and `SubjectMode()` is `SubjectUserID`), "Consumer chooses the username as subject" (`sub` `alice`, and `SubjectMode()` is `SubjectUsername`), "Empty subject" (a default generator and a principal with no `ID`: `errors.Is(err, token.ErrNoSubject)` and an empty token), and "Empty username under the username subject" (the same assertion);
  - in `authenticate`: "Valid token" (`Principal.ID` `u-1`, empty `Username`), "Consumer reads the subject as a username" (`Username` `ada`, empty `ID`), and "Token with no subject" (`errors.Is(err, authenticate.ErrAuthenticationFailed)`, nil result).
- [ ] **Step 3:** `go test -run 'Subject|ValidToken|NoSubject' -count=1 ./token/ ./authenticate/`. Expected: FAIL on "Default token", "Empty subject", "Valid token" and the `SubjectMode()` assertions. "Token with no subject" and the username cases pass today; prove them by inverting the subject check temporarily and editing it back.
- [ ] **Step 4 (green):**
  - `JWTGenerator` writes `Principal.ID` under the default and `Principal.Username` under `WithUsernameSubject()`, and `SubjectMode()` reports which;
  - `ErrNoSubject`'s text says the principal has no value for the chosen subject;
  - the package doc's "The subject", `Claims.Subject`'s godoc and `Generator.Generate`'s godoc describe both modes;
  - `JWTAuthenticator` builds `&identity.Principal{ID: identity.UserID(sub)}` under the default and `{Username: sub}` under the option, and its godoc says its option cannot be checked against any generator;
  - the test doubles report `SubjectUserID` unless a case needs the other.

  Run Step 3, then `go test -race ./token/... ./authenticate/...` and the `test` module. Expected: PASS.
- [ ] **Step 5: commit** `feat(token)!: the token subject is the user identifier by default`.

---

### Task 2.3: The chain's subject option and build check (decision 3; dispatch P2b, after P2a)

**Interfaces:**
- Consumes: `token.SubjectMode`, `token.Generator.SubjectMode()` (P2a).
- Produces: `func httpsec.WithBearerUsernameSubject() BearerTokenOption`.

- [ ] **Step 1 (red):** write `TestBearer_SubjectIsTheSessionUser`, a table over a chain with signed bearer tokens:
  - "Default token reloads the session's user": token `sub` `u-1` for a session of `u-1` whose username is `alice`. Assert that the loader was called through `LoadByUserID("u-1")` and never by username, and that the handler sees `ID` `u-1` and `Username` `alice`;
  - "Subject is not the session's user": `sub` `u-2` for a session of `u-1`. Assert `errors.Is(err, httpsec.ErrAuthenticationRequired)`, no loader call, and that the handler did not run;
  - "Consumer reads the subject as a username": `WithBearerUsernameSubject()`, `sub` `alice`, reloaded by username, and the principal's `ID` is `u-1`;
  - "Username reassigned to another user", under `WithBearerUsernameSubject()`: refused with the authentication-required error.

  Then write `TestChain_GeneratorSubjectModeMustMatchBearer`: a default bearer with a login generator whose `SubjectMode()` is `SubjectUsername` fails to build with a configuration error naming the option and the field, and a matching pair builds.
- [ ] **Step 2:** `go test -run 'TestBearer_SubjectIsTheSessionUser|TestChain_GeneratorSubjectModeMustMatchBearer' -count=1 ./httpsec/`. Expected: FAIL on the default, the subject mismatch and the build-check cases.
- [ ] **Step 3 (green):**
  - in `httpsec/bearer.go`, under the default, refuse when `claims.Subject()` is not the loaded session's `UserID`, then resolve with `lookupBySessionUser()`; under the option, keep `lookupByUsername(claims.Subject())`. The `cnf` binding check is unchanged;
  - add `checkSubjectGenerator(c *config, option, field string, g token.Generator) error` beside `checkBindingGenerator`, called wherever that one is, and for every generator 2.1 listed. It checks nothing when signed bearer tokens are off or `g` is nil;
  - `WithBearerUsernameSubject()`'s godoc names the default it replaces and the two options it must agree with.

  Run Step 2, then `go test -race ./httpsec/...` and the `test` module, including `test/httpsecconformance`. Expected: PASS.
- [ ] **Step 4: commit** `feat(httpsec)!: the signed bearer reloads the session's user by default`.

---

### Task 3.1–3.2: Signing-key retention (decision 4; dispatch P3)

**Interfaces:**
- Produces: `KeyStore.Delete(ctx context.Context, kids ...string) error`, idempotent, and `func signingkey.WithRetiredKeysKept() Option`.

- [ ] **Step 1 (3.1, red):** add `Delete` to the port as a stub returning nil in every store, so the tree compiles. Then write:
  - in `test/storetest/signingkey_suite.go`: "deleted keys are not loaded", "deleting a missing key is not an error", "delete with no keys is a no-op";
  - the seven `signing-keys` scenarios as table cases on a clockwork fake. "Failed delete retried" uses a store double whose `Delete` fails once and asserts that the error hook was called once. "Replicas delete the same retired key" runs two managers over one in-memory store and asserts no hook call. "Deleted key not republished on reload" asserts that the second manager's published set lacks the `kid` after its reload.

  Run them. Expected: FAIL on assertions.
- [ ] **Step 2 (3.2, green):** implement `Delete` in the memory store, `sqlstore`, `pgxstore` and `gormstore` (one statement, `kid` in the set), and in the sealing decorator (forwards). Implement the housekeeping deletion of keys retired for age only, with report and retry. Run `go test -race ./token/signingkey/... ./store/seal/...` and the conformance suite in the `test` module against every store (Docker). Expected: PASS.
- [ ] **Step 3: commit** `feat(signingkey)!: housekeeping deletes keys retired for age`.

---

### Task 4.1: Remove the unused passkey store method (decision 5; dispatch P4)

- [ ] **Step 1:** remove `DeleteAwaitingSavedCodes` from:
  - `passkey.CredentialStore`, and `MemoryCredentialStore` (`authenticate/passkey/store.go`) with its test case in `store_test.go`;
  - the three SQL implementations, and `internal/pgschema/passkey.go`'s `PasskeyDeleteAwaitingSavedCodes`;
  - the conformance suite and its broken-store variant.

  Regenerate the mocks with `go generate`. Run `go build ./...` and `go test ./...` in every module that changed, including the Docker suites. Expected: PASS, and `rg DeleteAwaitingSavedCodes --glob '!openspec/**' --glob '!.claude/.legacy'` finds nothing.
- [ ] **Step 2: commit** `refactor(passkey)!: drop the unused DeleteAwaitingSavedCodes port method`.

### Task 4.2: Reproduce or drop the MFA confirmation race (decision 6; dispatch P5)

- [ ] **Step 1:** write `TestConfirmEnrolment_DeviceProofBetweenReadAndConfirm` in `authenticate/mfa`. A store double blocks `Confirm` until the test lands a device proof of the same generation through the device path. Assert that the enrolment's outcome reflects the device proof: confirmed once, with no second confirmation overwriting it. Run it under `-race -count=10`. `ConfirmEnrolment`'s godoc already names this as a known limit, so a failure is expected; confirm that it fails on the outcome assertion, not on the double.
- [ ] **Step 2:** report the result and stop. If it passes, the main session records the claim as dropped. If it fails, the main session writes the fix's decision and a `multi-factor-auth` delta, and then plans the fix.

---

### Task 5.1–5.2: Integration gate (main session)

- [ ] **5.1:** dispatch a fresh Opus reviewer that edits nothing. It gets the five spec deltas, decisions 1–6, and `git diff main...HEAD`. Findings are labelled `REPRODUCED` (with a failing check) or `UNREPRODUCED`, and go back to the owning dispatch.
- [ ] **5.2:** run `make check` and `openspec validate pre-release-api-fixes --strict`, and keep the outputs.
