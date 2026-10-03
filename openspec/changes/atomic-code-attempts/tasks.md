# Tasks

An atomic attempt charge on the TOTP enrolment: the store contract and every store first, then TOTP verification, then the verify endpoint.

Every task is test-first: write the failing test, run it and see it fail for the intended reason (a compile error is not a red step), make it pass, then refactor. Tables follow the project's `table-test` skill, and mocks the `use-mockgen` skill. The durable suites use the `test` module's PostgreSQL helper (`use-testcontainers`). Each task names how it is verified. Names in parentheses are the spec requirements and design decisions the task covers.

- **Compilation:** changing `mfa.EnrolmentStore` owns every implementer across the workspace (the memory store, `seal`, `sqlstore`, `pgx`, `gorm`, the regenerated mocks and the `test` module's fakes). The workspace compiles and passes at the end of every group, not necessarily between the tasks of group 1.
- **Order:** groups run in order: 2 needs 1, and 3 needs 2.
- **Start condition:** implementation starts only after `shared-rate-limiting` has committed its edits to `test/internal/storefix/broken.go` and `httpsec/mfaverify.go`, which tasks 1.1 and 3.1 touch.

## 1. The charge and give-back in every store (security-state-stores "TOTP verification attempts are charged and given back by the write"; store-conformance "The enrolment suites prove the TOTP attempt charge"; decisions 1, 2, 3, 8)

- [x] 1.1 Contract and in-memory store.
  - Add `VerifyAttempts` and `VerifyWindowUntil` to `mfa.Enrolment`, and `ChargeVerifyAttempt` and `RefundVerifyAttempt` to `mfa.EnrolmentStore`, with godoc. `PutPending` clears both fields.
  - Red first: add the suite cases to `RunEnrolmentStoreSuite` in `test/storetest`, one per scenario of the security-state-stores requirement. Add a `RunVerifyChargeRace` rule (20 racers per enrolment, limit 5, 50 enrolments) with its `storefix` fixture. Run both against the memory store while its new methods refuse everything, and record each case failing on its assertion.
  - Then implement the memory store under its mutex, truncating window ends to microseconds, and regenerate the `mfa` mocks.
  - Verify with `go test -race -run 'TestMemoryEnrolmentStore' -count=1 ./storetest/...` in `test` and `go test -race ./mfa/...`.
- [x] 1.2 Broken-store variants in `test/storetest/broken_mfa_test.go`: an uncapped charge, read-then-write, a window that never ends, and a give-back that ignores its window. Each must be caught by the suite case named for it. Verify with `go test -race -run 'Broken' -count=1 ./storetest/` in `test`.
- [x] 1.3 `seal.NewEnrolmentStore` passes both operations through unchanged, and its tests show the inner store receives the user, instant, limit, window and window end it was given. Verify with `go test -race ./seal/...`.
- [x] 1.4 Schema and shared SQL.
  - Fold `verify_attempts integer NOT NULL DEFAULT 0` and `verify_window_until timestamptz NULL` into `mfa_enrolments` in the security-state migration file.
  - Add `pgschema.EnrolmentChargeVerifyAttempt` and `pgschema.EnrolmentRefundVerifyAttempt` as design decisions 2 and 3 give them.
  - Make the pending-enrolment statement clear both columns.
  - Verify with `go test -race ./migrate/... ./internal/pgschema/...`.
- [x] 1.5 `sqlstore`, `pgx` and `gorm` implement both operations over the shared SQL.
  - Red first: wire the group-1 suite cases and `RunVerifyChargeRace` into `test/sqlstore`, `test/pgxstore` and `test/gormstore` before the implementations exist, and record the failures.
  - Include a round-trip case showing that the window end a charge returns is the one a give-back matches, at microsecond precision.
  - Verify with `go test -race ./...` in the root, `pgx`, `gorm` and `test` modules.

## 2. TOTP verification charges, compares, then gives back (multi-factor-auth "TOTP verification charges each attempt before comparing it", "A successful TOTP verification gives its charge back", "The TOTP attempt limit and window are replaceable", "A refused charge is not counted as a failed verification"; decisions 4, 5)

- [x] 2.1 Red step for the overshoot, `TestTOTP_ConcurrentWrongCodesAreComparedAtMostTheLimit` in `mfa`.
  - It sends 20 concurrent wrong codes for one user through `VerifyThrottle` and `TOTP.Verify`, with a limiter whose `Exceeded` holds every caller at a barrier until all 20 have checked.
  - It asserts that at most 5 return `ErrInvalidCode`.
  - Run it on the unchanged `Verify` and record the failure showing 20 compared.
  - Verify with `go test -race -run TestTOTP_ConcurrentWrongCodesAreComparedAtMostTheLimit -count=1 ./mfa/`.
- [x] 2.2 `Verify` charges after reading the enrolment and before matching. A refused charge returns `ErrVerifyAttemptsExhausted` (matching `ErrVerifyThrottled`) without comparing, and a store failure returns a package-worded error. This turns 2.1 green. Table cases, red first:
  - a malformed code is charged;
  - a pending or absent enrolment is refused as an invalid code, with no charge;
  - a refused charge is not compared;
  - a store failure is neither an invalid code nor throttled;
  - a new window admits a valid code.
  
  Verify with `go test -race ./mfa/...`.
- [x] 2.3 Give-back after `AcceptStep` accepts, under `context.WithoutCancel`, naming the charged window end. A failed give-back is logged at WARN and does not refuse. Table cases, red first:
  - seven successive valid steps within 15 minutes are all accepted;
  - a replayed step keeps its charge;
  - a failing give-back still succeeds and logs;
  - a give-back with an already-cancelled request context still lands.
  
  Verify with `go test -race ./mfa/...`.
- [x] 2.4 `WithVerifyAttempts(limit, window)` on `NewTOTP`, defaulting to 5 per 15 minutes. A limit or window of zero or less is a configuration error. Its godoc names the default, states there is no off switch, and states the 2× bound at a window edge. Red first:
  - the default is covered;
  - a consumer limit of 3 per 10 minutes compares at most 3 of 4 concurrent codes;
  - a limit of 0 and a window of 0 each fail construction.
  
  Verify with `go test -race ./mfa/...` and `go doc ./mfa WithVerifyAttempts`.
- [x] 2.5 A recovery's TOTP proof is charged. Add a test in `recovery` showing that a recovery presenting a TOTP code charges one attempt against the user's enrolment before the compare, using the memory enrolment store. No production change is expected; if one is needed, stop and report it. Verify with `go test -race ./recovery/...`.

## 3. The verify endpoint (multi-factor-auth "A refused charge is not counted as a failed verification"; decision 6)

- [x] 3.1 `httpsec/mfaverify.go` skips `RecordFailure` for an error matching `mfa.ErrVerifyThrottled`, as it already does for `mfa.ErrAuthenticatorRefused`. Red first, in `httpsec`:
  - a verification whose charge is refused returns 401 and records no failure (the limiter mock expects no `RecordFailure`);
  - 20 concurrent wrong codes through the interceptor compare at most 5.
  
  Update the comment that lists what is not recorded. Verify with `go test -race ./httpsec/...`.

## 4. Integration

- [ ] 4.1 Whole-branch review against every requirement in this change's three spec deltas, by a fresh reviewer agent that did not write the code. Its findings are labelled `REPRODUCED` with a failing test, or `UNREPRODUCED`. Verify by the review report, with every finding resolved or recorded in `design.md`.
- [ ] 4.2 Final gate across every module in `go.work`: `go test -race ./...`, `go vet ./...`, `gofmt -l .` empty, `golangci-lint run`, and `openspec validate atomic-code-attempts --strict`. Verify by the clean output of each command.
