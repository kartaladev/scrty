# Tasks

Every task is test-first. Write the failing test, run it, and confirm it fails for the intended reason: a compile error is not a red step. Then implement, then refactor with the tests green. Where a test pins behaviour that already holds, the red step is a temporary inversion of the implementation that the test must notice, undone by editing the file back, never by a discarding git command.

## 1. A successful Basic authentication clears failures

- [x] 1.1 Reproduce the gap (design decision 6, UNREPRODUCED until this test fails): an `httpsec` test where `ada` has four failures, a Basic request with the correct password succeeds, and the attempt store is then asked to `Reset("ada")`. Red: see it fail on the current code with a missing `Reset` call. If it passes instead, stop and report: the claim was wrong, and decision 6 and the `http-security-chain` delta are removed. Then call the attempt store's `Reset` on Basic success, as form login does. Verify: `go test -count=1 -run 'TestBasic' ./httpsec/`.
- [x] 1.2 A failed clearing on Basic success is logged with fixed text and the store's error type, never the username or the error text, and the request still succeeds (spec "Failure to clear does not refuse"). Red: the test asserting one error record and the handler run. Verify: `go test -race -count=1 ./httpsec/`, and `go test -count=1 ./...` in the `test` module.

## 2. The streak store contract and its in-memory implementation

- [x] 2.1 Add the optional streak contract to `policy` (design decision 1; names provisional) and its record type. The contract adds a failure given the retention cutoff and the cap, reads a record given the cutoff, and deletes inactive records before a cutoff, refusing a zero cutoff. Its godoc states that a store implementing it clears the streak, hold included, in `Reset`. Red: a compile-time assertion that `MemoryAttemptStore` implements it, preceded by a behavioural test against the memory store that fails on a stub. Verify: `go test -count=1 -run 'TestMemoryAttemptStore' ./policy/`.
- [x] 2.2 Add `RunFailureStreakSuite` to `test/storetest` (`table-test` form), covering:
  - counting from one;
  - restart after the retention cutoff;
  - the hold set by the write that reaches the cap, and never moved;
  - a held record that never restarts or reads empty;
  - `Reset` clearing the streak and the hold;
  - an inactive purge that keeps holds and recent records, and refuses a zero cutoff;
  - identifiers matched exactly.

  Add a race case: 20 concurrent adds from a count of 90 with a cap of 100 end at 110, held, with exactly one add reporting that it set the hold. Run it against the memory store. Red: each case fails on a deliberately wrong memory store (for example, one that never restarts), then passes on the real one. Verify: `go test -race -count=1 ./storetest/...` in the `test` module.

## 3. Durable streak stores

- [x] 3.1 Add the streak table to `migrate/securitystate/20260926000000_security_state.sql` (folded in place: nothing is tagged), with:
  - a uuid primary key;
  - the login name as text, unique;
  - the count, and the newest failure instant;
  - a nullable hold instant with no default;
  - an index serving the inactive purge;
  - its drop in the down migration.

  Add its statements to `internal/pgschema`, including one conditional upsert that restarts, advances and sets the hold atomically. Red: a migration test for the spec scenario "Consecutive failure counts", plus the fourteen-table count, failing before the table exists. Verify: the migration tests in the `test` module.
- [x] 3.2 Implement the contract in `sqlstore`, `pgx` and `gorm`. Each `Reset` deletes the log rows and the streak in one statement or transaction. Each store takes part in an ambient transaction. Wire `RunFailureStreakSuite` for each backend in `test/sqlstore`, `test/pgxstore` and `test/gormstore`, emptying the table first. Red: the suite run against each adapter before its implementation fails on behaviour. Add stubs that compile and return wrong values first, so the failure is not a compile error. Verify: `go test -race -count=1 ./...` in the `test` module (Docker).
- [x] 3.3 Cross-backend and ambient coverage: a hold set through one backend's store is read as held, with the same count, by another backend's store on the same database (spec "A hold seen by another backend"). Add the streak store to the ambient-transaction suites for every backend: a streak written in a rolled-back transaction is gone. Red: run each case against a store that writes outside the transaction, and see it fail. Verify: `go test -count=1 ./...` in the `test` module.

## 4. The cap in the lockout policy

- [x] 4.1 Add `WithLockoutCap`, the NIST constant (100), and `WithLockoutCapRetention` (default 30 days) (design decisions 4 and 5). Each of the following is a configuration error naming the option:
  - a cap with a store that lacks the contract;
  - a cap not above the threshold;
  - a retention of zero or less, given without a cap, or shorter than the window.

  Red: table cases in `TestNewAccountLockoutPolicy` for each configuration error and for the defaults (spec "A cap is refused unless its wiring can enforce it"). Verify: `go test -count=1 -run 'TestNewAccountLockoutPolicy' ./policy/`.
- [x] 4.2 The view advances the streak, writing it before the log, with the policy's retention cutoff and cap (design decision 2). A failure of either write is returned. Without a cap the view never touches the streak. Red: a mocked-store test expecting no streak call without a cap; then, with a cap, the streak add before `RecordFailure`, using the expected cutoff and cap. Verify: `go test -count=1 -run 'TestLockoutCap' ./policy/`.
- [x] 4.3 Evaluation reads the streak first and refuses a held identifier with the account-locked refusal, carrying no wait and identifiable as a hold (provisional `ErrAccountHeld`). A failed read denies, wrapping the error. Otherwise the existing evaluation runs unchanged (design decision 3). Red: table cases for the spec scenarios:
  - "No cap by default", "Cap reached across days", "Consumer cap", "Below the cap" and "Unknown identifiers are held alike";
  - "Held refusal", "A windowed lock is not a hold" and "Unreadable hold";
  - "A hold outlives every window" and "The correct password does not lift a hold".

  Verify: `go test -count=1 -run 'TestLockoutCap|TestAccountLockoutPolicyLockoutError' ./policy/`.
- [x] 4.4 Retention and release. A count expires after inactivity, and a hold never does. `Reset` lifts the hold and clears the window together. Red: table cases for the spec scenarios "Inactive count restarts", "Consumer retention", "A hold does not expire" and "Reset unlocks". Verify: `go test -count=1 -run 'TestLockoutCap' ./policy/`.
- [x] 4.5 Concurrency through the policy: the spec scenario "Burst across the cap", 20 concurrent failures through the view from a count of 90, under `-race`. Exactly one report says the hold was set. Red: a temporary view that reads the count and then writes it in two steps (the crossing-detection design decision 1 rejects), which the test must catch. Verify: `go test -race -count=1 -run 'TestLockoutCap' ./policy/`.
- [x] 4.6 Observer and purge.
  - The view reports a hold once, on the write that set it, and reports its release in place of `Cleared` (design decision 7; spec scenarios "Held" and "Hold lifted").
  - `PurgeExpired` also deletes inactive streaks, with the retention cutoff, and keeps holds (spec scenario "Inactive counts are purged, holds are kept").

  Red: each case fails on the current view and purge. Verify: `go test -race -count=1 ./policy/`.
- [x] 4.7 Godoc.
  - `WithLockoutCap` states: the hold, what lifts it, that a cap above 100 is outside NIST SP 800-63B-4 §3.2.2's limit, the denial-of-service risk with its mitigations (recovery with codes, the source guard, the waits), and that unknown identifiers' holds are never pruned.
  - `AccountLockoutPolicy.Reset` is presented as the unlock.
  - The type documentation no longer says there is no lock record.

  Add an `Example` configuring the NIST cap. Verify: `go test -count=1 -run Example ./policy/` and `go doc ./policy WithLockoutCap`.

## 5. The chain enforces and conceals the hold

- [x] 5.1 The engine answers which attempt-store views its registered policies require (design decision 2). Chain assembly refuses form login or Basic handed any other store while a capped lockout policy is registered, naming the endpoint's `Attempts` setting. Store identity is compared as the password-change gate compares stores. Red: table cases for the spec scenarios "Raw store with a cap", "View with a cap" and "Raw store without a cap". Verify: `go test -count=1 -run 'TestLockoutCapWiring' ./httpsec/` and `go test -race -count=1 ./policy/ ./httpsec/`.
- [x] 5.2 Held refusal through the chain: the spec scenarios "Held by default" (401, one decoy, password not checked, identifiable as a hold), "Held, disclosure chosen" (Basic, 429, no challenge header) and "Unknown username held alike". Use a real lockout policy with a cap over the memory store. Red: temporarily skip the streak for the username `nobody`, and see the alike case fail. Verify: `go test -count=1 -run 'TestHeld' ./httpsec/`.
- [x] 5.3 Conformance scenario in `test/httpsecconformance`, run by every adapter, for the spec scenarios "Recover, change, sign in" and "Password proof refused while held":
  - a held `ada` recovers with a saved code and an issued code, resolves a password change, then signs in with the new password;
  - a recovery with a saved code and the password is refused as locked.

  Red: with the streak clearing temporarily removed from the memory store's `Reset`, the final login is refused as held. Verify: `go test -count=1 ./...` in the `test` module.
- [x] 5.4 Godoc: `FormLoginDeps.Attempts` and `BasicAuthDeps.Attempts` state that a capped lockout policy requires its view and that other wiring fails construction. `EnableBasicAuth` states that a success clears failures. Verify: `go doc ./httpsec FormLoginDeps`, `go doc ./httpsec BasicAuthDeps`.

## 6. Sweeping

- [x] 6.1 The login-attempt expiry task deletes inactive streaks through the policy's purge, and never a hold. Cover the `expiry-sweeping` spec scenarios "A hold survives every sweep", "A recent consecutive count survives" and "An inactive consecutive count is deleted", in `test/expirytasks_test.go` against a durable store. Red: temporarily make the purge delete held records, and see the first scenario fail. Verify: `go test -count=1 ./...` in the `test` module.

## 7. Whole-branch checks

- [x] 7.1 Run every module's suite and the static checks: `go test -race -count=1 ./...` in each module (root, `test`, `ginsec`, `fibersec`, `gorm`, `pgx`, `redis`, `sweep`, `passkey/webauthn`), `go vet ./...`, `gofmt -l .` (empty), and `golangci-lint run`. Verify: all green, with the output kept as evidence.
- [x] 7.2 Whole-branch review by a reviewer who wrote none of the code, against every requirement in this change's five delta specs and design decisions 1–7. Verify: the review reports no unresolved finding. Any defect it claims either has a failing test or is labelled `UNREPRODUCED`.

## Workflow follow-up

- Archive the change once 7.2 is clean, and sync its specs.
- If `shared-rate-limiting-postgres` lands first, rebase the migration fold and the `schema-migrations` delta's table count onto it.
