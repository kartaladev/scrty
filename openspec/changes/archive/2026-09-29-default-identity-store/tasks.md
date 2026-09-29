# Tasks

Every task is test-first: write the failing test, run it, confirm it fails for the intended reason
(never a compile error), then implement, then refactor with the suite green. Each task names the
tests that prove it.

## 1. Named password-changed-at time in the identity model

- [x] 1.1 Add `identity.FieldPasswordChangedAt`, `identity.WithUserPasswordChangedAt(t time.Time)` and the local-change option `identity.WithUserPasswordChange(hash []byte, at time.Time)` naming both fields, all reported by `NewUser.IsSet`; verify with a table test in `identity` that each option names exactly its fields and carries the values, including the zero time, and that `WithUserPassword` alone does not name the time
- [x] 1.2 Rewrite the `UserProvisioner.Provision`/`Update`, `Details.PasswordChangedAt` and option godoc to the modified `identity-model` contract: the time is written only when named, a password named alone never moves it, naming zero clears it; show the local-change call with `WithUserPasswordChange`, and state on `WithUserPassword` that naming it alone leaves the time as stored and so exempts a local change from password-age policy; verify with `go doc ./identity` and `go vet ./identity`
- [x] 1.3 Make `identitytest.InMemoryStore` write the time on Provision and Update only when named; verify with the suite cases of 2.1 against the in-memory store
- [x] 1.4 Pin that federated login never names the time: in a new `oidc` test file, a recording provisioner asserts that neither the password mirror's Update nor just-in-time Provision with a mapped password claim names `FieldPasswordChangedAt`; verify the test fails when the mirror's password option is temporarily swapped for `WithUserPasswordChange`

## 2. The identity ports' conformance suite (`test/identity`)

- [x] 2.1 Replace the `SeedPasswordChangedAt` hook with cases that set the time through the ports: a password named alone leaves a recorded time unchanged (Update) and zero (Provision); a named time is stored and returned (Provision and Update); naming zero clears it; verify each case fails against a deliberately broken store for "stamps on an unnamed password write" and "ignores a named time"
- [x] 2.2 Add a required `SeedOrganization` hook (an organization with its group) and cases for the loading rules the suite does not yet cover: complete record, primary grant first, organization without a group, dangling organization reference, and exact username matching (the inactive-user case is adapter-only, task 5.1, because the ports cannot deactivate a user); verify each against the in-memory store and a broken-store defect where the spec names one
- [x] 2.3 Make every hook required: remove the "may skip" allowance on `FailUserLoads`/`FailMFALookups`, and fail the run before any case, naming the hook, when one is missing; verify with a self-test that runs the suite with an MFA-required hook that returns `ErrHookUnsupported`, and asserts the failure names it
- [x] 2.4 Make every case use names unique to the case, so a factory may hand all cases a fixture over one shared database while they run in parallel; verify by running the suite against a single shared in-memory store instance
- [x] 2.5 Add `RunAmbientTx(t, h)` with a harness adding a begin-caller-transaction hook and a make-a-grant-write-fail hook, covering loaders seeing uncommitted rows, a failed provision leaving the caller's transaction usable and its earlier writes intact, and a consumer resolver's rollback; verify the part compiles against the in-memory harness shape and fails against a broken harness that ignores the transaction
- [x] 2.6 Extend the broken-store self-test with one defect per new "known defects are caught" entry (stamps an unnamed password write, ignores a named time, returns only amended fields, keeps the last duplicate grant, reports an unknown user as not requiring MFA) and assert the suite fails by assertion for each; flip the MFA lookup case "an unknown user is answered rather than refused" to require user-not-found, and make the in-memory store answer it; verify with `go test -count=1 ./identity/...` in the `test` module

## 3. Password history port and reuse guard (`password`)

- [x] 3.1 Add the `password.History` port, `ErrPasswordReused`, `ErrHistoryUnavailable`, `ErrConfig`, `WriteFunc`, and `NewReuseGuard(h, enc, depth, opts...)` with `WithReuseMatchers` and `WithReuseClock`; refuse a nil or typed-nil port, a nil encoder, depth ≤ 0, a nil matcher and a nil clock with `ErrConfig` naming the mistake; verify with a table test of every construction mistake and one consumer-port success
- [x] 3.2 Implement `Check(ctx, user *identity.Details, candidate)`: `user.Password` plus the N−1 newest retired hashes of `user.ID`, matched by verification with the guard's encoder and the built-in Argon2id, bcrypt and scrypt matchers, leaving out the built-in of the guard encoder's own type (replaceable extras); an absent current hash matches nothing; a nil user is `ErrConfig` with nothing read; verify with the depth-3, depth-1, no-local-password, older-parameters, retired-algorithm and consumer-matcher scenarios
- [x] 3.3 Implement `Change(ctx, user *identity.Details, candidate, write WriteFunc)` in the fail-closed order (read, match, retire keeping N−1, encode, write with the user, the hash and the guard clock's time), returning the write's error unchanged; verify with the consumer-write-receives-the-time scenario under a replaced clock, the pruning, retry-does-not-double-count, per-user boundary, read-failure and retire-failure scenarios, using a mockgen `History`
- [x] 3.4 Pin error hygiene: fixed text with no candidate, hash or user reference; the port's error reachable by `errors.Is`/`errors.As`; no log record; verify with the reuse-refusal-text and port-failure-quoting-a-hash scenarios
- [x] 3.5 Add an in-memory `password.History` to `test/identity` and `RunPasswordHistory(t, h)` covering newest-first order, the read bound, pruning, the same-bytes rule, keeping zero, forgetting a user, the per-user boundary and ambient rollback; also cover the write that ignores the time (moved from 3.6): over the in-memory identity store, a consumer write that names only the password completes the change and leaves the password-changed-at time unchanged; verify it passes against the in-memory history and fails against broken ones that return oldest first or never prune
- [x] 3.6 Add `ProvisionerWrite(p identity.UserProvisioner) (WriteFunc, error)`, refusing a nil or typed-nil provisioner with `ErrConfig`, whose write calls `p.Update(ctx, user.Username, identity.WithUserPasswordChange(hash, changedAt))` and nothing else; verify with a mockgen `UserProvisioner` asserting the exact named fields and values under a fixed clock, and the refusal rows (the write-that-ignores-the-time scenario lands with 3.5, in `test/identity`)

## 4. Identity migration set and shared query text

- [x] 4.1 Add `migrate.Identity()` and `migrate.IdentityVersionTable = "goose_identity"` over one consolidated goose migration under `migrate/identity` creating the seven tables of Decisions 2 and 12, with no foreign keys and a Down that drops them in reverse order with `IF EXISTS`; verify with a `migrate` unit test over the embedded files, then a `test` module PostgreSQL test for: identity set alone, security-state set alone, rollback leaving security state intact, and a consumer-named version table
- [x] 4.2 Add the identity query text to `internal/pgschema` (loads, privileges, provision `ON CONFLICT DO NOTHING`, locked update, grant rebuild with `position`, MFA lookup, history insert-and-prune ordered by `seq`); verify through the store tests of group 5, which exercise every statement

## 5. `database/sql` identity store (`sqlstore`)

- [x] 5.1 Add `sqlstore.NewIdentityStore(db, opts...)` honouring `WithTxResolver`, `WithIDGenerator` and `WithClock` (refusing other options; the clock binds every `created_at`, `updated_at` and `retired_at` the store writes), and implement the user loader, role loader and MFA lookup; verify with `test/sqlstore` runs of the loader and MFA suites against PostgreSQL, construction errors, and the storage-failure and missing-table scenarios
- [x] 5.2 Implement Provision and Update: collision decided by the insert, row-locked update naming only named fields (including the password-changed-at time), grant rebuild preserving first-stored attributes by `position`, identifiers from the generator with a mid-provision generator failure writing nothing, and error text without usernames or hashes; verify with the provisioner suite and the descending-generator scenarios
- [x] 5.3 Run provision and update in a savepoint inside an ambient transaction, and atomically otherwise; verify with `RunAmbientTx` against PostgreSQL
- [x] 5.4 Pin the two interleavings with adapter-only tests that hold one transaction at a blocking statement confirmed through `pg_stat_activity`: concurrent provisions produce one user and user-already-exists errors, and revoke-races-re-assert ends with the last committer's grants; verify both fail against a variant with a preceding read or no row lock
- [x] 5.5 Implement `password.History` on the store (read newest first by `seq`, retire with same-bytes rule and prune in one savepointed statement group, forget), refusing a malformed reference; verify with `RunPasswordHistory`, the no-port-call-records-history scenario, and the error-text-carries-no-hash scenario
- [x] 5.6 Verify the reuse guard end to end over the store with `ProvisionerWrite(store)`: a change inside one transaction that then rolls back leaves neither the password, the history entry nor the time stored; a committed change stores all three, the time being the guard clock's

## 6. `pgx` identity store

- [x] 6.1 Add `pgx.NewIdentityStore(pool, opts...)` implementing the four ports and `password.History` over the shared query text, with savepoints the store issues and releases itself (design Decision 6); verify with `test/pgxstore` runs of the full suite, `RunAmbientTx`, `RunPasswordHistory` and construction errors
- [x] 6.2 Port the adapter-only interleaving tests of 5.4 to pgx; verify both fail against a preceding-read or unlocked variant

## 7. `gorm` identity store

- [x] 7.1 Add `gorm.NewIdentityStore(db, opts...)` implementing the four ports and `password.History`, reaching the same statements through gorm's on-conflict clause, affected-row count and savepoint statements it issues and releases itself (design Decision 6); verify with `test/gormstore` runs of the full suite, `RunAmbientTx`, `RunPasswordHistory` and construction errors
- [x] 7.2 Port the adapter-only interleaving tests of 5.4 to gorm; verify both fail against a preceding-read or unlocked variant

## 8. HTTP: status row and the resolve endpoint

- [x] 8.1 Map `password.ErrPasswordReused` to 422 in `httpsec.StatusForError`, leaving `ErrHistoryUnavailable` at 500; verify with rows added to the status table test, including a wrapped reuse error
- [x] 8.2 Pin the resolve endpoint's behaviour with a reuse guard: a consumer function refusing through the guard gets 422 and the next request on the session is still refused with a password-change challenge; a function with no guard accepts the current password and clears the marker; verify with `httpsec` tests of both scenarios (no production change expected unless a test fails)

## 9. Documentation and final gate

- [x] 9.1 Write the godoc the design requires: the store's defaults and overrides, the migration set, user deletion calling `ForgetPasswords` beside removing grants, the reuse guard's cost per unit of N and its concurrency limit; verify with `go doc` on each new package symbol and `go vet`
- [x] 9.2 Run the final gate across every module (`go test -race -count=1`, `go vet`, `gofmt -l`, `golangci-lint run`) and a whole-branch review against every requirement of the change's specs; verify all are green and the review reports no open finding
