# Tasks

Every task is test-first: write the failing test, run it, and confirm it fails for the intended reason (a compile error is not a red step). Then implement, re-run, and refactor with the tests green. Conformance suites live in `test/storetest`, and durable-store runs live in the `test` module (run from `test/` with `go test -count=1 -run '<Name>' ./...`). Each group lands the godoc its own behaviour needs, naming the default and the override (`library-design.md`).

## 1. Reproduce the stale activity write (design: Defect claims)

- [ ] 1.1 Red: in `session`, add a test against the memory store in which request A loads a session, request B marks the same session enrolment-pending (lowering its absolute deadline) and saves it, and A then calls `Touch`. Assert the stored session keeps B's lowered deadline and enrolment-origin marker. Run it and record the output. If it fails on the restored deadline, the claim is `REPRODUCED`: keep the test as the red step for 3.1. If it passes, the claim is wrong: report it, so the main session removes the "Defect claims" entry and decision 2's lost-update motivation before group 3 starts.

## 2. Session model, store port and memory store (decisions 2, 5, 7; sessions and security-state-stores requirements)

- [ ] 2.1 Red: extend `test/storetest/session_suite.go` with the activity-write cases:
  - a fresher record is left unchanged without error;
  - other fields survive;
  - a missing record is not-found and is never inserted;
  - a superseded record is left unchanged.
  Add a broken memory-store variant whose activity write saves the whole record. Verify the new cases fail against the memory store because the port method is a stub that returns an error, not because of a compile error.
- [ ] 2.2 Add the library-only session fields (family identifier, family start, supersession time, window end, successor digest, first presentation). Add the store port methods: the narrow activity write, supersession, family revocation, first-presentation recording. Implement them in the memory store and delegate them in the encrypted store wrapper. Regenerate the `session.Store` mock per `use-mockgen`. `Create` starts a family. Verify 2.1 passes, `make generate-check` is clean, the broken variant is caught by the other-fields case, and `go test ./session/...` passes.
- [ ] 2.3 Red: add suite cases for supersession:
  - a stale observation is refused with the renewal-conflict error and nothing is written;
  - the successor is stored in the family with its start time;
  - load returns a superseded record past its window;
  - the sweep keeps a superseded record until the family's absolute deadline.
  Add cases for family revocation (it counts exactly one family) and first presentation (the first time is kept), plus the round trip of every new value and "save leaves them unchanged". Add a case that a supersession attempted after its family was revoked is not-found and inserts nothing. Verify each fails against the memory store for the stated reason, then implement until the memory runner (`test/storetest/memory_test.go`) passes.
- [ ] 2.4 Red: add the session supersession race to the race suite (8 racers × 50 sessions, exactly one successor each, the rest renewal-conflict), with its read-then-write broken variant. Verify against the memory store that the broken variant is caught and the real store passes.
- [ ] 2.5 Document the new port methods' contracts in `session/store.go` godoc: superseded records are returned by `Load`, the activity write never inserts, and what supersession is conditional on. Verify `go doc ./session Store` shows them and `go vet ./...` is clean.

## 3. Manager behaviour (decisions 1, 3, 6, 7, 8, 13; sessions requirements)

- [ ] 3.1 Red: add table tests for `WithTouchInterval`:
  - the default 0 writes every time;
  - a 1-minute interval skips a write 30 s after the last access and writes one 60 s after it;
  - a skipped write only brings expiry earlier;
  - construction refuses a negative interval and one at or above the idle timeout.
  Together with 1.1, verify they fail. Then route `Touch` through the narrow activity write and add the option. Verify 3.1 and 1.1 pass.
- [ ] 3.2 Red: add tests for `WithAbsoluteLifetime` and `WithMaxAbsoluteLifetime`:
  - the default maximum refuses 30 days and stores nothing;
  - a 30-day maximum admits 30 days;
  - no lifetime gives the absolute timeout;
  - construction refuses a maximum below the absolute timeout.
  Add a test that `RestoreEnrolmentDeadlines` restores a chosen 30-day lifetime exactly. Verify they fail, implement, and verify they pass along with the existing enrolment and recovery tests.
- [ ] 3.3 Red: add tests for families through rotation:
  - two sign-ins get different families;
  - `Rotate` and its successors keep the family and start time;
  - revoking a family leaves the user's other families.
  Verify they fail, implement, and verify they pass along with the existing rotation and MFA-verify tests.
- [ ] 3.4 Red: add tests for `RotateWithGrace`:
  - inside the window the old identifier loads;
  - the window is capped at the absolute deadline;
  - a grace below 0 or above 5 minutes is a configuration error;
  - re-rotation inside the window issues S2 and makes S1 reuse;
  - presentation after the window is `ErrSessionReused`, which also matches `ErrSessionExpired`, and revokes the family;
  - detection hours later still works;
  - the first successful `Load` records first presentation once;
  - a superseded session's `Touch` writes nothing.
  - after reuse, the logout path's `Delete` of the old identifier finds the family gone;
  - two managers on clocks either side of `AcceptUntil` judge it as inside the window and as reuse respectively.
  Verify each fails for its stated reason, then implement.
- [ ] 3.5 Red: add a barrier test in which two managers share one store and rotate one identifier concurrently. Exactly one succeeds and the other gets the renewal-conflict error, with one live successor. Run it with `-race`. Verify it fails against a deliberately unconditional rotation, and passes once rotation uses the store's supersession.
- [ ] 3.6 Red: add tests for `WithUnusedSuccessorRecovery`:
  - by default, a next-day retry with the old identifier is reuse;
  - with the option on, an unused successor is re-rotated;
  - with the option on, a used successor keeps the reuse verdict.
  Add tests for renewal lifetime:
  - the default carries the deadline over;
  - a chosen 30 days under a 90-day family maximum extends;
  - day 80 of a 90-day family is cut to end at the family maximum;
  - a chosen lifetime above the lifetime maximum is refused and stores nothing;
  - second-factor rotation never extends;
  - construction refuses a family maximum below the lifetime maximum.
  Add tests for `WithReuseObserver`:
  - none still revokes;
  - an observer is called once, after the revocation, with the user and family and no identifier;
  - nil is a configuration error.
  - the formatted report contains no session identifier.
  Verify they fail, implement, and verify they pass.
- [ ] 3.7 Write godoc for every new manager option and method, stating:
  - the default and the override;
  - the reuse trade-off of `WithUnusedSuccessorRecovery`;
  - the transaction rule on `ErrSessionReused` and the observer: commit on reuse, and audit inside a savepoint;
  - the NIST AAL lifetime figures on the maximum options.
  Run `/simplify` over `session/`. Verify `go test -race ./session/...` passes and `go doc` shows each default.

## 4. Schema and durable stores (decisions 5, 12; schema-migrations, security-state-stores and store-conformance requirements)

- [ ] 4.1 Red: in the `test` module, add migration tests:
  - the new columns, their nullability and the family index exist after applying;
  - a database populated before the migration backfills each session as the sole member of its own family, started at its creation time;
  - rollback restores the exact prior columns and indexes.
  Verify they fail because the migration does not exist.
- [ ] 4.2 Add the migration under `migrate/securitystate/`, with its down step. Verify 4.1 passes on PostgreSQL 15 and 18, along with the existing migration suite.
- [ ] 4.3 Add the statements to `internal/pgschema/sessions.go`:
  - the activity update, conditional on threshold and not superseded;
  - supersession as conditional updates plus the insert, run in one transaction that joins an attached one;
  - family delete;
  - first presentation `WHERE first_presented_at IS NULL`;
  - the new columns in insert and select. `SessionUpdate` must not write them.
  Implement the port methods in `sqlstore`. Verify the session suite and the race suite pass on the `sqlstore` runner (`test/sqlstore`), with the broken variants caught.
- [ ] 4.4 Implement the port methods in `pgx`. Verify the session suite, the race suite and the ambient-transaction suite pass on the `pgx` runner.
- [ ] 4.5 Map the new columns on `gorm/models.go`'s row type, and implement the port methods in `gorm`. Verify the session, race and ambient-transaction suites pass on the `gorm` runner.
- [ ] 4.6 Verify the stores join a caller's transaction for supersession and family revocation: a rolled-back caller transaction leaves neither a successor nor a revocation. This needs an ambient-transaction suite case per backend, written red first against a variant that opens its own transaction.

## 5. Shared resolution core and exported publication (decisions 10, 11; http-security-chain requirements)

- [ ] 5.1 Record a green baseline before the refactor: run the `httpsec` bearer, MFA, password-change and session-touch tests and keep the output. Verify it is green.
- [ ] 5.2 Red: add tests for the two `Exchange` methods:
  - a published session is readable through `SessionFromContext` and touched after the handler;
  - running the per-request phase for an enrolment challenge saves the session enrolment-pending and lets the enrolment gate refuse, as for a bearer request.
  Verify they fail because the methods are stubs.
- [ ] 5.3 Extract the signed bearer's steps after verification into the unexported core, built on the two `Exchange` methods. Behaviour must be unchanged. Verify 5.2 passes and the 5.1 suites pass unchanged.
- [ ] 5.4 Red: add a bearer test in which a token names a superseded session past its window. It is refused with an error matching both `ErrAuthenticationRequired` and `ErrSessionReused`, and the family is revoked. Verify it fails, implement it in the core, and verify it passes.
- [ ] 5.5 Update the `httpsec` package documentation's consumer-interceptor section to name the two methods. Verify `go doc ./httpsec` shows them, and that the doc's promise ("everything a built-in has") matches the code.

## 6. Session-reference bearer and credential issuance (decisions 10; http-security-chain and http-error-propagation requirements)

- [ ] 6.1 Red: add table tests for `EnableSessionBearer`:
  - a live reference authenticates;
  - a malformed value is refused with no store call (a mocked store via `use-mockgen` expects none);
  - the user is reloaded by `UserID` (a renamed user, whose old username belongs to someone else, authenticates as itself);
  - a reused reference gives the double-identity refusal;
  - a consumer scheme works.
  Verify they fail, implement on the core, and verify they pass.
- [ ] 6.2 Red: add construction tests:
  - both bearer modes is a configuration error;
  - a token generator on a credential-issuing endpoint while the reference mode is on is a configuration error.
  Verify they fail, implement, and verify they pass.
- [ ] 6.3 Red: add tests that, with the reference mode on, password login, second-factor verification and recovery completion hand their responders the session identifier, and a request bearing it authenticates. Verify they fail, route credential issuance through the mode, and verify they pass along with the existing login, MFA and recovery tests.
- [ ] 6.4 Red: add mapping-table cases (renewal conflict → 409; reused joined with authentication-required → 401) and the "reuse refusal is distinguishable" case, whose text carries no identifier. Add `ErrSessionRenewalConflict` to the public refusal set. Verify they fail, implement, and verify they pass.
- [ ] 6.5 Run the session-reference chain through `ginsec` and `fibersec` once each: a live reference authenticates and a reused one is refused. Verify both adapters pass with no adapter code change.

## 7. Renewal endpoint and login lifetime (decisions 4, 9, 13; http-security-chain requirements)

- [ ] 7.1 Red: add tests for `EnableSessionRenewal`. Cover the default endpoint:
  - `POST /session/renewal` answers 200 with a successor credential and `Cache-Control: no-store`;
  - the old credential works for 30 s;
  - a request with no authentication result is refused;
  - other requests pass through.
  - no log record holds either credential.
  Cover the consumer options: the path, a 60-second grace and a responder receiving the successor, the user and the kind `fresh`. Verify they fail, implement, and verify they pass.
- [ ] 7.2 Red: add tests for re-rotation inside the window (kind `re-rotation`), unused-successor recovery (kind `recovery`, with the manager option on), the lost race (409), a grace above the ceiling, and signed-token mode without a generator (both at construction). Also test that an enrolment-pending session posting to the renewal path is refused by the enrolment gate. Verify they fail, implement, and verify they pass.
- [ ] 7.3 Red: add tests for `WithRenewalLifetime`. The default carries the deadline over. A 30-day choice under a 90-day family maximum extends it. A choice whose deadline passes the family maximum is cut to it, and the responder sees the stored deadline. A choice above the lifetime maximum fails with a configuration error and stores nothing. Verify they fail, implement, and verify they pass.
- [ ] 7.4 Red: add tests for the login lifetime option. The default is the absolute timeout. A function returning 30 days for `remember: true` under a 30-day maximum gives a 30-day deadline. A lifetime above the maximum fails the login with a configuration error mapping to 500, and creates no session. Verify they fail, thread the choice through `completeLogin` into `WithAbsoluteLifetime`, and verify they pass.
- [ ] 7.5 Write godoc for the renewal endpoint and the login option: the defaults, the overrides, the commit-on-reuse transaction rule, and the client guidance to switch to the successor at once. Run `/simplify` over the touched `httpsec` files. Verify `go test -race ./httpsec/...` passes and `go doc` shows each default.

## 8. Integration gate

- [ ] 8.1 Run the whole-branch review against every requirement in this change's specs, with a fresh Opus reviewer that edits nothing. Verify every finding is fixed or explicitly declined in the design.
- [ ] 8.2 Run `make check` (fmt-check, vet, lint, test, vuln, generate-check) and `openspec validate first-party-sessions --strict`. Verify both are clean, and keep the output.

## Workflow follow-up

- Tell the `bff-resource-server` change to rebase its cookie mode on the shared resolution core from group 5.
- Archive the change after the integration gate, and sync the six capability specs.
