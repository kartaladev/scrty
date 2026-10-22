# Tasks

Every task is test-first: write the failing test, run it, and confirm it fails for the intended reason (a compile error is not a red step). Then implement, re-run, and refactor with the tests green. Conformance suites live in `test/storetest`, and durable-store runs live in the `test` module (run from `test/` with `go test -count=1 -run '<Name>' ./...`). Each group lands the godoc its own behaviour needs, naming the default and the override (`library-design.md`).

## 1. Reproduce the stale activity write (design: Defect claims)

- [x] 1.1 Red: in `session`, add a test against the memory store in which request A loads a session, request B marks the same session enrolment-pending (lowering its absolute deadline) and saves it, and A then calls `Touch`. Assert the stored session keeps B's lowered deadline and enrolment-origin marker. Run it and record the output. If it fails on the restored deadline, the claim is `REPRODUCED`: keep the test as the red step for 3.1. If it passes, the claim is wrong: report it, so the main session removes the "Defect claims" entry and decision 2's lost-update motivation before group 3 starts.

## 2. Session model, store port and memory store (decisions 2, 5, 7; sessions and security-state-stores requirements)

- [x] 2.1 Red: extend `test/storetest/session_suite.go` with the activity-write cases:
  - a fresher record is left unchanged without error;
  - other fields survive;
  - a missing record is not-found and is never inserted;
  - a superseded record is left unchanged.
  Add a broken memory-store variant whose activity write saves the whole record. Verify the new cases fail against the memory store because the port method is a stub that returns an error, not because of a compile error.
- [x] 2.2 Add the library-only session fields (family identifier, family start, supersession time, window end, successor digest, first presentation). Add the store port methods: the narrow activity write, supersession, family revocation, first-presentation recording. Implement them in the memory store and delegate them in the encrypted store wrapper. Regenerate the `session.Store` mock per `use-mockgen`. `Create` starts a family. Verify 2.1 passes, `make generate-check` is clean, the broken variant is caught by the other-fields case, and `go test ./session/...` passes.
- [x] 2.3 Red: add suite cases for supersession:
  - a stale observation is refused with the renewal-conflict error and nothing is written;
  - the successor is stored in the family with its start time;
  - load returns a superseded record past its window;
  - the sweep keeps a superseded record until the family's absolute deadline.
  Add cases for family revocation (it counts exactly one family) and first presentation (the first time is kept), plus the round trip of every new value and "save leaves them unchanged". Add a case that a supersession attempted after its family was revoked is not-found and inserts nothing. Verify each fails against the memory store for the stated reason, then implement until the memory runner (`test/storetest/memory_test.go`) passes.
- [x] 2.4 Red: add the session supersession race to the race suite (8 racers × 50 sessions, exactly one successor each, the rest renewal-conflict), with its read-then-write broken variant. Verify against the memory store that the broken variant is caught and the real store passes.
- [x] 2.5 Document the new port methods' contracts in `session/store.go` godoc: superseded records are returned by `Load`, the activity write never inserts, and what supersession is conditional on. Verify `go doc ./session Store` shows them and `go vet ./...` is clean.

## 3. Manager behaviour (decisions 1, 3, 6, 7, 8, 13; sessions requirements)

- [x] 3.1 Red: add table tests for `WithTouchInterval`:
  - the default 0 writes every time;
  - a 1-minute interval skips a write 30 s after the last access and writes one 60 s after it;
  - a skipped write only brings expiry earlier;
  - construction refuses a negative interval and one at or above the idle timeout.
  Together with 1.1, verify they fail. Then route `Touch` through the narrow activity write and add the option. Verify 3.1 and 1.1 pass.
- [x] 3.2 Red: add tests for `WithAbsoluteLifetime` and `WithMaxAbsoluteLifetime`:
  - the default maximum refuses 30 days and stores nothing;
  - a 30-day maximum admits 30 days;
  - no lifetime gives the absolute timeout;
  - construction refuses a maximum below the absolute timeout.
  Add a test that `RestoreEnrolmentDeadlines` restores a chosen 30-day lifetime exactly. Verify they fail, implement, and verify they pass along with the existing enrolment and recovery tests.
- [x] 3.3 Red: add tests for families through rotation:
  - two sign-ins get different families;
  - `Rotate` and its successors keep the family and start time;
  - revoking a family leaves the user's other families.
  Verify they fail, implement, and verify they pass along with the existing rotation and MFA-verify tests.
- [x] 3.4 Red: add tests for `RotateWithGrace`:
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
- [x] 3.5 Red: add a barrier test in which two managers share one store and rotate one identifier concurrently. Exactly one succeeds and the other gets the renewal-conflict error, with one live successor. Run it with `-race`. Verify it fails against a deliberately unconditional rotation, and passes once rotation uses the store's supersession.
- [x] 3.6 Red: add tests for `WithUnusedSuccessorRecovery`:
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
- [x] 3.7 Write godoc for every new manager option and method, stating:
  - the default and the override;
  - the reuse trade-off of `WithUnusedSuccessorRecovery`;
  - the transaction rule on `ErrSessionReused` and the observer: commit on reuse, and audit inside a savepoint;
  - the NIST AAL lifetime figures on the maximum options.
  Run `/simplify` over `session/`. Verify `go test -race ./session/...` passes and `go doc` shows each default.

## 4. Schema and durable stores (decisions 5, 12; schema-migrations, security-state-stores and store-conformance requirements)

- [x] 4.1 Red: in the `test` module, add migration tests:
  - the new columns, their nullability and the family index exist after applying;
  - a database populated before the migration backfills each session as the sole member of its own family, started at its creation time;
  - rollback restores the exact prior columns and indexes.
  Verify they fail because the migration does not exist.
- [x] 4.2 Add the migration under `migrate/securitystate/`, with its down step. Verify 4.1 passes on PostgreSQL 15 and 18, along with the existing migration suite.
- [x] 4.3 Add the statements to `internal/pgschema/sessions.go`:
  - the activity update, conditional on threshold and not superseded;
  - supersession as conditional updates plus the insert, run in one transaction that joins an attached one;
  - family delete;
  - first presentation `WHERE first_presented_at IS NULL`;
  - the new columns in insert and select. `SessionUpdate` must not write them.
  Implement the port methods in `sqlstore`. Verify the session suite and the race suite pass on the `sqlstore` runner (`test/sqlstore`), with the broken variants caught.
- [x] 4.4 Implement the port methods in `pgx`. Verify the session suite, the race suite and the ambient-transaction suite pass on the `pgx` runner.
- [x] 4.5 Map the new columns on `gorm/models.go`'s row type, and implement the port methods in `gorm`. Verify the session, race and ambient-transaction suites pass on the `gorm` runner.
- [x] 4.6 Verify the stores join a caller's transaction for supersession and family revocation: a rolled-back caller transaction leaves neither a successor nor a revocation. This needs an ambient-transaction suite case per backend, written red first against a variant that opens its own transaction.

## 5. Shared resolution core and exported publication (decisions 10, 11; http-security-chain requirements)

- [x] 5.1 Record a green baseline before the refactor: run the `httpsec` bearer, MFA, password-change and session-touch tests and keep the output. Verify it is green.
- [x] 5.2 Red: add tests for the two `Exchange` methods:
  - a published session is readable through `SessionFromContext` and touched after the handler;
  - running the per-request phase for an enrolment challenge saves the session enrolment-pending and lets the enrolment gate refuse, as for a bearer request.
  Verify they fail because the methods are stubs.
- [x] 5.3 Extract the signed bearer's steps after verification into the unexported core, built on the two `Exchange` methods. Behaviour must be unchanged. Verify 5.2 passes and the 5.1 suites pass unchanged.
- [x] 5.4 Red: add a bearer test in which a token names a superseded session past its window. It is refused with an error matching both `ErrAuthenticationRequired` and `ErrSessionReused`, and the family is revoked. Verify it fails, implement it in the core, and verify it passes.
- [x] 5.5 Update the `httpsec` package documentation's consumer-interceptor section to name the two methods. Verify `go doc ./httpsec` shows them, and that the doc's promise ("everything a built-in has") matches the code.

## 6. Session-reference bearer and credential issuance (decisions 10; http-security-chain and http-error-propagation requirements)

- [x] 6.1 Red: add table tests for `EnableSessionBearer`:
  - a live reference authenticates;
  - a malformed value is refused with no store call (a mocked store via `use-mockgen` expects none);
  - the user is reloaded by `UserID` (a renamed user, whose old username belongs to someone else, authenticates as itself);
  - a reused reference gives the double-identity refusal;
  - a consumer scheme works.
  Verify they fail, implement on the core, and verify they pass.
- [x] 6.2 Red: add construction tests:
  - both bearer modes is a configuration error;
  - a token generator on a credential-issuing endpoint while the reference mode is on is a configuration error.
  Verify they fail, implement, and verify they pass.
- [x] 6.3 Red: add tests that, with the reference mode on, password login, second-factor verification and recovery completion hand their responders the session identifier, and a request bearing it authenticates. Verify they fail, route credential issuance through the mode, and verify they pass along with the existing login, MFA and recovery tests.
- [x] 6.4 Red: add mapping-table cases (renewal conflict → 409; reused joined with authentication-required → 401) and the "reuse refusal is distinguishable" case, whose text carries no identifier. Add `ErrSessionRenewalConflict` to the public refusal set. Verify they fail, implement, and verify they pass.
- [x] 6.5 Run the session-reference chain through `ginsec` and `fibersec` once each: a live reference authenticates and a reused one is refused. Verify both adapters pass with no adapter code change.

## 7. Renewal endpoint and login lifetime (decisions 4, 9, 13; http-security-chain requirements)

- [x] 7.1 Red: add tests for `EnableSessionRenewal`. Cover the default endpoint:
  - `POST /session/renewal` answers 200 with a successor credential and `Cache-Control: no-store`;
  - the old credential works for 30 s;
  - a request with no authentication result is refused;
  - other requests pass through.
  - no log record holds either credential.
  Cover the consumer options: the path, a 60-second grace and a responder receiving the successor, the user and the kind `fresh`. Verify they fail, implement, and verify they pass.
- [x] 7.2 Red: add tests for re-rotation inside the window (kind `re-rotation`), unused-successor recovery (kind `recovery`, with the manager option on), the lost race (409), a grace above the ceiling, and signed-token mode without a generator (both at construction). Also test that an enrolment-pending session posting to the renewal path is refused by the enrolment gate. Verify they fail, implement, and verify they pass.
- [x] 7.3 Red: add tests for `WithRenewalLifetime`. The default carries the deadline over. A 30-day choice under a 90-day family maximum extends it. A choice whose deadline passes the family maximum is cut to it, and the responder sees the stored deadline. A choice above the lifetime maximum fails with a configuration error and stores nothing. Verify they fail, implement, and verify they pass.
- [x] 7.4 Red: add tests for the login lifetime option. The default is the absolute timeout. A function returning 30 days for `remember: true` under a 30-day maximum gives a 30-day deadline. A lifetime above the maximum fails the login with a configuration error mapping to 500, and creates no session. Verify they fail, thread the choice through `completeLogin` into `WithAbsoluteLifetime`, and verify they pass.
- [x] 7.5 Write godoc for the renewal endpoint and the login option: the defaults, the overrides, the commit-on-reuse transaction rule, and the client guidance to switch to the successor at once. Run `/simplify` over the touched `httpsec` files. Verify `go test -race ./httpsec/...` passes and `go doc` shows each default.

## 8. Integration gate

- [x] 8.1 Run the whole-branch review against every requirement in this change's specs, with a fresh Opus reviewer that edits nothing. Verify every finding is fixed or explicitly declined in the design.
- [x] 8.2 Run `make check` (fmt-check, vet, lint, test, vuln, generate-check) and `openspec validate first-party-sessions --strict`. Verify both are clean, and keep the output.

## 9. Pull request review (design: "Pull request review (2026-10-21)")

Every task here starts with its first test from the design. If that test passes on the current code, the claim is wrong: report it, and the main session withdraws the decision.

- [x] 9.1 Red: a renewed session reports its predecessor's authentication time and its own renewal time as creation time; satisfying a second factor refreshes the authentication time; regenerating recovery codes a minute after a renewal of a session signed in six hours earlier is refused as needing reauthentication. Verify they fail, then add `Session.AuthenticatedAt` (set at `Create`, refreshed on second-factor satisfaction, carried over by renewal), switch recovery-code regeneration to it, and verify they pass with the session and `httpsec` suites. Then, red first: a passkey registration a minute after a renewal of a session signed in six hours earlier is refused as needing reauthentication; switch `passkey.Manager`'s management freshness to `AuthenticatedAt` and verify it passes with the passkey suites and their conformance scenarios. In-memory and encrypted stores carry the field; the durable column lands in 9.4.
- [x] 9.2 Red: a load of the old identifier between a strict rotation's supersession and its delete returns the old session and revokes nothing; a strict rotation whose delete fails returns the successor, and the old identifier loads inside its in-flight window. Verify both fail, then give strict rotation the in-flight window and stop a failed delete failing the rotation. Verify they pass with the rotation race tests.
- [x] 9.3 Red: a conformance case in which creating a session with a nil family through the store fails and stores nothing, with a broken variant that accepts it. Verify it fails on every store, add the refusal to every `Store.Create`, remove logout's family-less fallback, and give every existing test fixture that creates a session without a family one. Verify the session, `httpsec` and store suites pass.
- [x] 9.4 Red: after the session-families migration, an insert that names neither family column nor the authentication time succeeds and the row has a family, a family start time and an authentication time; an existing row is backfilled with the later of its creation and second-factor times; the durable stores round-trip `AuthenticatedAt`. Verify they fail on PostgreSQL 15 and 18, add the defaults and the `authenticated_at` column to the unreleased migration and to every durable store's statements, and verify they pass with the migration and session suites.
- [x] 9.5 Red: `httpsec.New` refuses a chain whose session manager coalesces activity over 10 minutes and whose engine enforces a 5-minute idle timeout, and builds one with a 15-minute idle timeout. Verify it fails, expose the manager's interval and the engine's idle timeouts, add the check, and verify it passes.
- [x] 9.6 Red: a conformance case in which O is superseded by S1, S1 by S2 and S2 by S3, and O's stored deadlines and supersession state are unchanged by the later supersessions; a broken variant that rewrites earlier members is caught. Verify it fails on every store, then replace the deadline raise with `Supersession.RetainUntil`, lock only the rows a supersession writes in row-id order, give the memory store a family index, and remove the raise and its family-wide lock. Verify the session, race, lock-order and ambient suites pass on every store, on PostgreSQL 15 and 18.
- [x] 9.7 Red: a conformance case in which marking a superseded session's first presentation returns the superseded-session error and writes nothing, and a manager test in which a live session's first presentation under recovery makes exactly one load and one mark. Verify they fail, add `ErrSessionSuperseded` and the conditional mark in every store, replace the re-read, and verify the recovery race tests pass.
- [x] 9.8 Move the durable stores' shared digest, not-found and supersession-refusal helpers into `internal/storekit`, leaving driver-specific transaction code in each store. Verify the session, race and ambient suites pass unchanged on every store, and `golangci-lint` is clean.
- [x] 9.9 Red: one source presenting 100 well-formed unknown references in a minute is refused on the next request without a store lookup (a mocked store expects none); 1,000 requests with a live reference are never refused; a policy refusal is not recorded; a consumer limiter receives the failures; a shared factory builds it in the `session-reference` namespace. Verify they fail, add the guard and `WithSessionBearerLimiter`, and verify they pass with the bearer tests and the gin and fiber cases. Document the shared-address limit in the godoc.
- [x] 9.10 Red: an 11th renewal of one family within 10 minutes is refused with `ErrRenewalThrottled`, which maps to 429, and rotates nothing; another family of the same user still renews; a consumer limiter is used; lost-response retries inside the default limit succeed. Verify they fail, add the per-family limit and `WithRenewalLimiter`, and verify they pass. Add the multi-tab serialisation advice to the `EnableSessionRenewal` godoc and the recommended interval to the `WithTouchInterval` godoc.
- [x] 9.11 Run a whole-branch review of the group's changes against the requirements they touch, and `make check`. Verify both are clean.

## 10. Pull request review, second round (design: "Pull request review, second round (2026-10-22)")

The reproduction tests named in the design are these tasks' red steps; each is brought into the tree from its worktree and seen to fail again before the fix. A reproduction test that asserts the opposite of the amended specs is not brought over.

- [x] 10.1 Red: bring `TestSupersededRecord_RetentionIsNotADeadline` (finding 1, cases A, A2, A3, R1, B1, B2), and add a load inside the window of a superseded session whose idle deadline has passed (session-expired, nothing revoked) a presentation after the window of one whose own absolute deadline has passed (reuse, family revoked), and a load inside the window and a recovery exactly at the own idle deadline (expired, as a live session is). Verify they fail on the memory store, then add `Session.RetainUntil`: the memory and encrypted stores set it on supersession and on a knocked-out successor, never lower it, never change either deadline, return a superseded record until its retention deadline, sweep it after, and keep it on `Save`; the manager judges a superseded record inside its window by its own deadlines and refuses a recovery of one whose own deadline has passed. Rewrite the existing tests that pin the raised deadlines to the amended specs. Verify the session suites, the rotation and recovery race tests, and `go test -race ./session/...` pass. Then, red first (chosen after the review of this task): a renewal under recovery of a record past its window and its own idle deadline, whose successor was used, is reuse and revokes the family, and one whose unused successor is gone is expired; conformance cases for `Store.SuccessorPresented` (presented, unused, superseded, no longer stored, not stored; writes nothing) with a broken variant that reports a gone successor as used. Verify they fail, add the port method to the memory and encrypted stores, regenerate the mock, and consult it in the manager.
- [ ] 10.2 Red: conformance cases in which a supersession leaves the superseded session's own deadlines unchanged and sets its retention deadline; a superseded session loads past its own deadlines and until its retention deadline; the sweep keeps it until that deadline and deletes it after; a knocked-out successor keeps the later retention deadline; a stale save changes neither; the round trip includes the retention deadline; a superseded row with no retention deadline is kept and swept by its own deadlines; with broken variants that raise the deadlines, sweep by the deadlines, or lower the retention deadline. Add a migration case in which the column is nullable with no default, existing rows read back with none, and the down step removes it. Verify they fail on the durable stores on PostgreSQL 15 and 18, then add `retain_until` to the unreleased migration and to the `pgschema` statements and the `sqlstore`, `pgx` and `gorm` stores, and implement `Store.SuccessorPresented` in each as one read. Verify the session, race, lock-order and ambient suites and the migration tests pass on every store.
- [x] 10.3 Red: bring `TestReuse_RevokesTheFamilyWhenThePresentingRequestIsCancelled` (four paths) and `TestLogout_EndsTheSignInWhenTheClientHangsUp`. Verify they fail, run the reuse revocation and logout's family revocation on `context.WithoutCancel(ctx)`, and verify they pass with the session and `httpsec` suites.
- [ ] 10.4 Red: bring `TestRemove_EndsOtherSessionsByFamily` (both cases), and add conformance cases for deleting a user's other sessions: the named session inside its window keeps its successor and ends an unrelated session, the named current session ends its superseded predecessor, a named session whose family has no current member is kept alone, and a race-suite case in which a renewal and the cut interleave never leaves the named session's sign-in with no live session, with a broken variant that keeps only the named session and one that keeps the whole family. Verify they fail, then make `DeleteByUserExcept` keep the named session and its family's current session in one atomic operation in every store, and update its godoc in `session.Store` and `passkey.SessionRevoker`. Verify the passkey, session and store suites pass, and the passkey removal scenarios in the `httpsec` conformance suite.
- [x] 10.5 Red: a consumer interceptor publishing a session whose family is the nil identifier gets an error, nothing is published, and the request is answered 500; publishing a family-less session with no result is refused too; publishing a result with no session still works. Verify it fails, give `Exchange.PublishSession` an error return that refuses the nil family, update the built-in callers, and correct the `logout` type's documentation. Verify the `httpsec` suites and the gin and fiber cases pass.
- [ ] 10.6 Red, on PostgreSQL 15 and 18: a `gorm` supersession whose observed successor is absent writes a SQL NULL successor digest, and a supersession in the `sqlstore` and `gorm` stores whose context is cancelled mid-transaction leaves no row written and the connection reusable. A test that fails is fixed; one that passes records the claim as wrong in the design, and the store is aligned with the other two (`storekit.OptionalDigestArg`, rollback on `context.WithoutCancel`). Verify the session and race suites pass on every store.
- [ ] 10.7 Move `atomically`, `underSavepoint` and the supersession sequence of the `sqlstore`, `pgx` and `gorm` session stores into `internal/storekit` behind a small per-driver adapter, leaving each store its driver calls. Behaviour, statements and error text are unchanged. Verify the session, race, lock-order and ambient suites pass unchanged on every store on PostgreSQL 15 and 18, and `golangci-lint` is clean.
- [ ] 10.8 Red: a passkey conformance scenario in which registration and removal with a session older than the freshness window ask for reauthentication. Verify it fails with `passkey.Manager`'s freshness check disabled and passes with it in place, then remove the dead `AuthenticatedAt` assignment from the conformance fixture. Correct the godoc of `Session.AbsoluteExpiresAt`, `Session.CreatedAt`, `Store.Save` and `storeFailed` (design, findings 5 and 9). Verify the conformance suite passes on every store.
- [ ] 10.9 Run a whole-branch review of the group's changes against the requirements they touch, with a fresh Opus reviewer that edits nothing, and `make check` and `openspec validate first-party-sessions --strict`. Verify all are clean.

## Workflow follow-up

- Tell the `bff-resource-server` change to rebase its cookie mode on the shared resolution core from group 5.
- Archive the change after the integration gate, and sync the six capability specs.
