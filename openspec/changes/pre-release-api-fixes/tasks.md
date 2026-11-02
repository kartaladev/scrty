# Tasks

Every Go task is test-first: write the failing test, run it, and confirm it fails for the intended reason (a compile error is not a red step). Then implement, re-run, and refactor with the tests green. Each task states how it is verified. Tasks 1–4 moved here from `release-readiness` (its groups 6–9) on 2026-11-02, unchanged except for numbering.

## 1. Pre-release fixes in `notify` (decisions 1, 2; email-notification requirement "A queued sender returns without waiting for delivery")

- [ ] 1.1 Red: write `TestQueuedSender_WrappedSenderEndsItsGoroutine`, the scenario "Wrapped sender ends its goroutine", under `-race` with goleak. Run it and confirm it fails because the second message is never delivered. Then implement decision 1: a worker whose delivery did not return normally logs the failure and is replaced. Verify: the scenario and every queued-sender scenario pass under `-race`.
- [ ] 1.2 Pin the current behaviour with `TestSMTPSender_NoSenderAddressIsAConfigError`: a message with no `From`, through a sender with no default address, returns an error matching `ErrConfig`. It passes today, so prove it by temporarily wrapping a different error and watching it fail, then restore it by editing it back. Then update `ErrConfig`'s godoc per decision 2. Verify: the test passes, and every place that wraps `notify.ErrConfig` outside a constructor is named in the godoc.

## 2. The token subject (decision 3; token-issuance and authentication deltas)

- [ ] 2.1 Audit, read-only: list every use of `identity.Principal.Username` reachable from a bearer-authenticated request, on both paths: the standalone `JWTAuthenticator`, and the chain's session-backed bearer interceptor (`httpsec/bearer.go`, which reloads the user and builds the principal from the reloaded details). Use gopls references, not text search. Confirm that the chain path keeps filling `Username` from the reloaded user, and report which readers would see an empty username under the new default. The main session records the outcome in decision 3 before 2.2.
- [ ] 2.2 Red: write the `token-issuance` scenarios "Default token" (now `sub` `u-1`), "Consumer chooses the username as subject" and "Empty subject", and the `authentication` scenarios "Valid token" (principal identifier `u-1`) and "Consumer reads the subject as a username". Run them and confirm the default and empty-subject cases fail on their assertions. Also red: through the chain's bearer interceptor, a default token reloads its user by the session's user reference and the principal keeps the user's username; a token whose `sub` is not the session's user reference is refused. Then implement decision 3 with `token.WithUsernameSubject()` and `authenticate.WithJWTUsernameSubject()`, each naming the default it replaces. In `httpsec/bearer.go`, look the user up with `lookupBySessionUser` under the default and `lookupByUsername` under the username option. Verify: the scenarios pass, and so do the `token`, `authenticate`, `httpsec` and `test` suites.

## 3. Signing-key retention (decision 4; signing-keys delta)

- [ ] 3.1 Red: add delete cases to the key-store conformance suite (delete existing keys, delete a missing key without error, `LoadAll` no longer returns deleted keys), and the `signing-keys` scenarios "Old key removed" (also gone from the store), "Consumer keeps retired keys", "Failed delete retried", "Current key kept" and "Far-future key removed" (still stored). Run them and confirm they fail on their assertions, not on compiling: add `Delete` as a stub first.
- [ ] 3.2 Implement `KeyStore.Delete` in the in-memory store, `sqlstore`, `pgxstore`, `gormstore` and the sealing decorator, and the housekeeping deletion with `WithRetiredKeysKept()`. Verify: the conformance suite passes against every store, including the Docker suites, and every `signing-keys` scenario passes under `-race`.

## 4. Port clean-up (decisions 5, 6)

- [ ] 4.1 Remove `passkey.CredentialStore.DeleteAwaitingSavedCodes` from the port, the three SQL stores, `internal/pgschema`, the conformance suite and the mocks. This is a removal with no red step. Verify: every module builds and its tests pass, and `rg --glob '!.claude/.legacy' DeleteAwaitingSavedCodes` finds nothing outside `openspec/`.
- [ ] 4.2 Red: write `TestConfirmEnrolment_DeviceProofBetweenReadAndConfirm`, which lands a device proof between `ConfirmEnrolment`'s read and the store's `Confirm` and asserts the outcome `mfa-enrolment-path` says is wrong is not what happens. Run it. If it passes, report it so the main session records the claim as dropped in decision 6. If it fails, stop and report it, so the main session writes the fix's decision and a `multi-factor-auth` delta before any fix.

## 5. Integration gate

- [ ] 5.1 Run a whole-branch review against every requirement in this change's specs and decisions 1–6, with a fresh Sonnet reviewer that edits nothing. Verify every finding is fixed or explicitly declined in the design.
- [ ] 5.2 Run `make check` and `openspec validate pre-release-api-fixes --strict`. Verify both are clean, and keep the output.

## Workflow follow-up

- Archive the change after `close-security-gaps` is archived, and sync `token-issuance`, `authentication`, `signing-keys` and `email-notification`.
- `release-readiness`'s first changelog entry summarises this change's breaking items.
