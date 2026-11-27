# Tasks

Every fix starts with a red step: write the test, run it on the unmodified code, and see it fail
for the claimed reason. A compile error is not a red step. That failure is the reproduction
`defect-claims.md` asks for. If the test passes on the unmodified code instead, stop: the claim
was wrong, so the fix is not made, and it is reported (design, Failure modes). Verification is
scoped to the changed packages and their dependents (`test-scope.md`). The commands are in
`plans.md`.

## 1. CSRF refusal fails closed (design 1)

- [x] 1.1 Red: rows in `TestSessionCookie_RefusalExpires` (or the table that holds the CSRF token-source rows) with a `CSRFTokens` mock whose `Verify` returns `errors.Join(ErrAuthenticationRequired, nil-entry)` via a custom `Unwrap() []error`, and one with a typed-nil child; assert `ErrCrossSiteRequest`, `403`, handler not run, no charge, no `Set-Cookie`, no panic; see both fail on the unmodified code (admitted / panic)
- [x] 1.2 Green: `csrfAnswer` walks the error tree once through `internal/errwalk`, classifying nodes by type, and answers `ErrCrossSiteRequest` when no cause remains or the walk aborts (logged); the 1.1 rows and the existing outage row pass

## 2. Canonical cookie name prefixes (design 4)

- [x] 2.1 Red: rows in the cookie-options construction table for `__host-app`, `__HOST-app` (no domain) and `__secure-app` with domain `example.com`; assert `ErrConfig` whose message names `__Host-` or `__Secure-`; see them fail on the unmodified code (the chain builds)
- [x] 2.2 Green: `checkAttributes` matches the prefixes exactly, and refuses a name that matches a prefix only case-insensitively with a message naming the canonical spelling; existing `__Host-app` / `__Secure-scrty-session` rows still build; the godoc of `WithSessionCookieName` states the canonical-spelling rule

## 3. Bound session refused at continuation on a cookie chain (design 6)

- [x] 3.1 Red: on a cookie chain with a consumer authenticator that publishes a DPoP-bound session, second-factor verification, re-authentication and renewal each are refused with `ErrAuthenticationRequired` (401), the code or proof not spent, the session not rotated; see each fail on the unmodified code
- [x] 3.2 Green: `credentialDelivery.continuingProof` on a cookie chain refuses a session with a key binding, and returns nil for an unbound one; the existing "Invalid proof ignored" cookie-chain rows still pass

## 4. A delivery that quotes the cookie is refused (design 3)

- [x] 4.1 Red: a `SessionDelivery` that sets the chain's cookie with `Quoted: true`; assert the sign-in fails as an issuing failure, no session cookie on the response, and the session ended; see it fail on the unmodified code (the sign-in succeeds)
- [x] 4.2 Green: `sameCookie` compares `Quoted`; the godoc of `SessionDelivery` names quoting among the attributes it must not change

## 5. `MFAAtFirstFactor` pinned at every rotation (design 2)

- [x] 5.1 Red: in `session` tests, a strict `Rotate` of a copy that sets the mark on an unmarked session, and a `RotateWithGrace` with `WithSuccessorFromCaller(loaded)` of a copy that clears it on a marked session; assert the stored successor carries the stored mark; and a row where the unchanged copy keeps the mark; see the first two fail on the unmodified code
- [x] 5.2 Green: strict rotation and `successorFromCaller` take `MFAAtFirstFactor` from the stored record; reword the godoc of `Session.MFAAtFirstFactor`, `Rotate` and the store's rotation contract to say so
- [x] 5.3 Run the store conformance suite for sessions against the memory, pgx, sql and gorm stores (`test/storetest`) and confirm the mark round-trips through rotation in each

## 6. Role switch and the handler's return exclude each other (design 5, revised)

- [x] 6.1 Red: a barrier test where a role switch runs on a goroutine and is held inside the rotation while the handler returns, with an interceptor after `next` that reads `ex.Session`, `ex.Context()` and sets a response header; assert, under `-race`, no data race, the return waits for the switch, the response headers snapshotted right after the run carry the successor's cookie, and the interceptor saw the successor; a test that a switch after the handler returned is refused with `ErrConfig`, storing nothing; and a test that a queued switch whose context is cancelled gives up with that error and stores nothing; see the first and third fail on the current lane code (race report / blocked wait)
- [x] 6.2 Green: a per-request guard (a cancellable one-slot lock and a "handler returned" mark set under it by every handler return) is created only by a chain that rotates on a role switch, inherited by exchanges built inside a guarded run, and never by a detached copy; `SwitchActiveRole` takes it at its start honouring its context, then the role source's lock, checks the mark, and holds it through the rotation and the cookie write; the godoc of `SwitchActiveRole` states the handler's return waits for a switch in progress, that a switch after it is refused, and that the store's own timeouts bound the wait
- [x] 6.3 Run the switch, chain, nested-chain and logout-during-switch tests with `-race -count=20`, and the ginsec and fibersec suites, and confirm no deadlock or race

## 7. Documentation

- [x] 7.1 Update the `[Unreleased]` CHANGELOG entries for the canonical prefix rule, the `MFAAtFirstFactor` rotation fix, the CSRF fail-closed fix, the quoted-delivery refusal, the role-switch lock and the bound-session refusal

## 8. Gate

- [ ] 8.1 Run the scoped checks for every changed package and its dependents, then a whole-branch review against this change's specs, then `make check` and `make spec-check`, and read their output; verify both pass after the last edit
