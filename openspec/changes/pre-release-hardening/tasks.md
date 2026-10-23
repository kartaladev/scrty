# Tasks

## How every task runs

**Test-first.** Every task is test-first (`golang-tdd.md`):
- The red step is the finding's failing test, rewritten in scrty's own style: table tests per the `table-test` skill, mocks per `use-mockgen`, PostgreSQL via `use-testcontainers`.
- Each red test is run and seen failing **for the intended reason** before any code changes. A compile error is not a red step.
- The audit's tests in the scratch exports show the failing behaviour to reproduce. They are not copied over.
- A finding labelled `UNREPRODUCED` in `design.md` starts with its red test. If that test passes on HEAD, the claim was wrong: the task records that, writes no fix, and the main session removes the matching spec scenario.

**IDs.** IDs in brackets refer to the audit findings and to `design.md` decisions (D1–D18).

**Commands.** `(cd test && …)` runs the conformance module. PostgreSQL runs use the default image (18) and `SCRTY_TEST_POSTGRES_IMAGE=postgres:15.19-alpine`.

**Review.** Each group ends with a review by a fresh agent that did not write the code, on the model the design's lane table names.

## 1. Store isolation (lane F, D8)

- [x] 1.1 Add the READ COMMITTED transaction helper and the caller-isolation check to `pgx`, `sqlstore` and `gorm` [M7, S4, S5].
  - **Red tests:** in `test/{pgx,sql,gorm}store`, with the database default set to REPEATABLE READ:
    - concurrent failure streaks for one username all count;
    - overlapping saved-code replacements keep only the later set;
    - 8 concurrent provisions give exactly 1 success and 7 user-exists;
    - concurrent limiter records report no backend failure.
  - **Verify:** `(cd test && go test -race -count=1 -run 'RepeatableRead' ./pgxstore/ ./sqlstore/ ./gormstore/)` passes on PostgreSQL 18 and 15, where each case failed before.
- [x] 1.2 Make operations that need READ COMMITTED refuse a caller's stronger transaction with an error naming the level: recovery-code replace and `StreakAdd`.
  - **Red test:** a caller's REPEATABLE READ transaction replacing a saved-code set silently keeps both sets.
  - **Verify:** the refusal case passes on all three backends, and the caller's transaction is still usable afterwards.
- [x] 1.3 Bound the user-wide delete loops (`DeleteByUser`, `DeleteByUserExcept`, `DeleteByExternalSession`, `DeleteByUserAndExternalIssuer`) at 64 passes, ending with `session.ErrDeleteDidNotSettle` [U2, `UNREPRODUCED`].
  - **Red test:** concurrent `Create` for the user keeps the delete looping until its context deadline. If it passes on HEAD, record that and skip the fix.
  - **Verify:** the case returns before its deadline on all three backends.
- [x] 1.4 Add the isolation suite cases to `test/storetest` and wire them for every backend (store-conformance delta).
  - **Verify:** `(cd test && go test -race -count=1 ./...)` passes on PostgreSQL 18 and 15.
- [x] 1.5 Review (Opus) of group 1 against D8 and the `security-state-stores` and `store-conformance` deltas.
  - **Verify:** the review is clean, or its findings are folded by a fresh dispatch and reviewed again.

## 2. TOTP enrolment generations (lane D, D10)

- [x] 2.1 Change the MFA store port so `Confirm` and `AcceptStep` take the enrolment generation, and update every implementer, generated mock and suite fake together [L4, L5]. The implementers are memory, pgx, sqlstore, gorm, the sealing wrapper and `internal/pgschema/mfa.go`.
  - **Red tests:**
    - `TestConfirmEnrolment_NeverConfirmsASecretTheCodeWasNotFor`, where a store wrapper forces the interleaving;
    - `TestVerify_RefusesCodeOfARemovedSecretAfterReEnrolment`;
    - the storetest generation cases.
  - **Verify:** `go test -race -count=1 ./mfa/ ./seal/` and `(cd test && go test -race -count=1 ./storetest/... ./pgxstore/ ./sqlstore/ ./gormstore/)` pass.
- [x] 2.2 Require a whole-second TOTP period of at least one second, and wrap every `NewTOTP` and `NewVerifyThrottle` error in `ErrConfig` [L3].
  - **Red tests:** `TestNewTOTP_RefusesSubSecondPeriod`, which panics on HEAD, and a table of constructor errors that are not identifiable as `ErrConfig`.
  - **Verify:** `go test -race -count=1 ./mfa/` passes.
- [x] 2.3 Bind the sealed TOTP secret to its generation in `seal.MFASecretAAD`, and change `seal/mfa.go`'s sentinel `==` to `errors.Is` [U3, U12].
  - **Red test:** a G1 sealed secret restored onto a G2 enrolment opens.
  - **Verify:** `go test -race -count=1 ./seal/` and the sealed-column suite pass. The godoc states the re-enrolment break.
- [x] 2.4 Review (Opus) of group 2 against D10 and the `multi-factor-auth`, `security-state-stores`, `secrets-at-rest` and `store-conformance` deltas.
  - **Verify:** the review is clean.

## 3. Atomic bounded issuance (lane E, D7; starts after groups 1 and 2)

- [x] 3.1 Add `onetime.Store.InsertWithin` and `Manager.IssueWithin` with `ErrIssueLimitReached`, implemented in memory, pgx, sqlstore and gorm. The SQL takes a per-(purpose, subject) advisory lock inside group 1's READ COMMITTED helper, and refuses a stronger caller transaction.
  - **Red test:** 20 concurrent bounded issues with a limit of 5 issue more than 5 when written as count-then-issue.
  - **Verify:** `go test -race -count=1 ./onetime/` and the storetest race and isolation cases for one-time tokens pass on all backends.
- [x] 3.2 Move magic-link request and recovery start onto `IssueWithin` [L6].
  - **Red test:** `TestRequest_ConcurrentBurstStaysWithinIssuanceLimit` (20 against 5), plus the recovery-start twin.
  - **Verify:** `go test -race -count=1 ./magiclink/ ./recovery/` passes.
- [x] 3.3 Move MFA begin onto `IssueWithin` [N2]. This edits only the call site in `httpsec/mfabegin.go`, handed over from lane A for this one function, and starts after group 4 because 4.3 edits the same file. Also reset `sweepClock.claim` on a backwards clock step.
  - **Red test:** `TestMFABegin_ConcurrentBeginsDoNotExceedChallengeLimit` (12 against 3), and a backwards-clock sweep test.
  - **Verify:** `go test -race -count=1 -run 'MFABegin' ./httpsec/` passes.
- [x] 3.4 Add `passkey.CredentialStore.InsertWithin`, implemented on every backend, and move the passkey finish and registration begin onto the bounded calls [L7, passkey begin].
  - **Red test:** `TestFinishRegistration_ConcurrentFinishesStayWithinPasskeyLimit` (4 finishes against a limit of 1), plus the begin twin.
  - **Verify:** `go test -race -count=1 ./passkey/` and the passkey storetest race cases pass on all backends.
- [x] 3.5 Refuse a backed-up state without backup eligibility in the `passkey` core, for registration and assertion [L8].
  - **Red tests:** the two `BackupStateWithoutBackupEligible` tests.
  - **Verify:** `go test -race -count=1 ./passkey/...` passes.
- [x] 3.6 Register `ErrIssueLimitReached` in the sentinel registry, through lane A's owner, and update the race-suite docs.
  - **Verify:** `go test -count=1 -run TestStatusForErrorCoversEverySentinel ./httpsec/` passes.
- [x] 3.7 Review (Opus) of group 3 against D7 and the `one-time-tokens`, `magic-link`, `account-recovery`, `multi-factor-auth`, `passkey-authentication`, `security-state-stores` and `store-conformance` deltas.
  - **Verify:** the review is clean.

## 4. httpsec identity, cool-down and responses (lane A, D1, D4, D14, D15)

- [x] 4.1 Refuse a mismatched or inactive user in the shared resolve core and in `sessionRenewal.user()`, for both bearer modes and late renewal [H1, M1]. Fix the `TestRecoveryCodes` fixture that pairs mismatched IDs.
  - **Red tests:**
    - `TestBearer_RefusesTokenWhenUsernameReassigned`;
    - `TestBearer_RefusesDisabledUser`;
    - a disabled-user renewal inside and after the grace window;
    - a re-enabled user authenticating again.
  - **Verify:** `go test -race -count=1 ./httpsec/` and `(cd test && go test -race -count=1 ./httpsecconformance/...)` pass.
- [x] 4.2 Match the recovery cool-down's marked routes broadly: case-insensitive, ignoring trailing slashes, `HEAD` as `GET`. Keep every gate exemption and endpoint predicate exact [H3]. The godoc states the over-match and the fiber caveat for consumer authorization rules.
  - **Red tests:**
    - the case and trailing-slash variants refused;
    - `HEAD` on a marked `GET` route refused (`UNREPRODUCED` until this test fails on HEAD);
    - `POST /MFA/verify/totp` still not exempted.
  - **Verify:** `go test -race -count=1 -run 'Cooldown|Gate' ./httpsec/` passes.
- [x] 4.3 Set `Cache-Control: no-store` in the default login, magic-link, MFA verify, MFA begin and passkey login responders [L12].
  - **Red test:** `TestFormLogin_DefaultResponseIsNotCacheable`, plus a table over each responder.
  - **Verify:** the table passes.
- [x] 4.4 Panic at wiring on a nil ownership checker or extractor in the core guards [L13]. Bound the OIDC authorize `next` at 2048 bytes before it reaches the broker [M10, httpsec part].
  - **Red tests:** `TestOwnershipGuard_NilCheckerFailsClosedWithoutPanic`, rewritten to expect a wiring panic, and an over-long `next` test.
  - **Verify:** `go test -race -count=1 ./httpsec/` passes.
- [x] 4.5 Add the sentinels other lanes hand over (`ErrRotationRefused` 409, `ErrIssueLimitReached` 429, the did-not-settle error, the isolation refusal) to `status.go` where they map, and to `TestStatusForErrorCoversEverySentinel`. Register the `apikey`, `onetime` and `magiclink` packages; map `apikey.ErrKeyNotFound` to 404 and `magiclink.ErrInvalidLink` to 401 (it answered 500; reproduced by `TestMagicLinkRefusalStatus`) (`http-error-propagation` delta).
  - **Verify:** that test passes.
- [x] 4.6 Review (Opus) of group 4 against D1, D4, D14, D15 and the `http-security-chain` delta.
  - **Verify:** the review is clean.

## 5. Framework adapters (lane B, D16; starts after 4.4)

- [x] 5.1 Pass a fiber route's own error through unchanged, and have `ErrorHandler` honour `*fiber.Error` [M12].
  - **Red tests:** `TestFiber_ErrorHandlerKeepsNonRefusalStatuses` and `TestFiber_DefaultErrorHandlerKeepsRouteErrorText`.
  - **Verify:** `(cd fibersec && go test -race -count=1 ./...)` passes.
- [x] 5.2 Run the fiber chain on a context derived from fiber's and cancelled when the request's handling ends, and state in fibersec's godoc that a mid-request disconnect is not detected on fiber [U6].
  - **Red test:** a disconnecting client leaves a store lookup's context alive.
  - **Verify:** the test passes, or is recorded as not reproducing.
- [x] 5.3 Panic at wiring on nil ownership checkers or extractors in the fibersec and ginsec guards [L13].
  - **Red test:** `TestFiber_OwnershipGuardWithNilCheckerFailsAtWiring`, plus the gin twin.
  - **Verify:** `(cd fibersec && go test -race -count=1 ./...)` and `(cd ginsec && go test -race -count=1 ./...)` pass.
- [x] 5.4 Add a fiber conformance case showing the cool-down holds for `/Account/Email`, `/account/email/` and `/account/email//` with fiber's default routing [H3 end-to-end].
  - **Red test:** `TestFiber_RecoveryCooldownHoldsForEveryPathFiberRoutesToTheMarkedRoute`, which passes once group 4.2 has landed.
  - **Verify:** `(cd fibersec && go test -race -count=1 ./...)` passes.
- [x] 5.5 Review (Sonnet) of group 5 against D16 and the `framework-adapters` delta.
  - **Verify:** the review is clean.

## 6. Password encoding and authentication (lane C, D2, D3, D17)

- [x] 6.1 Apply the stored-record ceilings to scrypt, bcrypt and Argon2id, and refuse a constructor parameter above them [H2, N1].
  - **Red tests:**
    - `TestParseScrypt_RefusesParallelismBeyondFootprintCeiling`;
    - the scrypt CPU-time test;
    - `TestBcrypt_RefusesStoredRecordWithExcessiveCost`;
    - an Argon2id threads case;
    - constructor-ceiling tables. The Argon2id constructor case is `UNREPRODUCED` until it fails on HEAD.
  - **Verify:** `go test -race -count=1 ./password/` passes, and no `Match` in the suite takes over a second.
- [x] 6.2 Refuse NUL in bcrypt `Encode` and `Match`, subsuming the 72-byte padding guard [L9].
  - **Red test:** `TestBcryptMatch_RefusesNulJoinedRepetitionOfPassword`.
  - **Verify:** `go test -race -count=1 ./password/` passes, including the existing NUL-suffix test.
- [x] 6.3 Add the optional recognition interface to the three encoders, and spend exactly one discarded reference verification for a user with an empty or unrecognised hash [M2]. Fix the three fixtures that use hashless users with stub encoders.
  - **Red tests:**
    - `TestPasswordProvider_PasswordlessUserCostsSameAsUnknownUser`;
    - the unrecognised-hash case (`UNREPRODUCED` until it fails on HEAD);
    - a test that the reference password never admits.
  - **Verify:** `go test -race -count=1 ./authenticate/ ./password/` passes.
- [x] 6.4 Treat a delegate's `ErrNoEligibleAuthenticator` as a skip, and refuse typed-nil credentials in `Authenticate` and `VerifyDecoy` [L11, L13].
  - **Red tests:** `TestManager_NestedManagerThatSkipsLetsOuterTryNextDelegate` and `TestPasswordProvider_TypedNilCredentialsRefusedWithoutPanic`.
  - **Verify:** `go test -race -count=1 ./authenticate/` passes.
- [x] 6.5 Cap the OIDC password-claim cost band at 16 (identity-linking delta).
  - **Red test:** a band of 10 to 20 constructs.
  - **Verify:** `go test -race -count=1 ./oidc/` passes. The `oidc/passwordclaim.go` change is handed to lane J for this one function.
- [x] 6.6 Review of group 6 against D2, D3, D17 and the `password-encoding`, `authentication` and `identity-linking` deltas. 6.1, 6.2, 6.4 and 6.5 get Sonnet; 6.3 gets Opus.
  - **Verify:** the review is clean.

## 7. Recovery channels (lane G, D5, D6)

- [x] 7.1 Refuse an issued code paired with an email-channel MFA proof as a malformed recovery, before any proof is checked [M4].
  - **Red test:** `TestRecoverer_RefusesIssuedCodePairedWithEmailChannelMethod`, and the saved-code plus email-MFA case still succeeding.
  - **Verify:** `go test -race -count=1 ./recovery/` passes.
- [x] 7.2 Carry each authenticator's channel on `AuthenticatorRef` from the MFA kind, and stop the way-back check pairing an email-channel method with an issued code. Treat a loader's `(nil, nil)` as a user with nothing [M4, L13].
  - **Red tests:**
    - only an emailed MFA method with issued codes reports yes on HEAD;
    - `TestHasWayBack_LoaderWithNoDetailsDoesNotPanic`.
  - **Verify:** `go test -race -count=1 ./recovery/` passes.
- [x] 7.3 Fold ASCII case only in the cancel-link `localhost` check [N4]. Treat `(nil, nil)` record and list results as missing [S7, `UNREPRODUCED`]. Add D1's defensive ID check to recovery `Finish`.
  - **Red test:** `TestParseCancelLink_RefusesHTTPOnUnicodeFoldedLocalhost`.
  - **Verify:** `go test -race -count=1 ./recovery/` passes.
- [x] 7.4 Review (Opus) of group 7 against D5, D6 and the `account-recovery` delta.
  - **Verify:** the review is clean.

## 8. Signing keys (lane H, D9)

- [x] 8.1 Share one publishing predicate across construction, reload and housekeeping: within the lifetime, or the newest key of a configured algorithm [M5]. Update the fixtures that pin the old construction behaviour (`housekeep_test.go:96`, `algs_test.go:83`) and the 25-hour duplicate in `boundary_test.go:382`.
  - **Red tests:** `TestRestartedManager_RefusesTokensFromAKeyPastItsLifetime`, and a 3-day-old sole key kept with no replacement minted.
  - **Verify:** `go test -race -count=1 ./signingkey/` passes.
- [x] 8.2 Choose the current key only among keys not dated after now plus the reload interval, and retire non-current keys dated more than a lifetime ahead [M6]. Pass `WithClock` in `reload_test.go:88-108`.
  - **Red test:** `TestRotation_IsNotUndoneByAFutureDatedStoredKey`.
  - **Verify:** `go test -race -count=1 ./signingkey/` and `(cd test && go test -race -count=1 ./... -run SigningKey)` pass.
- [x] 8.3 Review (Opus) of group 8 against D9 and the `signing-keys` delta.
  - **Verify:** the review is clean.

## 9. Policy and bounded memory (lane I, D12, D13, D14)

- [x] 9.1 Bound the default attempt store: retention from the owning policy, an inline sweep, a 100,000-identifier cap (`WithAttemptStoreCapacity`), digests over 256 bytes, holds kept, fail closed when full, purge supported [M8]. Update the purge-unsupported tests the spec delta changes.
  - **Red test:** `TestDefaultLockoutStore_ReleasesIdentifiersOutsideWindow` (50,001 held), plus the full-store denial and the consumer capacity.
  - **Verify:** `go test -race -count=1 ./policy/` passes.
- [x] 9.2 Deny a nil input in `Engine.EvaluatePhase`, and a zero `Now` in the idle, password-age and enrolment-path policies [M11, L13].
  - **Red tests:** `TestIdleTimeout_ZeroNowDoesNotAllowIdleSession`, `TestPasswordAge_ZeroNowDeniesStalePassword`, an enrolment-path twin, and `TestEngine_NilInputDeniesRatherThanPanics`.
  - **Verify:** `go test -race -count=1 ./policy/` passes.
- [x] 9.3 Cap the outage hold, digest its long keys, answer exceeded when it is full, and re-arm its sweep after a backwards clock step [M9, L15].
  - **Red tests:** `TestUnavailable_RefuseHoldIsBoundedUnderKeySpray` and `TestHold_SweepsAfterClockStepsBackwards`.
  - **Verify:** `go test -race -count=1 ./internal/unavailable/` passes.
- [x] 9.4 Cap the log sampler's keys per window, with an overflow key [U5, `UNREPRODUCED`]. Refuse empty or `:`-bearing flow names in `NewSourceGuard` [U10].
  - **Red tests:** a one-million-key spray in one window, and a `login:2001` flow constructing.
  - **Verify:** `go test -race -count=1 ./pkg/logsample/ ./ratelimit/` passes.
- [x] 9.5 Review of group 9 against D12, D13, D14 and the `security-policy`, `rate-limiting` and `log-sampling` deltas. 9.1 gets Opus; the rest get Sonnet.
  - **Verify:** the review is clean.

## 10. Point fixes (lane J, D11, D14, D16, D17)

- [x] 10.1 API keys [M3, N3, L10]:
  - `Rotate` refuses revoked and expired keys with `ErrRotationRefused`;
  - `apikey.Store.Revoke` reports whether it moved the key, on every backend and fake;
  - `Rotate` revokes its replacement when it loses the race;
  - Issue and Verify refuse an empty digest, and `NewManager` probes a consumer digest.

  This is the `apikey` port change and goes to Opus.
  - **Red tests:** `TestRotate_RefusesRevokedKey`, `TestRotate_ConcurrentRotationsLeaveOneLiveReplacement` and `TestVerify_EmptyDigestDoesNotAcceptAnySecret`.
  - **Verify:** `go test -race -count=1 ./apikey/` and the API-key storetest cases on all backends pass.
- [ ] 10.2 OIDC and authorize [L1, M10, U11, L2]:
  - ASCII-only domain allowlist;
  - `next` over 2048 bytes not recorded, and over-long allowlist entries refused;
  - skew bounded at 5 minutes and logout max-age at 1 hour;
  - ASCII-only privilege comparer with ASCII-only trim.
  - **Red tests:** `TestBroker_RefusesProvisioningForUnicodeFoldedDomain`, `TestAuthorize_BoundsUntrustedNextLength`, the two bound cases, and `TestPrivilegeAuthorizer_DefaultComparerDoesNotFoldDistinctUnicodeNames` plus the NBSP case.
  - **Verify:** `go test -race -count=1 ./oidc/ ./authorize/` passes.
- [x] 10.3 Tokens, sessions and notify [S1, S6, S2, U4, L14]:
  - a typed-nil verification key is an unusable key set;
  - a whole-second token lifetime;
  - a `(nil, nil)` session load is not-found;
  - with recovery on, a failed first-use write fails the load;
  - SMTP normalises CR, LF and CRLF to CRLF.
  - **Red tests:** `TestSweep_VerifyTypedNilPublicKeyDoesNotPanic`, `TestSweep_SubSecondLifetimeProducesUsableTokens`, `TestSweep_ManagerLoadOfStoreReturningNoSessionDoesNotPanic`, the U4 case (`UNREPRODUCED`), and `TestBuild_WireCarriesNoBareCarriageReturn`.
  - **Verify:** `go test -race -count=1 ./token/ ./session/ ./notify/` passes.
- [ ] 10.4 Passkey and WebAuthn, after groups 3 and 4 [U8, S3, S9]:
  - RP ID must be a lowercase DNS name;
  - `(nil, nil)` user details refused at registration begin;
  - whole-second ceremony cookie TTLs.
  - a nil element in a stored credential list is treated as missing in `passkey/pending.go` [S7, `UNREPRODUCED`].
  - **Red tests:** `TestSweep_BeginRegistrationWithLoaderReturningNoUserDoesNotPanic`, plus the RP ID table (`UNREPRODUCED` until it fails on HEAD).
  - **Verify:** `go test -race -count=1 ./passkey/...` passes.
- [ ] 10.5 Documentation and layout [U1, M13]:
  - state the replica-read limit in `gorm/doc.go`;
  - after `release-readiness` task 2.1 lands, run the layout guard's file and `go.mod` checks for every workspace module except `./test`.
  - **Red test:** a planted `Mock*` type in a nested module, and a test-module import in a nested module, go undetected on HEAD.
  - **Verify:** `go test -count=1 -run 'TestModuleLayout|TestAudit' .` fails on each plant and passes without them.
- [ ] 10.6 Review of group 10 against D11, D14, D16, D17 and the `api-keys`, `oidc-login`, `oidc-logout`, `identity-linking`, `authorization`, `token-issuance`, `sessions`, `email-notification` and `passkey-authentication` deltas. 10.1 gets Opus; the rest get Sonnet.
  - **Verify:** the review is clean.

## 11. Gate

- [ ] 11.1 Record every breaking change in `CHANGELOG.md` under `Unreleased`, or, if `release-readiness` has not yet created it, in a note that change picks up. The breaking changes:
  - the port additions and signature changes;
  - sealed TOTP secrets needing re-enrolment;
  - hash ceilings and the bcrypt NUL refusal;
  - the email-pairing refusal;
  - the cool-down over-match.
  - **Verify:** every **BREAKING** item in `proposal.md` has an entry.
- [ ] 11.2 Run `make check` on PostgreSQL 18, and the `test` module on PostgreSQL 15, plus `golangci-lint run ./...`, `govulncheck ./...` and `gofmt -l .` in every module.
  - **Verify:** all are green, with the outputs kept.
- [ ] 11.3 Rerun every audit and sweep reproduction (`audit_*` and `sweep_*` tests in the scratch exports) against the branch.
  - **Verify:** each now passes, or is recorded as dropped because it was `UNREPRODUCED` and its red test passed on HEAD.
- [ ] 11.4 Run a whole-branch review (Opus) against every requirement in the change's delta specs and every decision in `design.md`, then `openspec validate pre-release-hardening --strict`.
  - **Verify:** both are clean.

## Workflow follow-up

- Archive the change after the gate and the whole-branch review pass.
- Verify the archived specs merged cleanly, in particular `identity-linking` and `security-state-stores`, which carry both ADDED and MODIFIED requirements.
