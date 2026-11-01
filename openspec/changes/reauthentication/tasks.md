# Tasks

Every task is test-first:

1. Write the failing test.
2. Run it and see it fail for the intended reason. A compile error is not a red step.
3. Make it pass.
4. Refactor.

Each task names how it is verified. A signature change owns every caller of the changed API across the workspace: `_test.go` files, `httpsec`, the adapters, the `test` module, Examples and README snippets. The workspace therefore compiles and passes at the end of every task group. Section names in parentheses are the spec requirements a task covers; D-numbers are design decisions.

## 1. One freshness check (`sessions`, `account-recovery`, `passkey-authentication`)

- [x] 1.1 `(*session.Session).AuthenticatedWithin(now time.Time, window time.Duration) bool`: no more than `window` elapsed, inclusive; a future authentication time counts as no time elapsed; a zero authentication time is never within (D1; ADDED sessions "One check decides whether a session authenticated within a window", every scenario as one table test). Also cover the MODIFIED sessions scenario "Saving cannot refresh it" against the in-memory store. Verify with `go test -race -run 'TestAuthenticatedWithin|TestSave' ./session/`
- [x] 1.2 Recovery-code regeneration (`httpsec/recovery_codes.go`) and the passkey manager's freshness check (`authenticate/passkey/passkey.go` `admit`) call `AuthenticatedWithin` instead of their own comparisons. Add boundary cases first:
  - exactly at the window's end is admitted;
  - a zero authentication time is refused.

  Each red step comes from inverting the boundary temporarily, because the refactor preserves behaviour. Their godoc and the README say freshness reads the session's authentication time (D1; MODIFIED account-recovery "Regenerating codes needs a recent authentication and notifies the user" and passkey-authentication "Registration admits a session only at the account's assurance and only while fresh", existing scenarios unchanged). Verify with `go test -race -run 'TestRecoveryCodes|TestManage|TestBeginRegistration' ./httpsec/ ./authenticate/passkey/`

## 2. Refusals (`http-error-propagation`)

- [x] 2.1 `httpsec.ErrReauthenticationRequired`, `*httpsec.ReauthenticationRequiredError{Window}` and `httpsec.ErrReauthenticationMethodNotUsable`:
  - the error type is `ErrReauthenticationRequired` under `errors.Is`, and exposes its window under `errors.As`;
  - its text names no session, user or handle;
  - both map to 403 in `statusTable`;
  - both are listed in `sentinelRegistry`, so `TestStatusForErrorCoversEverySentinel` passes;
  - godoc names where each is raised.

  (D2, D7; MODIFIED "Refusal errors are a stable public contract", scenario "Recency refusal carries its window"; MODIFIED "One public table maps refusals to a status", scenarios "Recency guard refusal" and "Re-proof method not usable".) Verify with `go test -race -run 'TestStatusForError|TestRefusalSentinelsAreDistinct|TestReauthenticationRequiredError' ./httpsec/`

## 3. The core recency guard (`reauthentication`)

- [x] 3.1 Guard options:
  - `WithRecentAuthenticationWindow`, `WithGuardClock` and `WithAuthenticationTime`, with `DefaultRecentAuthenticationWindow = 15 * time.Minute` and the system clock as defaults;
  - `NewGuards` fails with `ErrConfig` for a zero or negative window, a nil or typed-nil clock, and a nil authentication-time func, each message naming the option.

  (D2; "The recency window has a default, a guards-wide override and a per-route override" scenario "Zero guards-wide window"; "The recency guard reads time from a replaceable time source" scenario "Absent time source"; "The authentication time comes from the session unless the consumer supplies it" scenario "Absent consumer source".) Verify with `go test -race -run 'TestNewGuards' ./httpsec/`
- [x] 3.2 `RequireRecentAuthentication()` and `RequireAuthenticationWithin(d)` as judges on `g.guard`:
  - authentication time from `SessionFromContext`, or from the consumer func when given;
  - freshness via `AuthenticatedWithin`;
  - refusal `&ReauthenticationRequiredError{Window: d}`;
  - a zero or negative per-route window panics at wiring, naming the window;
  - a nil receiver panics like the other builders.

  One table test covers every scenario of these requirements through net/http with a controlled clock: "A recency guard refuses a session that authenticated too long ago", "An absent authentication time is never recent", "Only an authentication makes a session fresh again", "The recency window has a default, a guards-wide override and a per-route override", "The recency guard reads time from a replaceable time source", "The authentication time comes from the session unless the consumer supplies it", and "The reauthentication-required refusal names the window it needed". The re-authentication case "A re-authentication makes it fresh" is driven here by a rotated session carrying a new authentication time (D2). Verify with `go test -race -run 'TestRecencyGuard|TestGuardsFailClosed|TestGuardsWiringPanics' ./httpsec/`
- [x] 3.3 Godoc on every new option and method:
  - the default it replaces;
  - stacking inside privilege guards;
  - passing the chain's clock to `WithGuardClock`;
  - the window relative to the session's absolute lifetime.

  A runnable `Example` of a recency-guarded route, and the README guards section with the defaults table rows for the window and the clock (D2). Verify with `go test -run 'Example' ./httpsec/` and `go vet ./httpsec/`

## 4. Adapter recency guards (`framework-adapters`)

- [x] 4.1 `ginsec`: the same three options, two methods, validation and wiring panics, refusing through the gin error-channel path; godoc as in 3.3 (D8; ADDED "Adapter recency guards match the core recency guard" scenarios "gin stale session", "Fresh session on every adapter" for gin, "Per-route window on gin", "gin per-route window of zero"). Verify with `go test -race ./...` in `httpsec/ginsec`
- [x] 4.2 `fibersec`: the same, returning the refusal to fiber's error handler with its window; no error-handler option; godoc as in 3.3 (D8; scenarios "fiber stale session", "Fresh session on every adapter" for fiber, "fiber guards with an absent time source"). Verify with `go test -race ./...` in `httpsec/fibersec`

## 5. The MFA endpoints serve only a pending session (`multi-factor-auth`)

- [x] 5.1 Red first: a test showing that a full session posting a valid code to `/mfa/verify/totp` is accepted today, which the new requirement inverts. Then `verify` and `begin` refuse `s.MFA != session.MFAPending` with `ErrNoMFAChallengePending`:
  - after the session and caller refusals;
  - before the method name, the throttle, the body and any challenge issue;
  - counting nothing and leaving the handle unchanged.

  Sweep the workspace for callers that posted to verify or begin from a full session (tests, `test/httpsecconformance`, Examples) and move them to a pending session. Godoc on `EnableMFA` and the verify and begin endpoints states the refusal (D5; ADDED "The verify and begin endpoints serve only a session that owes a second factor", every scenario; MODIFIED http-error-propagation scenario "No MFA challenge pending at verify"). Verify with `go test -race -run 'TestMFAVerify|TestMFABegin|TestMFAGate' ./httpsec/` and `go test ./...` in the `test` module

## 6. The re-authentication endpoints (`reauthentication`, `sessions`, `account-recovery`, `passkey-authentication`)

- [x] 6.1 Wiring:
  - `EnableReauthentication(opts...)` with every `ReauthenticationOption` in D6 and their defaults;
  - `OrderReauthentication = 655`;
  - `DefaultReauthenticationPrefix = "/reauth"`;
  - registration after the MFA slot and form login are known;
  - every construction error in D6, as `ErrConfig`, each naming its cause.

  ("Re-proof endpoints exist only when re-authentication is enabled" scenarios "Off by default", "Consumer prefix"; "Re-authentication wiring mistakes fail at construction", every scenario; "Re-proof challenges are their own and bound to the session" scenario "Zero lifetime".) Verify with `go test -race -run 'TestEnableReauthentication|TestOrder' ./httpsec/`
- [x] 6.2 Admission, the factor policy, and `GET <prefix>/methods` with its default JSON body and replaceable responder:
  - the decision is shared by every endpoint;
  - a lookup failure refuses;
  - non-full sessions are refused by their gates and, if reordered, by the endpoint as authentication required.

  (D3, D4, D6; "Only a full session may re-prove" scenarios "No session", "Pending second factor", "Pending password change", "Enrolment-only session", "Recovery-pending session"; "The method listing reports how the session's user may re-prove", every scenario; "A consumer can require a second factor for every re-proof" scenario "Second factor only" at the listing.) Verify with `go test -race -run 'TestReauthMethods|TestReauthAdmission' ./httpsec/`
- [x] 6.3 Second-factor begin and verify:
  - the order in D6;
  - the MFA slot's throttle instance;
  - per-method challenge managers under `reauth-challenge:<method>`, bound to the session, with their own TTL, limit and store, swept by the chain's expiry task;
  - clone and suspension refusals unchanged and uncounted;
  - no same-channel refusal.

  ("A second-factor re-proof is verified like a second factor", every scenario; "Re-proof challenges are their own and bound to the session", every remaining scenario; "A refused authenticator at re-proof keeps its meaning", every scenario; "A user re-proves with the strongest factor they hold, by default" scenario "A passkey login re-proves with the passkey"; "Re-proof endpoints exist only when re-authentication is enabled" scenario "A method segment is required".) Verify with `go test -race -run 'TestReauthVerify|TestReauthBegin' ./httpsec/`
- [x] 6.4 `POST <prefix>/password`:
  - the factor policy before the body;
  - binding only `password` (form, then JSON) under the login body limit;
  - the username from the resolved caller;
  - the form login's password path, with lockout, decoy, failure recording and source accounting;
  - lockout failures cleared on success.

  ("A password re-proof checks the session's own user under the account lockout", every scenario; "A user re-proves with the strongest factor they hold, by default" scenarios "A TOTP holder offers a password", "A user without a second factor", "MFA not configured", "Lookup failure does not downgrade"; "A consumer can require a second factor for every re-proof", every scenario.) Verify with `go test -race -run 'TestReauthPassword' ./httpsec/`
- [x] 6.5 Resolve:
  - the authentication time from the chain's clock;
  - for a second factor, also the satisfied second factor at that time;
  - a strict rotation with rollback on failure;
  - publish, issue and answer through the responder with `Cache-Control: no-store`;
  - sampled refusal logs free of secrets.

  ("A successful re-proof refreshes the authentication time and rotates the session", every scenario; "Re-proof responses are not cached and re-proof logs carry no secret", every scenario; "Only a full session may re-prove" scenario "A fresh session re-proves"; MODIFIED sessions scenario "A re-authentication refreshes the authentication time"; MODIFIED account-recovery scenario "Fresh after a re-authentication"; MODIFIED passkey-authentication scenario "Freshness from a re-authentication".) Verify with `go test -race -run 'TestReauthResolve|TestRecoveryCodes|TestPasskeyRegister' ./httpsec/`
- [x] 6.6 Godoc on `EnableReauthentication`, every option, responder and endpoint, naming each default. The README gains a re-authentication section after the guards section:
  - the endpoints and the default JSON;
  - the factor policy, and why no "any factor" option exists;
  - OIDC-only users and the listing responder filter;
  - the in-memory challenge store's single-process limit;
  - the three reauthentication sentinels.

  The defaults table gains every new default (D6, D7, D9). Verify with `go test -run 'Example' ./httpsec/` and `go vet ./httpsec/`
- [x] 6.7 A same-channel re-proof refreshes freshness only, and the docs follow D4, D5 and D10:
  - `resolve` records the second factor as satisfied only when the method's channel is not the session's first-factor channel, using the test `/mfa/verify` applies; a same-channel re-proof sets the authentication time and leaves `MFA` and `MFASatisfiedAt` unchanged;
  - the passkey "step-up" docs (`authenticate/passkey/doc.go`, `authenticate/passkey/register.go`, `httpsec/passkey.go`, the README passkey section) say a full session re-proves at `/reauth`, not `/mfa/verify`, and that a same-channel re-proof refreshes freshness without meeting the second factor;
  - the README re-authentication section names the gate refusal for a session owing a challenge, and the 409 for a concurrent re-proof or MFA verification on one server;
  - `fibersec.DefaultRecentAuthenticationWindow` aliases `httpsec.DefaultRecentAuthenticationWindow`, as `ginsec` does;
  - the consumer-prefix row also re-proves with a valid TOTP code at `/account/confirm/verify/totp`.

  (D4, D8, D10; "A successful re-proof refreshes the authentication time and rotates the session" and the ADDED "A same-channel re-proof refreshes freshness only", every scenario; "Re-proof endpoints exist only when re-authentication is enabled" scenario "Consumer prefix".) Verify with `go test -race -count=1 ./httpsec/... ./authenticate/passkey/...`, `go test ./...` in `httpsec/fibersec`, and `go vet`

- [x] 6.8 One implementation per control, behaviour unchanged (D6):
  - one challenge spend and one expiry sweep, shared by the MFA slot and re-proof, with the purpose and the log names as parameters; the copies in `httpsec/reauth_verify.go` are removed;
  - one form-login method running the whole password order (source throttle, pre-authentication, lock refusal, source charging, password check), returning the proved authentication; login's handler and the password re-proof both call it, and `authenticatePassword` keeps its own callers' behaviour.

  Existing tests are the safety net; the red step for each extraction is a temporary divergence in the shared code that both a login or MFA test and a re-proof test catch. Verify with `go test -race -count=1 ./httpsec/...`, `go vet ./httpsec/`, `golangci-lint run ./httpsec/`, and `go test ./...` in the `test` module

## 7. A lost strict rotation is a renewal conflict (`sessions`, `multi-factor-auth`, `reauthentication`)

- [x] 7.1 Within the in-flight window after a strict rotation, the manager remembers the rotated handle's digest, and a strict `Rotate` of that handle that finds no record fails with `session.ErrRenewalConflict`:
  - no store write and no `judge` on that path, so reuse detection never fires and nothing is revoked;
  - past the window, or for a never-rotated revoked or unknown session, `ErrNotFound`; an expired session `ErrExpired`;
  - the old identifier stops loading at once;
  - the memory is bounded and pruned as entries expire;
  - `Rotate`'s godoc states the guarantee and that across managers sharing a store a loser may still get `ErrNotFound`; `ErrRenewalConflict`'s godoc says "a concurrent rotation".

  Change the tests that pin today's not-found: `session/sessions_test.go` "a handle already rotated away cannot be rotated again" splits into inside and after the window, and `TestManagerRotateConcurrent` expects every loser to be `ErrRenewalConflict`. In `httpsec`, the concurrent re-proof row in `TestReauthResolve` expects `ErrSessionRenewalConflict` (409), and `TestMFAVerifyRotationRefusals` gains two valid codes at once, one 409. (D10's first cut, replaced by section 10; ADDED sessions "A strict rotation that lost a race within one manager is a renewal conflict", since revised; ADDED multi-factor-auth "Concurrent verifications of one pending session yield one success"; reauthentication scenario "Concurrent re-proofs".) Verify with `go test -race -count=1 ./session/ ./httpsec/` and `go test ./...` in the `test` module

## 8. Conformance and close-out

- [x] 8.1 `test/httpsecconformance` on net/http, gin and fiber, each scenario mirroring a spec scenario:
  - a stale session refused by the recency guard, a TOTP re-proof, and the route accepted with the new credential;
  - a password re-proof by a user without a second factor;
  - a TOTP holder refused at `/reauth/password`;
  - a full session refused at `/mfa/verify/totp`;
  - a fiber refusal carrying its window to the error handler.

  (D9; framework-adapters "Adapter recency guards match the core recency guard" across adapters.) Verify with `go vet ./...` and `go test -race ./...` in the `test` module (needs Docker for durable backends)
- [x] 8.2 The whole-workspace gate:
  - `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...` and `golangci-lint run ./...` in every module listed by `go list -m`;
  - `gofmt -l` empty over tracked Go files;
  - `openspec validate reauthentication --strict`.

  Verify that every command exits 0 and its output is recorded.

## 9. Review findings: wiring, policy and one implementation (`reauthentication`, `multi-factor-auth`, `framework-adapters`)

Each defect task's red step is the reproducing test named in its design decision, rewritten into the package's own test file and the `table-test` form; the reproductions themselves live in disposable worktrees under `/private/tmp/claude-501/-Users-zakyalvan-Documents-RND-scrty/5335ea06-576b-4616-b14e-50643ee94c82/scratchpad/repro/` and are not copied as they are.

- [x] 9.1 Re-proof paths are checked by how each endpoint matches (D6 "Path collisions"):
  - two paths collide when equal, or when one lies under the other and the other is prefix-matched; re-proof begin and verify are prefix-matched, its listing and password exact;
  - checked against every enabled endpoint: the MFA verify, begin and enrolment prefixes and the passkey registration and credentials prefixes (prefix); logout, form login, the MFA listing, session renewal, password change and every account recovery path (exact); magic-link, OIDC and passwordless passkey login, each as its own `Intercept` matches;
  - red: the six collision rows of `TestReproReauthPathCollisionRefused` and the two rows of `TestReproReauthPrefixUnderFormLoginPathIsAllowed`; the rows `the_prefix_is_the_form_login_path` and `the_prefix_is_the_logout_path` in `TestEnableReauthentication` are rewritten to the accepted outcome.

  (Reauthentication "Re-proof paths are checked against every endpoint the chain answers", every scenario; "Re-authentication wiring mistakes fail at construction".) Verify with `go test -race -count=1 -run 'TestEnableReauthentication|TestReauth' ./httpsec/`
- [x] 9.2 A chain with the MFA slot and passkeys and no `EnableReauthentication` fails `New` with `ErrConfig` naming the option (D5 "Passkey management needs re-authentication"):
  - red: `TestRepro_FullSessionStepsUpAtMFAVerifyWithoutReauthentication`, rewritten to assert the construction refusal, plus the accepted rows (with re-authentication, and MFA without passkeys); the "With re-authentication" scenario drives an `MFANone` TOTP holder through `/reauth/verify/totp` to passkey `begin`;
  - the task owns every chain in the workspace that wires MFA and passkeys without re-authentication: `httpsec` tests and Examples, `test/httpsecconformance`, and README snippets.

  (ADDED multi-factor-auth "Passkey management on an MFA chain needs re-authentication", every scenario.) Verify with `go test -race -count=1 ./httpsec/... ./authenticate/passkey/...` and `go test ./...` in the `test` module
- [x] 9.3 An MFA challenge store without a re-proof challenge store fails `New` with `ErrConfig` naming both options; the same store given to both is accepted (D6 "A shared MFA store without a re-proof store"):
  - red: `TestReproReauthChallengeStoreFollowsSharedMFAStore`, rewritten to assert the refusal; the "One store for both" row keeps its two-chain begin-on-one, verify-on-the-other proof;
  - godoc on `WithReauthenticationChallengeStore` and `WithMFAChallengeStore`, and the README defaults table, name the rule.

  (Reauthentication scenarios "A shared MFA challenge store needs a re-proof store" and "One store for both".) Verify with `go test -race -count=1 -run 'TestEnableReauthentication|TestReauth' ./httpsec/`
- [x] 9.4 The password re-proof runs the post-authentication phase after `attemptPassword` and the proved-account check, before failures are reset (D6 Password order, step 6):
  - a deny refuses with the policy's reason; a challenge refuses with a `*ChallengeError` of that kind and no session; neither resets, rotates nor refreshes;
  - red: `TestReproPasswordReproofAppliesPostAuthenticationPolicy` (the deny row) and a challenge row.

  (ADDED reauthentication "A password re-proof applies the post-authentication policy as a login does", every scenario.) Verify with `go test -race -count=1 -run 'TestReauthPassword' ./httpsec/`
- [x] 9.5 Second-factor begin and verify look up only the named method's enrolment; the password endpoint and the listing keep the full lookup (D3 "Which lookups each endpoint needs"):
  - red: `TestReproReauthTOTPIgnoresUnrelatedMethodEnrolmentFailure`; the row "a lookup failure refuses and verifies nothing" in `reauth_verify_test.go` moves to a failure of the named method's own lookup, and the password and listing lookup-failure rows stay.

  (ADDED reauthentication "Each re-proof endpoint looks up only the enrolments its decision needs", every scenario; "A user re-proves with the strongest factor they hold, by default" scenario "Lookup failure does not downgrade".) Verify with `go test -race -count=1 -run 'TestReauth' ./httpsec/`
- [ ] 9.6 One second-factor response check, one challenge issue and one challenge-manager builder, shared by the MFA slot and re-proof, behaviour unchanged (D6 "The second-factor response check and challenge issue, too"):
  - the throttle check, response reader, challenge spend, failure classification, sweep, `IssueWithin` with its limit mapping and `BeginChallenge` run in one place, taking the throttle, the manager and the method; the managers come from one builder taking a purpose function;
  - admission and resolve stay each path's own.

  Existing tests are the safety net; the red step for each extraction is a temporary divergence in the shared code that both an MFA test and a re-proof test catch, as in 6.8. Verify with `go test -race -count=1 ./httpsec/...`, `go vet ./httpsec/` and `golangci-lint run ./httpsec/`
- [x] 9.7 One recency judge in `internal/guardauth`, used by `httpsec`, `ginsec` and `fibersec`, behaviour unchanged (D8, revised):
  - it holds the window, clock and time source, validates them, and judges a context against an optional per-route window, returning the verdict and the window; each adapter hands it the session-based default time source, builds `*httpsec.ReauthenticationRequiredError` and refuses on its own path;
  - each adapter's options, configuration-error wording and refusal path are unchanged.

  Red: a `guardauth` table test of the judge first; then, for each adapter, a temporary divergence in the shared judge that the adapter's recency tests catch. Verify with `go test -race -count=1 ./internal/guardauth/ ./httpsec/` and `go test -race ./...` in `httpsec/ginsec` and `httpsec/fibersec`

- [x] 9.8 The password re-proof's policy input and its recovery cancel (D6 Password order, steps 6 and 7):
  - `policy.Input.Reauthenticating bool`, documented as set only by a re-authentication of an existing session and false for every login; the password re-proof sets it;
  - `policy.ConcurrentSessions` denies a re-authentication only when the count is above the maximum, and a login at or above it as before; its godoc says why;
  - a successful password check cancels the user's held recoveries through the same call login makes, before the phase; a cancellation the store cannot record refuses the re-proof and leaves the session unchanged;
  - a row pinning that the phase receives login's input (a policy keyed on the user, the username, the first factor and the password-change time, such as a password-age gate, refuses the re-proof as it refuses the login);
  - red: `TestReproPasswordReproofRefusedByConcurrentSessionCapOfOwnSession` (refused with `policy: too many concurrent sessions`), a held-recovery row whose finish still succeeds after the re-proof, and the `ConcurrentSessions` re-authentication rows.

  (Reauthentication "A password re-proof applies the post-authentication policy as a login does" scenarios "A user at the session cap re-proves", "Consumer policy sees a re-proof"; "A password re-proof checks the session's own user under the account lockout" scenario "A held recovery is cancelled"; MODIFIED account-recovery "A held recovery is cancelled by the user"; MODIFIED security-policy "Concurrent sessions are capped".) Verify with `go test -race -count=1 ./policy/... ./httpsec/...` and `go test ./...` in the `test` module

## 10. A strict rotation that lost a race is a renewal conflict, decided by the store (`sessions`, `security-state-stores`, `schema-migrations`, `store-conformance`)

Sequenced: 10.1, then 10.2, then 10.3, then 10.4. 10.1 changes types every store compiles against.

- [x] 10.1 The mark in the store contract and the in-memory store (D10 "Stores"):
  - `session.Supersession.Strict` and `session.Session.RotatedStrictly`, documented as store-owned and never written by `Create` or `Save`; the `Store` godoc names them;
  - `MemoryStore` records the mark on `Supersede`, returns it on `Load`, and keeps it out of `Create` and `Save`; the encrypting decorator passes it through;
  - `test/storetest` session suite cases for the mark: recorded without grace, not with a grace window, returned on load, untouched by create and save, swept with the session at its retention deadline; and broken variants that drop the mark and that save it.

  Red: the new suite cases fail on the memory store before it records the mark. (ADDED security-state-stores "Session stores keep whether a supersession was a rotation without grace"; ADDED store-conformance "The session suite covers the strict-rotation mark", the store-variant scenarios.) Verify with `go test -race -count=1 ./session/ ./test/storetest/`
- [ ] 10.2 The durable stores and the migration (D10 "Schema", "Stores"):
  - a new migration in `store/migrate/securitystate` adding `rotated_strictly boolean NOT NULL DEFAULT false`, with a `Down` that drops it;
  - `internal/pgschema` and `internal/storekit` write and read it in the supersession and load statements; `sqlstore`, `pgxstore` and `gormstore` (`models.go`) carry it;
  - migration tests: the column, existing rows unmarked, an older writer's insert, rollback; the gorm statement pins.
  - the strict-rotation cases 10.1 gated to the memory store and its broken variants move into `RunSessionStoreSuite`, so every store that runs the suite, third-party ones included, must pass them; the gate (`runSessionStrictRotationSuite` and `test/storetest/export_test.go`) is removed.

  Red: the 10.1 suite cases fail on each durable backend, and the new migration-test rows fail before the migration exists. (ADDED schema-migrations "The security-state set adds the session strict-rotation mark", every scenario; the 10.1 requirements on every backend.) Verify with `go test -race -count=1 ./...` in the root, `store/pgxstore`, `store/gormstore` and `test` modules (needs Docker)
- [ ] 10.3 The manager reads the mark (D10 "Decision"):
  - a strict `Rotate` supersedes with `Strict: true`, `AcceptUntil` the in-flight window and `RetainUntil` the same end, and no longer deletes the old row;
  - `Load` of a marked record is `ErrNotFound`, never judged; `Rotate` and `RotateWithGrace` of one are `ErrRenewalConflict` inside the window, writing nothing, and `ErrNotFound` after;
  - `rotatedHandles` and its heap are removed; `Rotate`'s and `RotateWithGrace`'s godoc state the store-decided guarantee;
  - the tests pinning the delete change with it: the failed-delete test is removed, the "load between the writes" tests become "load after the write", and 7.1's within-window tests keep their outcomes.

  Red: `TestRepro_RotateWithGraceAfterStrictRotationIsRenewalConflict` and a load-after-the-window row. (MODIFIED sessions "Rotation with a grace window keeps the old identifier usable until the window ends", "A superseded identifier presented after its window revokes its family"; ADDED "Rotation at second-factor verification keeps the old session only until its in-flight window ends" and "A strict rotation that lost a race is a renewal conflict, decided by the store", every scenario; REMOVED "A failed delete does not fail a second-factor rotation" and "Rotation at second-factor verification keeps the old identifier only in flight".) Verify with `go test -race -count=1 ./session/ ./httpsec/`
- [ ] 10.4 Across managers sharing a store, on every backend (D10 "The line, stated"):
  - a `test/storetest` case rotating through one manager and again through a second over the same store, expecting `ErrRenewalConflict`; run on the memory store and every durable backend;
  - in `httpsec`, a renewal that loses to a re-proof on one server answers 409 (`ErrSessionRenewalConflict`), and two re-proofs through two chains sharing a session store yield one success and one 409.

  Red: `TestRepro_RotateOnSecondManagerAfterStrictRotationIsRenewalConflict`, rewritten as the suite case. (ADDED store-conformance scenario "Managers sharing a store"; sessions scenarios "Two managers sharing a store" and "A renewal that lost to a strict rotation".) Verify with `go test -race -count=1 ./session/ ./httpsec/` and `go test -race ./...` in the `test` module (needs Docker)

## 11. Conformance and close-out, again

- [ ] 11.1 `test/httpsecconformance` on net/http, gin and fiber gains: a re-proof prefix under the form login path accepted; a renewal that lost to a re-proof answered 409; a password re-proof refused by a post-authentication deny. (D9; the scenarios named.) Verify with `go vet ./...` and `go test -race ./...` in the `test` module (needs Docker)
- [ ] 11.2 The whole-workspace gate, as 8.2:
  - `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...` and `golangci-lint run ./...` in every module listed by `go list -m`;
  - `gofmt -l` empty over tracked Go files;
  - `openspec validate reauthentication --strict`.

  Verify that every command exits 0 and its output is recorded.

## Workflow follow-up

- Run one whole-branch review against every spec requirement this change covers before the final gate (8.2, and again before 11.2) and before archive.
- The planning artifacts merge to `main` on their own (PR #30). Implementation runs on a new branch from `main`, `feat/reauthentication`, and owns its own PR. Rebase onto `main` again before merging if `main` moves.
- Archive after merge.
