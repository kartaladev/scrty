# Tasks

Every task is test-first:

1. Write the failing test.
2. Run it and see it fail for the intended reason. A compile error is not a red step.
3. Make it pass.
4. Refactor.

Each task names how it is verified. A signature change owns every caller of the changed API across the workspace: `_test.go` files, `httpsec`, the adapters, the `test` module, Examples and README snippets. The workspace therefore compiles and passes at the end of every task group. Section names in parentheses are the spec requirements a task covers; D-numbers are design decisions.

## 1. One freshness check (`sessions`, `account-recovery`, `passkey-authentication`)

- [ ] 1.1 `(*session.Session).AuthenticatedWithin(now time.Time, window time.Duration) bool`: no more than `window` elapsed, inclusive; a future authentication time counts as no time elapsed; a zero authentication time is never within (D1; ADDED sessions "One check decides whether a session authenticated within a window", every scenario as one table test). Also cover the MODIFIED sessions scenario "Saving cannot refresh it" against the in-memory store. Verify with `go test -race -run 'TestAuthenticatedWithin|TestSave' ./session/`
- [ ] 1.2 Recovery-code regeneration (`httpsec/recovery_codes.go`) and the passkey manager's freshness check (`authenticate/passkey/passkey.go` `admit`) call `AuthenticatedWithin` instead of their own comparisons. Add boundary cases first:
  - exactly at the window's end is admitted;
  - a zero authentication time is refused.

  Each red step comes from inverting the boundary temporarily, because the refactor preserves behaviour. Their godoc and the README say freshness reads the session's authentication time (D1; MODIFIED account-recovery "Regenerating codes needs a recent authentication and notifies the user" and passkey-authentication "Registration admits a session only at the account's assurance and only while fresh", existing scenarios unchanged). Verify with `go test -race -run 'TestRecoveryCodes|TestManage|TestBeginRegistration' ./httpsec/ ./authenticate/passkey/`

## 2. Refusals (`http-error-propagation`)

- [ ] 2.1 `httpsec.ErrReauthenticationRequired`, `*httpsec.ReauthenticationRequiredError{Window}` and `httpsec.ErrReauthenticationMethodNotUsable`:
  - the error type is `ErrReauthenticationRequired` under `errors.Is`, and exposes its window under `errors.As`;
  - its text names no session, user or handle;
  - both map to 403 in `statusTable`;
  - both are listed in `sentinelRegistry`, so `TestStatusForErrorCoversEverySentinel` passes;
  - godoc names where each is raised.

  (D2, D7; MODIFIED "Refusal errors are a stable public contract", scenario "Recency refusal carries its window"; MODIFIED "One public table maps refusals to a status", scenarios "Recency guard refusal" and "Re-proof method not usable".) Verify with `go test -race -run 'TestStatusForError|TestRefusalSentinelsAreDistinct|TestReauthenticationRequiredError' ./httpsec/`

## 3. The core recency guard (`reauthentication`)

- [ ] 3.1 Guard options:
  - `WithRecentAuthenticationWindow`, `WithGuardClock` and `WithAuthenticationTime`, with `DefaultRecentAuthenticationWindow = 15 * time.Minute` and the system clock as defaults;
  - `NewGuards` fails with `ErrConfig` for a zero or negative window, a nil or typed-nil clock, and a nil authentication-time func, each message naming the option.

  (D2; "The recency window has a default, a guards-wide override and a per-route override" scenario "Zero guards-wide window"; "The recency guard reads time from a replaceable time source" scenario "Absent time source"; "The authentication time comes from the session unless the consumer supplies it" scenario "Absent consumer source".) Verify with `go test -race -run 'TestNewGuards' ./httpsec/`
- [ ] 3.2 `RequireRecentAuthentication()` and `RequireAuthenticationWithin(d)` as judges on `g.guard`:
  - authentication time from `SessionFromContext`, or from the consumer func when given;
  - freshness via `AuthenticatedWithin`;
  - refusal `&ReauthenticationRequiredError{Window: d}`;
  - a zero or negative per-route window panics at wiring, naming the window;
  - a nil receiver panics like the other builders.

  One table test covers every scenario of these requirements through net/http with a controlled clock: "A recency guard refuses a session that authenticated too long ago", "An absent authentication time is never recent", "Only an authentication makes a session fresh again", "The recency window has a default, a guards-wide override and a per-route override", "The recency guard reads time from a replaceable time source", "The authentication time comes from the session unless the consumer supplies it", and "The reauthentication-required refusal names the window it needed". The re-authentication case "A re-authentication makes it fresh" is driven here by a rotated session carrying a new authentication time (D2). Verify with `go test -race -run 'TestRecencyGuard|TestGuardsFailClosed|TestGuardsWiringPanics' ./httpsec/`
- [ ] 3.3 Godoc on every new option and method:
  - the default it replaces;
  - stacking inside privilege guards;
  - passing the chain's clock to `WithGuardClock`;
  - the window relative to the session's absolute lifetime.

  A runnable `Example` of a recency-guarded route, and the README guards section with the defaults table rows for the window and the clock (D2). Verify with `go test -run 'Example' ./httpsec/` and `go vet ./httpsec/`

## 4. Adapter recency guards (`framework-adapters`)

- [ ] 4.1 `ginsec`: the same three options, two methods, validation and wiring panics, refusing through the gin error-channel path; godoc as in 3.3 (D8; ADDED "Adapter recency guards match the core recency guard" scenarios "gin stale session", "Fresh session on every adapter" for gin, "Per-route window on gin", "gin per-route window of zero"). Verify with `go test -race ./...` in `httpsec/ginsec`
- [ ] 4.2 `fibersec`: the same, returning the refusal to fiber's error handler with its window; no error-handler option; godoc as in 3.3 (D8; scenarios "fiber stale session", "Fresh session on every adapter" for fiber, "fiber guards with an absent time source"). Verify with `go test -race ./...` in `httpsec/fibersec`

## 5. The MFA endpoints serve only a pending session (`multi-factor-auth`)

- [ ] 5.1 Red first: a test showing that a full session posting a valid code to `/mfa/verify/totp` is accepted today, which the new requirement inverts. Then `verify` and `begin` refuse `s.MFA != session.MFAPending` with `ErrNoMFAChallengePending`:
  - after the session and caller refusals;
  - before the method name, the throttle, the body and any challenge issue;
  - counting nothing and leaving the handle unchanged.

  Sweep the workspace for callers that posted to verify or begin from a full session (tests, `test/httpsecconformance`, Examples) and move them to a pending session. Godoc on `EnableMFA` and the verify and begin endpoints states the refusal (D5; ADDED "The verify and begin endpoints serve only a session that owes a second factor", every scenario; MODIFIED http-error-propagation scenario "No MFA challenge pending at verify"). Verify with `go test -race -run 'TestMFAVerify|TestMFABegin|TestMFAGate' ./httpsec/` and `go test ./...` in the `test` module

## 6. The re-authentication endpoints (`reauthentication`, `sessions`, `account-recovery`, `passkey-authentication`)

- [ ] 6.1 Wiring:
  - `EnableReauthentication(opts...)` with every `ReauthenticationOption` in D6 and their defaults;
  - `OrderReauthentication = 655`;
  - `DefaultReauthenticationPrefix = "/reauth"`;
  - registration after the MFA slot and form login are known;
  - every construction error in D6, as `ErrConfig`, each naming its cause.

  ("Re-proof endpoints exist only when re-authentication is enabled" scenarios "Off by default", "Consumer prefix"; "Re-authentication wiring mistakes fail at construction", every scenario; "Re-proof challenges are their own and bound to the session" scenario "Zero lifetime".) Verify with `go test -race -run 'TestEnableReauthentication|TestChainOrder' ./httpsec/`
- [ ] 6.2 Admission, the factor policy, and `GET <prefix>/methods` with its default JSON body and replaceable responder:
  - the decision is shared by every endpoint;
  - a lookup failure refuses;
  - non-full sessions are refused by their gates and, if reordered, by the endpoint as authentication required.

  (D3, D4, D6; "Only a full session may re-prove" scenarios "No session", "Pending second factor", "Pending password change", "Enrolment-only session", "Recovery-pending session"; "The method listing reports how the session's user may re-prove", every scenario; "A consumer can require a second factor for every re-proof" scenario "Second factor only" at the listing.) Verify with `go test -race -run 'TestReauthMethods|TestReauthAdmission' ./httpsec/`
- [ ] 6.3 Second-factor begin and verify:
  - the order in D6;
  - the MFA slot's throttle instance;
  - per-method challenge managers under `reauth-challenge:<method>`, bound to the session, with their own TTL, limit and store, swept by the chain's expiry task;
  - clone and suspension refusals unchanged and uncounted;
  - no same-channel refusal.

  ("A second-factor re-proof is verified like a second factor", every scenario; "Re-proof challenges are their own and bound to the session", every remaining scenario; "A refused authenticator at re-proof keeps its meaning", every scenario; "A user re-proves with the strongest factor they hold, by default" scenario "A passkey login re-proves with the passkey"; "Re-proof endpoints exist only when re-authentication is enabled" scenario "A method segment is required".) Verify with `go test -race -run 'TestReauthVerify|TestReauthBegin' ./httpsec/`
- [ ] 6.4 `POST <prefix>/password`:
  - the factor policy before the body;
  - binding only `password` (form, then JSON) under the login body limit;
  - the username from the resolved caller;
  - the form login's password path, with lockout, decoy, failure recording and source accounting;
  - lockout failures cleared on success.

  ("A password re-proof checks the session's own user under the account lockout", every scenario; "A user re-proves with the strongest factor they hold, by default" scenarios "A TOTP holder offers a password", "A user without a second factor", "MFA not configured", "Lookup failure does not downgrade"; "A consumer can require a second factor for every re-proof", every scenario.) Verify with `go test -race -run 'TestReauthPassword' ./httpsec/`
- [ ] 6.5 Resolve:
  - the authentication time from the chain's clock;
  - for a second factor, also the satisfied second factor at that time;
  - a strict rotation with rollback on failure;
  - publish, issue and answer through the responder with `Cache-Control: no-store`;
  - sampled refusal logs free of secrets.

  ("A successful re-proof refreshes the authentication time and rotates the session", every scenario; "Re-proof responses are not cached and re-proof logs carry no secret", every scenario; "Only a full session may re-prove" scenario "A fresh session re-proves"; MODIFIED sessions scenario "A re-authentication refreshes the authentication time"; MODIFIED account-recovery scenario "Fresh after a re-authentication"; MODIFIED passkey-authentication scenario "Freshness from a re-authentication".) Verify with `go test -race -run 'TestReauthResolve|TestRecoveryCodes|TestPasskeyRegister' ./httpsec/`
- [ ] 6.6 Godoc on `EnableReauthentication`, every option, responder and endpoint, naming each default. The README gains a re-authentication section after the guards section:
  - the endpoints and the default JSON;
  - the factor policy, and why no "any factor" option exists;
  - OIDC-only users and the listing responder filter;
  - the in-memory challenge store's single-process limit;
  - the three reauthentication sentinels.

  The defaults table gains every new default (D6, D7, D9). Verify with `go test -run 'Example' ./httpsec/` and `go vet ./httpsec/`

## 7. Conformance and close-out

- [ ] 7.1 `test/httpsecconformance` on net/http, gin and fiber, each scenario mirroring a spec scenario:
  - a stale session refused by the recency guard, a TOTP re-proof, and the route accepted with the new credential;
  - a password re-proof by a user without a second factor;
  - a TOTP holder refused at `/reauth/password`;
  - a full session refused at `/mfa/verify/totp`;
  - a fiber refusal carrying its window to the error handler.

  (D9; framework-adapters "Adapter recency guards match the core recency guard" across adapters.) Verify with `go vet ./...` and `go test -race ./...` in the `test` module (needs Docker for durable backends)
- [ ] 7.2 The whole-workspace gate:
  - `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...` and `golangci-lint run ./...` in every module listed by `go list -m`;
  - `gofmt -l` empty over tracked Go files;
  - `openspec validate reauthentication --strict`.

  Verify that every command exits 0 and its output is recorded.

## Workflow follow-up

- Run one whole-branch review against every spec requirement this change covers before the final gate and before archive.
- The planning artifacts merge to `main` on their own (PR #30). Implementation runs on a new branch from `main`, `feat/reauthentication`, and owns its own PR. Rebase onto `main` again before merging if `main` moves.
- Archive after merge.
