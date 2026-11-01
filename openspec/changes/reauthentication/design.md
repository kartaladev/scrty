# Design

## Context

See proposal.md for why. The current state that shapes the approach:

- **The authentication time exists and is library-owned.**
  - `session.Session.AuthenticatedAt` is set by `Sessions.Create`, carried over by every renewal, and moved only by a rotation that carries a new value. `Save` keeps the stored value, so a consumer cannot refresh it.
  - The MFA verify endpoint's `resolve` (`httpsec/mfa_verify.go:442`) sets it to the second-factor time, then calls `Sessions.Rotate`, which writes it into the successor.
- **Two freshness checks exist, written separately.**
  - `httpsec/recovery_codes.go:158` and the passkey manager's `admit` (`authenticate/passkey/passkey.go:448`) both compute `now.Sub(s.AuthenticatedAt) > window`, with 15-minute defaults and their own options.
  - Their spec text describes the time as "the later of creation and second-factor satisfaction". That is equal to `AuthenticatedAt` today, and stops being equal once a password re-proof exists.
- **Guards, as settled by `idiomatic-api-shape` (merged in PR #29).**
  - `NewGuards(az, opts...) (*Guards, error)` validates after its options run. `GuardOption` is `func(*Guards)`, with no error.
  - Every guard runs `g.guard(judge)`: principal, then authorizer, then the judge, whose error is refused unchanged.
  - The default refusal is `StatusForError` with no body. gin registers the refusal on `gc.Error`. fiber returns it to `fiber.Config.ErrorHandler`.
  - `ginsec` and `fibersec` re-implement the judge and reuse `httpsec` types and sentinels. The one decision all three adapters must make identically, where a guard finds its authorizer, lives in `internal/guardauth`; each adapter keeps its own error text and refusal path.
  - Builder methods panic at wiring on a nil receiver, checker or extractor.
  - Guards have no clock. A judge reads the session with `httpsec.SessionFromContext`.
- **The MFA slot can already be reached by a full session.**
  - `admit` (`httpsec/mfa_verify.go:357`) checks the session, the caller, the method name and usability. It does not check `s.MFA`, so a full session can begin and verify, refreshing `AuthenticatedAt` and rotating.
  - No spec scenario or test pins this. Only the listing (`mfa_verify.go:796`) and the gate (`:539`) look at `MFAPending`.
  - The same-channel rule applies there, so a passkey-login session cannot use the passkey method.
- **Password checks outside login already exist.** Account recovery is handed `login.checkPassword` (`httpsec/recovery.go:252`). It runs the pre-authentication policy (lockout), the chain's password authenticator and failure recording. The authenticator loads by username, and the resolved caller's `identity.Principal.Username` carries it.
- **Users with no password are indistinguishable** from other users except by an empty password hash, which the authenticator treats as a failed match after a decoy comparison.
- **OIDC sessions** record their local sign-in time as `AuthenticatedAt`. Neither `auth_time`, `max_age` nor `prompt` is used (`authenticate/oidc/doc.go:98`).
- **Interceptor slots** (`httpsec/chain.go`), in order:

  | Slot | Value |
  |---|---|
  | Bearer | 500 |
  | Account-recovery gate | 598 |
  | Enrolment gate | 599 |
  | MFA | 600 |
  | Password-change gate | 650 |
  | Passkeys | 660 |
  | Renewal | 675 |
  | Logout | 700 |

  A request that reaches 655 has passed every challenge gate.
- **The established design** declared a re-authentication challenge kind and never enforced or offered it. Nothing here departs from its behaviour. Everything below is new.

## Goals / Non-Goals

**Goals:**
- One meaning of "recent" across the library, decided by one check.
- A re-proof never accepts a weaker proof than the user holds, and no configuration can make it do so.
- A re-proof is throttled by the limits that already guard the same secrets: the per-user second-factor throttle and the password lockout. It gets no new budget of its own.
- The guard composes with the existing guards and keeps their fail-closed order.

**Non-Goals:**
- **Re-authentication through an OIDC provider** (`max_age`, `prompt=login`, `auth_time`). This is a follow-up. OIDC-only users become fresh by signing in again.
- **Binding approval to one transaction** (a code that approves one specific payment). This change uses time windows only.
- **A policy-engine phase for recency.** Recency is a per-route decision, and the policy engine judges every request.
- **Notifying the user of a re-proof.** No surveyed service does, and the actions that matter already notify (passkey binding, recovery-code regeneration).
- **Cookie delivery and CSRF for the re-proof endpoints.** `bff-resource-server` covers them with its other unsafe endpoints.

## Decisions

### D1. One freshness check on the session

```go
// AuthenticatedWithin reports whether s authenticated no longer than window before now.
func (s *Session) AuthenticatedWithin(now time.Time, window time.Duration) bool
```

- **Rule:** `!s.AuthenticatedAt.IsZero() && now.Sub(s.AuthenticatedAt) <= window`. A future `AuthenticatedAt` yields a negative elapsed time, which is fresh.
- **Callers:** the recovery-code regeneration check and the passkey manager's freshness check move to it. Both already used `> window` on `AuthenticatedAt`, so this is a behaviour-preserving refactor. The zero time was already refused, because the elapsed time is enormous.
- **Default:** none to configure. It is the definition. Windows stay per component: `WithRecoveryRegenerationFreshness`, `passkey.WithManagementFreshness`, and the guard's windows (D2).
- **Alternatives rejected:**
  - *A helper in `httpsec`.* The passkey core cannot import `httpsec`.
  - *Refusing an authentication time ahead of the clock.* Replicas whose clocks differ by seconds would refuse a session that just signed in. Since `AuthenticatedAt` is library-owned, a future value cannot be forged by a consumer or a client.

### D2. The recency guard

```go
const DefaultRecentAuthenticationWindow = 15 * time.Minute

func WithRecentAuthenticationWindow(d time.Duration) GuardOption
func WithGuardClock(c clock.Clock) GuardOption
func WithAuthenticationTime(fn func(ctx context.Context) (time.Time, bool)) GuardOption

func (g *Guards) RequireRecentAuthentication() func(http.Handler) http.Handler
func (g *Guards) RequireAuthenticationWithin(window time.Duration) func(http.Handler) http.Handler

var ErrReauthenticationRequired = errors.New("httpsec: reauthentication required")

// ReauthenticationRequiredError is the recency guard's refusal. It is ErrReauthenticationRequired.
type ReauthenticationRequiredError struct{ Window time.Duration }
```

- **Position.** Both are judges on `g.guard`, so a request first meets "no principal" (401), then "no authorizer" (403), then recency. The godoc says to stack a recency guard inside the privilege guards, so an unprivileged caller is told "access denied" and not "re-authenticate".
- **Judging.**
  1. Find the authentication time. By default this is `SessionFromContext(ctx)`; no session means none.
  2. If none is found, refuse.
  3. Otherwise refuse unless `AuthenticatedWithin` holds (D1), with the clock's `now` and the route's window.
- **Default:** 15 minutes; the system clock; the time from the session.
- **Overrides:**
  - `WithRecentAuthenticationWindow(d)` for all guards built together. Zero or less fails `NewGuards` with `ErrConfig`.
  - `RequireAuthenticationWithin(d)` for one route, taking precedence. Zero or less panics at wiring, naming the window, as the other builder methods do.
  - `WithGuardClock(c)`. An absent or typed-nil clock fails `NewGuards`. The option records that it was given, so `NewGuards` can tell "absent" from "not set".
  - `WithAuthenticationTime(fn)` for principals without a session, such as API keys, Basic or a consumer's own bearer. A nil func fails `NewGuards`. When given, it replaces the session lookup entirely, and a consumer who wants both composes them.
- **The window is fixed** (not sliding). Only an authentication moves the time. GitHub's sudo mode resets its timer on each sensitive action. That is a deliberate departure, because a sliding window would let a stolen session that keeps acting stay fresh until its absolute timeout. It also matches the settled `http-security-chain` requirement "A renewal does not refresh authentication for freshness checks". **Override:** none. A consumer wanting a longer effective window raises it.
- **Why 15 minutes, not GitHub's 2 hours:**
  - It is the window scrty already applies to credential management, in recovery codes and passkeys. There, the 2-hour alternative was rejected because a stolen session must not plant a lasting credential.
  - It matches NIST AAL3's inactivity limit and the low-risk end of OWASP's idle-timeout range.
  - The library cannot see what a consumer guards, so the safe default is the short one.
- **The refusal** is `*ReauthenticationRequiredError`. `Is(ErrReauthenticationRequired)` and `errors.As` give the window, so an error handler can render RFC 9470's `max_age`. Its text names no session or user.
- **Status 403, not RFC 9470's 401.**
  - scrty's two existing reauthentication refusals are 403.
  - A client that receives 401 treats the credential as gone and sends the user to sign in, which is the opposite of "confirm it is you".
  - The table's 401 rows mean "your credential did not authenticate". Here it did.
- **The clock is the guards' own.** Guards are built outside the chain and see no chain configuration. The godoc tells a consumer who sets `httpsec.WithClock` to pass the same clock to `WithGuardClock`.
- **Alternatives rejected:**
  - *A `ChallengeError` of a new kind.* In scrty a challenge is a pending state recorded on the session, which a gate enforces on every route. Recency is per route and stateless, and the "any other kind is 401" rule would also apply.
  - *No default window.* That contradicts the opinionated-default rule, and a consumer who does not know what to pick would guess.
  - *Reading the chain's clock from the request context.* That is implicit coupling, and the time-source spec has each component take its source through an option.

### D3. The factor policy: strongest held, never weaker

- **Default ("strongest held"):**
  - If the user is enrolled on any of the chain's configured MFA methods, they re-prove with one of those, and the password endpoint refuses them with `ErrReauthenticationMethodNotUsable` (403). That refusal comes before the body is read, so no password is checked and nothing is recorded.
  - If the user is enrolled on none, they re-prove with the password, when form login is enabled.
  - If neither applies, there is no re-proof method. The listing says so, and the user signs in again.
- **Override:** `RequireSecondFactorForReauthentication()`. Users with no second factor then have no re-proof method. It fails construction without the MFA slot.
- **Why no "any factor" option (GitHub-like).** Passkey registration binds a new authenticator at the account's highest assurance (NIST SP 800-63B-4 §4.1.2.1, settled in `passkey-authentication`). Its freshness reads the authentication time.
  - A password re-proof by a user who holds a second factor would make a session fresh at single-factor strength. That session could then plant a passkey that later meets both factors, and regenerate recovery codes.
  - An adversary-in-the-middle phisher holds the password and the session cookie, but not a fresh TOTP code, which scrty's replay guard refuses once used.
  - This is the line the library-design rule asks to state: the option would weaken a documented guarantee, so it does not exist.
- **Enrolment lookup failure** refuses the request, and never falls back to the password. Otherwise an outage of the enrolment store would downgrade every user.
  - **Which lookups each endpoint needs.** The listing names every enrolled method, so it looks up every method, and any failure refuses. The password endpoint needs only to know whether the user holds *any*: it looks methods up in order and refuses with `ErrReauthenticationMethodNotUsable` at the first enrolled one, and a failure before one is found refuses as a failed lookup, so it never falls back to the password (second review; reproduced by `TestRepro2PasswordEndpointStopsLookingAtTheFirstEnrolledMethod`: three lookups where one settles it). Second-factor begin and verify name their method; the user presenting an enrolled second factor is already the strongest proof the policy can ask for, so they look up only the named method's enrolment, and a failure of that lookup refuses. A failure of an unrelated method's lookup cannot cause a downgrade on that path, so it no longer refuses a TOTP re-proof because the passkey store is down. The password path keeps its full lookup, so the downgrade guard is unchanged.
  - **Reproduced:** `TestReproReauthTOTPIgnoresUnrelatedMethodEnrolmentFailure`. With TOTP enrolled and a second method whose enrolment lookup fails, a valid TOTP code at `/reauth/verify/totp` is refused with "the re-authentication methods could not be looked up". It is task 9.5's red step. The existing row "a lookup failure refuses and verifies nothing" in `reauth_verify_test.go` pinned the old behaviour on this path and moves to the named method's own lookup.
- **Email-channel methods** that a consumer supplies count like any enrolled method. No built-in one exists.
- **Users with no password** cannot be told apart without loading the user. The listing reports the password as accepted for anyone with no second factor. Their password re-proof then fails as a wrong password would, after the authenticator's decoy comparison. A consumer listing responder can filter it out (Risks).

### D4. Re-proof does not apply the same-channel rule

- **Rule:** a re-proof second factor is any configured MFA method the user is enrolled on, whatever its channel. A session that signed in with a passkey may re-prove with the passkey method.
- **Why:** the same-channel rule exists so that two factors at login are independent. A re-proof is one factor, presented alongside the live session secret. That is what NIST SP 800-63B-4 allows for AAL2 reauthentication ("a single authentication factor ... in conjunction with the session secret").
  - Applying the rule would leave a passwordless passkey user with no re-proof at all, or push them to a weaker password.
- **Freshness, not assurance.** A re-proof whose method shares the session's first-factor channel refreshes the authentication time only. It does not record the second factor as satisfied, because it proves the same authenticator again, not an independent one. A re-proof on another channel (TOTP after a password sign-in) records the second factor as satisfied, as at MFA verify.
  - Otherwise, where the consumer counts a passkey sign-in as one factor only (`WithoutSecondFactorAtLogin`), a passkey-only session would reach "second factor met" with one authenticator, and passkey registration, which trusts that state for the account's assurance, would admit it.
  - The channel test is the one `/mfa/verify` applies; only its consequence differs.
- **Override:** none. Strengthening is available through D3's second-factor-only option. Weakening is not offered.

### D5. The MFA verify and begin endpoints refuse a session that owes no challenge (BREAKING, pre-tag)

- **Change:** after the session and caller refusals, `verify` and `begin` refuse `s.MFA != session.MFAPending` with `ErrNoMFAChallengePending` (403), as the listing does. The refusal comes before the method, the throttle or the body, so nothing is counted or issued.
- **Why:**
  - The verify requirement already says the endpoint "resolves the challenge", and a session with none has nothing to resolve.
  - Keeping the path open would give re-proof two homes with different rules: the same-channel rule (D4), the factor policy (D3) and the challenge purposes (D6).
  - It would also flip a never-challenged `MFANone` session to "satisfied" through an endpoint whose contract is about login.
- **Classification:** this is unpinned behaviour, not a reported defect. No test or scenario covers it. The first task writes the failing test that shows a full session accepted today, then turns it into the refusal.
- **Default:** refuse. **Override:** none. Re-proof is `/reauth`.
- **Migration:** a consumer who posted codes to `/mfa/verify` from a full session moves to `/reauth/verify/{method}`. Nothing is tagged yet.
- **Passkey management needs re-authentication on an MFA chain (wiring rule).** A full session that has not met its second factor (an `MFANone` session of a user who enrolled after signing in, or whose policy asked for none at sign-in) can reach "second factor met" only through a re-proof once this refusal lands. Passkey registration and removal require that state for a user enrolled on an MFA method on the slot. A chain with the MFA slot and passkeys but without `EnableReauthentication` would therefore build, and then refuse that user's passkey management for good, with no route to repair it short of a sign-in the policy may never challenge. Before this change, `/mfa/verify` was that route, as it is in the established design.
  - **Decision:** `New` fails with `ErrConfig` when the chain has the MFA slot and passkeys and not `EnableReauthentication`, naming the missing option. A wiring that leaves a user unable to reach a state a feature requires is a configuration error (library-design rule 6), and re-proof keeps one home.
  - **Default:** the refusal. **Override:** enabling re-authentication, which is the remedy. Recovery-code regeneration needs freshness only, which a new sign-in gives, so it is not part of the rule. On such a chain without re-authentication a stale session regenerates codes only after signing in again; the regeneration endpoint's godoc and the README say so (second review: `TestRepro2_StaleSessionOnMFAChainWithoutReauthentication` shows the path; the user's decision was to keep the wiring accepted).
  - **Reproduced:** `TestRepro_FullSessionStepsUpAtMFAVerifyWithoutReauthentication`. On a chain with MFA and passkeys and no re-authentication, an `MFANone` session's valid TOTP code at `/mfa/verify/totp` is refused with `ErrNoMFAChallengePending`, and passkey `begin` stays refused with `passkey.ErrReauthenticationRequired`. It becomes the red step of task 9.2, reworded to assert the construction refusal.
  - **Alternatives rejected:** *enabling re-authentication by default whenever MFA is on*, which registers endpoints the consumer never asked for and needs an off switch of its own; *restoring step-up at `/mfa/verify` while re-authentication is off*, which gives re-proof two homes with different rules in that configuration.

### D6. The re-authentication interceptor

```go
const DefaultReauthenticationPrefix = "/reauth"
const OrderReauthentication = 655

func EnableReauthentication(opts ...ReauthenticationOption) Option
type ReauthenticationOption func(*reauthInterceptor) error

func WithReauthenticationPrefix(prefix string) ReauthenticationOption
func WithReauthenticationTokens(gen token.Generator) ReauthenticationOption
func WithReauthenticationResponder(fn ReauthenticationResponder) ReauthenticationOption
func WithReauthenticationBeginResponder(fn MFABeginResponder) ReauthenticationOption
func WithReauthenticationMethodsResponder(fn ReauthenticationMethodsResponder) ReauthenticationOption
func WithReauthenticationChallengeTTL(d time.Duration) ReauthenticationOption
func WithReauthenticationChallengeLimit(n int) ReauthenticationOption
func WithReauthenticationChallengeStore(s onetime.Store) ReauthenticationOption
func RequireSecondFactorForReauthentication() ReauthenticationOption

type ReauthenticationResult struct{ Token string; Session *session.Session }
type ReauthenticationResponder func(ex *Exchange, r ReauthenticationResult) error
type ReauthenticationMethods struct{ Methods []MFAMethod; Password bool }
type ReauthenticationMethodsResponder func(ex *Exchange, m ReauthenticationMethods) error
var ErrReauthenticationMethodNotUsable = errors.New("httpsec: reauthentication method not usable")
```

- **Slot 655.** That is after the password-change gate (650), so every challenge gate (598, 599, 600, 650) has refused a pending or confined session first. It is before passkeys (660) and renewal (675).
  - The endpoint still refuses any non-full session that reaches it, as authentication required. That covers a consumer who reorders interceptors.
- **Paths:**
  - `GET <prefix>/methods`;
  - `POST <prefix>/begin/{method}` and `POST <prefix>/verify/{method}`, matched by prefix, so an empty or unknown method is `ErrUnknownMFAMethod` (404);
  - `POST <prefix>/password`.
  - Anything else passes through.
- **Dependencies the chain already has.**
  - **Second-factor re-proof uses the MFA slot's** methods, lookups and **its `*mfa.VerifyThrottle` instance**. Failures at login and at re-proof share one per-user count (5 per 15 minutes by default), and re-proof has no budget of its own.
  - **Password re-proof uses the form login's** password path: its pre-authentication step (lockout), the decoy-even authenticator and failure recording on the attempt store, and the form login's own source guard, charged exactly as a login charges it (a lock and a refused password; never a policy refusal). Success clears the user's lockout failures, as a login does.
  - **The proved account must be the session's.** The username comes from the resolved caller, so the endpoint refuses, as authentication failed, a caller whose ID is not the session's user before any password is checked, and a password that proved an account other than the session's user before anything is reset or refreshed. The second refusal is reachable only through a consumer interceptor that rewrites the caller's username, a wiring fault rather than a request, so it records no failure and charges no source: a failure would count a correct password against the other account's lockout.
- **One implementation per control.** Re-proof calls the same code as the paths it mirrors, never a copy: one challenge spend and one expiry sweep shared with the MFA slot (the purpose and log names as parameters), and one form-login method for the whole password order (source throttle, pre-authentication and lock refusal, source charging, the password check) shared by login and the password re-proof. A fix to either path then reaches both, so re-proof never becomes a weaker pathway (OWASP ASVS 4.0 §1.2.4; CWE-1041). Behaviour is unchanged.
  - **The second-factor response check and challenge issue, too.** After task 6.8 the MFA slot's `verify`, `begin` and `wireChallenges` and re-proof's `verify`, `begin` and `buildChallenges` still repeat the same order: the throttle check, the response reader, the challenge spend, the classification of a failed `Verify` (not counted for `mfa.ErrAuthenticatorRefused` or `mfa.ErrVerifyThrottled`), the sweep, `IssueWithin` with its `ErrIssueLimitReached` mapping, `BeginChallenge`, and the per-method manager construction. They become one response check and one challenge issue taking the throttle, the manager and the method, and one manager builder taking a purpose function. Admission and resolve stay each path's own, because they differ. Behaviour is unchanged; this is a refactor, not a defect claim.
- **One full-session check.** Re-proof, passkey management and recovery-code regeneration judge "a full session" through one shared check, the strictest of the three the first cut had: MFA none or satisfied, no pending password change, no enrolment or recovery marker. The gates refuse every session in a confined state first (second review: `TestRepro2ConfinedSessionIsRefusedAt{PasskeyManagement,RecoveryCodes}` passed). Passkey management and regeneration additionally refuse, as authentication required, two sessions they used to serve and no gate looks at: one with second factor none or satisfied that still carries the enrolment marker, and one in an unnamed second-factor state. No library path produces either, since every path that moves a session to none or satisfied clears the marker and none writes an unnamed state, so only a consumer's store or interceptor could; refusing them is the safe default. The shared check stops the three from drifting (CWE-1041). The method listing writer is likewise shared with the MFA listing.
- **Admission:** a session with a resolved caller, and `MFA` in {`MFANone`, `MFASatisfied`}. It must have no `PasswordChangePending`, no enrolment or recovery marker (`EnrolmentOriginDeadline`; `RecoveredAt` is history, not a marker), and no challenge a consumer gate raised on the request (`Exchange.RaisedChallenge`), as the recovery-code endpoint already checks. Otherwise it is refused as authentication required. A fresh session is served: re-proving early is harmless and throttled.
  - The raised-challenge check means a consumer gate registered after slot 655 still cannot let a session owing its challenge become fresh. The alternative, documenting that consumer gates must sit before 655, was rejected: it leaves the spec's "no pending challenge of any kind" true only for a correctly ordered chain.
- **Verify order:**
  1. admission;
  2. method name;
  3. the factor policy (D3, D4) through the named method's own enrolment lookup, where a failure refuses (D3, "Which lookups each endpoint needs");
  4. throttle check;
  5. read the response with the method's reader;
  6. spend the re-proof challenge for a challenge method;
  7. `Verify`;
  8. on failure, `RecordFailure` unless the error is `mfa.ErrAuthenticatorRefused` or `mfa.ErrVerifyThrottled`. Clone and suspension keep their meaning, and the passkey core's clone revocation applies unchanged;
  9. on success, resolve.

  Steps 1 to 3 count nothing.
- **Password order:**
  1. admission;
  2. the factor policy, before the body;
  3. bind only `password`, from the form field or a JSON body, under the login body limit. A missing field is `ErrCredentialsMissing` (400);
  4. the username comes from `ex.Authentication.Principal.Username`, never the request. An empty username refuses as authentication failed;
  5. the form login's `attemptPassword`, the order login itself runs (source throttle, pre-authentication and lock refusal, the password check, each refusal charged as login charges it), then the check that the proved account is the session's user;
  6. held account recoveries of the user are cancelled, as a login cancels them once its first factor is proved, and a cancellation the recovery store cannot record refuses the re-proof, as it refuses a login;
  7. the post-authentication policy phase, with the input a login builds for the same principal, first factor, username and password-change time, read at the chain's time, and marked as the re-authentication of an existing session (`policy.Input.Reauthenticating`). A deny refuses with the policy's reason, as a login is refused. A challenge refuses with a `*ChallengeError` of that kind carrying no session: re-proof never marks or rotates a session into a pending state, so the user meets the challenge by signing in. Neither outcome resets failures, rotates or refreshes anything;
  8. on success, reset failures and resolve.
  - **Why the phase runs.** A password re-proof is a first-factor authentication, and the post-authentication phase is where a consumer refuses one: a suspended account, a disallowed network, an expired password. Without it, a user that login refuses could still make an existing session fresh and pass every recency-guarded route. The pre-authentication phase is already shared through `attemptPassword`, so this closes the same gap for the phase after it (OWASP ASVS 4.0 §1.2.4). A second-factor re-proof runs it too (revised on second review, the user's decision): after a verified response and before resolve, with the input a login builds for the session's principal and first factor, marked as a re-authentication. A consumer's post-authentication denies and the session cap then bind every re-proof path alike (OWASP ASVS 4.0 §1.2.4). MFA verify at login still does not run it, because the login's own first factor ran it moments before. **Reproduced:** `TestRepro2ReproofRunsThePostAuthenticationPhase` — a TOTP re-proof by a user above the cap, or one a consumer policy denies, succeeded where the password re-proof is refused.
    - **Every deny binds; the input is the login's own (revised on the third review, the user's decision).** The first cut honoured a deny except the same-channel refusal, and ignored every challenge. Review reproduced that this fails open: the engine ends the phase at its first deny (deny-overrides), so a same-channel deny from `policy.MFA` registered ahead of the session cap or a consumer deny hid them, and the exemption then allowed the re-proof (rows with a same-channel deny ahead of the cap and ahead of a consumer deny re-proved where refusal was expected). It also showed the cause: the input left out what the login carried. A session whose login met its second factor at its first (a user-verified passkey sign-in) records it in the library-owned, write-once `MFAAtFirstFactor`; the re-proof input dropped it, so the MFA policies judged that session as a one-factor login and refused it as same-channel or as owing an enrolment (with `MFARequirement` registered first, a passkey re-proof was refused with "this user must enrol a second factor").
    - **Decision.** The input carries the login's proof, rebuilt from the session record: when `MFAAtFirstFactor` is set, `SecondFactorAtLogin` holds a library-minted proof for the session's first factor at its satisfaction time, and `FederatedAssurance` carries the provider evidence a federated session records, rebuilt as the per-request phase rebuilds it (third review: `TestReproReproofDropsFederatedAssurance`, an OIDC session that every request admits under `FederatedAssuranceRefuse` was refused at re-proof with "the provider did not assert the assurance this login requires"). The proof's time is the session's satisfaction time, which a cross-channel re-proof moves; no policy reads it. With that, the phase gives a re-proof the answer it gives a login for the same user now, and **every deny refuses**; there is no same-channel exception at the enforcement point. The place that enforces a policy decision never discards a deny; an exception, where one is wanted, is the policy's to make from the input (OWASP "Fail securely"; ASVS 4.0 §4.1.5; XACML deny-overrides). D4 still governs which methods may re-prove; it does not exempt a re-proof from the policy's answer. A session that a login would now refuse as same-channel (a passkey-only user whose other method was removed after signing in) is refused, as it would be at sign-in.
    - **Only an MFA challenge is ignored.** The user is presenting a second factor at that moment, which answers `ChallengeMFA`. Any other kind refuses as the password re-proof does: a kind nothing on the chain enforces is a configuration error, otherwise a `*ChallengeError` of that kind with no session, the session unchanged. Ignoring them would let, for example, a user owing a password change become fresh by TOTP (ASVS 4.0 §1.2.4).
    - **The caller must be the session's user**, checked before the throttle and the phase, so nothing is counted, verified or judged for a principal a consumer interceptor substituted. It refuses as authentication required; the password path refuses the same caller as authentication failed, after its factor policy, because there the check guards a password about to be checked. Both answer 401.
    - **Default:** as above. **Override:** a consumer policy reads `Reauthenticating` and decides what a re-proof means to it (library-design rule 5).
  - **The input says it is a re-proof.** A re-proof creates no session: it rotates the one it re-proves, which is already counted. A policy that counts sessions, such as the library's own `policy.ConcurrentSessions`, would otherwise refuse every re-proof of a user at the cap, so a one-session-per-user consumer could never re-prove by password. `policy.Input` gains `Reauthenticating bool`, set by every re-proof (password and second factor); `ConcurrentSessions` then denies only when the count is above the maximum, because the session being re-proved is among those counted. A consumer's own policies read the same field and decide what a re-proof means to them (library-design rule 5). **Default:** false, as every login, magic-link, OIDC and passkey completion builds it. **Reproduced:** `TestReproPasswordReproofRefusedByConcurrentSessionCapOfOwnSession` (task 9.4's review): with a cap of 1 and the user's one session re-proving, the re-proof is refused with `policy: too many concurrent sessions`. It is task 9.8's red step.
  - **Held recoveries are cancelled, as at login.** A proved password shows the user still holds the account, which is why a login cancels a held recovery; a re-proof proves the same thing and now has the same effect (the user's decision, on review). Anyone able to re-prove with the password could sign in and cancel it anyway, so no one gains a power. The cancel runs where login runs it, after the password and before the phase, so a re-proof the phase then refuses has still cancelled, as a refused login has. Second-factor re-proof does not cancel, as MFA verify does not: it proves no first factor.
  - **Failures are reset only on success**, after the phase. Login resets before the phase, so a login that a policy denies has still cleared the user's failures; re-proof is stricter, as the requirement states, and that difference is deliberate.
  - **Reproduced:** `TestReproPasswordReproofAppliesPostAuthenticationPolicy`. With a policy denying in `PostAuthentication`, login for the user is refused, and `POST /reauth/password` with the correct password succeeds and rotates the session. It is task 9.4's red step.
- **Resolve:**
  1. Set `AuthenticatedAt = now` from the chain's time source.
  2. For a second factor, also set `MFA = MFASatisfied` and `MFASatisfiedAt = now`.
  3. `Sessions.RotateIssuing(ctx, s, issue)` (strict, no grace), which is the same rotation and fixation defence as MFA: it builds the successor, calls `issue` with it before anything is stored, and stores the supersession only when `issue` returns a credential. A credential that cannot be issued aborts the rotation with nothing written, so the old handle keeps working (second review, the user's decision; reproduced by `TestRepro2ReproofWhoseTokenCannotBeIssuedDoesNotSignTheCallerOut`: a failing generator left the caller with no credential that authenticates). MFA verify issues the same way, closing the same window it has had since before this change. `Rotate` is `RotateIssuing` with no issue step.
  4. Publish the rotated session with its credential.
  5. Answer through the responder.
  - The new fields are set on a copy of the session, never on the exchange's, so a failed rotation or issue has nothing to put back. A failed rotation returns `rotationRefusal`, so a concurrent winner gives 409; a credential that cannot be issued is refused with the issuer's failure. The in-flight window is counted from the instant read before the issue step, which the godoc states.
  - A spent TOTP step or challenge stays spent, as at MFA verify.
- **Challenges.**
  - Each challenge method gets its own `onetime` manager under the purpose `reauth-challenge:<method>`, distinct from `mfa-challenge:<method>`. A login challenge never answers a re-proof, and the reverse holds too.
  - Each challenge's subject is the user and it is bound to the session ID. It expires after 5 minutes, with an issuance limit of 10 per user and method per hour.
  - The default store is in memory, documented as single-process, and the chain's expiry sweep covers it as it covers the MFA challenges.
  - These settings are separate options because the project rule says one option never silently governs two subsystems. The defaults are the MFA slot's values.
  - **A shared MFA store without a re-proof store is a wiring error.** When the MFA slot was given a store (`WithMFAChallengeStore`), re-authentication was not (`WithReauthenticationChallengeStore`), and a configured MFA method has a challenge step, so re-proof issues challenges at all, the consumer has said that challenges must outlive one process, and the re-proof default contradicts it: a challenge begun on one replica is unknown to the next, its verify fails with `mfa.ErrInvalidCode` and counts against the user's throttle. `New` fails with `ErrConfig` naming both options. Single-process chains, which set neither, keep the in-memory default. The re-proof store does not follow the MFA store silently, because that would let one option govern two subsystems; the consumer passes the same store to both if that is what they want.
  - **Reproduced:** `TestReproReauthChallengeStoreFollowsSharedMFAStore`. Two chains share an MFA challenge store and a session store, with no re-proof store; a re-proof begun on one is refused on the other with `mfa: invalid code`, and the failure is recorded. It is task 9.3's red step, reworded to assert the construction refusal.
- **Responses.** The default verify and password responder writes the same credential document as MFA verify, with `Cache-Control: no-store`. The default listing writes `{"methods":[{"name","channel","begins"}],"password":bool}`. Each responder is replaceable, and a consumer responder owns its headers.
- **Construction errors (`ErrConfig`):**
  - neither the MFA slot nor form login;
  - second-factor-only without the MFA slot;
  - an empty prefix;
  - a re-proof path colliding with a path another enabled endpoint answers (below);
  - enabling twice;
  - a token-bearer chain without `WithReauthenticationTokens`;
  - a zero or negative challenge lifetime or limit;
  - a nil store or responder;
  - an MFA challenge store without a re-proof challenge store (Challenges, above);
  - a re-proof challenge store on a chain without the MFA slot, where nothing issues re-proof challenges (second review; reproduced by `TestRepro2_ReauthChallengeStoreWithNoChallengeMethodIsRefused`, the no-MFA-slot row). A TOTP-only slot still accepts it, so one store can be given to both options before a challenge method is added.
- **Path collisions, by how each endpoint matches.** Two paths collide when they are equal, or when one lies under the other and the other is matched by prefix. Re-proof's begin and verify are matched by prefix; its listing and password paths are exact. Checked against every endpoint the chain enabled, in both directions:
  - matched by prefix: the MFA verify and begin prefixes, the MFA enrolment prefixes (begin, confirm, email), the passkey registration and credentials prefixes;
  - exact: logout, form login, the MFA listing, session renewal, the password-change endpoint, and every account recovery path (start, finish, complete, cancel, codes);
  - and every other endpoint the chain can enable (magic-link login, OIDC login and callback, passwordless passkey login), each as its own `Intercept` matches it.
  - So `/login/reauth` is accepted, because form login and logout answer only their own path, and `/passkey/register` as the prefix is refused, because re-proof begin would answer `/passkey/register/begin`. The check reads the other endpoints' paths at construction, so a later endpoint with a configurable path joins it in the same pass.
  - **Reproduced:** `TestReproReauthPathCollisionRefused` (six families accepted unrefused: passkey registration, passkey credentials, MFA enrolment, session renewal, password change, account recovery start) and `TestReproReauthPrefixUnderFormLoginPathIsAllowed` (`/login/reauth` and `/logout/reauth` refused as collisions). Both are task 9.1's red steps. The existing rows `the_prefix_is_the_form_login_path` and `the_prefix_is_the_logout_path` in `TestEnableReauthentication` pinned the over-strict check and are rewritten with them.
- **Logs** go through the chain's sampled refusal logging, with reasons and never secrets.
- **Default:** off. **Override:** `EnableReauthentication`. The guard works without the endpoints, and a stale user then signs in again.
- **Alternatives rejected:**
  - *Extending `/mfa/verify` to full sessions.* That would mix two contracts and the same-channel rule (D4, D5).
  - *A separate per-source or per-user re-proof limiter.* It would give an attacker a second budget for the same secret.

### D7. Refusals and the status table

- **New sentinels:** `ErrReauthenticationRequired`, plus its error type, and `ErrReauthenticationMethodNotUsable`. Both are 403 and join the 403 row and the sentinel registry test.
- **Reused:**
  - `ErrUnknownMFAMethod` (404) and `ErrCredentialsMissing` (400);
  - `mfa.ErrInvalidCode` and `mfa.ErrVerifyThrottled` (401);
  - `authenticate.ErrAuthenticationFailed` and `authenticate.ErrUnavailable` (401);
  - the passkey clone and suspension refusals (403);
  - `ErrSessionRenewalConflict` (409).
- **The wrong-secret refusals stay 401,** as at login and MFA verify. A client knows which endpoint it called, and a different status for the same refusal would break the table's single meaning.
- **The recovery and passkey reauthentication sentinels stay their own.** Each names its own condition, and their cores cannot import `httpsec`. A consumer who wants "any reauthentication is needed" matches all three, and the README lists them together.

### D8. Adapters

`ginsec` and `fibersec` gain the same three options, two methods and validation, following their existing re-implemented judges.
- **One recency judge in `internal/guardauth` (revised).** The first cut kept the decision single only at `(*session.Session).AuthenticatedWithin` (D1) and left each adapter its own copy of the rest: the window, clock and time-source state, the option validation, the session-or-consumer time lookup, and the refusal. That is about 150 lines repeated three times, and a change to how a missing session or a zero time is judged has to be made in each. `internal/guardauth`, which already holds the one decision the adapters must make identically (where a guard finds its authorizer), gains a recency type holding the window, the clock and the time source, with its validation and one check taking the context and an optional per-route window and returning whether the caller is recent and the window it was judged against. `httpsec` imports `guardauth`, so `guardauth` cannot name `httpsec`'s error type or its session lookup: the default time source (the session's authentication time through `httpsec.SessionFromContext`) is handed to it by each adapter, and each adapter builds the `*httpsec.ReauthenticationRequiredError` from the verdict. Every adapter validates its recency options before the authorizer fallback, so one wiring mistake gives one error on every adapter (second review: fiber validated after it; reproduced by `TestRepro2_NewGuardsReportsWindowErrorBeforeMissingAuthorizer`). The judge calls `session.AuthenticatedWithin(at, now, window)`, a function on the time itself that the method delegates to, rather than building a throwaway session. Each adapter keeps only its options' surface, its handler wrapper, that error and its refusal path (gin's error channel, fiber's error handler), and words its configuration errors in its own terms from the reason the shared validation returns, as `guardauth` already leaves error text to the adapter. No new internal package is added. Behaviour is unchanged; this is a refactor, not a defect claim (CWE-1041).
- They read the session through `httpsec.SessionFromContext` on the request context: gin's `gc.Request.Context()`, and fiber's route context that the middleware writes back.
- They build the same `*httpsec.ReauthenticationRequiredError`.
- gin refuses through its error-channel path. fiber returns the refusal to `fiber.Config.ErrorHandler` and gains no error-handler option, as settled.

### D9. Conformance and documentation

- `test/httpsecconformance` gains scenarios on net/http, gin and fiber:
  - a stale session refused by the recency guard and accepted after a TOTP re-proof with the new credential;
  - a password re-proof by a user without a second factor;
  - a TOTP holder refused at the password endpoint;
  - a full session refused at `/mfa/verify`.
- The README gains a re-authentication section: the guard, the endpoints, the factor policy and its missing "any factor" option, the windows, the clock note, OIDC users, and the three reauthentication sentinels. The defaults table gains the new defaults.

### D10. A strict rotation that lost a race is a renewal conflict, decided by the store

- **Problem.** `Sessions.Rotate` (strict, no grace) supersedes the old record and then deletes it. The loser of two concurrent re-proofs, or of two concurrent MFA verifications, that reads the session after the delete finds no record and gets `session.ErrNotFound`, which `httpsec` answers as 401. A client then believes it was signed out, although the winner already holds a valid credential, and a revoked session cannot be told apart from a lost race. A renewal (`RotateWithGrace`) racing a strict rotation loses the same way.
- **First cut, replaced.** Task 7.1 made the manager remember, in process, the digests it had rotated away, so a strict `Rotate` of one of them answered `ErrRenewalConflict`. Review reproduced two gaps: `RotateWithGrace` never consulted that memory (`TestRepro_RotateWithGraceAfterStrictRotationIsRenewalConflict`), and two managers sharing one store still gave the loser `ErrNotFound` (`TestRepro_RotateOnSecondManagerAfterStrictRotationIsRenewalConflict`). Both fail on the first cut with `session not found` where `the session was renewed concurrently` is expected, and become the red steps of tasks 10.3 and 10.4. The user chose to close both here, with the store deciding, rather than leave the cross-replica case to `release-readiness`.
- **Decision: the old row stays, marked, until its in-flight window ends.**
  - `session.Supersession` gains `Strict bool`, and `session.Session` gains `RotatedStrictly bool`, a store-owned field that `Create` and `Save` never write, like the other supersession fields.
  - A strict `Rotate` supersedes with `Strict: true`, the in-flight window as `AcceptUntil` (`DefaultRenewalGrace`, 30 seconds, capped at the absolute deadline) and that same window end as `RetainUntil`, and **does not delete** the old row. The expiry sweep removes it once its retention deadline passes.
  - Which rotation wins is already decided by the store: `Supersede` is conditional on the observed successor, so a loser that read the session before the winner wrote gets `ErrRenewalConflict` from the store with nothing written. The marker keeps that evidence for a loser that reads after the winner wrote, on any manager sharing the store.
  - The manager reads the marker before anything else is judged:
    - `Load` of a strictly rotated record fails with `ErrNotFound` inside its window and is never judged as reuse. The old identifier stops working the moment the rotation succeeds, as it did when the row was deleted.
    - `Rotate` or `RotateWithGrace` of a strictly rotated record fails with `ErrRenewalConflict` inside its window, writing nothing and revoking nothing.
    - **After the window,** the store itself judges the row: its retention deadline is the window's end, so until the sweep removes it the store returns `ErrExpired`, as for any superseded session past its retention (settled `security-state-stores` load contract), and `ErrNotFound` after. Both answer 401, neither revokes anything, and neither is reuse. Widening the store contract so that such a row loads as `ErrNotFound` was rejected: it changes four stores' load judgement and the conformance suite to change a refusal no client can tell apart.
  - **A save of a marked row is refused as not-found.** A request that loaded the session before the strict rotation and saves its copy afterwards would otherwise succeed onto a row that never loads again, so its write would be lost without an error; before this change the row was gone and the save was not-found. Every store's save refuses a row marked as rotated without grace with `ErrNotFound`, so the write is reported, as the library-design rule asks (the user's decision, on review). **Reproduced:** `TestReview_SaveOfStrictlyRotatedSessionIsNotFound` (whole-branch review): the save returns nil where not-found is expected. It is task 10.5's red step.
  - The in-process `rotatedHandles` memory and its heap are removed; the per-session lock in `Rotate` stays as an in-process shortcut, no longer the guarantee.
  - The manager still never judges a strictly rotated record, so reuse detection cannot fire on a loser and the winner's family is never revoked.
- **Stores.** Every store persists and returns the marker: the in-memory default, `sqlstore`, `pgxstore` and `gormstore` through `internal/pgschema` and `internal/storekit`, and the encrypting decorator unchanged by passing it through. The `Store` interface keeps its method set, so the generated mocks do not change; the contract godoc names the new field. A third-party store that drops the marker fails the conformance suite (store-conformance delta), so the guarantee's dependency on it is checked, not assumed.
- **Schema.** A new security-state migration adds `rotated_strictly boolean NOT NULL DEFAULT false` to the sessions table. Existing rows read back unmarked, an older writer's insert that names no such column still succeeds, and rolling it back drops the column. No released migration is edited.
- **Rolling upgrade.** A build without the marker would load a marked row inside its window as a grace-superseded session, and judge it as reuse after the window. No version of scrty is tagged, so no deployment runs such a build against a migrated table. After the first tag this would need the migration and a reader of the marker to ship before any writer of it; that is recorded here so the release does not reintroduce the case.
- **Docs.** `rotationRefusal` and `resolve` state that a lost race through any manager sharing the store is the renewal conflict (409) inside the window (second review found them still saying 401 across servers).
- **Default:** on. **Override:** none. It changes which refusal a lost race receives and how long an old strict row is kept (its window, at most 30 seconds), never whether a rotation succeeds.
- **The line, stated (library-design rule 4).** The guarantee now holds across managers sharing a store, for strict rotation and renewal alike, as long as the store honours the marker, which the conformance suite checks. Past the in-flight window, an old identifier is `ErrExpired` until the sweep and `ErrNotFound` after it; both answer 401, as the deleted row's `ErrNotFound` did.
- **Settled requirements this revises (sessions):** "Rotation at second-factor verification keeps the old identifier only in flight" (the old identifier no longer loads between two writes, because there is one write), "A failed delete does not fail a second-factor rotation" (removed, as there is no delete), "A superseded identifier presented after its window revokes its family" (a strictly rotated record is excluded), and the last sentence of "Rotation with a grace window keeps the old identifier usable until the window ends". `security-state-stores` gains the marker's persistence, `schema-migrations` the column, and `store-conformance` the cases.
- **Alternatives rejected:**
  - *Keeping the first cut's per-manager memory and extending it to `RotateWithGrace`.* It closes the renewal gap on one manager only.
  - *Superseding with a zero window instead of deleting, with no marker.* Every later load of the old handle would be judged as reuse and revoke the winner's family.
  - *Keeping the superseded row with a live window, with no marker.* The old handle would keep loading for the window, which breaks strict rotation's defence against fixation.
  - *A separate tombstone table with new `Store` methods.* The largest change, and it breaks third-party stores' method sets.
  - *Accepting 401 and revising the scenario.* Rejected by the user: a client told 401 drops a credential the winner just made valid.

## Risks / Trade-offs

- [A stolen session can spend the user's second-factor throttle or password lockout through the re-proof endpoints, locking the real user out of MFA verification or password login for a window] → The same is already possible at login for anyone who knows a username. The documented limits apply, and they are replaceable.
- [The listing reports the password as accepted for a user who has no password, such as an OIDC-only user] → Their re-proof fails as a wrong password. The README tells consumers with federated users to filter through the listing responder, which receives the decision and runs on the request carrying the session. A follow-up can add an optional user lookup.
- [The guard's clock and the chain's clock can differ in tests] → The godoc names both options together. Production uses the system clock for both.
- [A window longer than the session's absolute lifetime can never be reached] → It is harmless. The guard cannot see the session manager's configuration, and the godoc states the relation.
- [An OIDC session's authentication time is its local sign-in. A silent single sign-on at the provider makes a session "fresh" without the user proving anything] → This is documented. The follow-up reads `auth_time` and sends `max_age`. Consumers can shorten their provider's session meanwhile.
- [Within 30 seconds of a strict rotation, a rotation of the old handle that is then revoked answers 409 instead of 401 (D10)] → The client retries and gets 401. Harmless.
- [A strictly rotated row stays stored for its in-flight window, at most 30 seconds, instead of being deleted at once (D10)] → It never loads and is never judged; the sweep removes it. A user-wide delete or a family revocation removes it with the rest.
- [A third-party session store that does not persist the strict-rotation marker turns a lost race back into 401 and lets the old identifier load for its window (D10)] → The store-conformance suite fails such a store, and the `Store` contract godoc names the field.
- [A chain with MFA and passkeys now needs `EnableReauthentication` to build (D5)] → The construction error names the option. Nothing is tagged yet.
- [A chain that gave MFA a challenge store must give re-authentication one too (D6)] → The construction error names both options; passing the same store to both is allowed.
- [D5 breaks a consumer who used `/mfa/verify` for step-up] → Nothing is tagged yet, and the migration is one path. A chain that would leave such a user stranded fails at construction (D5).
- [Re-proof challenges in the in-memory store do not survive across replicas] → Same as the MFA challenges. `WithReauthenticationChallengeStore` takes a durable `onetime.Store`, and a chain that gave MFA a shared store without one fails at construction (D6).

## Migration Plan

- This change builds on `NewGuards` returning an error and on the adapter guard shape from `idiomatic-api-shape`, merged in PR #29 and archived in PR #31. Its branch is rebased onto `main` after both.
- **Schema:** one new security-state migration adds the `rotated_strictly` column (D10). Consumers apply it with the rest of the set before running this version. Existing rows need no backfill.
- The re-proof endpoints are off until enabled. The guard is new API.
- **Behaviour changes for existing chains**, recorded in the changelog as breaking before the first tag: D5's pending-only MFA endpoints; a chain with MFA and passkeys and no re-authentication failing construction (D5); a strict rotation keeping its old row, marked, for its window (D10).
- **Rollback** is a revert of the change and a rollback of the migration, which drops the column. Marked rows left behind expire within 30 seconds and are swept as superseded sessions.

## References

### Researched (accessed 2026-10-31)

**D2: window, fixed window, status**
- [GitHub Docs: Sudo mode](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/sudo-mode): accepted factors (password, passkey, security key, GitHub Mobile, TOTP; not SMS), a 2-hour window reset by each sensitive action, and the list of protected actions.
- [django-sudo configuration](https://django-sudo.readthedocs.io/en/latest/config/index.html): sudo mode lasts 3 hours by default (`SUDO_COOKIE_AGE`), deliberately shorter than the session.
- [GitLab admin mode work item](https://gitlab.com/groups/gitlab-org/-/work_items/2158): admin mode expires after 6 hours. This is a design document, unverified against current product documentation.
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html): idle timeouts of 2–5 minutes for high-value applications and 15–30 for low-risk ones; reauthenticate on high-risk events.
- [Microsoft Entra: reauthentication for sensitive actions](https://techcommunity.microsoft.com/t5/microsoft-entra-blog/prompt-users-for-reauthentication-on-sensitive-apps-and-high/ba-p/4062703) and [session lifetime](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-session-lifetime): per-action reauthentication, and the warning that overusing it causes MFA fatigue. Read through search summaries.
- [RFC 9470: OAuth 2.0 Step Up Authentication Challenge](https://datatracker.ietf.org/doc/rfc9470/), read through [WorkOS's summary](https://workos.com/blog/rfc-9470-step-up-authentication-challenge): 401 `insufficient_user_authentication` with `max_age` and `acr_values`. Unverified against the RFC text.

**D3, D4: which factors may re-prove**
- [NIST SP 800-63B-4: Authenticator Assurance Levels](https://pages.nist.gov/800-63-4/sp800-63b/aal/): AAL2 reauthentication may use a single factor (password or biometric) with the session secret; AAL3 reauthentication is a full authentication; AAL2 and AAL3 timeouts.
- [NIST SP 800-63B-4: Session Management](https://pages.nist.gov/800-63-4/sp800-63b/session/): successful reauthentication resets both timeouts; for federated logins the relying party decides whether reauthentication is met.
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html): require an authenticator already bound to the account and extra verification for sensitive actions; no security questions; rotate tokens after re-authentication.
- [Google: Verify it's you for sensitive actions](https://support.google.com/accounts/answer/7162782): risk-based reauthentication by a second factor or a device registered for at least 7 days. Read through a search summary.

**D4: a same-channel re-proof refreshes freshness only** (accessed 2026-11-01)
- [NIST SP 800-63B-4: Session Management](https://pages.nist.gov/800-63-4/sp800-63b/session/): a session "SHALL NOT be considered at a higher AAL than the authentication event"; reauthentication confirms continued presence.
- [NIST SP 800-63B-4: Authenticator Assurance Levels](https://pages.nist.gov/800-63-4/sp800-63b/aal/): AAL2 needs "two distinct authentication factors"; AAL2 reauthentication may be a single factor with the session secret.
- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html): multiple instances of the same factor do not constitute MFA; factors must be independent; a passkey is MFA only with user verification.
- [PCI SSC Multi-Factor Authentication Guidance](https://listings.pcisecuritystandards.org/pdfs/Multi-Factor-Authentication-Guidance-v1.pdf) and [Mozilla accounts: step-up authentication](https://mozilla.github.io/ecosystem-platform/relying-parties/how-tos/step-up-authentication): a step-up needs an independent factor. Read through a search summary.

**D6: one implementation per control** (accessed 2026-11-01)
- [OWASP ASVS 4.0 §1.2.4](https://owasp-aasvs4.readthedocs.io/en/latest/1.2.4.html): all authentication pathways implement consistent control strength, with no weaker alternatives (Levels 2 and 3).
- [CWE-1041: Use of Redundant Code](https://cwe.mitre.org/data/definitions/1041.html): a weakness fixed in one copy may be left in another.

**D6: rotation after re-proof**
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) and [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html): renew the session identifier on privilege change and after re-authentication.

**D1, D5, D7, D8, D9, D10**
- Reasoned from scrty's own settled specs (`sessions`, `http-security-chain`, `multi-factor-auth`, `account-recovery`, `passkey-authentication`, `http-error-propagation`, `framework-adapters`, `time-source`), the accepted `idiomatic-api-shape` design, and the established design.

**Review findings folded in (accessed 2026-11-01)**
- D3 (named-method lookup), D5 (passkey wiring rule), D6 (path collisions, challenge-store wiring, the post-authentication phase), D10 (the store-decided marker, now with `security-state-stores`, `schema-migrations` and `store-conformance`): reasoned from scrty's own settled specs and the established design, each backed by the reproducing test named in its decision.
- D6 (the re-proof mark on the policy input, held recoveries cancelled on a password re-proof): reasoned from scrty's own settled specs (`security-policy` "Concurrent sessions are capped", `account-recovery` "A held recovery is cancelled by the user") and the user's decisions on review.
- D6 (the post-authentication phase) and D6, D8 (one response check, one recency judge): [OWASP ASVS 4.0 §1.2.4](https://owasp-aasvs4.readthedocs.io/en/latest/1.2.4.html) and [CWE-1041](https://cwe.mitre.org/data/definitions/1041.html), as for D6's one implementation per control above.

**D6: every deny binds a second-factor re-proof** (accessed 2026-11-01)
- [OWASP: Fail securely](https://owasp.org/www-community/Fail_securely): a control's exception handling must not enable behaviour the control would otherwise refuse.
- [OWASP ASVS 4.0 §4.1.5](https://owasp-aasvs4.readthedocs.io/en/latest/4.1.5.html): access controls fail securely, including when an exception occurs.
- [CWE-636: Not Failing Securely](https://cwe.mitre.org/data/definitions/636): entering a less secure state inherits its weaknesses.
- XACML 3.0 deny-overrides, through [HL7 FHIR's rule-combining code system](https://www.hl7.org/fhir/codesystem-permission-rule-combining.json.html), which mirrors XACML's definitions: a deny takes priority over a permit. The OASIS core specification (Appendix C) was not read; read through secondary sources.

### Primary documentation

- [NIST SP 800-63B-4: Authenticator Event Management](https://pages.nist.gov/800-63-4/sp800-63b/events/), §4.1.2.1: binding at the account's highest available assurance, which D3 protects. It is cited by the settled `passkey-authentication` design.
- [RFC 6238: TOTP](https://www.rfc-editor.org/rfc/rfc6238): the second factor whose single use D3's phishing argument relies on.
