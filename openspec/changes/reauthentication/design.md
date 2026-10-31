# Design

## Context

See proposal.md for why. The current state that shapes the approach:

- **The authentication time exists and is library-owned.**
  - `session.Session.AuthenticatedAt` is set by `Sessions.Create`, carried over by every renewal, and moved only by a rotation that carries a new value. `Save` keeps the stored value, so a consumer cannot refresh it.
  - The MFA verify endpoint's `resolve` (`httpsec/mfa_verify.go:442`) sets it to the second-factor time, then calls `Sessions.Rotate`, which writes it into the successor.
- **Two freshness checks exist, written separately.**
  - `httpsec/recovery_codes.go:158` and the passkey manager's `admit` (`authenticate/passkey/passkey.go:448`) both compute `now.Sub(s.AuthenticatedAt) > window`, with 15-minute defaults and their own options.
  - Their spec text describes the time as "the later of creation and second-factor satisfaction". That is equal to `AuthenticatedAt` today, and stops being equal once a password re-proof exists.
- **Guards, as settled by `idiomatic-api-shape` (PR #29).**
  - `NewGuards(az, opts...) (*Guards, error)` validates after its options run. `GuardOption` is `func(*Guards)`, with no error.
  - Every guard runs `g.guard(judge)`: principal, then authorizer, then the judge, whose error is refused unchanged.
  - The default refusal is `StatusForError` with no body. gin registers the refusal on `gc.Error`. fiber returns it to `fiber.Config.ErrorHandler`.
  - `ginsec` and `fibersec` re-implement the judge and reuse only `httpsec` types and sentinels.
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
- **Email-channel methods** that a consumer supplies count like any enrolled method. No built-in one exists.
- **Users with no password** cannot be told apart without loading the user. The listing reports the password as accepted for anyone with no second factor. Their password re-proof then fails as a wrong password would, after the authenticator's decoy comparison. A consumer listing responder can filter it out (Risks).

### D4. Re-proof does not apply the same-channel rule

- **Rule:** a re-proof second factor is any configured MFA method the user is enrolled on, whatever its channel. A session that signed in with a passkey may re-prove with the passkey method.
- **Why:** the same-channel rule exists so that two factors at login are independent. A re-proof is one factor, presented alongside the live session secret. That is what NIST SP 800-63B-4 allows for AAL2 reauthentication ("a single authentication factor ... in conjunction with the session secret").
  - Applying the rule would leave a passwordless passkey user with no re-proof at all, or push them to a weaker password.
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
  - **Password re-proof uses the form login's** password path (`authenticatePassword`). That gives the pre-authentication lockout, the decoy-even authenticator, failure recording on the attempt store and its source accounting. Success clears the user's lockout failures, as a login does.
- **Admission:** a session with a resolved caller, and `MFA` in {`MFANone`, `MFASatisfied`}. It must have no `PasswordChangePending` and no enrolment or recovery marker. Otherwise it is refused as authentication required. A fresh session is served: re-proving early is harmless and throttled.
- **Verify order:**
  1. admission;
  2. method name;
  3. the factor policy (D3, D4) through the enrolment lookups, where a failure refuses;
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
  5. `authenticatePassword`;
  6. on success, reset failures and resolve.
- **Resolve:**
  1. Set `AuthenticatedAt = now` from the chain's time source.
  2. For a second factor, also set `MFA = MFASatisfied` and `MFASatisfiedAt = now`.
  3. `Sessions.Rotate` (strict, no grace), which is the same rotation and fixation defence as MFA.
  4. Publish the rotated session and issue its credential.
  5. Answer through the responder.
  - A failed rotation rolls the in-memory fields back and returns `rotationRefusal`, so a concurrent winner gives 409.
  - A spent TOTP step or challenge stays spent, as at MFA verify.
- **Challenges.**
  - Each challenge method gets its own `onetime` manager under the purpose `reauth-challenge:<method>`, distinct from `mfa-challenge:<method>`. A login challenge never answers a re-proof, and the reverse holds too.
  - Each challenge's subject is the user and it is bound to the session ID. It expires after 5 minutes, with an issuance limit of 10 per user and method per hour.
  - The default store is in memory, documented as single-process, and the chain's expiry sweep covers it as it covers the MFA challenges.
  - These settings are separate options because the project rule says one option never silently governs two subsystems. The defaults are the MFA slot's values.
- **Responses.** The default verify and password responder writes the same credential document as MFA verify, with `Cache-Control: no-store`. The default listing writes `{"methods":[{"name","channel","begins"}],"password":bool}`. Each responder is replaceable, and a consumer responder owns its headers.
- **Construction errors (`ErrConfig`):**
  - neither the MFA slot nor form login;
  - second-factor-only without the MFA slot;
  - an empty prefix;
  - a path colliding with logout, form login, the MFA verify or begin prefix, or the MFA listing path;
  - enabling twice;
  - a token-bearer chain without `WithReauthenticationTokens`;
  - a zero or negative challenge lifetime or limit;
  - a nil store or responder.
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

## Risks / Trade-offs

- [A stolen session can spend the user's second-factor throttle or password lockout through the re-proof endpoints, locking the real user out of MFA verification or password login for a window] → The same is already possible at login for anyone who knows a username. The documented limits apply, and they are replaceable.
- [The listing reports the password as accepted for a user who has no password, such as an OIDC-only user] → Their re-proof fails as a wrong password. The README tells consumers with federated users to filter through the listing responder, which receives the decision and runs on the request carrying the session. A follow-up can add an optional user lookup.
- [The guard's clock and the chain's clock can differ in tests] → The godoc names both options together. Production uses the system clock for both.
- [A window longer than the session's absolute lifetime can never be reached] → It is harmless. The guard cannot see the session manager's configuration, and the godoc states the relation.
- [An OIDC session's authentication time is its local sign-in. A silent single sign-on at the provider makes a session "fresh" without the user proving anything] → This is documented. The follow-up reads `auth_time` and sends `max_age`. Consumers can shorten their provider's session meanwhile.
- [D5 breaks a consumer who used `/mfa/verify` for step-up] → Nothing is tagged yet, and the migration is one path.
- [Re-proof challenges in the in-memory store do not survive across replicas] → Same as the MFA challenges. `WithReauthenticationChallengeStore` takes a durable `onetime.Store`.

## Migration Plan

- This change branches from `refactor/idiomatic-api-shape` (PR #29) and merges after it, because it builds on `NewGuards` returning an error and on the adapter guard shape.
- There is no data or schema migration. The re-proof endpoints are off until enabled. The guard is new API.
- D5 is the only behaviour change for existing chains, and it is recorded in the changelog as breaking before the first tag.
- Rollback is a revert of the change. No stored state depends on it.

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

**D6: rotation after re-proof**
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) and [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html): renew the session identifier on privilege change and after re-authentication.

**D1, D5, D7, D8, D9**
- Reasoned from scrty's own settled specs (`sessions`, `http-security-chain`, `multi-factor-auth`, `account-recovery`, `passkey-authentication`, `http-error-propagation`, `framework-adapters`, `time-source`), the accepted `idiomatic-api-shape` design, and the established design.

### Primary documentation

- [NIST SP 800-63B-4: Authenticator Event Management](https://pages.nist.gov/800-63-4/sp800-63b/events/), §4.1.2.1: binding at the account's highest available assurance, which D3 protects. It is cited by the settled `passkey-authentication` design.
- [RFC 6238: TOTP](https://www.rfc-editor.org/rfc/rfc6238): the second factor whose single use D3's phishing argument relies on.
