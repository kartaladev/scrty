## Context

See proposal.md for why this change exists. The constraints that shape the approach:

- **Current behaviour this change modifies:**
  - **The MFA requirement policy** (`security-policy`) denies a required user with no usable enrolment in the post-authentication and per-request phases, with the enrolment-required reason. "No usable enrolment" means one of:
    - the user is not enrolled;
    - the user is enrolled only on the first factor's channel.

    A lookup error also denies. Stateless requests are denied as MFA-required. A required user with a usable enrolment is allowed at post-authentication, and the second-factor challenge policy raises the challenge.
  - **The second-factor challenge interceptor** (`multi-factor-auth`) serves the verify endpoint. At `OrderMFAChallenge` (600) it blocks every other request whose session has the MFA challenge pending, except the logout path wherever the consumer places it (`auth-methods` departure D15). Chain assembly hands the gate the configured logout path.
  - **The password-change gate** (`http-security-chain`) sits at `OrderPasswordChange` (650). It lets through only its own resolve endpoint, not logout.
  - **The unenforced-challenge refusal** (`httpsec/chain.go`) fails assembly when a registered policy declares `ChallengeMFA` through `policy.Challenger` and nothing is registered at `OrderMFAChallenge`: `EnableMFA`, or any consumer interceptor at that slot, satisfies it. It checks that one kind only, and only at assembly. A policy that does not implement `Challenger` is read as raising nothing (`auth-methods` design, section 15).
  - **Enrolment is begin, then confirm** (`multi-factor-auth`). A pending enrolment does not count as enrolled. A confirmed one cannot be replaced silently. Confirmation is one atomic store write (`EnrolmentStore.Confirm`) that both records the code's time step and marks the enrolment confirmed.
  - **A lost enrolment never downgrades a required user.** The requirement lives with the user (`identity-model`).
  - **Enrolment has no HTTP endpoint.** Begin and confirm are Go APIs the consumer puts behind their own routes, which a required, unenrolled user can never reach.
  - **Rotation** is specified inside the `multi-factor-auth` verify requirement, and `session.Manager.Rotate` carries every field except the identifier over, both deadlines included.
  - **The status mapping** (`http-error-propagation`) maps a password-change challenge to 403 and a challenge of any other kind to 401.
- **Behaviour owned elsewhere and used here, not restated:**
  - the same-channel rule and the first-factor exemption classification (`security-policy`);
  - library-owned challenge fields and the absolute deadline every store enforces (`sessions`);
  - the limiter port (`rate-limiting`);
  - the sender port and queued sender (`email-notification`);
  - sealing of secrets on the enrolment record (`secrets-at-rest`);
  - the login completion step and slots (`http-security-chain`), and the challenge error (`http-error-propagation`).
- **Project rules:**
  - every default documented and replaceable (library-design);
  - wiring mistakes fail at construction;
  - safe defaults, with the convenient choice as an option;
  - test-first (golang-tdd).

## Goals / Non-Goals

**Goals:**
- A required user with no usable enrolment can bind a second factor through the library, and reaches nothing else until that factor is proven.
- An attacker holding only the password cannot bind their own authenticator without the account's email owner seeing it and, by default, taking part.
- With the path off, every observable behaviour is identical to today.

**Non-Goals:**
- Recovery codes, WebAuthn and other method kinds. The enroller port admits them later.
- An administrative HTTP surface. Resetting an enrolment is a Go API the consumer puts behind their own authorised routes.
- Replacing an existing confirmed enrolment through the path. A lost authenticator is an operator reset, then the path.
- Per-user grace windows measured from when a user became required. That needs a timestamp the requirement lookup port does not return today; see Open Questions.
- Letting an API-key login or a stateless request enter the state.

## Decisions

### 1. The path is off by default

```go
func WithMFAEnrolmentPath(opts ...EnrolmentPathOption) MFARequirementOption // policy
func EnableMFAEnrolment(d EnrolmentDeps, opts ...EnrolmentOption) Option     // httpsec
```

- **Default:** off. A required user with no usable enrolment is refused with the enrolment-required reason, as today.
- **Override:** the consumer turns the path on explicitly, on both the policy and the chain.
- **Construction errors:**
  - the policy option is set but the chain has no enrolment interceptor. This is not a check of its own: with the path on, the requirement policy declares `ChallengeMFAEnrolment` through `Challenger`, and the generalised unenforced-challenge check (decision 12) refuses it;
  - the interceptor is enabled but no registered policy declares `ChallengeMFAEnrolment`, so the endpoints could never be reached.
- **Why off:** the settled rule is that the safe choice is the default. The path gives a password alone the power to establish a second factor. That is a real change in threat model, so an operator must opt into it.
- **Alternative rejected:** on by default whenever require-for-all is set. It is convenient, but it would silently change what require-for-all guarantees.

### 2. How the state is issued

The MFA requirement policy returns a challenge of kind `ChallengeMFAEnrolment` in place of denying with `ErrMFAEnrollmentRequired` when all of the following hold:
- the path is on, and its rollout deadline (decision 5) has not passed;
- the phase is post-authentication or per-request;
- the user is required;
- the enrolment lookup succeeded and reported no usable enrolment;
- the first factor's kind is on the path's allowlist (decision 9);
- the MFA method's channel differs from the first factor's (decision 8).

Every other outcome of that policy is unchanged:
- exempt first factors are allowed;
- a lookup failure denies;
- a stateless request, or a deployment with no method, is denied as MFA-required;
- a satisfied session is allowed;
- a usable enrolment is allowed at post-authentication and left to the second-factor challenge policy.

**At login.** The login completion step creates the session, then marks any pending challenge and saves it, before issuing the token. For this kind, marking sets second-factor state `enrolment-pending`, sets the enrolment-origin marker and lowers the absolute deadline (decision 7). The request is refused with `*ChallengeError{Kind: ChallengeMFAEnrolment, Session, Token}`, so the client holds a token for a session that can reach only the enrolment routes. Form login, magic-link redemption and OIDC handoff redemption all end through this step, so all three behave the same way wherever their first factor is on the allowlist.

**Mid-session.** When a user becomes required while holding a full session with no usable enrolment, the per-request phase challenges for enrolment. The bearer interceptor marks the session and saves it itself, once, when the session first enters `enrolment-pending`. It cannot leave that to the session-touch step at slot 800, as a mid-session MFA challenge does, because the enrolment gate at slot 599 refuses the request before slot 800 runs: the mark and its lowered deadline would be lost, and the confined session would keep its full lifetime (reproduced by `TestBearerMarksEnrolment`). A failed save refuses the request. The gate then confines it. This replaces a refusal on every request.

**Two challenges at once.** When the password-age challenge and the enrolment challenge both apply at login, the first challenge in registration order wins, as `security-policy` already states. The other is raised by the per-request phase on the next request, after the first is resolved.

**Status:** a challenge of kind MFA enrolment maps to 403. This is a new special case, not an existing pattern: today only the password-change kind maps to 403, and every other kind to 401. The caller is authenticated and must act; retrying credentials will not help. The row is an `http-error-propagation` delta of this change.

- **Default and override:** no separate override. The state exists only when decision 1's opt-in is set.
- **Alternative rejected:** issuing no session and returning a one-time enrolment ticket instead. That duplicates session expiry, logout and rotation, which `sessions` already owns.

### 3. Routes an enrolment-only session may reach

The enrolment interceptor registers at a named slot, `OrderMFAEnrolment`, equal to `Before(OrderMFAChallenge)`. For a session in `enrolment-pending` it lets through exactly:

| Route | Default path | Purpose |
|---|---|---|
| `POST` begin | `/mfa/enrol/begin` | start or restart a pending enrolment |
| `POST` confirm | `/mfa/enrol/confirm` | prove the authenticator with a code |
| `POST` out-of-band confirm | `/mfa/enrol/confirm-email` | enter the emailed code (decision 5) |
| `POST` logout | the chain's logout path | end the session |

Every path can be replaced by an option (`WithEnrolmentBeginPath`, `WithEnrolmentConfirmPath`, `WithEnrolmentEmailConfirmPath`).

**Fails closed.** Every other request is refused with `*ChallengeError{Kind: ChallengeMFAEnrolment, Session}` before any later interceptor runs, whatever its method or path. This covers:
- the MFA verify endpoint;
- the password-change resolve endpoint;
- the authorizer;
- every consumer interceptor at a later slot;
- the handler.

**Logout.** Logout sits after the gate, so the gate lets the logout path through by reading it from the chain's logout configuration, the same way as the MFA gate (D15). If logout is not enabled, nothing extra passes. A federated session's logout may run the provider's end-session step and answer with a body; that is unchanged.

**Principal visibility.** The exchange carries the session so the enrolment endpoints can use it. No handler, authorizer or consumer interceptor after the gate runs for this session. Consumer interceptors registered between the bearer slot and the gate (500–599) do run and do see the principal, as they do for an MFA-pending session today; godoc says so. That includes an interceptor at `OrderMFAEnrolment` itself (`Before(OrderMFAChallenge)`) registered before `EnableMFAEnrolment`, since interceptors in one slot run in registration order; one registered after it runs behind the gate.

- **Default:** the paths above.
- **Override:** each path. There is no option to allow further routes, because an allowlist would reopen the account-attribute surface decision 6 closes. The limit is stated in godoc.

### 4. Upgrading to a full session

The flow, with the defaults on:
1. **Begin** returns the provisioning data (for TOTP, a secret and a URI), and records the new enrolment generation on the session.
2. **Confirm** with a valid code proves the device. The enrolment is not yet usable. The emailed code is sent (decision 5).
3. **Out-of-band confirm** with the emailed code marks the enrolment confirmed. The session moves from `enrolment-pending` to MFA `pending`. The enrolment-origin marker and the lowered deadline stay. From here the ordinary gate and verify endpoint govern it.
4. **Verify** with a fresh code runs through the existing verify endpoint, with its per-user throttle and same-channel check. Success marks the session satisfied, restores the normal absolute deadline for a session carrying the enrolment-origin marker (decision 7), and rotates the handle.

- **The per-request phase must see a satisfied session.** The upgrade ends at a protected route only if the bearer tells the per-request policies that the session satisfied its second factor. It did not: its policy input left `MFASatisfied` unset, so the requirement policy challenged every required user again after a successful verify, on this path or any other (reproduced by `TestEnrolmentPathEndToEnd`, and pinned minimally at the bearer). This change sets it from the session's state.
- **Both conditions are required.** A session becomes full only after the enrolment is confirmed and a second factor has been verified in the same session. Confirmation alone never marks it satisfied.
- **Why a separate verify:** it keeps exactly one place that resolves an MFA challenge. Throttling, same-channel refusal and handle rotation live there. A second resolver would have to repeat each of them and could drift.
  - A fresh code is needed because device proof recorded its time step and replays are refused. The user may wait up to one step (30 s by default).
  - Against the password-holding attacker, verify adds no assurance of its own; decision 5 is what defends there. This design does not claim otherwise.
- **Same flow.** Every step is tied to the session in which the enrolment began, through the enrolment generation that session recorded at begin:
  - confirm and out-of-band confirm act only on the pending enrolment of that session's user, and only while its generation equals the session's;
  - logging out, or the session expiring, abandons the flow;
  - the pending enrolment stays pending and is replaced by the next begin, which starts a new generation.
- **Override:** none for the ordering. It is the guarantee.
- **Alternative rejected:** treating a successful confirmation as the second factor. It saves one step, but the confirmation path would need its own throttle, rotation and same-channel check.

### 5. Silent binding by a password holder

**The threat.** An attacker who has only the password logs in. They receive an enrolment-only session and bind their own authenticator. They now pass MFA as the user, and the real user is refused, because the account already has a confirmed enrolment.

The mitigations below are layered.

**Contact address (default: the username).**
- The address for the notification and the emailed code comes from a `ContactResolver` (user reference and loaded details → address).
- **Default:** the username is the address, the convention `magic-link` already settled. No configuration is needed where usernames are addresses.
- **Override:** `WithContactResolver`. The library does not interpret the user's details beyond the default.
- The provisioning URI's account label follows the same convention through a `LabelResolver`, defaulting to the username, and is never taken from the request.

**Notification (default on).**
- When an enrolment becomes confirmed, the user is sent a plain-text message through the `email-notification` sender port. The message names the method and the time. It contains no code, secret or provisioning URI.
- Delivery follows the same non-blocking sender rule as magic links. A synchronous sender is refused at construction unless explicitly accepted, with an option modelled on `magiclink.WithSynchronousDelivery`.
- A notification the sender refuses to queue after completion is logged as a sampled refusal with a reporter. The completion is not rolled back: with email confirmation on, the mailbox owner has already taken part.
- The notification is sent once the enrolment is confirmed, whether or not the session's move to MFA pending can then be saved: the binding stands either way, and the owner is told of every binding.
- **Override:** `WithoutEnrolmentNotification()`, whose godoc states what it gives up.
- **Construction error:** the notification is on but no sender is supplied.

**Out-of-band confirmation (default on).**
- The emailed code is kept on the pending enrolment record, not issued as a one-time token:
  - 6 digits from `crypto/rand`;
  - sealed at rest like the TOTP secret, under `secrets-at-rest`, so a database dump alone reveals neither;
  - with an expiry 10 minutes after device proof;
  - with an attempt count, charged before each comparison; the fifth wrong code voids it.
- **Why not a one-time token.** `one-time-tokens` defines a token as a record identifier and a 32-byte secret. A 6-digit code is neither, and its plain hash at rest is reversible by trying 10⁶ values. A short-code mode there would need a server-side keyed hash, a new lookup path and a key operators must manage, and would still need the enrolment generation below. Keeping the code on the enrolment reuses the sealing the record already has, and leaves that contract untouched.
- **Generation binding.** Every begin gives the pending enrolment a new generation, a `pkg/id` identifier, never derived from the ciphertext, which a re-seal changes. Begin records it on the session. Device proof and completion are conditional writes on that generation. So an emailed code can confirm only the secret that was proven when the code was sent. Without this, a user who proves a device in one session could confirm, with the code emailed to them, a secret an attacker re-provisioned in another session. That race is reproduced by `TestNewerBeginInvalidatesEarlierProof`, which fails against a generation-blind completion.
- **Redemption is charge-then-compare-then-consume.** Charge one attempt with a conditional write that succeeds only while the generation equals the session's, the device is proven, the code has not expired and fewer than five attempts have been charged; compare the code in constant time; then complete with one conditional write last. A refusal never completes the enrolment. Every presented code, malformed or not, is charged before it is compared, and a wrong one also counts against the per-user confirmation limiter (decision 6).
  - **Why charge first.** Checking a failure count loaded before the comparison, and counting a failure after it, leaves a gap: requests that all load before the fifth failure lands each get a comparison, so the bound becomes the number of concurrent requests, not five. Charging first, in the write that decides, caps the comparisons against one code at five however many requests race. A correct code charged fifth still completes; the sixth attempt is refused.
  - The single-call `Confirm`, kept for out-of-band enrolment, clears any outstanding emailed code when it confirms, and never moves the recorded time step backwards, so a device-proving code cannot be replayed.
- **Delivery failure fails closed.** The contact address is resolved before the device is proven, so an unresolvable address leaves no proof behind. If the sender then refuses to queue the code, the confirm request fails and the code is voided by charging its remaining attempts, so no later emailed-code request can complete that proof and the user begins again. A synchronous sender can report a failure after the relay accepted the mail; voiding means a code that did arrive is still refused, as the failed request told the user.
- **Fixed bounds, no override.** The code's length (6 digits), its lifetime (10 minutes after device proof) and its attempt cap (5) are fixed. Together they set the chance of guessing a code, which is the guarantee the path makes; a consumer could only weaken it. They are stated in godoc. The time the code message names is the chain's clock; the expiry that decides is the one the method stored.
- **Same method on both sides.** The requirement policy's method lookup and the method given to `EnableMFA` must be the same method; the chain cannot check it. If they differ, the policy's same-channel test can admit a login that begin then refuses as same-channel, and that user stays confined until the session expires. Godoc says so.
- **No resend endpoint.** A lost or expired code means beginning again, which starts a new generation. Emails are therefore bounded by the begin limit (decision 6).
- A code rather than a link keeps the proof inside the session that began the enrolment. A link opened on another device would carry no session, and a mail scanner that follows links would confirm a binding with nobody involved.
- **Override:** `WithoutEmailConfirmation()`. The godoc states that without it, a password alone binds a second factor, and notification is then the only signal. Device proof and completion then run back to back, on the same generation.
- **Stated limit:** after a magic-link login the first factor already proved control of the mailbox, so the emailed code adds no assurance there. The same holds for a federated login admitted through the allowlist (decision 9), where the provider account usually includes the mailbox. The notification still goes. The godoc says so rather than skipping the step silently.

**Rollout window (default none).**
- `WithEnrolmentPathUntil(t time.Time)` closes the path at an instant the operator chooses. After it, the policy denies with the enrolment-required reason, as when the path is off.
- This lets an operator open the path for a require-for-all rollout and close it once the user base has enrolled.
- **Instant:** compared with the request's `Input.Now`, as the other time-based policies are. A zero instant means no cutoff.
- **Default:** none, so the path is open while it is enabled. With email confirmation on, the mailbox owner must take part in every binding. A deadline adds little where that holds, and a mandatory one would push operators into picking arbitrary dates.

**Recommended default, grounded in the safe-default rule.** Path off (decision 1). When it is enabled, both notification and email confirmation are on, and each needs an explicit opt-out.

### 6. What the state cannot do

- **No password change or account attributes.**
  - The gate refuses the password-change resolve endpoint and every consumer route (decision 3).
  - The enrolment endpoints read only a `code` field. They write only to the enrolment store, and to the session's library-owned second-factor fields.
- **No removal or replacement.**
  - Begin on a user with a confirmed enrolment fails with the already-enrolled error, decided by the store's write, as `multi-factor-auth` already requires.
  - No endpoint removes an enrolment.
- **Rate limits** (options named for what they govern):

| Option | Default | Keyed by | Governs |
|---|---|---|---|
| `WithEnrolmentBeginLimiter` | in-memory, 5 per hour | user reference | begin calls, every call recorded |
| `WithEnrolmentConfirmLimiter` | in-memory, 5 failures per 15 min | user reference | failed device and emailed-code confirmations |

- **The begin limiter records every call,** through the limiter port's failure-recording step. `rate-limiting` states that limits count failures, not requests; this limiter deliberately counts requests, because every begin generates a secret and can lead to an email. Its godoc says so. It is what bounds emails per user.
- **Why per user:** the attacker already holds a first factor and can rotate addresses, as with verification.
- **A limiter error refuses.** A nil limiter is a construction error.
- **A failure is recorded even after a hang-up.** Recording runs under `context.WithoutCancel`, as the `multi-factor-auth` verify throttle and `rate-limiting` require.
- **Separate from verification.** The verify endpoint's throttle is not shared. Confirmation failures lock only the enrolment path, not verification of an existing enrolment.
- **Limits, stated:**
  - the in-memory limiters are per replica, as `rate-limiting` documents;
  - a password holder can exhaust a user's begin budget for an hour; this is a documented lockout-for-an-hour trade-off;
  - enrolment-only sessions count toward the concurrent-session cap. A password holder can occupy cap slots, each for at most the enrolment TTL. This is documented, and bounded by decision 7.
- **Refusal statuses.** In `http-error-propagation`:
  - an invalid device code maps through a new "invalid second-factor code" row (401), which the verify endpoint's wrong code shares; an invalid, expired or voided emailed code is identifiable as that same refusal;
  - a per-user throttle refusal, of verification or of enrolment, maps through a new row (401), alongside the throttled-source row;
  - the already-enrolled error joins the 403 row;
  - begin on the first factor's channel uses the existing same-channel row (403).
  - Reproduced: `httpsec/status.go` mapped none of `mfa`'s errors, so the verify endpoint's refusals reached clients as 500. `TestStatusForError` failed with 500 for `ErrInvalidCode`, `ErrVerifyThrottled`, `ErrSameChannel` and `ErrAlreadyEnrolled` before the rows were added.
- **Input:** the enrolment endpoints read `code` from a URL-encoded POST body only, never from the URL query, which reaches access logs. A body that carries no code, is not a URL-encoded form (multipart included) or does not parse is refused as missing credentials (400) and is not charged against a limiter, as form login does; the godoc states the limit. Only a code actually presented and wrong is charged.
- **Returned errors:** every error the enrolment interceptor returns, including a store, session or sender outage, carries fixed library text, with the cause and any library sentinel reachable through `errors.Is`/`errors.As`, so statuses are unchanged and a consumer's error handler that prints the message prints no label, address or bucket key.
- **Logs:** no record contains a presented code, the emailed code, a secret, a provisioning URI or an address. Refusals are sampled under `WithEnrolmentLogInterval` (1 min), with a reporter. The chain's `FlushRefusalLogs` flushes the enrolment sampler with the rest, so held-back counts are not lost at shutdown.

### 7. Lifetime of an enrolment-only session

- **Mechanism:** marking a session `enrolment-pending` lowers its existing `AbsoluteExpiresAt` to the earlier of its current value and now plus the enrolment TTL, clamps `IdleExpiresAt` to it, and sets a library-owned enrolment-origin marker. The marker is the absolute deadline the session held immediately before the mark, not a flag: its presence is the marker, and its value is what the upgrade may restore at most. No new deadline field is added, so every store's load, the concurrent-session count and the expiry sweep enforce the cap with no store change.
- **Default TTL:** 15 minutes.
  - It leaves room to install an authenticator app and read an email.
  - It is not long enough for a stolen token to be worth much, since the state reaches nothing but enrolment.
- **Override:** `WithEnrolmentSessionTTL(d)`.
  - **Construction error:** `d` is zero or less, or longer than the session manager's absolute timeout.
- **On upgrade.** A successful verify on a session carrying the marker restores `AbsoluteExpiresAt` to the earlier of `CreatedAt` plus the manager's absolute timeout and the deadline the marker recorded, and `IdleExpiresAt` to the earlier of now plus the idle timeout and that deadline. It then clears the marker and the enrolment generation, and rotates with the plain `Rotate`, which copies the restored deadlines.
  - The restored deadline is never later than a normal login would have had, nor later than the deadline the session held before the mark, even when that deadline had been lowered by something else or the absolute timeout was raised in between. A plain `CreatedAt` plus the timeout would not guarantee the second half, which is why the marker records the deadline.
  - A session already past its lowered deadline is not restored: the restore fails with the session-expired error and leaves the session unchanged, so a caller that saves rather than rotates cannot revive it.
  - `Rotate` stays a plain copy, so "rotation never extends a session" holds as other changes rely on it.
  - A fault in the restore ends a session early, never late.
- **On expiry:** the user logs in again and receives a new enrolment-only session.
- **Idle deadline:** the enrolment endpoints answer the request themselves, so the session-touch step does not run for a confined session. With an idle timeout shorter than the enrolment lifetime, an active user can idle out mid-enrolment; godoc says so.
- **Delta for `sessions`:** the new `enrolment-pending` state, appended to the second-factor states and never inserted before existing ones, since durable stores keep the ordinal; the enrolment-origin marker; the enrolment generation; and the lowering and restoring rules above.
- **Alternatives rejected:**
  - A separate enrolment-deadline field. Every store, the count and the sweep would have to learn it, and a consumer's own store that does not would keep an enrolment session alive for the full absolute timeout: it fails open.
  - Fresh deadlines from the upgrade time. That extends a session past the deadline it was created with, and needs a second rotation-like operation that must never be confused with `Rotate`.

### 8. The same-channel rule applies to enrolment

- **At begin.** The enrolment interceptor refuses begin with the same-channel error, before generating anything, when the MFA method's channel equals the session's first-factor channel. It reads the channel from the session's recorded first factor, so `BeginEnrolment`'s signature does not change. There is no override.
  - `security-policy` already treats such an enrolment as no usable enrolment for a required user.
  - Its complete-on-first-factor mode does not apply to required users.
  - Binding it would therefore leave the user refused on their next login.
- **At issue.** The policy issues `ChallengeMFAEnrolment` only when the MFA method's channel differs from the first factor's. Otherwise it denies with the enrolment-required reason, as today. A session is never confined to a path that cannot complete.
- **Example:** a deployment whose method is an email one-time-code method cannot enrol magic-link users through the path. This is documented as a limit.

### 9. Which first factors can enter the state: an allowlist of kinds

```go
func WithEnrolmentFirstFactors(kinds ...factor.Kind) EnrolmentPathOption
```

The path has its own eligibility allowlist of first-factor kinds. It governs only whether a login that the requirement policy would otherwise deny for enrolment enters the path. It does not change whether MFA is required, or which first factors are exempt; that classification stays `security-policy`'s, and `oidc-mfa-assurance`'s mode where that change applies.

| First factor | Default | Why |
|---|---|---|
| `password` | on the list | the case this change exists for |
| `magic-link` | on the list | uses the same login completion step; the email-confirmation limit (decision 5) is documented. A consumer who finds that limit unacceptable leaves it off. |
| unrecorded | on the list | not exempt, per `security-policy`. No channel, so any method is on a different channel. |
| `oidc` | **off the list** | a stolen provider account usually includes its mailbox, so the emailed code adds nothing and the notification may reach the attacker too. Adding it is an explicit choice, and its godoc states that limit. |
| `api-key` | never, whatever the list | exempt and stateless; a machine credential has no session to confine |
| `basic` | never, whatever the list | stateless; denied as MFA-required, unchanged |

- **Default:** password, magic link and unrecorded. Setting the option replaces the list; it does not add to it.
- **Override:** the option. A kind that can never enter (API key, basic) is a construction error on the list, and so is an empty list: a path that admits nothing would still declare `ChallengeMFAEnrolment` and demand an enforcer no login can reach.
- **Combined with `oidc-mfa-assurance`,** for a required user with no usable enrolment whose federated login did not meet assurance:

| Mode | Outcome |
|---|---|
| Exempt | allowed before any lookup; never reaches the path |
| Refuse | denied with assurance-not-met; the provider is the only MFA authority, so a local enrolment would be meaningless |
| Challenge | follows the allowlist: with `oidc` listed and the path on, the enrolment challenge; otherwise denied with enrolment-required |

  Until `oidc-mfa-assurance` lands, an OIDC login is exempt by default and never reaches the path. A consumer who removes that exemption today gets the Challenge-mode row. `oidc-mfa-assurance` carries this table into its own design as a follow-up revision.
- **Why an allowlist rather than a federated-only switch:** the same email-confirmation limit applies to magic link, and a switch for one kind would leave that case unclosable. The list governs one subsystem, entry to the path, so it does not duplicate the exemption rule.

### 10. Enroller port

```go
type Enroller interface {
    Method
    BeginEnrolmentGeneration(ctx context.Context, user identity.UserID, accountLabel string) (Provisioning, id.ID, error)
    ProveDevice(ctx context.Context, user identity.UserID, gen id.ID, code string, emailCode bool, emailCodeTTL time.Duration) (string, error) // proves the code, stays pending; returns the emailed code when asked
    CompleteEnrolment(ctx context.Context, user identity.UserID, gen id.ID) error                // marks confirmed; the path uses it only with email confirmation off
    RedeemEmailCode(ctx context.Context, user identity.UserID, gen id.ID, code string) error      // charge, compare in constant time, complete last
    SupportsEnrolmentPath() bool                                                                  // the store implements the device-proof port
}
```

Begin returns the generation it drew, so the enrolment interceptor records it on the session without a second read. `BeginEnrolment` keeps its signature for out-of-band enrolment.

- **Only a redeemed code completes an enrolment whose proof issued one.** Whether a device proof issued an emailed code is recorded by its expiry, `EmailCodeUntil`, which the proof sets and only a new begin clears; a store never clears it on expiry, exhaustion or completion, never clears the proof time except on a new begin, and never clears the code itself except on completion, confirmation or a new begin.
  - `CompleteEnrolment` completes only when its read shows the device already proven on that generation with no code issued (`EmailCodeUntil` zero). A proven device's proof fields never change within a generation, and a new begin changes the generation the conditional write checks, so that read cannot go stale before the write. A read that shows the device not yet proven is refused, which also closes a proof that lands between the read and the write.
  - The single-call `ConfirmEnrolment` refuses any enrolment whose device was proven through the path, or whose proof issued a code, whatever the state of that code: such an enrolment completes only through the path.
  - So email confirmation does not rest on the interceptor choosing the right branch, a proof whose code could not be queued, expired or ran out of attempts can never be completed, and the user begins again.
  - Reproduced, then fixed: a review of the first version of this rule, which read only the code, showed a proof landing between the read and the write, and a store reporting an exhausted code (and then its proof) as absent, each confirming without the code. `TestTOTPEnroller` pins every case: "completion is refused when a proof with an emailed code lands between its read and its write", "... when the store reports an exhausted code as absent" (completion and single-call confirm), "the single-call confirm is refused when the store reports an exhausted proof as absent", and the expired and out-of-attempts rows.
  - **Stated limit, `UNREPRODUCED`:** the single-call `ConfirmEnrolment` reads the enrolment and then calls the store's `Confirm`, which conditions on neither the generation nor the device proof. A device proof landing between that read and that write, or not yet visible to a store whose reads lag its writes, is not seen. The single-call confirm is reachable only through a consumer's own out-of-band route, which an enrolment-only session cannot reach past the gate (decision 3), and the store's `Confirm` contract is kept unchanged so stores built against it keep their semantics. Closing it would be a condition on `Confirm` itself, left to a change of its own; godoc states the limit.

- **Exactly one enroller: the MFA method.** The method given to `EnableMFA` must implement `Enroller`. The requirement policy and the verify endpoint each wire one method, so an enroller that is not that method could not complete step 4 and would leave the user in the state. Begin therefore names no enroller.
- **TOTP implements the port.** `multi-factor-auth`'s single-call confirm remains for consumers enrolling out of band.
- **Store delta.** The enrolment record gains the generation, a device-proven time, the sealed emailed code, its expiry and its attempt count. Three conditional writes are added, each decided by the write, not by a preceding read. They live on a separate port beside `EnrolmentStore`, not on it, so a store written against today's port, a consumer's or the durable ones, keeps compiling and keeps serving out-of-band enrolment. `EnableMFAEnrolment` fails at construction when the MFA method's store does not implement the port:
  - device proof: records the time step, the device-proven time and the sealed code only where the generation matches, the enrolment is pending and not yet proven, and the step is later than the recorded one;
  - completion: marks the enrolment confirmed only where the generation matches, the device is proven and the enrolment is not yet confirmed.
  - charging an emailed-code attempt: increments the attempt count only where the generation matches, the device is proven, the code is outstanding and unexpired, and fewer than five attempts have been charged.

  `PutPending` starts a new generation and clears the device proof and the code. The existing `Confirm` and `AcceptStep` keep their contracts. The durable side lands in this change after `durable-persistence` is archived: the columns are squashed into its initial security-state migration (free before a tag), the `database/sql`, `pgx` and `gorm` enrolment stores implement the port, the emailed code is sealed with its own binding so it cannot be moved into the secret column or another user's row, and `security-state-stores` and `secrets-at-rest` deltas are added to this change once those capabilities are promoted.
- **Construction error:** the path is enabled and the MFA method's store does not implement the device-proof port.
- **Default:** the TOTP method.
- **Override:** a consumer `Enroller` as the MFA method.
- **Construction error:** `EnableMFAEnrolment` is used when the MFA method is not an `Enroller`, or when no MFA method is enabled.

### 11. Operator reset

```go
func ResetEnrolment(ctx context.Context, user identity.UserID, deps ResetDeps, opts ...ResetOption) error // mfa
```

- **What it does:**
  1. removes the user's enrolment;
  2. deletes every session of the user (`sessions`), so a session that satisfied MFA with the lost authenticator ends;
  3. sends the notification.
- **Order and failure:** every dependency is checked before anything is written. Removal comes first. Any later failure (deleting sessions, loading the user, resolving the address, sending) is returned after the removal, never swallowed; the operator retries what failed.
- **Delivery:** through the sender as given, with no non-blocking requirement. The magic-link rule exists because response time would reveal which addresses have accounts; an operator-named reset reveals nothing of the kind.
- **Message:** by default a fixed subject and a body naming the reset time, with no code, secret or identifier. `WithResetMessage` replaces the subject and body; the library still sets the recipient from the contact resolver.
- **Result:** the requirement is untouched. With the path on, the user's next login enters the enrolment-only state. With it off, they are refused until enrolled out of band.
- **Default:** notify and delete sessions.
- **Override:** `WithoutSessionRevocation()` for a consumer who revokes elsewhere, and `WithoutResetNotification()`.
- **Construction error:** notification is on but no sender is supplied. This is the same pattern as decision 5: an explicit opt-out, never a nil dependency read as one.
- **Not HTTP:** the consumer puts it behind their own authorised administrative route.

### 12. Every declared challenge kind needs an enforcer

- **Rule:** chain assembly fails when a registered policy declares, through `policy.Challenger`, a challenge kind that nothing registered enforces. It replaces today's `ChallengeMFA`-only check.
- **Built-in kinds and their enforcers.** A built-in kind counts as enforced only when its own built-in interceptor is registered, not when any interceptor occupies its slot: a consumer interceptor placed with `Before(OrderMFAChallenge)` lands on `OrderMFAEnrolment` and would otherwise pass for the enrolment gate while confining nothing (reproduced in review). The same rule holds at assembly and at runtime:
  - `ChallengeMFA`: the MFA interceptor;
  - `ChallengePasswordChange`: the password-change gate;
  - `ChallengeMFAEnrolment`: the enrolment interceptor.
- **Consumer kinds:** a consumer that registers its own challenging policy and its own gate declares the pairing with `WithChallengeEnforcer(kind)`. When the bearer's per-request phase raises such a kind, the library cannot mark it (the session has no field for a kind it does not know), so it records the raised kind on the exchange and continues; the consumer's declared gate reads it there and refuses or resolves. The declaration is the consumer's statement that such a gate exists and reads it; godoc says so. The option refuses `ChallengeNone` and the built-in kinds at construction: accepting a built-in kind could only switch the check off for it.
- **Consequence, intended:** a chain that registers the password-age policy without the password-change gate now fails to assemble. Today the session is marked pending and the caller proceeds with the challenge unsatisfied, and nothing reports it.
- **Default:** the check runs. A policy that does not implement `Challenger` is still read as raising nothing, as `auth-methods` recorded, so working deployments are not refused on a guess.
- **At runtime too.** The assembly check reads the policies registered when the chain is built. A policy added to the engine afterwards, which `Engine.Add` permits during wiring, would escape it (reproduced in review). So a challenge actually raised at runtime whose kind has no enforcer in the chain refuses the request with a configuration error (500), never marks the session and lets it through. At login it refuses before the session is created, so no orphan session or token is left behind. The redemption flows (magic link, OIDC handoff) refuse in their own policy check, before the one-time credential is spent. A challenge raised in the pre-authentication phase (form login, basic) whose kind is unenforced is refused the same way; what pre-authentication does with an enforced challenge is unchanged by this change. A stateless request that raises a challenge after its credential is checked is still refused with that challenge whatever the kind, since it marks nothing and lets nothing through. The godoc of `WithPolicyEngine` and `Engine.Add` says to register every policy before the chain is built, so the assembly check reports the mistake before traffic.
- **Override:** `WithChallengeEnforcer` for a kind the library does not know. There is no option to switch the check off, because what it prevents is a silent bypass.

### 13. The password-change gate lets logout through

- **Rule:** a session with a password change pending may reach the logout path wherever the consumer places it. Chain assembly hands the gate the configured logout path, as it does for the MFA gate. Every other request is refused as today.
- **Why:** a caller stranded mid-challenge must be able to end their session; on a device that is not theirs, that is the one thing they most need to do. `auth-methods` settled this for the MFA gate, and the enrolment gate (decision 3) follows the same pattern. After this change, all three gates agree.
- **Default:** logout passes. If logout is not enabled, nothing extra passes.
- **Override:** none. Refusing logout to a pending session protects nothing.
- **Status:** reproduced by `TestPasswordChangeGateLogout`, which failed with a password-change challenge at the logout path before the exemption.

### 14. Recovery codes

Out of scope. A lost authenticator is recovered through the operator reset (decision 11), then the path. Recovery codes are a method kind of their own, with their own storage and single-use rules. The enroller port admits them later.

### 15. Naming

New symbols use "Enrolment", matching the `mfa` package and this change's name. The existing `ErrMFAEnrollmentRequired` keeps its spelling here. Renaming it is free before a tag, and is left to a change of its own, so this one does not rename an established error in passing.

### 16. Departures

Everything else here is new behaviour, with no established behaviour to depart from: there was no enrolment surface, no enrolment limits, no notification and no reset helper. Three rows change established behaviour:

| # | scrty does | Instead of | Justification |
|---|---|---|---|
| E1 | With the path explicitly on, challenges a required, unenrolled user whose first factor is on the allowlist for enrolment, and confines the session | Refusing at login and on every request | Closes a stated limit: `multi-factor-auth` records that require-for-all locks out unenrolled users. With the path off, the established refusal is kept exactly. |
| E2 | The password-change gate lets the logout path through | Refusing every request but its own resolve endpoint | Settled scrty decision: `auth-methods` D15 established the rule for the MFA gate. Reproduced by `TestPasswordChangeGateLogout` (decision 13). |
| E3 | Refuses, at assembly and at runtime, any declared or raised challenge kind whose built-in gate is not enabled and that no consumer declared | Checking `ChallengeMFA` alone, at assembly, and accepting any interceptor at its slot | Extends `auth-methods`' `ChallengeMFA` refusal to every kind, for the same reason: an unenforced challenge is otherwise a silent bypass. |

### 17. Test-first throughout

- **`policy`:** tables for the requirement policy with the path on and off:
  - every existing outcome unchanged;
  - lookup failure still denies;
  - a same-channel method denies;
  - a first factor off the allowlist denies; a consumer list admits `oidc`;
  - the rollout deadline passed;
  - a mid-session challenge.
- **`httpsec`:**
  - the gate refuses a table of routes, each seen to fail by removing the gate: verify, password-change resolve, a consumer interceptor, the authorizer, GET on the enrolment paths;
  - logout passes the enrolment gate and the password-change gate;
  - end-to-end begin → confirm → emailed code → verify → rotated full session with the restored deadline;
  - verify before confirmation is refused;
  - a code from an earlier generation is refused and does not complete;
  - the fifth wrong code voids the emailed code;
  - a sender that refuses to queue fails the confirm;
  - limiter tables, including limiter errors and a cancelled request context;
  - status mapping for the enrolment challenge and the endpoints' refusals;
  - construction errors: one-sided wiring, an unenforced declared kind, a consumer kind declared with `WithChallengeEnforcer`, a method that is not an `Enroller`, an ineligible kind on the allowlist.
- **`session`:** state round trip, the lowered deadline, the restore on upgrade and its cap at creation plus the absolute timeout, all under an injected clock.
- **`mfa`:** device proof and completion against the store conformance suite, including the two-session race on generations; reset ordering with a failing session store.

Each group ends with a `/simplify` pass and a re-run.

## Risks / Trade-offs

- [With email confirmation turned off, a password alone binds a second factor] → Off only by an explicit option whose godoc says so. Notification stays on unless also turned off.
- [An attacker who controls the mailbox as well as the password can bind an authenticator] → Such an attacker already has a full account takeover path through password reset. The limit is documented, and require-for-all deployments that care enrol out of band.
- [After a magic-link login, or a federated login admitted by the allowlist, the emailed code adds nothing] → Documented on the option and the allowlist. `oidc` is off the list by default, and a consumer can take magic link off too.
- [A password holder can exhaust a user's begin budget for an hour] → Documented. The limiter is replaceable, and an operator reset does not consume it.
- [Enrolment-only sessions occupy concurrent-session cap slots] → Each lasts at most the enrolment TTL. Documented.
- [Three steps plus a wait of up to one time step make first login slower] → Each step is independently justified (decisions 4 and 5). The upgrade guarantee is not configurable.
- [A notification that cannot be queued after completion is lost] → Logged as a sampled refusal with a reporter. With email confirmation on, the mailbox owner has already taken part.
- [A consumer interceptor at `OrderMFAChallenge` no longer stands in for `EnableMFA`, and `WithChallengeEnforcer` refuses built-in kinds] → Intended: an interceptor at the slot is not known to enforce anything, and it let an unrelated interceptor (at `Before(OrderMFAChallenge)`) pass for the enrolment gate. A consumer with their own second-factor gate keeps the MFA policies off the engine, or enables the built-in gate. The construction error names the option.
- [Generalising the enforcer check refuses chains that register the password-age policy without its gate] → Intended; such a chain lets a pending password change through silently today. The construction error names the kind and the missing enforcer.
- [In-memory limiters multiply by replica count] → A documented limit of `rate-limiting`, closed by `shared-rate-limiting`.
- [`request-input-and-log-flush` also modifies the verify-endpoint requirement of `multi-factor-auth` (the code is read from a URL-encoded body only)] → Whichever archives second carries the other's text in its MODIFIED requirement; that change is expected to archive first, so this delta must add its body-only sentence before archive.
- [Several active changes touch the same artifacts] → `durable-persistence` lands first unchanged, and this change adds the enrolment and session columns to its initial migration afterwards; `oidc-mfa-assurance` takes decision 9's table; `shared-rate-limiting` and `operations` add the enrolment limiters and wiring, whichever lands after this change.

## Migration Plan

Not applicable: a new library with no consumers and no tags. The path is off by default, so deployments that do not enable it see no change.

## Open Questions

- **Per-user grace windows.** Should the requirement lookup port report when a user became required, so the path can close per user? That is an `identity-model` port change, deferred. It adds an option to the path without changing this flow.

Settled in this design, recorded here because earlier drafts asked them: the path is off by default; email confirmation is on by default; recovery codes are out of scope; the enrolment-only TTL is 15 minutes; the contact address defaults to the username; `oidc` is off the allowlist by default.
