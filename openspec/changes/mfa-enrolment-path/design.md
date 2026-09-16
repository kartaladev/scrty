## Context

See proposal.md for why this change exists. The constraints that shape the approach:

- **Current behaviour this change modifies:**
  - **The MFA requirement policy** (`security-policy`) denies a required user with no usable enrolment in the post-authentication and per-request phases, with the enrolment-required reason. "No usable enrolment" means one of:
    - the user is not enrolled;
    - the user is enrolled only on the first factor's channel.

    A lookup error also denies. Stateless requests are denied as MFA-required.
  - **The second-factor challenge interceptor** (`multi-factor-auth`) serves the verify endpoint. At `OrderMFAChallenge` (600) it blocks every other request whose session has the MFA challenge pending. Logout sits at `OrderLogout` (700), after that gate.
  - **Enrolment is begin, then confirm** (`multi-factor-auth`). A pending enrolment does not count as enrolled. A confirmed one cannot be replaced silently. Confirmation records the code's time step, so the same code cannot be used again.
  - **A lost enrolment never downgrades a required user.** The requirement lives with the user (`identity-model`).
  - **Enrolment has no HTTP endpoint.** Begin and confirm are Go APIs the consumer puts behind their own routes, which a required, unenrolled user can never reach.
- **Behaviour owned elsewhere and used here, not restated:**
  - the same-channel rule and the first-factor exemption classification (`security-policy`);
  - handle rotation and library-owned challenge fields (`sessions`);
  - check-then-consume redemption and issuance counting (`one-time-tokens`);
  - the limiter port (`rate-limiting`);
  - the sender port and queued sender (`email-notification`);
  - the login completion step, slots and challenge error (`http-security-chain`).
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
- Letting an exempt login (OIDC, API key) or a stateless request enter the state.

## Decisions

### 1. The path is off by default

```go
func WithMFAEnrolmentPath(opts ...EnrolmentPathOption) MFARequirementOption // policy
func EnableMFAEnrolment(d EnrolmentDeps, opts ...EnrolmentOption) Option     // httpsec
```

- **Default:** off. A required user with no usable enrolment is refused with the enrolment-required reason, as today.
- **Override:** the consumer turns the path on explicitly, on both the policy and the chain.
- **Construction errors:**
  - the policy option is set but the chain has no enrolment interceptor;
  - the interceptor is enabled but the policy option is not set.

  With only one side configured, the policy would challenge a session that no gate can resolve, or the endpoints would never be reached.
- **Why off:** the settled rule is that the safe choice is the default. The path gives a password alone the power to establish a second factor. That is a real change in threat model, so an operator must opt into it.
- **Alternative rejected:** on by default whenever require-for-all is set. It is convenient, but it would silently change what require-for-all guarantees.

### 2. How the state is issued

The MFA requirement policy returns `Challenge(ChallengeMFAEnrolment)` in place of `Deny(ErrMFAEnrollmentRequired)` when all of the following hold:
- the path is on;
- the phase is post-authentication or per-request;
- the user is required;
- the enrolment lookup succeeded and reported no usable enrolment;
- at least one configured enroller has a channel that differs from the first factor's (decision 8).

Every other outcome of that policy is unchanged:
- exempt first factors are allowed;
- a lookup failure denies;
- a stateless request, or a deployment with no method, is denied as MFA-required;
- a satisfied session is allowed;
- a usable enrolment is challenged for MFA.

**At login**, the login completion step already marks a challenge pending and saves the session before issuing the token. The session is created with second-factor state `enrolment-pending`. The request is refused with `*ChallengeError{Kind: ChallengeMFAEnrolment, Session, Token}`, so the client holds a token for a session that can reach only the enrolment routes. Form login and magic-link redemption both use this step, so both behave the same way.

**Mid-session**, when a user becomes required while holding a full session with no usable enrolment, the per-request phase challenges for enrolment. The bearer interceptor marks the session `enrolment-pending` and continues, and the gate then confines it. This replaces a refusal on every request, and matches how a mid-session MFA challenge already works.

**Status:** a challenge of kind MFA enrolment maps to 403, the same as a password-change challenge. The caller is authenticated and must act; retrying credentials will not help. This is a row in `http-error-propagation`, flagged to its owner.

- **Default and override:** no separate override. The state exists only when decision 1's opt-in is set.
- **Alternative rejected:** issuing no session and returning a one-time enrolment ticket instead. That duplicates session expiry, logout and rotation, which `sessions` already owns.

### 3. Routes an enrolment-only session may reach

The enrolment interceptor registers at `Before(OrderMFAChallenge)`. For a session in `enrolment-pending` it lets through exactly:

| Route | Default path | Purpose |
|---|---|---|
| `POST` begin | `/mfa/enrol/begin` | start or restart a pending enrolment on a named enroller |
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

**Logout.** Logout sits after the gate, so the gate lets the logout path through by reading it from the chain's logout configuration. If logout is not enabled, nothing extra passes.

**No principal for handlers.** The exchange carries the session so the enrolment endpoints can use it. No handler runs for this session, so no consumer code sees it as authenticated.

- **Default:** the paths above.
- **Override:** each path. There is no option to allow further routes, because an allowlist would reopen the account-attribute surface decision 6 closes. The limit is stated in godoc.

### 4. Upgrading to a full session

The flow, with the defaults on:
1. **Begin** returns the provisioning data (for TOTP, a secret and a URI).
2. **Confirm** with a valid code proves the device. The enrolment is not yet usable. The emailed code is sent (decision 5).
3. **Out-of-band confirm** with the emailed code marks the enrolment confirmed. The session moves from `enrolment-pending` to MFA `pending`. From here the ordinary gate and verify endpoint govern it.
4. **Verify** with a fresh code runs through the existing verify endpoint, with its per-user throttle and same-channel check. Success marks the session satisfied and rotates the handle.

- **Both conditions are required.** A session becomes full only after the enrolment is confirmed and a second factor has been verified in the same session. Confirmation alone never marks it satisfied.
- **Why a separate verify:** it keeps exactly one place that resolves an MFA challenge. Throttling, same-channel refusal and handle rotation live there. A second resolver would have to repeat each of them and could drift.
  - A fresh code is needed because confirmation recorded its time step and replays are refused. The user may wait up to one step (30 s by default).
  - Against the password-holding attacker, verify adds no assurance of its own; decision 5 is what defends there. This design does not claim otherwise.
- **Same flow.** Every step in the flow is tied to the session in which the enrolment began:
  - confirm and out-of-band confirm act only on the pending enrolment of that session's user;
  - the emailed code's one-time token is bound to that session's identifier;
  - logging out, or the session expiring, abandons the flow;
  - the pending enrolment stays pending and is replaced by the next begin.
- **Upgraded lifetime.** At rotation the session gets the manager's normal idle and absolute deadlines, counted from the rotation time (decision 7).
- **Override:** none for the ordering. It is the guarantee.
- **Alternative rejected:** treating a successful confirmation as the second factor. It saves one step, but the confirmation path would need its own throttle, rotation and same-channel check.

### 5. Silent binding by a password holder

**The threat.** An attacker who has only the password logs in. They receive an enrolment-only session and bind their own authenticator. They now pass MFA as the user, and the real user is refused, because the account already has a confirmed enrolment.

The mitigations below are layered.

**Notification (default on).**
- When an enrolment becomes confirmed, the user is sent a plain-text message through the `email-notification` sender port. The message names the method and the time. It contains no code, secret or provisioning URI.
- The address comes from a consumer-supplied `ContactResolver` (user reference → address). The library does not interpret the user's details.
- Delivery follows the same non-blocking sender rule as magic links. A synchronous sender is refused at construction unless explicitly accepted.
- **Override:** `WithoutEnrolmentNotification()`, whose godoc states what it gives up.
- **Construction error:** the notification is on but no sender or resolver is supplied.

**Out-of-band confirmation (default on).**
- After the device code is confirmed, a 6-digit code is issued as a one-time token:
  - purpose `mfa-enrolment-confirm`;
  - subject: the user reference;
  - bound to the session identifier;
  - TTL 10 minutes.
- The code is mailed to the resolved address. The enrolment becomes confirmed only when that code is entered in the same session.
- Redemption is check-then-consume. The token, the session binding and the pending enrolment are checked, then the token is consumed, then the enrolment is confirmed. A refusal never spends the code.
- Wrong codes count against the per-user confirmation limiter (decision 6).
- A code rather than a link keeps the proof inside the session that began the enrolment. A link opened on another device would carry no session.
- **Override:** `WithoutEmailConfirmation()`. The godoc states that without it, a password alone binds a second factor, and notification is then the only signal.
- **Stated limit:** after a magic-link login the first factor already proved control of the mailbox, so the emailed code adds no assurance there. The notification still goes. The godoc says so rather than skipping the step silently.

**Rollout window (default none).**
- `WithEnrolmentPathUntil(t time.Time)` closes the path at an instant the operator chooses. After it, the policy denies with the enrolment-required reason, as when the path is off.
- This lets an operator open the path for a require-for-all rollout and close it once the user base has enrolled.
- **Default:** none, so the path is open while it is enabled. With email confirmation on, the mailbox owner must take part in every binding. A deadline adds little where that holds, and a mandatory one would push operators into picking arbitrary dates.

**Recommended default, grounded in the safe-default rule.** Path off (decision 1). When it is enabled, both notification and email confirmation are on, and each needs an explicit opt-out.
- A deployment gets the strongest available binding without configuring anything beyond turning the path on.
- The weaker variants exist, named for what they remove.

### 6. What the state cannot do

- **No password change or account attributes.**
  - The gate refuses the password-change resolve endpoint and every consumer route (decision 3).
  - The enrolment endpoints read only an enroller name and a `code` field. They write only to the enrolment store, and to the session's second-factor state.
  - The account label for the provisioning URI comes from a consumer-supplied `LabelResolver` over the loaded user details. It is never taken from the request.
- **No removal or replacement.**
  - Begin on a user with a confirmed enrolment fails with the already-enrolled error, as `multi-factor-auth` already requires.
  - No endpoint removes an enrolment. The already-enrolled case cannot arise here anyway, since the state is issued only to users with no usable enrolment.
- **Rate limits** (options named for what they govern):

| Option | Default | Keyed by | Governs |
|---|---|---|---|
| `WithEnrolmentBeginLimiter` | in-memory, 5 per hour | user reference | begin calls, counted on every call |
| `WithEnrolmentConfirmLimiter` | in-memory, 5 failures per 15 min | user reference | failed device and emailed-code confirmations |

- **Why per user:** the attacker already holds a first factor and can rotate addresses, as with verification. Counting every begin also bounds provisioning churn and, with email confirmation, the number of emails sent.
- **A limiter error refuses.** A nil limiter is a construction error.
- **Separate from verification.** The verify endpoint's throttle is not shared. Confirmation failures lock only the enrolment path, not verification of an existing enrolment.
- **Limits, stated:** the in-memory limiters are per replica, as `rate-limiting` documents. A password holder can exhaust a user's begin budget for an hour; this is documented as a lockout-for-an-hour trade-off.
- **Logs:** no record contains a presented code, the emailed code, a secret, a provisioning URI or an address. Refusals are sampled under `WithEnrolmentLogInterval` (1 min), with a reporter.

### 7. Lifetime of an enrolment-only session

- **Default:** an absolute lifetime of 15 minutes from creation, capped by the manager's normal absolute deadline. Recording activity cannot extend past it.
  - 15 minutes leaves room to install an authenticator app and read an email.
  - It is not long enough for a stolen token to be worth much, since the state reaches nothing but enrolment.
- **Override:** `WithEnrolmentSessionTTL(d)`.
  - **Construction error:** `d` is zero or less, or longer than the session manager's absolute timeout.
- **On upgrade:** the rotated handle gets normal deadlines from the rotation time. On expiry, the user logs in again and receives a new enrolment-only session.
- **Delta for `sessions`:** a session in `enrolment-pending` carries its own absolute deadline in a library-owned field, set in the write that marks the state. For a session marked mid-session, this is the earlier of the existing absolute deadline and now plus the TTL.

### 8. The same-channel rule applies to enrolment

- **At begin.** Begin refuses an enroller whose channel equals the session's first-factor channel, with the same-channel error, before generating anything. There is no override.
  - `security-policy` already treats such an enrolment as no usable enrolment for a required user.
  - Its complete-on-first-factor mode does not apply to required users.
  - Binding it would therefore leave the user refused on their next login.
- **At issue.** The policy issues `ChallengeMFAEnrolment` only when at least one configured enroller has a channel different from the first factor's. Otherwise it denies with the enrolment-required reason, as today. A session is never confined to a path that cannot complete.
- **Example:** a deployment whose only enroller is an email one-time-code method cannot enrol magic-link users through the path. This is documented as a limit.

### 9. Which first factors can enter the state

| First factor | Behaviour | Why |
|---|---|---|
| `password` | eligible | the case this change exists for |
| `magic-link` | eligible, a first factor like any other | uses the same login completion step; the email-confirmation limit (decision 5) is documented |
| `oidc` | never; exempt, allowed before any lookup | the classification is `security-policy`'s. If `oidc-mfa-assurance`, or a consumer's exemption rule, makes some OIDC logins non-exempt, they become eligible like any other first factor. Nothing here special-cases OIDC. |
| `api-key` | never; exempt and stateless | a machine credential has no session to confine |
| `basic` | never; stateless | denied as MFA-required, unchanged |
| unrecorded or unknown | eligible when required | not exempt, per `security-policy`. No channel, so any enroller is on a different channel. |

- **Default:** as above.
- **Override:** the consumer's exemption rule in `security-policy`. This change adds no separate eligibility list, so one knob does not govern two subsystems.

### 10. Enroller port

```go
type Enroller interface {
    Method
    BeginEnrolment(ctx context.Context, user identity.UserID, accountLabel string) (Provisioning, error)
    ConfirmDevice(ctx context.Context, user identity.UserID, code string) error    // proves the code, stays pending
    CompleteEnrolment(ctx context.Context, user identity.UserID) error             // marks confirmed
}
```

- **TOTP implements the port.** With email confirmation off, the interceptor calls `ConfirmDevice` then `CompleteEnrolment` back to back. `multi-factor-auth`'s single confirm call remains, for consumers enrolling out of band.
- **Store delta:** the enrolment record gains a "device proven" time, separate from its confirmation time. This is flagged to `security-state-stores`, and squashing it into the initial migration is free before a tag.
- **Default:** the TOTP method.
- **Override:** a consumer `Enroller`.
- **Construction error:** `EnableMFAEnrolment` is given a method that is not an `Enroller`, or none at all.
- **Begin names the enroller.** It takes the enroller name. With one enroller configured, the name may be omitted.

### 11. Operator reset

```go
func ResetEnrolment(ctx context.Context, user identity.UserID, deps ResetDeps) error // mfa
```

- **What it does:**
  1. removes the user's enrolment;
  2. deletes every session of the user (`sessions`), so a session that satisfied MFA with the lost authenticator ends;
  3. sends the notification when a sender is configured.
- **Order and failure:** removal comes first. A session-deletion failure is returned after the removal, never swallowed.
- **Result:** the requirement is untouched. With the path on, the user's next login enters the enrolment-only state. With it off, they are refused until enrolled out of band.
- **Default:** notify and delete sessions.
- **Override:** `WithoutSessionRevocation()` for a consumer who revokes elsewhere, and a nil sender to skip notification, as godoc states.
- **Not HTTP:** the consumer puts it behind their own authorised administrative route.

### 12. Recovery codes

Out of scope. A lost authenticator is recovered through the operator reset (decision 11), then the path. Recovery codes are a method kind of their own, with their own storage and single-use rules. The enroller port admits them later. See Open Questions.

### 13. Departures

Everything here is new behaviour that closes a gap the established behaviour admits: a required user with no usable enrolment is refused at login and on every request, so no in-library enrolment endpoint is reachable, and require-for-all locks out every unenrolled user. One row changes existing behaviour:

| # | scrty does | Instead of | Justification |
|---|---|---|---|
| E1 | With the path explicitly on, challenges a required, unenrolled user for enrolment and confines the session | Refusing at login and on every request | Defect (admitted gap): unenrolled required users can never reach an enrolment endpoint, so require-for-all locks out every unenrolled user. With the path off, the established refusal is kept exactly. |

### 14. Test-first throughout

- **`policy`:** tables for the requirement policy with the path on and off:
  - every existing outcome unchanged;
  - lookup failure still denies;
  - same-channel-only enrollers deny;
  - the rollout deadline passed;
  - a mid-session challenge.
- **`httpsec`:**
  - the gate refuses a table of routes, each seen to fail by removing the gate: verify, password-change resolve, a consumer interceptor, the authorizer, GET on the enrolment paths;
  - logout passes;
  - end-to-end begin → confirm → emailed code → verify → rotated full session;
  - verify before confirmation is refused;
  - an emailed code from another session is refused and not consumed;
  - limiter tables, including limiter errors;
  - construction errors for one-sided wiring.
- **`session`:** state round trip, TTL cap and rotation deadlines under an injected clock.
- **`mfa`:** `ConfirmDevice` / `CompleteEnrolment` against the store conformance suite; reset ordering with a failing session store.

Each group ends with a `/simplify` pass and a re-run.

## Risks / Trade-offs

- [With email confirmation turned off, a password alone binds a second factor] → Off only by an explicit option whose godoc says so. Notification stays on unless also turned off.
- [An attacker who controls the mailbox as well as the password can bind an authenticator] → Such an attacker already has a full account takeover path through password reset. The limit is documented, and require-for-all deployments that care enrol out of band.
- [A password holder can exhaust a user's begin budget for an hour] → Documented. The limiter is replaceable, and an operator reset does not consume it.
- [Three steps plus a wait of up to one time step make first login slower] → Each step is independently justified (decisions 4 and 5). The upgrade guarantee is not configurable.
- [Today's MFA-pending gate at slot 600 also blocks logout at slot 700] → Out of scope here. The enrolment gate passes logout explicitly. Whether the MFA-pending gate should do the same is flagged to `multi-factor-auth`.
- [The emailed code adds nothing after a magic-link login] → Documented on the option. The notification still goes.
- [In-memory limiters multiply by replica count] → A documented limit of `rate-limiting`, closed by `shared-rate-limiting`.

## Migration Plan

Not applicable: a new library with no consumers and no tags. The path is off by default, so deployments that do not enable it see no change.

## Open Questions

- **Is the path off by default?** This design says off. Turning it on by default would change only the default, not the structure.
- **Is out-of-band email confirmation on by default?** This design says on, with an opt-out. If the answer is off, the option flips and nothing else moves.
- **Are recovery codes in scope?** This design says out, as a later method kind. Bringing them in would add a method and its store, not change this flow.
- **What is the enrolment-only session TTL?** This design says 15 minutes. Any value within the manager's absolute timeout fits the design.
- **Per-user grace windows.** Should the requirement lookup port report when a user became required, so the path can close per user? That is an `identity-model` port change, deferred.
