## Why

Today, a user who is required to use MFA but has no confirmed enrolment is refused at login and on every later request. No in-library enrolment endpoint is reachable to them. This causes two problems:
- **Flagging users is a two-step job.** Operators must enrol each user out of band, or through a session from an exempt login, before they flag that user as required.
- **Require-for-all cannot be used on an existing user base.** Switching it on locks out every unenrolled, non-exempt user at once.

`auth-methods` records this as a stated limit and names this change as the fix. It should land before anyone deploys require-for-all, because the only workaround means building an enrolment flow outside the library.

## What Changes

- Add a **restricted enrolment-only session state**:
  - It is issued after a successful first factor for a user who is required to use MFA and has no usable enrolment. Today that login is refused with the enrolment-required reason.
  - It reaches only the enrolment endpoints (begin, confirm, and the out-of-band confirmation when that is on) and logout. Every other request fails closed with a challenge error of a new enrolment kind.
  - It has a short lifetime of its own.
  - It becomes a full session only after the enrolment is confirmed and a second factor is then verified in the same flow. The session handle is rotated at that point.
- Add **HTTP endpoints for beginning and confirming an enrolment**, usable only from an enrolment-only session. They cannot change a password or any account attribute. Begin attempts and failed confirmations are rate limited per user.
- Add **defences against an attacker who holds only the password**. By default:
  - the user is notified by email when an authenticator is bound;
  - an emailed one-time code must be entered before the enrolment counts.

  Each can be turned off by an explicit, documented option. An operator can also close the path at a set time.
- **The path is off by default.** With it off, behaviour is exactly as today: refused, with the enrolment-required reason.
- Add an **operator helper for resetting a user's enrolment**. It removes the enrolment, ends the user's sessions and notifies the user.
- **Generalise the unenforced-challenge refusal beyond `ChallengeMFA`.** `auth-methods` made chain assembly fail when a registered policy can raise an MFA challenge and nothing is registered to enforce it, because the chain marks the session pending either way and a caller then proceeds with the challenge unsatisfied while nothing reports it. The refusal covers that one kind. This change adds a **new** challenge kind for the enrolment-only state, so it inherits the same question immediately and cannot ship without answering it — and the same argument already holds, untouched, for `ChallengePasswordChange`, which only the opt-in password-change gate enforces. Extend the check to every challenge kind a registered policy declares, rather than adding a second special case.
- **Give the password-change gate the logout exemption the MFA gate has.** `auth-methods` established that a caller stranded mid-challenge must still be able to end their session, because on a device that is not theirs that is the one thing they most need to do; its gate exempts logout wherever the consumer puts it. The password-change gate sits outside logout's slot and has no such exemption, so the two gates disagree about the same question. This change is where the disagreement gets settled, because its own restricted state reaches "only the enrolment endpoints and logout" and must make the same call a third time.
- **Rules that carry over unchanged:**
  - enrolling a method on the first factor's channel follows the `security-policy` same-channel rule, so it can never become the second factor;
  - OIDC and API-key logins stay exempt and never enter the state;
  - stateless logins are still refused.

Not in this change: recovery codes, WebAuthn, and per-user grace windows measured from when the requirement began.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

Delta specs for these capabilities are deferred until `auth-methods` and `authn-authz-core` are archived.

- `multi-factor-auth`: the enrolment-only gate and its allowed routes; the begin and confirm endpoints with their per-user limits; the out-of-band confirmation and notification defaults; the upgrade that needs confirmation plus verification; the enrolment reset helper; and removal of the "require-for-all locks out unenrolled users" limit when the path is on.
- `security-policy`: when the path is on, the MFA requirement policy challenges a required user with no usable enrolment for enrolment, instead of denying, in the post-authentication and per-request phases. Stateless requests, lookup failures and same-channel-only enrolments are unchanged.
- `sessions`: a new library-owned second-factor state (enrolment pending) and a shorter lifetime for sessions in that state.

## Impact

- **Code in the core module:**
  - `policy`: an enrolment challenge kind, and an option on the MFA requirement policy;
  - `session`: the new state and its lifetime;
  - `mfa`: an enroller port that the TOTP method implements, plus the reset helper;
  - `httpsec`: the enrolment interceptor and gate, and a status row for the new challenge kind.
- **Other capabilities touched, flagged to their owners:**
  - `http-error-propagation` needs a status for the enrolment challenge kind (403, the same as a password-change challenge);
  - `one-time-tokens` gains a purpose for the emailed confirmation code;
  - `security-state-stores` needs the enrolment record to hold the out-of-band confirmation state.
- **Depends on:** `multi-factor-auth`, `email-notification`, `security-policy`, `sessions`, `one-time-tokens`, `rate-limiting`, `http-security-chain`, `identity-model`. Before this change's specs are written, it also needs to be read against `oidc-mfa-assurance`.
- **Dependencies:** none new.
- **Consumers:** none yet. Nothing is tagged, and the path is off by default, so enabling it is an explicit choice.
