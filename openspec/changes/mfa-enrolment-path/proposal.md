## Why

Today, a user who is required to use MFA but has no confirmed enrolment is refused at login and on every later request. No in-library enrolment endpoint is reachable to them. This causes two problems:
- **Flagging users is a two-step job.** Operators must enrol each user out of band before they flag that user as required. The one in-library workaround, enrolling from a session opened by an exempt OIDC login, disappears under `oidc-mfa-assurance`'s default, which stops treating an OIDC login without provider assurance as exempt.
- **Require-for-all cannot be used on an existing user base.** Switching it on locks out every unenrolled, non-exempt user at once.

`auth-methods` records this as a stated limit and names this change as the fix. It should land before anyone deploys require-for-all, because the only workaround means building an enrolment flow outside the library.

## What Changes

- Add a **restricted enrolment-only session state**:
  - It is issued after a successful first factor for a user who is required to use MFA and has no usable enrolment. Today that login is refused with the enrolment-required reason.
  - It reaches only the enrolment endpoints (begin, confirm, and the out-of-band confirmation when that is on) and logout. Every other request fails closed with a challenge error of a new enrolment kind, mapped to 403.
  - It lives at most a short time: entering the state lowers the session's existing absolute deadline, so every store already enforces it.
  - It becomes a full session only after the enrolment is confirmed and a second factor is then verified in the same flow. The session handle is rotated at that point, and the normal absolute deadline is restored, never later than a normal login would have had.
- **Which first factors may enter the state is an allowlist of first-factor kinds.** By default: password, magic link and an unrecorded first factor. Federated (OIDC) logins are excluded by default, because a stolen provider account usually comes with its mailbox and the emailed confirmation then adds nothing. A consumer may add them. API-key and stateless logins never enter the state.
- Add **HTTP endpoints for beginning and confirming an enrolment**, usable only from an enrolment-only session. They cannot change a password or any account attribute. Begin attempts and failed confirmations are rate limited per user.
- Add **defences against an attacker who holds only the password**. By default:
  - the user is notified by email when an authenticator is bound;
  - an emailed one-time code must be entered before the enrolment counts. The code is kept sealed on the pending enrolment and is bound to that enrolment's generation, so it can confirm only the secret that was proven when it was sent.

  Each can be turned off by an explicit, documented option. An operator can also close the path at a set time.
- **The path is off by default.** With it off, behaviour is exactly as today: refused, with the enrolment-required reason.
- Add an **operator helper for resetting a user's enrolment**. It removes the enrolment, ends the user's sessions and notifies the user.
- **Generalise the unenforced-challenge refusal beyond `ChallengeMFA`.** `auth-methods` made chain assembly fail when a registered policy can raise an MFA challenge and nothing is registered to enforce it, because the chain marks the session pending either way and a caller then proceeds with the challenge unsatisfied while nothing reports it. The refusal covers that one kind. This change adds a **new** challenge kind, so it inherits the same question immediately, and the same argument already holds for `ChallengePasswordChange`, which only the opt-in password-change gate enforces. Extend the check to every challenge kind a registered policy declares, with a way for a consumer to declare the enforcer of a kind of its own.
- **Give the password-change gate the logout exemption the MFA gate has.** `auth-methods` established that a caller stranded mid-challenge must still be able to end their session; its MFA gate exempts logout wherever the consumer puts it. The password-change gate has no such exemption, so the two gates disagree. This change settles it, because its own restricted state must make the same call a third time.
- **Rules that carry over unchanged:**
  - enrolling a method on the first factor's channel follows the `security-policy` same-channel rule, so it can never become the second factor;
  - the MFA exemption classification is untouched; the allowlist above governs only entry to the enrolment path;
  - stateless logins are still refused.

Not in this change: recovery codes, WebAuthn, and per-user grace windows measured from when the requirement began.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `multi-factor-auth`: the enrolment-only gate and its allowed routes; the begin and confirm endpoints with their per-user limits; device proof and completion as separate conditional writes on the enrolment; the out-of-band code, sealed on the enrolment and bound to its generation; the notification default; the upgrade that needs confirmation plus verification, and the deadline it restores; the enrolment reset helper; removal of the "require-for-all locks out unenrolled users" limit, and of "the next login is refused" after a lost enrolment, when the path is on.
- `security-policy`: when the path is on and the first factor's kind is on the path's allowlist, the MFA requirement policy challenges a required user with no usable enrolment for enrolment, instead of denying, in the post-authentication and per-request phases. Stateless requests, lookup failures, same-channel-only methods and kinds off the allowlist are unchanged.
- `sessions`: a new library-owned second-factor state (enrolment pending) and an enrolment-origin marker; entering the state lowers the absolute deadline; the upgrade restores the normal absolute deadline measured from creation.
- `http-security-chain`: the unenforced-challenge refusal covers every declared challenge kind, with a consumer declaration for kinds of its own; the password-change gate lets the logout path through.
- `http-error-propagation`: a challenge of the enrolment kind maps to 403; the enrolment endpoints' refusals get their rows.
- `oidc-login`: a scenario for a consumer who removes the OIDC exemption and adds `oidc` to the path's allowlist.

## Impact

- **Code in the core module:**
  - `policy`: an enrolment challenge kind, and the path option with its allowlist on the MFA requirement policy;
  - `session`: the new state, the enrolment-origin marker and the deadline rules;
  - `mfa`: an enroller port that the TOTP method implements, the enrolment store's new conditional writes, and the reset helper;
  - `httpsec`: the enrolment interceptor and gate, the status rows, the generalised unenforced-challenge check, and the password-change gate's logout exemption.
- **Durable stores, after `durable-persistence` lands:** this change carries the durable side itself. It adds the enrolment record's generation, device-proven time, sealed emailed code, expiry and failure count, and the session's enrolment-origin marker and generation, to the initial security-state migration (squashing is free before a tag); implements the device-proof port on the `database/sql`, `pgx` and `gorm` enrolment stores; extends the conformance suites; and adds `security-state-stores` and `secrets-at-rest` deltas once those capabilities are promoted. Until then the device-proof writes are a separate port, so the stores `durable-persistence` builds against today's `EnrolmentStore` keep compiling.
- **Follow-ups on other changes, each a revision of its own:**
  - `oidc-mfa-assurance`: its "no usable enrolment" outcome in Challenge mode follows this change's allowlist instead of always denying;
  - `shared-rate-limiting` and `operations`: whichever lands after this change adds the two enrolment limiters' namespaces, their prune tasks, and the path to the optional DI wiring.
- **Depends on:** `multi-factor-auth`, `email-notification`, `security-policy`, `sessions`, `rate-limiting`, `http-security-chain`, `http-error-propagation`, `identity-model`, `secrets-at-rest`.
- **Dependencies:** none new.
- **Consumers:** none yet. Nothing is tagged, and the path is off by default, so enabling it is an explicit choice.
