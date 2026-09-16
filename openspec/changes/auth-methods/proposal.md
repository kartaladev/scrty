## Why

With `authn-authz-core` in place, scrty can authenticate a password, hold a session and decide on policy, but it offers no authentication method beyond the password and the bearer token. Applications need three more:
- a second factor;
- passwordless login by email;
- a credential for machines.

Each is where authentication libraries tend to fail quietly and at great cost:
- a TOTP code accepted twice, or guessed without limit;
- a lost enrolment record that silently lets a required user skip MFA;
- a magic link spent by a refused login, or replayed for free until it expires;
- a mailer that blocks forever, or whose response time tells an attacker which addresses have accounts;
- an API key stored in clear, or indistinguishable in a leaked log.

This change adds the methods with each of those failures written down as a requirement.

## What Changes

- Add **multi-factor authentication**:
  - a method port whose implementations declare the channel their codes travel over;
  - a built-in TOTP method (RFC 6238) whose issuer is required configuration, with no brand default;
  - enrolment that becomes usable only after a code is confirmed;
  - replay protection per time step;
  - failed verifications throttled per user;
  - a verify endpoint that refuses a second factor on the first factor's channel before reading the code, resolves the session's MFA challenge and rotates the session handle.

  A lost, deleted or unreadable enrolment never downgrades a user who is required to use MFA.
- Add **magic-link login**:
  - an enumeration-safe request;
  - links bound to the user reference they were minted for;
  - per-user issuance limits;
  - check-then-consume redemption, in which a refusal or lookup failure never spends the link;
  - refused redemptions of a valid link counted against the per-source rate limit by default, with an opt-out;
  - same-device binding with a constant-presence cookie;
  - POST-only consumption and an exact-match redirect allowlist.
- Add **API keys**:
  - shown once;
  - hashed at rest;
  - recognisable by a configurable prefix;
  - bound to a service principal with scopes;
  - optional expiry, revocation and rotation;
  - verification over an `Authorization` scheme, with per-source failure throttling and no session.
- Add **email notification**:
  - a sender port the consumer can replace;
  - an SMTP sender bounded by one overall deadline that includes the dial, refusing header injection and requiring STARTTLS by default;
  - a non-blocking queued sender;
  - nothing brand-specific in any default.

Not in this change:
- The path by which a user who is already required to use MFA, but has not enrolled, can enrol. This is the later `mfa-enrolment-path` change. Until then, requiring MFA for all users locks out every unenrolled user, and this is a documented limit.
- Recovery codes and WebAuthn.
- HTTP endpoints for issuing, listing or revoking API keys. These are the consumer's administrative surface.

## Capabilities

### New Capabilities

- `multi-factor-auth`: second-factor methods and their channels, TOTP codes and enrolment, verification with replay protection and throttling, the verify endpoint, and the guarantee that a lost enrolment never lets a required user through.
- `magic-link`: requesting, delivering and redeeming single-use sign-in links by email, including enumeration safety, redemption ordering, rate-limit accounting, same-device binding and redirect safety.
- `api-keys`: issuing, verifying, revoking and rotating machine credentials bound to service principals, and authenticating requests that carry them.
- `email-notification`: sending messages through a replaceable port, with a bounded, encrypted-by-default SMTP sender and a non-blocking queued sender.

### Modified Capabilities

None. No specs have been archived yet.

## Impact

- **New code in the core module:** `mfa`, `magiclink`, `apikey` and `notify` packages, plus the method interceptors in `httpsec`.
- **Dependencies:** the core module gains `github.com/pquerna/otp` for TOTP code computation. SMTP uses the standard library. Neither brings a framework, driver, scheduler or DI container, so the `module-layout` dependency guard still holds.
- **Test module:** an SMTP test-server helper for `notify`'s integration tests.
- **Depends on other changes:**
  - `identity-model`: principal, user reference, user loader, first-factor kinds and channels, MFA requirement lookup;
  - `sessions`: first factor, challenge state and handle rotation;
  - `security-policy`: the post-authentication and stateless phases, the MFA requirement and the same-channel rule;
  - `rate-limiting`: limiter port and source guard;
  - `one-time-tokens`: magic-link token issuance, checking, redemption and issuance counting;
  - `authorization`: scope requirements for service principals;
  - `http-security-chain` and `http-error-propagation`: interceptor slots, challenge errors and status mapping;
  - `security-state-stores` and `secrets-at-rest`: durable MFA enrolment and API key stores, and sealing of MFA secrets;
  - `log-sampling` and `id-generation`.
- **Consumers:** none yet. Nothing is tagged, so every default here is recorded as a decision, not a compatibility obligation.
