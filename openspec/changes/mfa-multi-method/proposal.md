## Why

scrty's second-factor slot takes exactly one MFA method for the whole chain, and verifies it in one step: a `code` read from a URL-encoded form. So a deployment cannot offer a user more than one second factor, for example TOTP and an emailed code, and a method that must issue a challenge before it can verify cannot plug in at all. WebAuthn works that way, and the planned `passkey-authentication` change needs it to be a second factor. Fixing the slot first, as its own change, keeps one place deciding that a second factor is satisfied, and serves consumers who never use passkeys.

## What Changes

- **The MFA slot takes several methods.** The chain is given a set of MFA methods, not one. Each keeps its own name and channel, and the construction rule on an empty channel applies to each.
- **Per-user method selection, by path.** A user may be enrolled on any subset of the configured methods. Each method answers at its own path under one prefix, `/mfa/verify/{method}` by default, so every verify request names its method, and the method choice is never read from a header, the query or the body. The slot verifies against that method only. It refuses a method the user is not enrolled on, or one whose channel equals the session's first factor.
- **Challenge-capable methods.** A method can declare a begin step that issues method-specific challenge data for the session's user before verification, such as a WebAuthn challenge. The slot gains a begin endpoint for such methods, one per method at `/mfa/begin/{method}` by default, replaceable like the verify prefix. A method with no begin step, such as TOTP, verifies in one step as today.
- **Each method declares its response format.** This is the user's decision, and it replaces the rule that the verify endpoint reads only a URL-encoded `code` field.
  - **Declaration:** a method declares whether its response is a URL-encoded form field or a JSON body, and the largest body it accepts. TOTP keeps the form field and 4 KiB, so a plain HTML form with no JavaScript still verifies a code. A WebAuthn assertion is JSON, and a legal one can exceed 4 KiB.
  - **Library-owned readers only:** the body is read by one of two readers the library owns, never by the method. The form reader is today's. The new JSON reader keeps the same rules:
    - it never reads the URL query;
    - it requires the declared content type;
    - it bounds the body;
    - a body over the limit is refused as too large, and one that does not parse is refused as missing credentials, and neither is counted against the verification throttle.
  - **Nothing after parsing forks:** the method receives only the response bytes. The same-channel check, the throttle, refusal logging, challenge resolution and session rotation run once, after parsing, the same for every method.
- **A pending challenge is a one-time token.** This is the user's decision. A challenge method's begin step issues its challenge through a one-time token manager of its own purpose, and the token string is the challenge.
  - **Binding and lifetime:** the token is bound to the session that asked for it, and expires after a short lifetime.
  - **Rebuilt, not stored:** everything else the method needs at verify is rebuilt from configuration and the method's own store, never kept with the challenge.
  - **Industry pattern, existing machinery:** this is the pattern common WebAuthn libraries use, a challenge kept server-side in a store keyed by something the browser presents, short-lived and used once. It is built on the library's one-time store, so single use is decided by the store's conditional write, only hashes are stored, and the durable adapters and conformance cases already exist.
  - **Spent on every attempt:** a challenge is spent by any verify attempt that presents it, whether the answer is accepted or refused, so one challenge allows one try. This departs from the library's check-then-consume rule, under which a refusal spends nothing. That rule protects credentials the user holds, such as a magic link. A challenge is not one: reissuing it costs a begin request, and one try per challenge is the simpler guarantee.
  - **Never from the client:** a challenge is only ever compared with one the server issued, never taken from the request.
- **The MFA challenge tells the client which methods it can use.** This is the user's decision.
  - **What it carries:** when a request is refused with the MFA challenge, the challenge error carries the session user's usable methods, each with its name (also its path segment), its channel and whether it has a begin step.
  - **Rendering stays the consumer's:** the list is data on the typed error, rendered by the consumer's error handling like the rest of the challenge. With nothing wired, the response is still a bare status code. No listing endpoint and no new default response body is added.
  - **Scoped by construction:** only a request that owes the MFA challenge ever carries the list, and it names methods only, never a credential or enrolment detail.
  - **One definition of usable:** the list comes from the same function the MFA policies use to decide usability (enrolled, readable, and on a channel that differs from the first factor's), so a client is never offered a method the slot then refuses. A failed lookup refuses as today, and never yields an empty list. The function is exported, so a consumer can build their own listing route.
  - **A single entry:** a client offered one method goes straight to it, so the library names no default method.
  - **An opt-in listing endpoint.** A consumer can also enable an endpoint that lists the same usable methods. It builds on the same function, so it can never disagree with the challenge or the policies.
    - **Off by default:** no endpoint exists unless enabled.
    - **Requests:** it answers GET requests on its own path, `/mfa/methods` by default and replaceable, and never reads the URL query.
    - **Who it answers:** only a session whose MFA challenge is pending. Every other caller is refused, including an unauthenticated caller and a fully authenticated session, so the endpoint never reveals a user's authenticators to anyone else.
    - **Failures:** a failed lookup is a refusal, never an empty list.
    - **Response:** a documented JSON body by default, replaceable through a responder, as the verify endpoint's response is.
    - **Wiring:** one option on `EnableMFA`, `WithMFAMethodListing(settings ...)`. Given alone it enables the endpoint with every default. Its own settings, a path and a responder, can be written only inside it, so a setting can never be given for an endpoint that is off. This is a design decision, and the first option in `httpsec` to take settings of its own:

      ```go
      httpsec.EnableMFA(methods, httpsec.WithMFAMethodListing()) // all defaults

      httpsec.EnableMFA(methods, httpsec.WithMFAMethodListing(
          httpsec.ListingPath("/account/mfa/methods"),
          httpsec.ListingResponder(myResponder),
      ))
      ```

      An explicitly passed empty path or nil responder is refused, never read as "use the default", as with every other option. A struct or positional form was rejected, because it would read an empty value as the default.
    - **Wiring mistakes** fail at construction, for example an empty path, a nil responder, or enabling the endpoint with no MFA method configured.
  - **Out of scope:** a settings page's "which second factors do I have" is enrolment management. It needs a full session and includes methods on the first factor's channel. It is left to a later change, and the listing endpoint does not serve it.
- **One place clears the MFA challenge.** However many methods exist, only the slot's verify step resolves a session's MFA challenge. A login whose second factor the library itself recorded at the first factor, such as a user-verified passkey login under `passkey-authentication`, never has the challenge raised, so it does not create a second place that resolves one. The same-channel refusal, the per-user verification throttle, refusal logging and session rotation stay in that one place and apply to every method.
- **The policies read "any usable method".** The second-factor challenge policy and the MFA requirement policy decide from the user's enrolments across all configured methods. "Usable" means enrolled, readable, and on a channel that differs from the first factor's. A lookup failure on any method still refuses, and never downgrades a user.
- **The enrolment path names its method.** With several enrollable methods, the path enrols the one the caller names, from the configured methods that can enrol. Which methods may be enrolled through the path is consumer configuration.
- **BREAKING (pre-tag):**
  - `EnableMFA`'s single-method signature changes.
  - The verify endpoint moves from `/mfa/totp` to a path per method under `/mfa/verify/`, and TOTP's field is read under the new response contract.
  - The rule that the endpoint reads only a URL-encoded `code` becomes a response format each method declares.
  - The enrolment and challenge policies' "the configured method" wording becomes "the configured methods".

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `multi-factor-auth`: several methods per chain, per-user selection by path, the optional begin step, the response format each method declares and the two library-owned readers, the enrolment path choosing among enrollable methods, and one place resolving the challenge.
- `http-error-propagation`: the challenge error carries the usable methods when it is the MFA challenge, and a request naming a method that is not configured, or that the user may not use, maps to a status row.
- `http-security-chain`: the opt-in MFA method-listing endpoint, and the per-method verify and begin paths the chain registers.
- `one-time-tokens`: no requirement changes. Pending challenges use one-time token managers under their own purposes, as the settled capability already allows.
- `magic-link` and `oidc-login`: a one-time-credential login reuses the post-authentication decision its pre-consume check made, so a policy lookup failure never spends the credential, and a replaced redeemer that returns a different user than it checked is refused (found while fixing the method lookup's placement).
- `security-policy`: the enrolment lookup, the second-factor challenge policy and the MFA requirement policy work over a set of methods and each user's usable enrolments.

## Impact

- **Code:** `mfa` gains the optional challenge step on its method port. `httpsec`'s MFA verify and enrolment endpoints and their options take a method set. `policy`'s MFA policies and method lookup take a set.
- **APIs:** breaking changes to `EnableMFA`, `EnableMFAEnrolment` and the MFA policy constructors, allowed before the first tag and recorded in the design.
- **Stores:** no store contract or schema change. Enrolment storage is one per user in TOTP's own store (`mfa_enrolments`), so each method type owns its enrolment storage (design D1, the user's decision); pending challenges use the existing one-time token store under per-method purposes.
- **Dependencies:** none.
- **Ordering:** the queue is `default-identity-store`, then this change, then `recovery-codes`, then `passkey-authentication`, by the user's decision. This change does not depend on `default-identity-store`. `recovery-codes` builds on the multi-method slot, and `passkey-authentication` depends on both.

## Open Questions

None open. The questions raised during exploration were decided by the user:
- the response format each method declares, with library-owned readers only;
- method selection by path;
- pending challenges as one-time tokens, spent on every attempt;
- the usable methods carried on the MFA challenge, with an opt-in listing endpoint.

## References

All sources below are **Researched**: they were consulted while exploring this change, on 2026-09-28, and are grouped by the decision they informed.

### Response format: each method declares its own
- [Web Authentication, Level 3 (W3C)](https://www.w3.org/TR/webauthn-3/): a WebAuthn response is structured data, and credential IDs of up to 1023 bytes make a legal assertion exceed 4 KiB when form-encoded
- [protocol package of go-webauthn (pkg.go.dev)](https://pkg.go.dev/github.com/go-webauthn/webauthn/protocol): assertions parse from bytes (`ParseCredentialRequestResponseBytes`), so the library's own readers can hand a method its response without an `*http.Request`

### Pending challenges are one-time tokens, spent on every attempt
- [HttpSessionPublicKeyCredentialRequestOptionsRepository (Spring Security API)](https://docs.spring.io/spring-security/reference/api/java/org/springframework/security/web/webauthn/authentication/package-summary.html): server-side challenge state, in the session by default
- [Yubico java-webauthn-server](https://github.com/Yubico/java-webauthn-server) and [AssertionRequest API](https://developers.yubico.com/java-webauthn-server/JavaDoc/webauthn-server-core/2.8.2/com/yubico/webauthn/AssertionRequest.html)
- [Passkeys (SimpleWebAuthn)](https://simplewebauthn.dev/docs/advanced/passkeys) and [Usernameless flow: storing the challenge (discussion #321)](https://github.com/MasterKale/SimpleWebAuthn/discussions/321): a challenge deleted after any attempt, "even if verification fails"
- [GHSA-gjjc-pcwp-c74m (OneUptime advisory)](https://github.com/OneUptime/oneuptime/security/advisories/GHSA-gjjc-pcwp-c74m): why a challenge is never taken from the client
- [Server-side passkey authentication (Google for Developers)](https://developers.google.com/identity/passkeys/developer-guides/server-authentication?authuser=9)
- [Clarity on challenge length, w3c/webauthn issue #1803](https://github.com/w3c/webauthn/issues/1803): challenges of at least 16 random bytes
- [Server Requirements, WebAuthn Level 3 and CTAP 2.3 (FIDO Alliance)](https://fidoalliance.org/specs/fidoserver/fido-server-v2.3-rd-20260226.html)

### The same-channel rule and a passkey as a second factor
- [About passkeys (GitHub Docs)](https://docs.github.com/en/authentication/authenticating-with-a-passkey/about-passkeys) and [Sign in with a passkey (Google Account Help)](https://support.google.com/accounts/answer/13548313?hl=en): services accept a passkey both as a sign-in and as the second step after a password, which is why the slot must hold several methods per user
