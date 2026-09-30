# Design

## Context

See proposal.md for why. The current state that shapes the approach:

- **One method, one path.**
  - `httpsec.EnableMFA(method mfa.Method, …)` holds a single method.
  - The verify interceptor matches POST on one path, `/mfa/totp` by default.
  - It reads a `code` form field through the library's form reader (4 KiB, body only).
  - It then runs, in order: the same-channel check, the per-user throttle, the method's `Verify`, challenge resolution, session rotation, and the responder.
- **The method port takes a code string.** `mfa.Method` is `Name`, `Channel`, `Enrolled`, and `Verify(ctx, user, code string)`. It has no begin step and declares no response format. `mfa.Enroller` extends it for the enrolment path, and only TOTP implements it.
- **Policies see one method.**
  - `policy.NewMFAPolicy` and `policy.NewMFARequirementPolicy` take one `policy.MFAMethodLookup` (`Enrolled`, `Channel`).
  - "Usable" is decided inline, twice: enrolled, and on a channel that differs from the first factor's.
  - `mfa.LookupFor` adapts one method.
- **Enrolment storage is one per user.**
  - `mfa.EnrolmentStore` is keyed by user alone.
  - The durable `mfa_enrolments` table has `user_id UNIQUE` and no method column.
  - This is TOTP's own store: it holds a TOTP secret and the last accepted time step.
- **The reset takes one remover.** `mfa.ResetEnrolment` removes through one remover.
- **Import direction.** `mfa` imports `policy`, so anything the policies and `httpsec` share about methods lives in `policy`, over its own lookup port.
- **Templates already in the tree.**
  - OIDC's per-provider paths: a prefix plus exactly one segment, with collision checks, and an unknown provider mapped to 404.
  - The login and magic-link JSON readers: they declare JSON through the content type and bound the body.
  - `policy.WithMFAEnrolmentPath(opts …)`: the one option that takes settings of its own.
- **The established design** had exactly one second-factor method. It had no begin step, no method list and no listing endpoint. This change goes beyond it throughout, as the proposal decides.

  Four rules carry over unchanged, and this design keeps them:
  - the same-channel refusal at verify;
  - a failed enrolment lookup is a refusal, never "not enrolled";
  - the challenge policy is only ever built alongside its gate;
  - challenge errors render nothing themselves.

## Goals / Non-Goals

**Goals:**
- Several methods behind one slot, with every refusal rule, the throttle and session rotation still in one place.
- A method that needs a server-issued challenge plugs in without the slot learning its protocol.
- "Usable method" has one definition, shared by the policies, the verify endpoint, the challenge error and the listing endpoint.
- No store contract or schema change.

**Non-Goals:**
- **Shipping a second method.** TOTP stays the only built-in method. A test double exercises the challenge path. WebAuthn arrives with `passkey-authentication`.
- **Enrolment management** ("which second factors do I have" on a settings page).
- **A method column on `mfa_enrolments`** (D1).
- **Per-method throttles** (D8).

## Decisions

### D1. Each method type owns its enrolment storage; nothing is re-keyed

`mfa.EnrolmentStore` and the `mfa_enrolments` table stay TOTP's own store, with one TOTP enrolment per user. A future method brings a store shaped for its own data: a passkey needs a credential ID, a public key and a sign count, not a TOTP secret.

- **Why:** this was the user's decision. Re-keying by (user, method) would change the store contract, a migration, three drivers and their conformance suites. No current method needs that, and the data of different method types does not share a shape.
- **Stated limit:** two TOTP-style methods cannot share one store instance. A consumer wanting two such methods gives each its own store. For the durable drivers, that means their own table. The godoc of `mfa.EnrolmentStore` states this.
- **Default:** unchanged.
- **Override:** a consumer's method brings any store it likes. The slot never reads a method's store.

### D2. The method port: a declared response format, and response bytes at verify

```go
package mfa

type Method interface {
    Name() string            // one path segment: [a-z0-9][a-z0-9-]*
    Channel() factor.Channel // constant, non-empty
    Enrolled(ctx context.Context, user identity.UserID) (bool, error)
    Response() ResponseFormat
    Verify(ctx context.Context, user identity.UserID, response []byte) error
}

// ResponseFormat is built only through FormField or JSONBody.
type ResponseFormat struct{ /* kind, field, limit */ }

func FormField(name string, limit int64) ResponseFormat // URL-encoded body, one field
func JSONBody(limit int64) ResponseFormat               // whole body, declared JSON
```

- **What the method gets.** It never sees the request. For a form-field method it receives that field's value. For a JSON method it receives the whole body. TOTP declares `FormField("code", 4<<10)`, and `TOTP.Verify` takes the code as bytes.
- **Readers.** Two readers are owned by `httpsec`:
  - the existing form reader;
  - a JSON reader built on the existing `declaresJSON` test, with the same rules: body only, the declared content type, a bounded body.

  In both, a body over the limit is `ErrRequestTooLarge`, and an unparseable or empty one is `ErrCredentialsMissing`. Neither is counted against the throttle.
- **Construction checks.** A limit of zero or less, or one above 1 MiB, is a configuration error. So is an empty form-field name, and a format that is not one of the two.
- **Default:** TOTP's format is as above. A consumer's method declares its own.
- **Override:** none on the reader side, by design. A method never reads the request, so parsing rules cannot fork per method (proposal: "nothing after parsing forks").
- **Alternatives rejected:**
  - *Hand the method the request.* Every method would re-implement body limits and query exclusion.
  - *One JSON format for all.* A plain HTML form could then not verify a TOTP code.

### D3. Challenge methods: the slot owns the pending challenge, the method owns its protocol

```go
package mfa

type ChallengeMethod interface {
    Method
    // BeginChallenge returns the data the client needs (JSON), built around challenge,
    // a server-issued random string the slot will later match.
    BeginChallenge(ctx context.Context, user identity.UserID, challenge string) (json.RawMessage, error)
    // PresentedChallenge extracts the challenge the client answered from its response.
    PresentedChallenge(response []byte) (string, error)
}
```

**Begin** is a POST to `/mfa/begin/{method}` by default. The slot:
1. applies the same session, method and usability checks as verify (D5);
2. refuses while the user's verification is throttled;
3. issues a one-time token through a manager of purpose `mfa-challenge:<name>`, with subject the user and binding the session handle (`onetime.WithBinding`);
4. passes the token string to `BeginChallenge` as the challenge;
5. writes the returned JSON through a replaceable begin responder.

**Verify for a challenge method.** After parsing, the slot:
1. calls `PresentedChallenge`;
2. calls `Check(challenge, binding = session handle)`;
3. calls `Consume` whatever happens next, so the challenge is spent by this attempt;
4. only then calls `Verify`.

A missing, unknown, expired, spent or mismatched challenge is refused as the invalid second-factor code (`mfa.ErrInvalidCode`). It counts as a failed verification.

- **Why the slot and not the method.**
  - Single use, hashing, expiry and the durable adapters already exist in `onetime`, with conformance suites.
  - The challenge is only ever compared with one the server issued, never taken from the client.
  - Spending on every attempt is one place's rule, not each method's.
- **Rotation cannot break it.** Begin and verify both happen before rotation, since rotation happens at verify success. The binding is therefore the pre-rotation handle both times.
- **Departure from check-then-consume.** This is recorded in the proposal: a challenge is not a credential the user holds, and one try per challenge is the simpler guarantee.
- **Defaults:**
  - challenge lifetime 5 minutes, within WebAuthn's recommended ceremony timeout range;
  - in-memory challenge store.
- **Override:**
  - `WithMFAChallengeTTL(d)`;
  - `WithMFAChallengeStore(onetime.Store)`, for several replicas;
  - `WithMFABeginResponder(fn)`;
  - `WithMFAChallengeLimit(n)`, default 10 per issuance window.

  The begin prefix is replaceable by `WithMFABeginPrefix`. A begin path naming a method with no begin step is refused as an unknown method (D9).
- **Bounded issuance.** Begin counts the challenges it issued to the user for that method within the one-time manager's issuance window (`IssuedCount`, one hour by default), and refuses as throttled at the limit, 10 by default, replaceable by `WithMFAChallengeLimit(n)`. It also purges the method's expired challenges (`PurgeExpired`) at most once per issuance window, ignoring and logging a failed purge. Found in review: without both, a session past its first factor could grow the default store without bound. The resend limit of the magic link is the established precedent for counting issuance this way.
  - **Stated limit:** the count and the issue are separate steps, so begins that race can exceed the limit by the number that raced, as the magic-link resend limit can. The godoc of `WithMFAChallengeLimit` says so. Making it exact would need a conditional insert in every one-time store, a store contract change this design rules out (D1).
  - **Sweep timing:** the sweep runs under the begin's own context, so a slow store never holds a begin past its deadline. A sweep that fails or is cancelled gives back its turn, and a later begin tries again. The exception is a store that cannot purge at all (`onetime.ErrReapUnsupported`), which would not start purging on a retry. It keeps its turn and is logged once per window. It is at most once per issuance window per method **per process**: several replicas each sweep. This is harmless, because a sweep only removes records that are both expired and older than the window.
- **Stated limit:** the default in-memory challenge store is per process. On several replicas, a begin and a verify that land on different replicas fail. The godoc says so, as it does for the other in-memory defaults.

### D4. One definition of "usable", exported from `policy`

```go
package policy

type MFAMethodLookup interface {
    Name() string
    Channel() factor.Channel
    Enrolled(ctx context.Context, user identity.UserID) (bool, error)
}

// UsableMFAMethods returns, in configuration order, the methods the user is enrolled on
// whose channel differs from first's. Any lookup error is returned; it never yields a
// shorter list.
func UsableMFAMethods(ctx context.Context, methods []MFAMethodLookup, user identity.UserID, first factor.Kind) ([]MFAMethodLookup, error)
```

`MFAMethodLookup` gains `Name`. Every `mfa.Method` already satisfies the larger port. `mfa.LookupFor(m)` becomes `mfa.LookupsFor(methods ...Method) ([]policy.MFAMethodLookup, error)`, which is the single construction check for methods. It refuses:
- an empty set;
- a nil or typed-nil method;
- an empty channel;
- a name that is not a valid segment;
- duplicate names;
- an invalid response format.

Its errors wrap `mfa.ErrConfig`.

The following all call `UsableMFAMethods`:
- the challenge policy;
- the requirement policy;
- the verify and begin endpoints, for "may this user use the method named in the path";
- the challenge error's method list (D6);
- the listing endpoint (D7).

A client is therefore never offered a method the slot then refuses.

- **Default and override:** not applicable. It is a pure function over the consumer's lookups, exported so a consumer can build their own route.

### D5. The verify endpoint: per-method paths, one ordered pipeline

POST `/mfa/verify/{method}` by default. The prefix is replaced by `WithMFAVerifyPrefix`, which replaces `WithMFAVerifyPath`, and is normalised and validated like OIDC's prefix. Order:

1. The request has no session, or its session has no resolved caller: refused as authentication required.
2. The path names no configured method: refused as the unknown MFA method (404).
3. The method's channel equals the session's first-factor channel: refused with `mfa.ErrSameChannel`, and nothing is recorded.
4. `UsableMFAMethods` excludes the method: refused as the MFA method not usable (403), and nothing is recorded. A lookup error propagates (500).
5. The per-user throttle is checked.
6. The library reader declared by the method runs (D2). Parse failures are not counted.
7. For a challenge method only, the challenge is extracted, checked and consumed (D3).
8. `Verify` runs. A failure records a throttle failure and propagates unchanged.
9. Resolve, restore enrolment deadlines, rotate, generate the credential, and respond. This step is unchanged.

Steps 1–4 happen before the body is read. The method choice is only ever read from the path. The MFA gate exempts every path under the verify prefix and the begin prefix.

- **Default:** prefixes `/mfa/verify` and `/mfa/begin`.
- **Override:** the two prefix options.

  Wiring mistakes fail at construction:
  - an empty prefix, `/`, or no leading `/`;
  - the verify and begin prefixes are equal, or one lies under the other, since one endpoint would then answer the other's POSTs;
  - either prefix equals the logout path or the listing path.

### D6. The MFA challenge error carries the usable methods

`httpsec.ChallengeError` gains `Methods []MFAMethod`, where `type MFAMethod struct{ Name string; Channel factor.Channel; Begins bool }`.

For `Kind == policy.ChallengeMFA`, the chain fills it from `UsableMFAMethods` at the one place it builds MFA challenges. That covers the per-request gate and the login completions (form login, magic link, OIDC handoff). A lookup error replaces the challenge with that error, so a failed lookup never yields an empty list.

For a login whose first factor is a one-time credential (magic link, OIDC handoff), the method lookup runs in the side-effect-free checks before the credential is spent. A failed lookup therefore refuses without spending it, as the project's check-then-consume rule requires. Found in review. For the same reason, the login tail of such a login reuses the policy decision the pre-consume check made, rather than evaluating the post-authentication policies again after the credential is spent. Before this change, a policy lookup failing on that second evaluation refused the login and still spent the credential. Review reproduced this with `TestRedemption_PostRedeemPolicyLookupFailureKeepsCredential`, and it is fixed here because this change's refactor is what carries the decision to the tail. Reusing a decision is only sound for the principal it was made about. A redeemer (the consumer can supply their own) that returns a different principal or password-change time than the one its check saw is therefore refused with `policy.ErrPolicyDenied` before any session exists. "Different" means a different user reference, or a password-change time that is not equal. The comparison is by user reference and instant, not deep equality, so a redeemer that reloads the same user with times in another location is not refused. The built-in redeemers always return the principal they checked.

`Error()` is unchanged, so names stay out of the text. Nothing else about rendering changes: with nothing wired, the response is still a bare 401.

- **Default:** the list is always carried on the MFA challenge.
- **Override:** none needed. It is data on a typed error, rendered only by the consumer's handler.

### D7. The opt-in listing endpoint, and the first `httpsec` option with settings of its own

```go
httpsec.EnableMFA(methods, httpsec.WithMFAMethodListing())                       // GET /mfa/methods
httpsec.EnableMFA(methods, httpsec.WithMFAMethodListing(
    httpsec.ListingPath("/account/mfa/methods"), httpsec.ListingResponder(fn)))
```

- **Requests.** GET only. It never reads the query.
- **Who it answers.** Only a session with the MFA challenge pending:
  - no session: refused as authentication required;
  - any other session: refused as no MFA challenge pending (403);
  - an enrolment-only session: stopped earlier by the enrolment gate.
- **Response.** The default body is the JSON `{"methods":[{"name":…,"channel":…,"begins":…}]}`, from `UsableMFAMethods`. A lookup error is a refusal.
- **Defaults:** off; path `/mfa/methods`; that JSON document.
- **Override:** the two settings, which can only be written inside `WithMFAMethodListing`. An explicit empty path or nil responder is refused.
- **Wiring mistakes:** the path collides with a verify, begin or logout path.
- **Alternative rejected:** a struct or positional form. It reads an empty value as the default (proposal).

### D8. The throttle stays per user and is shared across methods

`mfa.VerifyThrottleKey` stays `mfa-verify|<user>`, so failures on any method count toward one limit.

- **Why:** a per-method throttle multiplies an attacker's guesses by the number of methods.
- **Default:** unchanged (5 failures per 15 minutes).
- **Override:** unchanged (`WithMFAVerifyLimiter`).

### D9. New refusals and their status rows

| Error | Where | Status | Why |
|---|---|---|---|
| `httpsec.ErrUnknownMFAMethod` | a verify or begin path naming no configured method, or a begin path for a method with no begin step | 404 | Mirrors the unknown OIDC provider. The method set is configuration, not a secret. |
| `httpsec.ErrMFAMethodNotUsable` | the user is not enrolled on the named method | 403 | Like the same-channel refusal: this user may not take this step. |
| `httpsec.ErrNoMFAChallengePending` | the listing endpoint called by a session that owes no MFA challenge | 403 | The endpoint exists only for the pending state. |

A refused pending challenge maps to the existing invalid-code row (401).

### D10. Policies decide over a method set

- **The constructors take the set.** `NewMFAPolicy(methods []MFAMethodLookup, …)` and `NewMFARequirementPolicy(required, methods []MFAMethodLookup, …)` take the set. A nil or empty entry, or duplicate names, is a configuration error.
- **The requirement policy with no methods.** An empty set means "no method configured", which keeps today's deny with MFA required. Requiring MFA for all with an empty set is a configuration error.
- **Challenge policy.**
  1. Exempt, or already satisfied: allow.
  2. Any lookup error: deny.
  3. Any usable method: challenge.
  4. Enrolled only on same-channel methods: the same-channel decision.
  5. Otherwise: allow.
- **Requirement policy.** "Usable enrolment" means `UsableMFAMethods` is non-empty.

  Enrolment-path admission needs a method in the set that supports the enrolment path and whose channel differs from the first factor's. Support is detected through a structural interface declared in `policy` (`SupportsEnrolmentPath() bool`), so `policy` still does not import `mfa`.
- **Defaults and overrides:** every existing option is unchanged. The godoc keeps saying the policies' set and `EnableMFA`'s set must be the same methods.

### D11. The enrolment path names its method

The three enrolment paths become prefixes, each taking exactly one method segment:
- `/mfa/enrol/begin/{method}`
- `/mfa/enrol/confirm/{method}`
- `/mfa/enrol/confirm-email/{method}`

`EnableMFAEnrolment` enrols from the `EnableMFA` methods that implement `mfa.Enroller` and report `SupportsEnrolmentPath()`. `WithEnrolmentMethods(names …)` narrows that set.

- **Generations belong to one method.** The session's generation belongs to the method whose store issued it. A confirm naming another method is refused by that method's store, as a stale generation is today. This needs no new session field.
- **Wiring mistakes:**
  - no enrollable method;
  - `WithEnrolmentMethods` naming an unknown or non-enrollable method, or an empty list;
  - prefix collisions.
- **Default:** every enrollable configured method.
- **Override:** `WithEnrolmentMethods`, and the three prefix options, which replace the path options.

### D12. The operator reset clears every method

`mfa.ResetDeps.Enrolments` becomes `[]EnrolmentRemover`.

- **Order.** The reset removes the user's enrolment on every remover, in order, before deleting sessions.
- **Failure.** A removal failure stops the reset and returns that error. Sessions are then not deleted and no notification is sent. The removals already done stay done.
- **Construction.** An empty list, or a nil entry, is a configuration error, checked before anything is removed.
- **Why stop rather than continue.** Continuing would delete sessions and notify "your second factors were reset" while one still exists.
- **Default:** unchanged options.
- **Override:** unchanged options.

## Risks / Trade-offs

- **[A consumer passes different method sets to the policies and to `EnableMFA`.]** → This is documented, as today, on both policy constructors and on `EnableMFA`. `mfa.LookupsFor` builds the policies' set from the very methods given to `EnableMFA`, so the documented wiring is one list used twice. Checking the two sets at assembly would need an accessor on the policy types, which this change does not add.
- **[Per-request cost of the method list.]** → It is computed only for a session that owes the MFA challenge, one `Enrolled` read per configured method. Full sessions never pay it.
- **[In-memory challenge store on several replicas.]** → Stated in godoc (D3). `WithMFAChallengeStore` takes the durable one-time stores that already exist.
- **[Breaking API for every MFA caller.]** → Nothing is tagged. Every caller is in this repository: tests, `test/httpsecconformance` and examples. They move in the same change.

## Migration Plan

This change lands after `clock-seam` (archived). Its code order compiles at each step:
1. `mfa`: the port and the formats, `LookupsFor`, TOTP, reset.
2. `policy`: the lookup port, `UsableMFAMethods`, both policies.
3. `httpsec`: readers, verify, begin, challenge methods, the challenge error, listing, enrolment, status rows.
4. The `test` module's conformance scenarios.

**Rollback:** revert the change's commits. No stored data or schema changes.

## References

### Researched (accessed 2026-09-28, carried forward from the proposal)

**D2: each method declares its response format**
- [Web Authentication, Level 3 (W3C)](https://www.w3.org/TR/webauthn-3/): a WebAuthn response is structured data, and a legal assertion can exceed 4 KiB when form-encoded.
- [protocol package of go-webauthn (pkg.go.dev)](https://pkg.go.dev/github.com/go-webauthn/webauthn/protocol): assertions parse from bytes, so the library's readers can hand a method its response without the request.

**D3: pending challenges as one-time tokens, spent on every attempt**
- [Spring Security WebAuthn authentication package](https://docs.spring.io/spring-security/reference/api/java/org/springframework/security/web/webauthn/authentication/package-summary.html): server-side challenge state.
- [Yubico java-webauthn-server](https://github.com/Yubico/java-webauthn-server) and [AssertionRequest API](https://developers.yubico.com/java-webauthn-server/JavaDoc/webauthn-server-core/2.8.2/com/yubico/webauthn/AssertionRequest.html): the request object the server keeps between begin and finish.
- [Passkeys (SimpleWebAuthn)](https://simplewebauthn.dev/docs/advanced/passkeys) and [discussion #321](https://github.com/MasterKale/SimpleWebAuthn/discussions/321): a challenge deleted after any attempt, even a failed one.
- [GHSA-gjjc-pcwp-c74m](https://github.com/OneUptime/oneuptime/security/advisories/GHSA-gjjc-pcwp-c74m): why a challenge is never taken from the client.
- [w3c/webauthn issue #1803](https://github.com/w3c/webauthn/issues/1803): challenges of at least 16 random bytes. A one-time token carries 32.
- [FIDO Server Requirements (FIDO Alliance)](https://fidoalliance.org/specs/fidoserver/fido-server-v2.3-rd-20260226.html) and [Server-side passkey authentication (Google)](https://developers.google.com/identity/passkeys/developer-guides/server-authentication?authuser=9).

**D5, D10: the same-channel rule with several methods**
- [About passkeys (GitHub Docs)](https://docs.github.com/en/authentication/authenticating-with-a-passkey/about-passkeys) and [Sign in with a passkey (Google Account Help)](https://support.google.com/accounts/answer/13548313?hl=en): a passkey accepted both as a sign-in and as a second step, which is why one user holds several methods.

**D1, D4, D6–D9, D11, D12**
- Reasoned from scrty's own settled specs (`multi-factor-auth`, `security-policy`, `http-error-propagation`, `http-security-chain`, `one-time-tokens`) and the established design.
