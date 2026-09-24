## Context

See proposal.md for why this change exists. The constraints that shape the approach:

- **Starting point.** Earlier changes provide:
  - `identity` (principal, user reference, user loader, first-factor kinds and channels, MFA requirement lookup);
  - `session`, `policy`, `ratelimit` and `onetime` from `authn-authz-core`;
  - `httpsec`'s interceptor chain and error contract from `http-security`, including the named slots
    (`OrderMagicLink`, `OrderAPIKey`, `OrderMFAChallenge`), the login completion step and the source
    throttle step, which this change is the first to use — `http-security` shipped them tested but
    with no built-in caller;
  - durable stores and sealing from `durable-persistence`;
  - `pkg/id` and `pkg/logsample`.
- **Behaviour owned elsewhere and used here, not restated:**
  - the MFA requirement policy, the second-factor challenge policy and the same-channel rule (`security-policy`);
  - atomic single-use consumption and issuance counting (`one-time-tokens`);
  - source canonicalisation, unattributable-source refusal and guard logging (`rate-limiting`);
  - sealing of MFA secrets and "unreadable is an error, never absence" in durable stores (`secrets-at-rest`, `security-state-stores`);
  - scope requirements (`authorization`).
- **Project rules:**
  - every default documented and replaceable (library-design);
  - wiring mistakes fail at construction;
  - test-first (golang-tdd);
  - table tests in the `assert` closure form;
  - mocks outside production builds;
  - heavy services from testcontainers helpers.
- **Settled decisions this design must honour:**
  - one-time credentials are check-then-consume;
  - refused redemptions of a valid link count against the source limit by default, with an opt-out;
  - a TOTP issuer is required;
  - a same-channel second factor is an explicit decision with a safe default;
  - a lost enrolment never downgrades a required user;
  - email sending is a port with a deadline-bounded SMTP default;
  - API keys are shown once, hashed, prefixed, bound to a service principal, throttled per source and revocable;
  - secrets come from `crypto/rand`.

### Inbound dependency from `http-security`

**This change must refuse, at construction, a policy that can challenge for a second factor when its
challenge interceptor is not enabled.**

`http-security` records this as a flagged dependency it cannot enforce itself. The chain's
per-request phase marks a second-factor challenge pending on the session and continues, because the
gate for that challenge is what enforces it and its verify endpoint must stay reachable. That gate
is the challenge interceptor at `OrderMFAChallenge`, which this change adds. With a policy that can
raise the challenge and no interceptor to enforce it, sessions are marked pending and nothing ever
acts on the marker: the caller proceeds with an unsatisfied second factor, and nothing in the
request path reports it.

The failure is silent, which is why it has to be a construction error rather than a documented
caution — the same rule the rest of this design applies to wiring mistakes.

## Goals / Non-Goals

**Goals:**
- Each method's failure modes are closed by construction or by a tested requirement, not by documentation asking the consumer to be careful.
- The HTTP pieces of each method follow the same shape as the rest of `httpsec`: interceptors registered in ordered slots, errors propagated, no rendering.
- Every place where scrty behaves differently from the established behaviour these methods were modelled on is recorded below, with its justification.

**Non-Goals:**
- An enrolment path for a user who is already required to use MFA but has no usable enrolment (`mfa-enrolment-path`).
- Recovery codes, WebAuthn, SMS or push methods. The method port admits them later.
- HTTP endpoints for TOTP enrolment, and for API key issuance, listing, rotation or revocation. These are Go APIs, and the consumer puts them behind their own authenticated, authorised routes.
- An email template system, HTML bodies, or delivery tracking.
- Inspecting an identity provider's MFA claims (`oidc-mfa-assurance`).
- A shared (cross-replica) limiter (`shared-rate-limiting`).

## Decisions

### 1. Packages and where the HTTP pieces live

| Package | Role | Imports |
|---|---|---|
| `notify` | Sender port, SMTP sender, queued sender | standard library |
| `mfa` | Method port, TOTP method, enrolment store port and in-memory store, verification throttle | `identity`, `ratelimit`, `pkg/logsample`, `github.com/pquerna/otp` |
| `magiclink` | Manager: request and redeem | `identity`, `onetime`, `notify`, `policy` (decision types only) |
| `apikey` | Manager, key store port and in-memory store | `identity`, `pkg/id` |
| `httpsec` | `EnableMFA`, `EnableMagicLink`, `EnableAPIKey` interceptors in the slots `http-security-chain` defines | the above |

- **Why `httpsec` holds the interceptors:** the chain, the exchange, the challenge error and the source guard wiring all live there. A method package that imported `httpsec` would create a cycle through `session`.
- **Dependency:** `pquerna/otp` computes and validates TOTP codes, as the behaviour these methods were modelled on did. scrty adds the per-step matching and replay record around it (decision 5). Its module graph adds `boombuler/barcode`, used only if the consumer renders a QR image, which scrty does not.
- **Durable stores:** the enrolment and key store contracts defined here are implemented by `security-state-stores` on each backend. The enrolment table needs two columns beyond the secret, a confirmation time and a last accepted step; see Risks.

### 2. Email: the port and the SMTP sender

```go
type Message struct { To, From, Subject, TextBody string }
type Sender interface { Send(ctx context.Context, msg Message) error }

// NonBlocking is implemented by senders whose Send returns without waiting for delivery.
type NonBlocking interface { NonBlocking() bool }

func NewSMTPSender(host string, opts ...SMTPOption) (*SMTPSender, error)
```

| Option | Default | Construction error when |
|---|---|---|
| `WithSMTPPort` | 587 | outside 1–65535 |
| `WithSMTPAuth(user, pass)` | none: no AUTH | — |
| `WithSMTPFrom` | none: each message must set `From` | — |
| `WithSMTPTimeout` | 30 s, one bound for dial plus exchange | ≤ 0 |
| `WithSMTPOpportunisticTLS()` | off: STARTTLS required | — |

- **Header injection:** `To`, `From` and `Subject` containing CR or LF are refused with `ErrUnsafeHeaderValue` before dialling. They are never stripped or escaped, because escaping silently changes caller content and folding rules are easy to get wrong.
- **One deadline:**
  - an absolute deadline, the earlier of `now + timeout` and the context deadline, is fixed before dialling;
  - it is passed to the dialler and set on the connection;
  - `context.AfterFunc` forces the connection deadline to now when the context ends, which unblocks `net/smtp` mid-exchange.

  A dial timeout followed by a fresh deadline would allow nearly twice the bound.
- **Credentials:** `smtp.PlainAuth` refuses to send credentials over an unencrypted connection except to localhost. scrty relies on that and tests it.
- **Encoding:**
  - the body is normalised to CRLF and sent as `text/plain; charset=UTF-8`;
  - a non-ASCII subject is encoded with `mime.QEncoding`;
  - no header names scrty.
- **Override:**
  - every option above;
  - any `Sender`, such as a transactional-email API client, a queue or a test double, replaces SMTP entirely.
- **Alternative rejected:** a third-party mail library. `net/smtp` is frozen but sufficient for submission with STARTTLS and PLAIN auth, and adds nothing to the module graph.

### 3. Email: the queued sender

```go
func NewQueuedSender(inner Sender, opts ...QueuedOption) (*QueuedSender, error)
func (s *QueuedSender) Close(ctx context.Context) error
```

- **Defaults:** 2 workers, a queue of 256, a send timeout of 30 s, and `slog.Default()` for the
  failure records. Each is replaceable (`WithQueueWorkers`, `WithQueueSize`, `WithQueueSendTimeout`,
  `WithQueueLogger`), and non-positive values are construction errors. The logger default is
  `slog.Default()` and not a discarding handler for the reason section 15 gives: `Send` has already
  returned nil by the time a queued message is dropped, so a discarded record would make a lost
  sign-in link invisible at both ends. A consumer wanting silence passes a discarding handler, which
  makes the silence visible at the wiring.
- **Behaviour:**
  - the request context is detached with `context.WithoutCancel`, so values survive while cancellation does not;
  - a full queue drops the message, logs at error and returns `ErrQueueFull`, never blocking;
  - `Close` stops intake and drains, bounded by its context;
  - a panic in the inner sender is recovered and logged.
- **Why drop rather than block:** blocking would put delivery time back into the request, and it would be longest for real accounts under load.
- **Lifecycle:** `NewQueuedSender` starts its workers, and `Close` joins them. The godoc and README say to call `Close` on shutdown. `di-wiring` registers it as a shutdown hook.
- **Limit, stated:** the send timeout only bounds an inner sender that honours context cancellation mid-transfer. The SMTP sender does. A custom sender that does not can occupy workers indefinitely.

### 4. MFA: method port and channels

```go
type Method interface {
    Name() string
    Channel() identity.Channel      // constant, non-empty
    Enrolled(ctx context.Context, user identity.UserID) (bool, error)
    Verify(ctx context.Context, user identity.UserID, code string) error
}
```

- **The channel values are `identity-model`'s.** `mfa` defines no channel constant. The TOTP method reports identity-model's authenticator-app channel, which is not the channel of any first-factor kind. A consumer method reports whichever identity-model channel its codes travel over.
- **An empty channel is a construction error in every component that takes a `Method`:** `EnableMFA` and the enrolment lookup handed to `security-policy`. See departure D1.
- **What `security-policy` needs from this capability.** It is written here and flagged to `authn-authz-core`. The second-factor challenge policy and the MFA requirement policy consult an enrolment lookup:

  ```go
  type EnrolmentLookup interface {
      Enrolment(ctx context.Context, user identity.UserID) (enrolled bool, channel identity.Channel, err error)
  }
  func LookupFor(m Method) EnrolmentLookup
  ```

  The contract, pinned by tests here:
  - `enrolled` is true only for a confirmed enrolment;
  - a store error or an unreadable secret is returned as `err`, never as `enrolled == false`;
  - `channel` is the method's constant channel.

  The policies already deny on a lookup error and treat a same-channel enrolment as unusable.
- **Override:** a consumer `Method` (for example email one-time codes), and a consumer `EnrolmentLookup` spanning several methods.

### 5. TOTP

```go
func NewTOTP(store EnrolmentStore, issuer string, opts ...TOTPOption) (*TOTP, error)
func (t *TOTP) BeginEnrolment(ctx context.Context, user identity.UserID, accountLabel string) (Provisioning, error) // {Secret (base32), URI}
func (t *TOTP) ConfirmEnrolment(ctx context.Context, user identity.UserID, code string) error
func (t *TOTP) RemoveEnrolment(ctx context.Context, user identity.UserID) error
```

| Option | Default | Construction error when |
|---|---|---|
| issuer (argument) | none, required | empty, or contains `:` |
| `WithDigits` | 6 | not 6 or 8 |
| `WithPeriod` | 30 s | ≤ 0 |
| `WithClock` | `time.Now` | — |
| `WithRandom` | `crypto/rand.Reader` | — |

- **Algorithm:** HMAC-SHA-1, with a tolerance of one step on either side. The set of accepted steps is fixed, because authenticator apps widely ignore any other algorithm parameter.
- **Matching a step:**
  - `Verify` rejects anything that is not exactly the configured number of ASCII digits;
  - it computes the expected code for steps `s-1`, `s` and `s+1` and compares each in constant time;
  - it takes the matched step, and only then asks the store to accept that step.
- **Replay (D2).** `EnrolmentStore.AcceptStep(ctx, user, step)` is one conditional write: `UPDATE ... SET last_step = $2 WHERE user_id = $1 AND confirmed_at IS NOT NULL AND last_step < $2`. It reports false when nothing changed, and `Verify` then returns `ErrInvalidCode`.
- **Enrolment store port:**

  ```go
  type Enrolment struct { User identity.UserID; Secret []byte; ConfirmedAt time.Time; LastStep int64; CreatedAt time.Time }
  type EnrolmentStore interface {
      Get(ctx context.Context, user identity.UserID) (Enrolment, bool, error)
      PutPending(ctx context.Context, e Enrolment) error            // ErrAlreadyEnrolled when a confirmed one exists, decided by the write
      Confirm(ctx context.Context, user identity.UserID, step int64, at time.Time) (bool, error)
      AcceptStep(ctx context.Context, user identity.UserID, step int64) (bool, error)
      Delete(ctx context.Context, user identity.UserID) error
  }
  ```

  The in-memory store is the non-durable default. It is documented for tests and single-process use, where enrolments are lost on restart. Because the requirement lives with the user (decision 7), losing them fails closed.
- **Enrolment surface.** This is new behaviour, not a departure; see D3.
  - `BeginEnrolment` generates 20 random bytes and stores a pending record.
  - It returns the base32 secret and `otpauth://totp/<issuer>:<label>?secret=…&issuer=…&digits=…&period=…`.
  - A pending record is replaced by a later begin. A confirmed record refuses one.
  - The label belongs to the consumer, typically an email address, and is never derived from the user reference, which may be an internal identifier.
- **Override:**
  - every option;
  - a consumer `EnrolmentStore`, which must pass the `store-conformance` suite;
  - a consumer `Method` in place of TOTP.

### 6. MFA verification: throttle, same channel, endpoint and gate

```go
func EnableMFA(method mfa.Method, opts ...MFAOption) Option
```

| Option | Default | Governs |
|---|---|---|
| `WithMFAVerifyPath` | `/mfa/totp` | the POST path |
| `WithMFAVerifyLimiter` | in-memory, 5 failures per 15 min, keyed by user reference | failed-code throttling only |
| `WithMFALogInterval` | 1 min | MFA throttle-log sampling only |
| `WithMFAResponder` | a JSON body carrying an access token for the rotated session and its expiry | the success response |
| `WithMFATokens` | none: required, and a chain enabling MFA without one fails to assemble | the generator that issues the post-rotation credential |

**The session manager is the chain's, and there is no option for another.** Magic link takes
`WithMagicLinkSessions` because it *creates* a session and a consumer may legitimately want it made
somewhere specific. The verify endpoint only ever *rotates* a session the chain already resolved, so
a second manager could only ever be the wrong one — it would look up a handle that the rest of the
chain does not know about. The asymmetry is deliberate: the option is absent because supplying it
would be a wiring mistake, which is the same reason the rest of this design turns wiring mistakes
into construction errors.

**Verify endpoint, in order:**
1. **Session.** No session returns `ErrAuthenticationRequired`.
2. **Same channel.** If `method.Channel() == session.FirstFactor().Channel()`, return `mfa.ErrSameChannel` before reading `code`. No failure is recorded, and the challenge stays pending.
3. **Throttle.** Check the limiter for the user reference. If it is exceeded or errors, return `mfa.ErrVerifyThrottled`.
4. **Verify the code.** On failure, record a failure against the user and return the error unchanged.
5. **Success.**
   - resolve the MFA challenge on the session, which sets the second-factor-satisfied time;
   - rotate the handle (D5);
   - place the new handle on the exchange, and call the **MFA responder** with the rotated session;
   - end the chain.

**Why a responder and not a bare 200.** Implementation showed that placing the new handle on the
exchange reaches nobody. The endpoint answers the request itself, so no downstream handler runs, and
with `Chain.Middleware()` a consumer has no hook that sees the rotated identifier. A bearer caller's
access token still named the deleted session, so completing the second factor signed the user out —
rotation turning into a denial of service against the users who did exactly what was asked of them.

`httpsec` already solved this shape once: `EnableFormLogin` takes a `LoginResponder`, "called instead
of the downstream handler, because a login is the library's own endpoint and the application has no
route behind it". The verify endpoint has the same shape, so it takes the same kind of thing.

- **Default:** a JSON body carrying a freshly issued access token for the rotated session and its
  expiry — the same shape the default login responder writes, so a client handles both alike.
- **Override:** `WithMFAResponder` replaces the whole response, for a consumer who sets a cookie, who
  answers 204, or who returns their own document. An error it returns becomes the request's refusal.

**Gate:** any other request whose session has the MFA challenge pending returns `&ChallengeError{Kind: ChallengeMFA, Session: s}`. The one exception is the configured logout endpoint (POST on its path), which passes through (D15). Chain assembly gives the gate the logout path, so a consumer's logout path is exempt too, and slot order cannot strand a pending session.

- **Why the limiter is keyed by user and not by source (D4):** the attacker already holds the victim's first factor and can rotate addresses at will. The user is the resource under attack.
- **Limit, stated:** an attacker holding the password can lock the real user out of MFA verification for 15 minutes. That is the accepted price, and it is documented.
- **Same channel has no override at verify.** Whether a same-channel login is challenged at all is the security-policy rule, which refuses by default and offers an explicit choice to complete on the first factor. A code on the first factor's channel is never counted as a second factor.

### 7. A lost enrolment never downgrades; the require-for-all limit

- **The requirement lives with the user.** It comes from `identity`'s `MFARequirementLookup`, and nothing in `mfa` can clear it. `RemoveEnrolment` deletes only the enrolment record.
- **Fail closed at both ends:**
  - the durable store returns an unreadable or unavailable enrolment as an error (`secrets-at-rest`);
  - `LookupFor` passes it through (decision 4);
  - `security-policy` denies on it.

  The test here runs the whole path: required user, enrolment deleted or store failing, password login refused, no session.
- **Require-for-all:** a user with no usable enrolment is refused at every non-exempt login. Nothing in this change lets them enrol through that refusal. The README and the godoc of the require-for-all option say:
  - enrol users before enabling it, out of band or through a session established by an exempt login;
  - `mfa-enrolment-path` will add the path.

### 8. Magic link: requesting a link

```go
func NewManager(tokens *onetime.Manager, users identity.UserLoader, sender notify.Sender, linkBaseURL string, opts ...Option) (*Manager, error)
func (m *Manager) Request(ctx context.Context, address, next string) RequestResult   // {BindingNonce}
func (m *Manager) BindingEnabled() bool
func (m *Manager) TTL() time.Duration
```

| Option | Default | Construction error when |
|---|---|---|
| `linkBaseURL` (argument) | none, required | empty, not absolute, or `http` on a host that is not loopback |
| `WithConfirmPath` | `/login/magic/confirm` | not host-relative |
| `WithIssuanceLimit` | 5 per one-time-token issuance window (1 h) | < 1 |
| `WithAddressResolver` | submitted address as username, via `LoadByUsername` | — |
| `WithRenderer` | neutral plain text | — |
| `WithSameDeviceBinding(bool)` | true | — |
| `WithSynchronousDelivery()` | off | — |

Link lifetime is the `onetime.Manager`'s TTL (15 minutes by default), configured there.

**`Request`:**
1. Resolve the address to user details. Unknown, disabled, or an error: log and return the empty result.
2. Count issuance for the user reference. At the limit, or an error: log and return the empty result.
3. Issue a one-time token with subject = user reference (D7) and, when binding is on, a binding value.
4. Build the link as `base + confirmPath + "?token=" + token + "&next=" + QueryEscape(next)` and render the message.
5. Force `To` to the submitted address and send. A send error is logged.
6. Return the binding nonce.

`Request` returns no error at all. Every branch returns the same empty result, so a caller cannot branch on it.

- **Synchronous delivery refused (D6):** `NewManager` returns a configuration error unless `sender` implements `notify.NonBlocking` reporting true, or `WithSynchronousDelivery()` is given.
- **Limit, stated:** the store read and the insert still run only for real accounts, so a small timing difference remains. It is documented and not closed here.
- **Alternative rejected:** sending from a goroutine inside `Request`. That hides an unbounded, unjoinable goroutine inside a constructor-less call. The queued sender makes the lifecycle explicit.

### 9. Magic link: redemption

```go
type Check func(ctx context.Context, p identity.Principal, passwordChangedAt time.Time) error
func (m *Manager) Redeem(ctx context.Context, token, bindingNonce string, checks ...Check) (Redemption, error) // {Principal, PasswordChangedAt}
```

- **Built on `one-time-tokens`' redemption operation.** It checks the token, runs its refusal checks, then consumes. `Redeem` passes, as the first refusal check, a resolver that:
  - loads by user reference;
  - refuses a miss, a disabled user or an ID mismatch (D7);
  - records the principal.

  The caller's checks follow. The ordering and the side-effect-free obligation are therefore the one-time-token capability's contract, with account resolution placed inside it.
- **Errors:**
  - the token check, resolution failures, loader errors and the consume write all return `ErrInvalidLink`, with the cause logged at debug (miss or disabled) or error (outage);
  - the caller's check errors are returned unchanged.
- **Interceptor check.** The consume interceptor passes a `Check` that evaluates `PostAuthentication` with `FirstFactor: magic-link` and the password-change time. It captures `decision` and `evaluated` in the closure.
  - `Deny` returns `decision.Reason`, or `ErrPolicyDenied` when the reason is nil. A nil return would read as "no refusal" and spend the link.
  - `Challenge` and `Allow` return nil.
- **Guard after success:** if `!evaluated || decision.Outcome == Deny`, the interceptor returns the deny reason (or `ErrPolicyDenied`) and creates no session. `Redeemer` is an interface, and a non-conforming implementation cannot be trusted. The guard cannot un-spend a link such an implementation consumed, and the godoc says so.
- **On success:**
  - create the session with `WithFirstFactor(magic-link)`;
  - mark any challenge pending in the creating flow;
  - issue the access token;
  - set `Referrer-Policy: no-referrer`;
  - write the response through the **magic-link responder**;
  - return the challenge error or the success result.

- **The success response is replaceable.** The consume endpoint is the library's own, with no route
  behind it, so the same argument that gives form login a `LoginResponder` and the verify endpoint an
  `MFAResponder` applies here. With none supplied the library writes the access token, an empty
  refresh token, the session's validity and the resolved redirect target; `WithMagicLinkResponder`
  replaces that whole document, for a consumer who sets a cookie or answers with a redirect instead.
  The responder receives the resolved target, never the submitted one, so a consumer cannot
  reintroduce the open redirect the allowlist closed.

- **`PostAuthentication` is evaluated twice on this path**: once as the redemption check that decides
  whether to spend the link, and again inside the shared login tail. The tail is shared deliberately,
  so that challenge marking, the save-before-token ordering and the challenge error are identical to
  form login's rather than a second copy that drifts. The cost is the second evaluation.

  This is safe because a policy is a decision, not an action: the capability's contract is that
  evaluating one has no side effects. A consumer policy that counts attempts, scores risk
  adaptively or writes anywhere will therefore fire twice per redemption, and must not be written
  that way. It is recorded here rather than left to be discovered, and closing it means letting the
  tail accept a decision already made — a change to a helper form login also uses, which belongs to
  its own change.
- **Rate-limit accounting (D8):**
  - the source guard is checked before `Redeem`;
  - on any `Redeem` error, the interceptor records a failure for the source;
  - `WithMagicLinkCountRefusals(false)` exempts exactly the refusal the interceptor's own check produced (matched with `errors.Is` against the captured `denyErr`) and the consumer check errors;
  - every other error, including one from a redeemer that discarded the deny and failed for another reason, is still recorded.
- **Defaults:** 10 failures per source per 15 minutes, from a limiter owned by this flow alone (`WithMagicLinkLimiter`). A nil or typed-nil limiter is a construction error.

### 10. Magic link: HTTP details

| Option | Default |
|---|---|
| `WithMagicLinkRequestPath` | `/login/magic` |
| `WithMagicLinkConsumePath` | `/login/magic/consume` |
| `WithBindingCookieName` | `magic_link_binding` |
| `WithAllowedRedirects(...)` | empty: every `next` becomes `/` |
| `WithAllowedOrigins(...)` | empty: no absolute redirect entry accepted |
| `WithMagicLinkCountRefusals(bool)` | true |
| `WithMagicLinkLimiter` | in-memory, 10 per 15 min |
| `WithMagicLinkResponder` | a JSON body carrying the access token, an empty refresh token, the session's validity and the resolved redirect target |

- **Request endpoint:**
  - POST only;
  - reads `email` and `next` from the form, falling back to a JSON body, with parse failures degrading to empty values;
  - sanitises `next` and calls `Request`;
  - when `BindingEnabled()` is true, always sets the cookie with the genuine nonce or a same-shaped decoy (16 random bytes, base64url);
  - the cookie is `HttpOnly; Secure; SameSite=Lax; Path=<consumePath>; Max-Age=<TTL>`, with its lifetime taken from configuration and never from the result;
  - writes 202 with a fixed body.
- **Binding is read, not configured, by the interceptor.** The interceptor asks the manager, so cookie emission can never disagree with what `Request` does.
- **Consume endpoint:** POST only, so GET and HEAD from mail scanners pass through. It reads `token` and `next` from the form and the nonce from the cookie.
- **Redirects:**
  - `next` is used only on an exact match with an allowlist entry that is host-relative, or absolute without userinfo on a declared origin;
  - otherwise it becomes `/`;
  - allowlist and origin entries are validated at construction, with errors naming the entry;
  - declared origins must be `https`, except `http` on loopback;
  - both sides of an origin comparison are normalised for case and default port.

  `oidc-login` needs the same helper. It lives unexported in `httpsec` and is shared.

### 11. API keys

```go
func NewManager(opts ...Option) (*Manager, error)
func (m *Manager) Issue(ctx context.Context, principal identity.UserID, name string, scopes []string, lifetime time.Duration) (presented string, rec Key, err error)
func (m *Manager) Verify(ctx context.Context, presented string) (identity.Principal, Key, error)
func (m *Manager) Revoke(ctx context.Context, id id.ID) error
func (m *Manager) Rotate(ctx context.Context, id id.ID, lifetime time.Duration) (string, Key, error)
func (m *Manager) List(ctx context.Context, principal identity.UserID) ([]Key, error)
```

| Option | Default | Construction error when |
|---|---|---|
| `WithStore` | in-memory | — |
| `WithPrefix` | `sk` | not 1–16 of `[a-z0-9]` |
| `WithDigest(func([]byte) []byte)` | SHA-256 | nil |
| `WithIDGenerator` | `pkg/id` UUIDv7 | nil |
| `WithClock`, `WithRandom` | `time.Now`, `crypto/rand.Reader` | nil |

- **Presented form:** `<prefix>_<id>.<secret>`.
  - `id` is the record's `pkg/id.ID` in canonical text (D9);
  - `secret` is base64url of 32 random bytes;
  - parsing strips `<prefix>_`, cuts at the first `.`, and strictly parses `id` before any store call;
  - the prefix exists so secret scanners and log redactors can recognise a key (D10).
- **Record:** `Key{ID, Principal, Name, Scopes, SecretDigest, ExpiresAt *time.Time, RevokedAt *time.Time, LastUsedAt *time.Time, CreatedAt}`. The secret itself is never stored. A lifetime of zero or less means no expiry, as documented on `Issue`.
- **Why a fast digest and not a password hash:** the secret is 256 bits of CSPRNG output, so there is no search space for a slow KDF to defend. A slow hash would only add latency to every machine request.
- **Verify:**
  - every failure, including store errors, returns `ErrVerificationFailed`;
  - it compares digests in constant time;
  - on success it writes `LastUsedAt` best effort, ignoring errors;
  - it builds `Principal{ID: rec.Principal, Kind: KindService, DisplayName: rec.Name, Scopes: rec.Scopes}`.
- **Rotate:** issue new, then revoke old. It is atomic only inside an attached transaction (the adapter's `WithTx` or resolver), as the godoc states.
- **Interceptor (`EnableAPIKey`):**
  1. Match the literal `Authorization` prefix `ApiKey ` (`WithAPIKeyScheme`). Without it, pass through without consulting the limiter.
  2. Check the source guard. If throttled, return `ErrAuthenticationFailed` joined with `ErrVerificationFailed`.
  3. Verify. On failure, record a failure for the source and return the same joined error.
  4. Evaluate `StatelessAuthentication` with `FirstFactor: api-key`. A deny returns its reason, and is not recorded, because the credential was valid.
  5. Populate the exchange without a session.

  The default limiter allows 20 failures per source per minute (`WithAPIKeyLimiter`). A nil limiter is a construction error.

  **Correction, proven during implementation.** An earlier draft of this decision said "guards given
  the same limiter instance share buckets, as `rate-limiting` documents". That is false, and
  `rate-limiting` documents the opposite: `NewSourceGuard`'s flow name "becomes part of every key the
  guard reads and writes, so a source that exhausts one flow's allowance still has its own in
  another". Sharing a limiter shares the *store and the limit*, never the allowance. The test
  `TestFlowLimitersAreIndependent/one limiter shared by both flows` hands one `MemoryLimiter` to both
  `WithMagicLinkLimiter` and `WithAPIKeyLimiter` and pins that exhausting one leaves the other
  untouched. A consumer who genuinely wants one combined allowance across flows cannot get it by
  sharing a limiter.
- **Override:** every option. A consumer `Store` must pass `store-conformance`. Scope enforcement is the consumer's rule set, through `authorization`'s scope requirements.

### 12. Logging

- **Throttle refusals** in all three flows go through `rate-limiting`'s source guard, or for MFA the per-user throttle, each with its own sampler and reporter.
- **Log content:**
  - no record contains a presented code, TOTP secret, provisioning URI, magic-link token, binding value, submitted address, API key or email body;
  - request and redemption causes are logged at debug for expected traffic and at error for outages;
  - loader and store error values are logged, and their messages come from adapters that do not embed submitted values (`security-state-stores`).

### 13. Departures from the behaviour these methods were modelled on

| # | scrty does | Instead of | Justification |
|---|---|---|---|
| D1 | Refuses an MFA method with an empty channel at construction | Accepting it | Settled: wiring mistakes fail at construction. An empty channel equals the channel of an unrecorded first factor, and would be refused at verify on every such session. |
| D2 | Records the accepted TOTP step and refuses replays atomically | Accepting the same code any number of times within its window | Defect: RFC 6238 §5.2 requires that a verifier not accept an OTP a second time after a successful validation. |
| D3 | Requires the issuer; puts it in a provisioning URI; enrolment is begin, then confirm | A branded default issuer stored but never used, and an enrol call that is usable immediately | Settled: the issuer is required configuration with no brand default. The write-only issuer was an admitted gap, pending a provisioning surface. |
| D4 | Throttles failed MFA codes per user (5 per 15 min) | No limit on code guesses | Defect: an unthrottled 6-digit code with a ±1 step window falls to online guessing within hours. |
| D5 | Rotates the session handle when the second factor succeeds | Keeping the pre-MFA handle | Defect: session fixation. A handle obtained before the privilege change stays valid after it, and `sessions` provides rotation for exactly this step. |
| D6 | Refuses a magic-link manager with a synchronous sender unless explicitly accepted | Documenting that deployments should wrap their sender | Defect: an admitted gap. The timing channel was closed only for deployments that remembered to wrap the sender. |
| D7 | Records the user reference on the link, loads by reference, and refuses a mismatch | Recording and loading by username | Settled: a link must verify the user it was minted against. A username is a reusable handle, so a reissued username would inherit a live link. |
| D8 | Records a source failure for policy and check refusals of a valid link by default, with an opt-out | Never recording them | Settled: refused redemptions of a valid link count against the source limit by default. The opt-out restores the old accounting exactly. |
| D9 | Uses the record's `pkg/id.ID` as the API key identifier | 16 random bytes in base64url | Settled: library-owned records use `pkg/id.ID`. The identifier is not a secret. |
| D10 | Prefixes presented API keys (`sk_` by default, configurable) | An unprefixed `id.secret` | Settled: keys are prefix-identifiable. |
| D11 | Requires an absolute `https` link base URL (loopback `http` allowed) at construction | An empty default that produces a host-relative link | Settled: wiring mistakes fail at construction. A host-relative link in an email cannot be followed, so the empty default was broken. The `https` rule is the same one already applied to redirect origins. |
| D12 | Requires STARTTLS by default, with opportunistic TLS as an explicit option | Opportunistic STARTTLS by default | Settled: safe defaults, where the safe choice is the default and the convenient one an option. The messages carry live sign-in links, and opportunistic STARTTLS can be stripped by an on-path attacker. |
| D13 | Fails construction on a missing SMTP host or a non-positive timeout | Failing at send time, and silently ignoring a non-positive timeout | Settled: wiring mistakes fail at construction, and limits on flexibility are never silently relaxed. |
| D14 | Encodes non-ASCII subjects | Writing raw UTF-8 into the header | Defect: RFC 5322 header fields are ASCII without SMTPUTF8, so raw bytes can be mangled or rejected. |
| D15 | Lets a session with a pending MFA challenge reach the logout endpoint, which deletes it | The pending gate refusing every request but verify. The gate's slot is outside logout's, so a user mid-challenge cannot sign out. | Defect: a user stranded mid-challenge cannot end their session, for example on a shared device. |

Everything else follows the established behaviour, including:
- enumeration-safe requests;
- check-then-consume redemption with checks returned unchanged;
- the nil-reason deny and the post-success guard;
- constant-presence binding cookies;
- POST-only consumption;
- exact-match redirects;
- the per-source limits (10 per 15 min, 20 per min);
- the single SMTP deadline;
- the queued sender's drop-on-full behaviour;
- opaque API key failures, best-effort last-use and non-atomic rotation outside a transaction.

### 14. Test-first throughout

- **`notify`:**
  - table tests for header refusal and construction errors;
  - a scripted in-process SMTP server for greeting stalls, deadline across dial, cancellation, a STARTTLS offer that cannot handshake, and server rejections;
  - a testcontainers SMTP server helper in the `test` module for delivery, auth and encoding;
  - `testing/synctest` and `goleak` for the queued sender.
- **`mfa`:**
  - the RFC 6238 Appendix B vectors;
  - step boundaries under an injected clock;
  - replay and a 16-goroutine race on `AcceptStep`;
  - enrolment begin, confirm, replace and already-enrolled;
  - throttle with a mock limiter, and a limiter error;
  - an end-to-end fail-closed test (deleted enrolment and failing store, for a required user).
- **`magiclink`:**
  - uniformity table across every request branch, with the same result and no send;
  - redemption ordering with a counting store, asserting no consume on each refusal;
  - a racing redemption test;
  - the reissued-username case.
- **`httpsec`:**
  - a non-conforming redeemer that discards a deny, and one that never runs checks, each written first and seen to fail by removing the guard;
  - rate-limit accounting with the opt-out on and off;
  - decoy cookie shape;
  - redirect validation tables;
  - API key interceptor tables;
  - MFA verify endpoint, including same-channel before code read and handle rotation.
- **`apikey`:** issue, verify, revoke and rotate tables; prefix parsing; rotation rollback inside a transaction against the conformance suite.

Each group ends with a `/simplify` pass and a re-run.

### 15. What implementation corrected in these artifacts

The decisions above were written before the code they describe. Implementation found them wrong in
places. The code is right and these artifacts are now corrected; this section records what moved, so
that a later reader does not "fix" the code back towards an earlier draft.

**Vocabulary.** `factor` owns the first-factor and channel vocabulary and imports nothing, so the
snippets' `identity.Channel` is `factor.Channel`, first-factor kinds are `factor.Kind`
(`factor.Password`, `factor.MagicLink`, `factor.APIKey`, `factor.Basic`, `factor.OIDC`), and the
authenticator-app channel is `factor.AuthenticatorApp`.

**Ports that already existed.** Decision 4 proposed a new `mfa.EnrolmentLookup`. It was not needed:
`policy.MFAMethodLookup` already exists with `Enrolled` plus `Channel`, and its godoc already pins
the contract decision 4 describes — "a store failure, or a stored secret that will not decrypt, is an
error, never a false". `mfa.LookupFor` therefore **adapts** a `Method` to that port and declares no
new one. Likewise decision 10's redirect helper: `internal/origin.Allowlist` already validates
entries and declared origins and resolves a requested target, so `httpsec` reuses it rather than
growing a private copy, and `oidc-login` will reuse the same one.

**Field and function names the snippets got wrong.** `identity.Details`'s reference field is `ID`,
not `UserID`; its active flag is `Active`, not `Enabled`. `identity.Principal`'s display name is
`Name` — there is no `DisplayName`. `pkg/id` has no package-level `New()`; identifiers come from
`id.Generator.NewID()`. `session.Store.Save` never inserts, so `Rotate` writes with `Create`.
`Exchange`'s writer is `Writer`, not `ResponseWriter`, and its client address is `ClientIP()`.
`ErrAuthenticationFailed` belongs to `authenticate`, not `httpsec`. The module layout guard is
`TestModuleLayout`, and the identity port guard is `TestIdentityShipsNoPortImplementation` — three
artifacts named a `TestLayoutGuard` that does not exist, so the command they gave matched nothing and
passed vacuously.

**Options the design did not name but the design's own code required.** `httpsec` needed
`WithMFATokens` and `WithMagicLinkTokens` (both required — the library ships no signing key, and an
endpoint that cannot issue a credential cannot complete a login), `WithMagicLinkSessions`,
`WithMagicLinkRedeemer`, `WithMagicLinkChecks`, and the `Default*` path, scheme and cookie-name
constants that match `DefaultLoginPath` and `DefaultLogoutPath`. `notify` needed `WithSMTPTLSConfig`
(a private certificate authority is a real deployment, and required STARTTLS cannot be tested
against a self-signed server without it), `WithSMTPDialer` and the logger options. `apikey` and
`magiclink` each needed `WithLogger` and `ErrConfig`, following the convention eleven other packages
already share. `magiclink` also needed `WithRandom` and the exported `BindingNonceLength`.

**Option names that had to differ between packages.** Decision 6 names `WithMFAVerifyLimiter` and
`WithMFALogInterval`; those are the `httpsec` names, and they forward to `mfa`'s own
`WithVerifyLimiter` and `WithVerifyLogInterval`. One name per subsystem, as the project's option
rule requires.

**Where the artifacts contradicted each other, and what was chosen.**

- *The binding nonce.* Decision 8 said every `Request` branch returns "the same empty result" while
  decision 10 had the interceptor synthesising a decoy. With binding enabled, `Request` now always
  returns a nonce of `BindingNonceLength` — genuine when a link went out, a fresh decoy otherwise,
  drawn **before** the address is resolved so the result cannot depend on anything learned
  afterwards. The interceptor synthesises nothing and holds no decoy branch. This closes the channel
  in the package that owns the secret rather than trusting every caller of `Request` to remember the
  decoy, which is decision 8's own argument for refusing a synchronous sender, applied again.

- *Limiter sharing.* Corrected in decision 11 above, with the test that proves it.

**The MFA throttle logs to `slog.Default()`,** not to a discarding logger. A default that silently
drops security-refusal records is not the safe default this project requires, and `policy` and
`ratelimit` already log there. Silence remains available, but a consumer must ask for it explicitly,
which makes the silence visible at the wiring.

**`mfa.VerifyThrottleKey` is exported.** A consumer who supplies a shared limiter needs to name the
bucket these failures land in — to read it, or to clear it after an administrative unlock — and a
well-known key belongs in a documented contract rather than a string a consumer has to guess. It is
`VerifyThrottleKey` and not `Key` because `apikey.Key` is a record type in a package consumers import
alongside this one.

**A policy that does not implement `policy.Challenger` is taken to raise no challenges.** Decision 14
below rests on that reading; it is recorded on the interface itself.

### 16. The three prerequisite APIs this change added

The archived `sessions` and `identity-model` capabilities did not ship three things these specs
require. Nothing is tagged, so they are additive. Each was added to the package that owns the
concept, not to this change's own packages:

| Added | Where | Required by |
|---|---|---|
| `Session.MFASatisfiedAt time.Time` | `session` | "records the second-factor-satisfied time". It is library-owned, so it sits beside `MFA` rather than in consumer `Data`, which a consumer could otherwise forge. |
| `(*session.Manager).Rotate` | `session` | D5, session fixation. Rotation belongs to the manager that owns identifiers and the store, not to the HTTP layer that asks for it. |
| `identity.UserLoader.LoadByUserID` | `identity` | D7. A link records a user reference, so redeeming it must load by that reference; loading by username is what D7 exists to prevent. |

**`Rotate` decides a race with a presence check and an in-process keyed lock.** The `Store` port
cannot express "the delete found nothing": `Delete` returns no count, and its contract states that
deleting an absent session is not an error. Reporting it would mean changing a public interface this
change has no mandate to change. The lock is keyed by session identifier, not held per manager, so
rotations of different sessions do not serialise — `Rotate` runs on every successful second factor,
and in durable mode it spans three store round-trips. The guarantee is therefore **within one
process**: two managers over one shared durable store can still both rotate the same handle, and a
consumer needing that across replicas enforces it in the store's delete. `Rotate`'s godoc says so.

**Reported, not acted on:** the archived `sessions` and `identity-model` specs now understate their
packages by exactly these three APIs. This change does not edit archived specs.

### 17. What this change could not close

**API key rotation is not atomic outside a transaction.** `Rotate` issues the new key, then revokes
the old one: two writes. The spec scenario that demands a failed revoke roll the whole thing back
needs a `Store` that can carry a caller-attached transaction, and none exists until
`durable-persistence` lands. `UNREPRODUCED` — there is no code to reproduce it against. What ships
is tested: the new key verifies, the old one fails, an unknown key issues nothing, and a failed
revoke returns an error naming **both** identifiers so an operator knows which key to revoke by hand,
with the old key still live. `Rotate`'s godoc states the limit.

**Flagged to `durable-persistence`:**
- the MFA enrolment table needs `confirmed_at` and `last_step` columns beyond the sealed secret;
- an API key table matching `apikey.Key`;
- three `store-conformance` scenarios these ports depend on and that no in-memory store can prove
  for a real backend: `AcceptStep`'s conditional write, `PutPending`'s already-enrolled decision
  being made **by the write**, and API key rotation's atomicity inside an attached transaction.

**Flagged to `identity-model`:** `LoadByUserID` is the one `identity.UserLoader` method the
`identitytest` conformance suite does not pin, so a consumer store could trim or case-fold a
reference and still pass. D7's guarantee is tested in `magiclink` against that package's own loader,
so this change's behaviour is covered; the *port contract* is not. A conformance case belongs with
whichever change next touches that suite.

**`PostAuthentication` is evaluated twice on the magic-link path**, as decision 9 records. Policies
are not pure in practice — `policy.MFARequirement` reaches a store through `Enrolled` — so each
magic-link sign-in costs a duplicate enrolment lookup.

### 18. Claims raised during implementation

Each was found while reviewing this change's own code, and each is labelled per the project's rule on
defect claims. None was fixed under cover of the simplification pass; the two that fell inside this
change's own packages were closed afterwards, test-first, as tasks 17.1 and 17.2. The rest are
recorded because the next change to touch those areas should start from them.

**Closed here.**

- **`mfa.VerifyThrottle.RecordFailure` abandoned a recorded failure when the caller went away.**
  `ratelimit.Limiter`'s contract says implementations should expect a cancellation-stripped context —
  "a client that hangs up mid-attempt must still be charged for the guess it made" — and both
  `ratelimit.SourceGuard.RecordFailure` and `httpsec`'s source recorder honour it. This one passed
  the live request context straight through, and the verify endpoint hands it the request's own.
  Invisible with the built-in in-memory limiter, which ignores the context entirely; a
  consumer-supplied networked limiter — precisely what `WithMFAVerifyLimiter` exists for — would
  fail to count a guess from a client that hung up, handing an attacker a free retry against the
  throttle D4 exists to impose. **REPRODUCED** by task 17.2's red step and closed with
  `context.WithoutCancel`.

- **`notify`'s senders defaulted to a discarding logger**, while section 15 records that a default
  which silently drops records is not the safe default this project requires. A dropped queued
  message is a sign-in link that never arrives, and `Send` has already returned nil, so the failure
  was invisible at both ends. The two defaults sat inside one change and one of them was wrong. Not a
  defect — a default that contradicted the change's own stated rule. Closed as task 17.1: both
  senders now report to `slog.Default()`, and silence is available but must be asked for.

**Left open, for the changes that own them.**

- **UNREPRODUCED — `httpsec.WithIPv6SourcePrefix` and `WithRateLimiter` reach none of this change's
  flows.** `config.ipv6Prefix` and `config.limiter` are copied onto `Chain` and read by nothing in
  production. The magic-link and API-key guards this change added build their own limiters with the
  default `SourceKeyer`, so a consumer who narrows IPv6 keying or supplies a fleet-wide limiter at
  chain level gets it applied to nothing — with no error and no log, while both options' godoc
  describes behaviour that does not happen. This is a `library-design` rule 2 and 4 problem: an
  override point that silently does nothing. It appears to predate this change, which merely brought
  the first flows that could have honoured it. Unreproduced because the fix is a design decision —
  which flows honour chain-level settings — rather than a repair.


- **UNREPRODUCED — the unenforced-challenge refusal covers only `ChallengeMFA`.** Decision 14's
  argument is that a challenge nothing enforces marks sessions that are then served anyway, silently.
  That argument holds word for word for `ChallengePasswordChange`, which `policy`'s password-age
  policy raises and which only the opt-in password-change gate enforces, while the chain marks the
  session pending either way. The check now has the mechanism to cover both — `Challenger` is
  implemented by the password-age policy — and covers one.

- **UNREPRODUCED — the password-change gate has no logout exemption.** D15 established that a caller
  stranded mid-challenge must still be able to end their session, because on a shared device that is
  the one thing they most need to do. The MFA gate exempts logout; the password-change gate, which
  sits outside logout's slot, does not. The two gates disagree about the same question.


- **Library-design gap, not a defect:** the magic-link endpoints hard-code their form parameter names
  and borrow `DefaultLoginBodyLimit` for a bound no option can set, where form login — the endpoint
  they were modelled on — makes all four replaceable.

## Risks / Trade-offs

- [The durable enrolment table defined by `durable-persistence` holds only the sealed secret] → This change needs `confirmed_at` and `last_step` columns. Squashing into the initial migration is free before the first tag. It is flagged to `durable-persistence`.
- [`durable-persistence` also owes this change an API key table matching `apikey.Key`, and three `store-conformance` scenarios] → `AcceptStep`'s conditional write, `PutPending`'s already-enrolled decision being made by the write, and API key rotation's atomicity inside an attached transaction. The first two are contracts an in-memory store satisfies trivially and a real backend may not; the third is the scenario this change could not close at all (section 17). Flagged.
- [`LoadByUserID` is not pinned by the `identitytest` conformance suite] → A consumer store could trim or case-fold a user reference and still pass, while D7's guarantee depends on byte-for-byte matching. This change's own behaviour is covered by `magiclink`'s tests; the port contract is not. Flagged to `identity-model`.
- [The archived `sessions` and `identity-model` specs now understate their packages] → By `Session.MFASatisfiedAt`, `session.Manager.Rotate` and `identity.UserLoader.LoadByUserID` (section 16). Reported, not edited: archived specs are not this change's to rewrite.
- [A consumer policy that can challenge but does not implement `policy.Challenger` is invisible to the wiring check] → Decision 14's refusal covers the library's own policies and any consumer policy that opts in. Enforcement for a silent consumer policy is the consumer's. The alternative — reading silence as "may raise anything" — would refuse working deployments, and a check that does that is one consumers disable.
- [An attacker holding a user's password can lock them out of MFA verification for 15 minutes] → Documented. The limiter is replaceable, and the window is a per-flow option.
- [Requiring MFA for all locks out unenrolled users] → Documented on the option and in the README. It is closed by `mfa-enrolment-path`.
- [The magic-link request still does store work only for real accounts] → A small timing difference remains after the queued sender. It is documented, and a constant-work decoy path is left for later.
- [Counting refused redemptions by default can throttle a user repeatedly refused by policy from one shared address] → The limit is per source and short. The opt-out exists, and the refusal reason still reaches the consumer so the user can be told what to fix.
- [A queued sender loses messages still queued at a crash or a missed `Close`] → Documented. A consumer needing durable delivery supplies a queue-backed `Sender`.
- [API keys without a lifetime never expire] → Documented on `Issue`. Revocation is immediate, and `LastUsedAt` supports finding stale keys.
- [Synchronous `LastUsedAt` writes add one store write per API request] → Accepted for now. A throttled write is a later option if latency shows it.
- [The in-memory limiters multiply by the replica count] → A documented limit of `rate-limiting`, closed by `shared-rate-limiting`.
- [`pquerna/otp` pulls `boombuler/barcode` into the module graph] → It is not a framework, driver, scheduler or DI container, so the guard allows it. Replacing the dependency with scrty's own RFC 6238 code later touches only `mfa`.

## Migration Plan

Not applicable: a new library with no consumers and no tags.
