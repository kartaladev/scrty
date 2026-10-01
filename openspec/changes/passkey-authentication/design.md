# Design

## Context

See proposal.md for why. The current state that shapes the approach:

- **The MFA slot already has a challenge method contract.**
  - `mfa.ChallengeMethod` adds `BeginChallenge(ctx, user, challenge) (json.RawMessage, error)` and `PresentedChallenge(response) (string, error)` to `mfa.Method`.
  - `mfa.JSONBody(limit)` declares a JSON response read by the library.
  - The slot issues the challenge as a one-time token bound to the session handle (TTL 5 minutes, `DefaultMFAChallengeTTL`, limit 10 per hour, `DefaultMFAChallengeLimit`). At verify it spends the challenge on every attempt before `Verify`, recording a failure for any error (`httpsec/mfaverify.go`).
  - The passkey second factor therefore needs no endpoint of its own.
- **Policy input.**
  - `policy.Input.MFASatisfied` is a plain claim. The second-factor challenge policy honours it in the post-authentication phase (`policy/mfa.go`).
  - The requirement policy honours it only per request (`policy/mfarequirement.go`, step 5).
  - Bearer sets it from `s.MFA == session.MFASatisfied`.
  - Nothing today lets a login prove at the post-authentication phase that its first factor met the second.
- **The login tail.** `httpsec.completeLogin` evaluates the phase (or takes a decision already made), creates the session with `session.WithFirstFactor`, marks any challenge, saves, mints the token, and publishes. It takes the caller's own `session.CreateOption`s, applied in the creating write.
- **The enrolment path.**
  - The requirement policy enters it only through a method whose `SupportsEnrolmentPath()` is true (`policy/enrolmentpath.go`).
  - The enrolment gate has no option to let further routes through.
  - Its email confirmation (`WithoutEmailConfirmation`), confirmation limiter, notification and contact resolver are `EnableMFAEnrolment` options.
- **Recovery** (archived 2026-10-01).
  - `recovery.AuthenticatorKind{Kind, Held, Remove}` is the reset port.
  - `recovery.NewWayBackCheck(WayBackDeps{Users, Codes, Kinds, IssuedCodes, LinkedLogins, Exempt})` counts any held authenticator of any kind.
  - `(*recovery.Codes).Generate` replaces a set and returns it once, and `Confirm` checks without spending, throttled per user.
  - The recovery gate's exemptions are fixed in code. Its requirement says a capability that binds authenticators adds its endpoint.
- **One-time tokens.**
  - `onetime.NewManager(purpose, …)`: `Issue(ctx, subject, WithBinding(v))` returns `<id>.<base64url secret>` with a 32-byte secret, `Check(ctx, presented, binding)` writes nothing, and `Consume` is atomic.
  - `IssuedCount` counts per subject over the issuance window.
  - A subject is required.
- **The magic-link binding cookie** is the precedent for a cookie that ties a one-time token to a browser: HttpOnly, Secure, SameSite Lax, scoped to the redemption path, with the link's lifetime.
- **Secrets at rest.** Durable MFA enrolment stores take a `seal.Cipher` at construction and seal the emailed code with an AAD naming the generation and user (`seal.MFAEmailCodeAAD`).
- **Migrations.** One security-state file, edited in place while nothing is tagged (recovery-codes D15). `test/migrate_securitystate_test.go` pins the table list.
- **The established design had no WebAuthn.** Everything here is new, and no decision departs from established behaviour.
- **The WebAuthn library.** `github.com/go-webauthn/webauthn` v0.18.2 (latest on 2026-10-01) declares `go 1.26.0`, which is within scrty's floor. It needs CBOR, JWT, TPM and UUID modules.

## Goals / Non-Goals

**Goals:**
- One core package, `passkey`, that owns the ceremonies, the credential and handle ports, the pending and suspended states, the clone rule, notices and the recovery kind. `httpsec` only reads, gates and responds. The WebAuthn library sits behind one port, in one nested module.
- The passkey second factor rides the existing MFA slot unchanged in shape. The slot stays the only resolver of a raised MFA challenge.
- A user-verified passkey login meets the second factor through a proof only library code can create, recorded on the session in its creating write.
- Every state change a race could corrupt is decided by a conditional write: duplicate credential IDs, the counter, pending reasons, emailed-code attempts and handle assignment.

**Non-Goals:**
- Username-first passwordless login, which lists allowed credentials for a typed username. It leaks which usernames exist and which credentials they hold (WebAuthn L3 §14.6.2). Non-discoverable credentials serve as a second factor only.
- Passkey as a recovery proof. A recovery has no session to bind a begin step to (recovery-codes D4).
- Conditional mediation (autofill UI) specifics, Related Origin Requests and cross-origin iframes. The defaults leave them off (the library's `RPAllowCrossOrigin` stays false). A consumer serving several origins lists them in the allowed origins.
- FIDO certification of scrty itself.
- Rendering. Every response is data, or a bare status by default.

## Decisions

### D1. Packages and the verification port

```go
package passkey // core module

type RelyingParty struct{ ID, Name string; Origins []string }

// Verifier is the only seam to WebAuthn parsing and verification.
type Verifier interface {
    RelyingParty() RelyingParty
    CreationOptions(ctx context.Context, in CreationInput) (json.RawMessage, error)
    RequestOptions(ctx context.Context, in RequestInput) (json.RawMessage, error)
    ParseRegistration(body []byte) (ParsedRegistration, error)
    VerifyRegistration(ctx context.Context, p ParsedRegistration, exp RegistrationExpectation) (*NewCredential, error)
    ParseAssertion(body []byte) (ParsedAssertion, error)
    VerifyAssertion(ctx context.Context, p ParsedAssertion, c *Credential, exp AssertionExpectation) (*AssertionResult, error)
}
type ParsedRegistration interface{ Challenge() string; CredentialID() []byte; Name() string }
type ParsedAssertion   interface{ Challenge() string; CredentialID() []byte; UserHandle() []byte }

func New(deps Deps, opts ...Option) (*Manager, error)
```

- **Layout.**
  - The core package `passkey` holds the ports, the record types, the `Manager` that runs the ceremonies, the MFA method, the recovery kind and the in-memory stores.
  - The nested module `github.com/kartaladev/scrty/passkey/webauthn` implements `Verifier` over go-webauthn. It lives in the directory `passkey/webauthn` with its own `go.mod`, so Go excludes it from the core module. This was the user's decision (2026-10-01): the core needs the package path `passkey`, and a nested module at `passkey/` would take that import path.
  - The package `passkey/webauthn/webauthntest` holds a software authenticator for tests (D20).
- **No library type escapes.** The parsed values are interfaces. The adapter's concrete types are unexported and type-asserted back inside `Verify*`, so a go-webauthn breaking release touches only the adapter (proposal, Library Choice).
- **One source for the relying party.** `passkey.New` reads `Verifier.RelyingParty()` and validates it as the spec requires. The adapter's constructor `webauthn.New(rp, opts…)` validates it too, so both fail at construction.
- **Default:** a consumer wires `webauthn.New(...)` as `Deps.Verifier`. There is no in-core default, because the core carries no WebAuthn dependency.
- **Override:** any `Verifier`. Its godoc states that a replacement is trusted exactly as the library's own: its `AssertionResult.UserVerified` decides whether a login meets the second factor (D10).
- **Alternatives rejected:**
  - A top-level `webauthn` module. Its package name collides with go-webauthn's own `webauthn` package (user's decision).
  - Putting the ports in the nested module. `httpsec` in the core needs them.

### D2. Kind and channel

- `factor.Passkey` is `"passkey"`. `factor.PublicKey` is the channel `"public-key"`, named after WebAuthn's credential type `public-key`.
- The kind is not exempt.
- The passkey MFA method reports the same channel. The existing same-channel rules (the usable-methods function, the verify endpoint and the challenge policy) therefore stop a passkey from serving as the second factor of a passkey login, with no new code.
- **Override:** none, because the vocabulary is closed (`identity-model`). A consumer's own exemption rule still applies to the kind, as to any.
- **Alternative rejected:** reusing `authenticator-app`. TOTP after a passkey login would then be refused as the same channel.

### D3. The credential record, its states and the handle

```go
type State uint8 // Active, Pending, Suspended
type PendingReason uint8 // bit set: AwaitingSavedCodes | AwaitingEmailCode

type Credential struct {
    ID           id.ID          // library identifier
    User         identity.UserID
    CredentialID []byte         // WebAuthn credential ID, ≤ 1023 bytes
    PublicKey    []byte         // COSE_Key
    SignCount    uint32
    BackupEligible, BackupState bool
    Transports   []string
    AAGUID       []byte         // 16 bytes or nil
    AttestationFormat string; AttestationStatement []byte // record mode only
    Name         string
    CreatedAt, LastUsedAt time.Time
    State        State
    Pending      PendingReason
    EmailCode    *EmailCode     // sealed at rest; expiry; attempts
}
```

- **State.**
  - A credential is pending while any reason bit is set.
  - Clearing the last bit makes it active, in the same conditional write.
  - Suspension is terminal (D13).
- **Ports.**
  - `CredentialStore` implements every operation the `security-state-stores` requirement lists.
  - `HandleStore` provides `Assign(ctx, user, offered []byte) ([]byte, error)` and `UserFor(ctx, handle) (identity.UserID, bool, error)`.
- **Handle.**
  - 64 bytes from `crypto/rand`, as WebAuthn L3 §14.6.1 recommends.
  - It is assigned at the first registration begin with insert-if-absent, so concurrent first registrations agree.
  - It is never deleted with credentials, so a re-registration after losing every passkey overwrites the authenticator's old entry.
- **Name.** A trimmed name of up to 64 characters with no control characters. The default name is `Passkey <YYYY-MM-DD>`.
  - **Decided during implementation:** format characters (Unicode category Cf: bidirectional overrides, zero-width characters) are refused too. The name is chosen by whoever holds the session, possibly an attacker, and it is quoted in the binding, removal and suspension notices the user relies on to object (security audit, reproduced). The cost: the zero-width joiner is a format character, so an emoji sequence joined by it (such as 👩‍💻) makes the name fall back to the default; single emoji and variation selectors are kept. A clear notice outweighs a decorative name.
- **Default:** in-memory stores, with godoc stating the single-process limit.
- **Override:** `Deps.Credentials`, `Deps.Handles`, or the durable stores (D19).
- **Alternative rejected:** keeping the handle on credential rows. Two concurrent first registrations would mint two handles, and a user with no credentials would have nowhere to keep one.

### D4. Ceremony challenges are one-time tokens

- **Managers.**
  - Registration uses `onetime.NewManager("passkey-registration", WithTTL(5m))`. Its subject is the user and its binding is the session handle.
  - Passwordless login uses `"passkey-login"`. Its subject is the constant `"passkey-login"` and its binding is the ceremony cookie value (D5).
  - The second factor uses the MFA slot's own manager, unchanged.
- **The challenge.** The challenge is the token string's UTF-8 bytes. The client returns it base64url-encoded in `clientDataJSON.challenge`, and `PresentedChallenge` decodes it. The token's 32-byte secret is above the 16 bytes WebAuthn L3 §13.4.3 asks for.
- **Spent on every attempt.** Finish runs `Check` and then `Consume` before verification, as the MFA slot's `spendChallenge` does.
  - This departs from the check-then-consume rule on purpose, as `mfa-multi-method` already decided for challenges: a challenge is the server's nonce for one attempt, not a credential the user holds.
  - It also settles races, because exactly one consumer proceeds.
- **The rest of the ceremony** is rebuilt from configuration and the stores: the relying party, origins, user-verification requirement and allowed credentials. Nothing is read from the client except the response itself (GHSA-gjjc-pcwp-c74m).
- **Defaults and overrides.**
  - TTL: 5 minutes, the recommended default in WebAuthn L3 §15.1. Replaced by `passkey.WithChallengeTTL(d)`; zero or less is refused.
  - Registration issuance: 10 per hour through `IssuedCount`. Replaced by `passkey.WithRegistrationChallengeLimit(n)`; below 1 is refused.
  - Store: in-memory. Replaced by `Deps.Challenges onetime.Store`.
  - Expired login tokens are purged at most once per TTL, inside a begin. A failed purge does not refuse the begin.
- **Alternative rejected:** go-webauthn's `SessionData` held server-side in a table of its own. It would be a second single-use store with its own conformance surface, and it carries library types.

### D5. The passwordless ceremony cookie

- **Value.** 32 random bytes, base64url-encoded. The token is issued `WithBinding(value)`.
- **Attributes.**
  - `HttpOnly; Secure; SameSite=Strict`.
  - `Path=<finish path>`.
  - `Max-Age` equal to the challenge TTL.
  - Strict rather than the magic link's Lax, because both requests are same-site `fetch` calls and no cross-site navigation ever carries this cookie.
- **Name.** `passkey_ceremony` by default, replaced by `httpsec.PasswordlessCookieName(name)`.
- **Cleared** on every finish response, accepted or refused, with `Max-Age=0` and the same path.
- **Why a cookie at all.** Begin runs before there is a session, so the challenge needs something to bind it to the browser that asked for it. Otherwise a challenge harvested from one client could be answered from another.
- **Override:** the name only. Binding has no opt-out. Unlike the magic link, where an emailed link may legitimately open on another device, a passkey ceremony always starts and finishes in one browser.

### D6. Who may register: assurance and freshness

- **Full sessions.**
  1. If `policy.UsableMFAMethods(methods, user, s.FirstFactor)` is non-empty, `s.MFA` must be `MFASatisfied`. This is NIST SP 800-63B-4 §4.1.2.1's binding rule: authenticate at the highest AAL available in the account. A lookup error refuses.
  2. Freshness: `now - max(s.CreatedAt, s.MFASatisfiedAt) <= window`. This was the user's decision (2026-10-01), with the same rule and default as recovery-code regeneration. A user-verified passkey login sets `MFASatisfiedAt = CreatedAt`, so it starts fresh.

  Either failure is `passkey.ErrReauthenticationRequired` (403).
- **Confined sessions.** `MFARecoveryPending` and `MFAEnrolmentPending` sessions skip both checks. The recovery is their authentication, the enrolment-only user has no usable factor (AAL1), and both live at most 15 minutes.
- **Removal** applies the same two checks. Renaming and listing do not, because they change no authenticator.
- **Default:** a window of 15 minutes.
- **Override:** `passkey.WithManagementFreshness(d)`, where zero or less is refused. It governs registration and removal, which are the same subsystem.
- **Why the window is not GitHub's two hours.** A registered passkey is a lasting credential that later meets both factors. A stolen session must not be able to plant one, and the binding notice only reports it after the fact.
- **Decided during implementation: the chain supplies the configured methods** (user's decision, 2026-10-01, after the final review reproduced the gap).
  - **The gap.** The manager decided the assurance rule over `Deps.MFAMethods` alone, which a consumer may leave empty, and the chain never reconciled it with the MFA slot. A chain with `EnableMFA(totp)` and no `Deps.MFAMethods` let a session that still owed TOTP register a passkey, which then met both factors at login. The passkey method itself could never be listed there, because it exists only after the manager.
  - **The rule.** `RegistrationContext` gains `MFAMethods`, and `BeginRegistration`, `FinishRegistration` and `Remove` all take a `RegistrationContext`. `httpsec` fills it with the MFA slot's methods, including the passkey method when it is on the slot, on every request. The manager decides admission over `rc.MFAMethods` when it is non-empty, and over `Deps.MFAMethods` otherwise.
  - **Default:** inside the chain, the slot's methods, with no configuration. **Override:** a direct caller of the manager passes its own `RegistrationContext`, or relies on `Deps.MFAMethods`.
  - **Alternative rejected:** refusing at assembly when a slot method is missing from `Deps.MFAMethods`. It makes the consumer wire the methods twice, and the manager would still have to count its own passkey method unconditionally, which would lock passkey management for a user whose chain has no passkey method on the slot.
- **Decided during implementation: the user's own passkeys count** (user's decision, 2026-10-01, after the security audit reproduced two gaps). This amends how rule 1 measures the account's assurance; the rule itself stands.
  - **The gaps.** Rule 1 asked only whether a *configured MFA method* was usable against the session's first factor. A passkey login without user verification (under `UVPreferred`) is single-factor and gets no proof, yet the same-channel filter dropped the passkey method, so the session was admitted: a stolen security key without a PIN could bind a user-verifying passkey and remove the victim's. And with no MFA slot, a password session of a user holding a passkey was admitted, although that user's passkey login meets both factors.
  - **The rule.** For a full session, the user's own active passkeys count as a second factor the account has, with no channel filter, whenever a passkey route can meet the second factor: the passkey MFA method is among the admission methods, or passwordless login is enabled and mints proofs (`WithoutSecondFactorAtLogin` not set). `RegistrationContext` carries whether the chain has passwordless login enabled, and the chain sets it. Such a session must then be `MFASatisfied`. A password session steps up through `/mfa/verify/passkey`. A session whose first factor is a passkey cannot, since its passkey shares the first factor's channel: the user signs in again with user verification, or by password and then the passkey step-up.
  - **Lookup failures and bad input.** A failed listing of the user's passkeys refuses with fixed text, as a failed MFA lookup does. A nil entry in `RegistrationContext.MFAMethods`, typed nil included, refuses the call with `ErrConfig`: it is a direct caller's wiring mistake that the chain cannot produce, and it fails closed rather than panicking on the request path.
  - **An accepted limit, failing closed.** Only with three non-default choices together (`WithoutSecondFactorAtLogin`, the passkey method on the MFA slot, and a policy that completes a passkey-first session without a second factor) can a passkey login leave a session that owes a step-up it cannot take. A user with a password still reaches passkey management through a password login and the passkey step-up; a user without one cannot manage passkeys from such a session. Admitting it instead would let a single factor bind a credential while the account has a two-factor route, against NIST SP 800-63B-4 §4.1.2.1, so the refusal stands (found in the final review, reproduced; decided at close-out, open to the user's review).
  - **Identity, not name.** The passkey method counts as a route only when it is this manager's own `MFAMethod` value. The chain passes the slot's methods through unwrapped. A consumer who decorates the method on the slot loses this route, and the godoc says so; the passwordless route and the configured-method check are unaffected.
  - **Why only when a route exists.** With no route, a passkey can meet no second factor, and counting it would leave its holder unable ever to manage passkeys from that chain.
  - **Default:** as stated, with no configuration. **Override:** none on the rule itself. Binding at the account's highest assurance is what NIST SP 800-63B-4 §4.1.2.1 requires, and relaxing it would let a single factor plant a credential that later meets two. A consumer's freshness window remains replaceable.
- **Decided during implementation: who is admitted.** A session with a pending password change is refused like any other pending challenge, by the manager as well as by the chain's password-change gate. The endpoints refuse a request whose session carries no resolved caller as authentication required, as the MFA verify endpoint does.

### D7. Registration finish order and pending reasons

The core implements `(*Manager).FinishRegistration(ctx, s *session.Session, body []byte, rc RegistrationContext)`. `RegistrationContext` carries whether the enrolment path's email confirmation applies (D8). The steps run in this order:

1. Parse the body. A parse failure reads as missing credentials.
2. Spend the challenge, bound to the session and the user.
3. Verify against the relying party and the user-verification setting. The attestation policy runs in the adapter (D14).
4. Run the consumer's registration check (`WithRegistrationCheck`). Its error is returned unchanged.
5. Count the user's credentials, refusing at the limit (25 by default, `WithPasskeyLimit(n)`, below 1 refused).
6. Decide the pending reasons:
   - **AwaitingEmailCode** when the session is enrolment-pending and the path's email confirmation is on.
   - **AwaitingSavedCodes** when codes are wired (`Deps.Recovery`), the optional mode is off, and `WayBackCheck.HasWayBack` reports no. A check error refuses.
7. Delete any credential of the user still awaiting saved codes, when the new one awaits them too, and any credential still awaiting an emailed code, when the new one awaits one too. This makes the abandoned registration replaceable, and it is the only way to replace a lost or expired emailed code, since there is no resend. The manager lists and deletes; a concurrent finish for the same user may leave an extra pending credential, which the next registration removes.
8. If AwaitingSavedCodes is set, generate codes.
9. If AwaitingEmailCode is set, generate the 6-digit code and queue it. A refused queue fails the finish before the insert.
10. Insert. A duplicate credential ID is the authentication-failed refusal.
11. If the credential is active: queue the binding notice, and move a confined session to `MFAPending` (D8).
12. Return the result: whether it is pending and why, the codes once, `backupEligible`, `noSyncedPasskey`, and `recoveryNotSetUp` in the optional mode.

- **Why codes are generated before the insert.** A failed generation must not leave a credential awaiting codes that were never shown.
- **The cost of that order.** If the insert then fails, the user's previous set has been replaced by codes they never saw. The user retries, and the retry generates again. This matches the "Minting fails after a reissue" risk accepted in recovery-codes.
- **Confirm endpoints.**
  - **`/passkey/register/confirm`:** `Codes.Confirm(ctx, user, code)`, which is throttled per user, then `ClearReason(credID, AwaitingSavedCodes)`. The credential is the user's only one awaiting saved codes; none is a refusal.
  - **`/passkey/register/confirm-email`:** follows `security-state-stores`' charge, compare and clear write order, with the enrolment path's confirmation limiter (`EnrolmentConfirmThrottleKey`).

  A clear that activates the credential runs step 11.
- **An abandoned registration still awaits codes** (decided during implementation). While the user holds a credential awaiting saved codes, step 6 sets AwaitingSavedCodes again without asking the way-back check. The codes generated for the abandoned registration are unspent, so the check would otherwise report a way back and activate the replacement at once, against the spec's "Abandoned registration is replaced". The cost is that a user who has meanwhile gained another way back is still asked to confirm codes, which fails safe.
- **The limit counts the abandoned credential.** Step 5 runs before step 7, so a user at the limit whose credentials include one awaiting codes is refused rather than replaced. The user removes a passkey first.
- **Finish does not repeat the admission check.** The challenge is bound to the session and issued only after admission, at most one challenge TTL earlier.
- **Saved-code confirm errors.** A wrong code (`recovery.ErrRefused`) is `mfa.ErrInvalidCode`, a throttled one is returned unchanged, and any other failure is returned as an outage, not as a wrong code.
- **Optional mode.** `passkey.WithOptionalRecoveryCodes()`. Its godoc says it allows accounts that only the operator can recover.
- **Wiring.** Passwordless login without `Deps.Recovery` and without the optional mode is `ErrConfig`, as recovery-codes decided.

### D8. Passkeys through the enrolment path and from a recovery

This was the user's decision (2026-10-01): an enrolment-only session can register a passkey, and the path's email confirmation applies to it.

- **Policy side.** The passkey MFA method implements `SupportsEnrolmentPath() bool`, returning true. The requirement policy then sends a required, unenrolled password or magic-link user to the path when only the passkey method could serve them.
- **Chain side.**
  - The enrolment interceptor counts the passkey method among its enrolling methods when it is one of the slot's methods and is not excluded by `WithEnrolmentMethods`.
  - Assembly fails when it is counted and passkey registration is not enabled.
  - The enrolment gate exempts the four registration POSTs when passkey registration serves the path.
  - The enrolment interceptor does not serve passkey paths itself. The passkey endpoints accept an `MFAEnrolmentPending` session only when the passkey method is an enrolling method.
- **Shared settings.**
  - Email confirmation follows the path's `WithoutEmailConfirmation()`, and that option's godoc now says it covers passkeys.
  - The emailed-code limiter, the contact resolver and the binding notice come from the path's configuration when the session is enrolment-pending, so one user's budget is shared.
- **The upgrade.** When a credential becomes active for an `MFAEnrolmentPending` or `MFARecoveryPending` session, the endpoint sets `s.MFA = MFAPending`, keeps `EnrolmentOriginDeadline` and `RecoveredAt`, and saves. The user then runs `/mfa/begin/passkey` and `/mfa/verify/passkey`. The verify endpoint already restores the deadlines and rotates for a marked session.
- **No AAL check on the upgrade.** The new passkey's channel (`public-key`) differs from the session's first factor (password, magic link or recovery), so it is usable at verify.
- **Recovery gate.** The gate exempts the same four POSTs when passkey registration is enabled and the passkey method is on the MFA slot, and the passkey endpoints refuse a recovery-pending session otherwise. Without the method, a passkey bound from a recovery would move the session to MFA pending with nothing able to resolve it, stranding the user (found in review, decided during implementation). `EnableAccountRecovery`'s "nothing to bind" check accepts passkey registration plus the passkey method on the MFA slot as a binding route.
- **The sender.** `RegistrationContext` carries the path's confirmation setting, contact resolver and limiter, not its sender. An enrolment-only session's emailed code and binding notice therefore go through the passkey manager's `Deps.Sender`, not `EnrolmentDeps.Sender`. A consumer wires the same sender to both.
- **Alternative rejected:** activating the passkey and making the session full at once. That would give a second resolver of the MFA challenge, against `mfa-multi-method`'s single-resolver rule.

### D9. Passwordless login

- **Begin.** `POST /passkey/login/begin` runs:
  1. the source guard (flow `passkey-login`, records every begin, 30 per 15 minutes, `httpsec.PasswordlessLimiter(l)`);
  2. a 32-byte cookie value;
  3. `Issue` bound to the value;
  4. the opportunistic purge;
  5. `RequestOptions` with no allowed credentials, user verification from configuration and timeout = TTL.

  It always sets the cookie and answers 200 with the options JSON through `PasswordlessBeginResponder`.
- **Finish.** `POST /passkey/login/finish` runs the spec's order. Steps 3–8 are core (`(*Manager).Authenticate(ctx, body, binding)`), which returns a `LoginResult{User, Credential, Proof}`. The interceptor then loads the user (`identity.UserLoader.LoadByID`) and calls `completeLogin` with `factor.Passkey` and the proof.
- **The default response** is form login's JSON credential response, and is replaceable as the form login responder is.
- **The cookie** is cleared on every outcome. The clearing header is set at the start of finish, before the body is read, since a header set after the responder has written never reaches the client.
- **Uniform refusal.** An unknown credential, a handle mismatch, a bad signature and a missing or mismatched cookie are all `authenticate.ErrAuthenticationFailed`. The pending and suspended refusals come only after the signature verifies, so a client without the private key cannot learn a credential's existence or state (found in review; the step order was changed during implementation).
- **Discoverable only.** Registration asks `residentKey: required` by default, so every passkey can sign in without a username.
  - **Override:** `passkey.WithResidentKey(passkey.ResidentKeyPreferred)`. Its godoc states that a non-discoverable credential then serves only as a second factor.
- **Slot.** A new `OrderPasskeyLogin` (380), between the one-time link slot and Basic.
- **Wiring.** Passwordless login is off by default and is enabled by `httpsec.WithPasswordlessLogin(settings…)` inside `EnablePasskeys`. It requires a token generator (`PasswordlessTokens`, defaulting to form login's) and a user loader.

### D10. The second factor met at the first factor

```go
package assurance // internal/assurance
type Proof struct{ kind factor.Kind; at time.Time } // zero value proves nothing
func New(kind factor.Kind, at time.Time) Proof      // callable only inside the module
func (p Proof) Holds() bool

package policy
type SecondFactorProof = assurance.Proof
// Input gains: SecondFactorAtLogin SecondFactorProof
```

- **Who can mint it.** Only packages of the core module can import `internal/assurance`. `passkey.Manager.Authenticate` mints one exactly when the verifier reported user verification and `WithoutSecondFactorAtLogin` is not set.
- **What a consumer can do with it.** A consumer can name the type through the alias and copy a value it was handed. It cannot create a holding one. The godoc states that copying a proof from another login is the consumer's own act.
- **Policies.**
  - The challenge policy allows when `in.SecondFactorAtLogin.Holds()`.
  - The requirement policy allows in post-authentication on it, before the usability check, so the enrolment challenge never fires for such a login.
  - Neither consults the exemption rule for it.
- **The login tail.** `completeLogin` passes the proof into the phase input. When it holds, the tail adds `session.WithSecondFactorAtLogin()` to the creating options. That sets `MFA = MFASatisfied`, `MFASatisfiedAt = CreatedAt` and `MFAAtFirstFactor = true` in the creating write, applied before any challenge mark, so a password-change challenge still marks.
- **Session.** A new library-owned field `MFAAtFirstFactor bool`, carried by `Rotate` and persisted in `sessions.mfa_at_first_factor`.
- **Stricter option** (departure from the proposal's wording).
  - The proposal places "require a separate second factor anyway" under `security-policy`. The design puts it on the passkey login as `passkey.WithoutSecondFactorAtLogin()`, which stops the proof from being minted.
  - **Why:** the proof must also decide the session's state. A policy-side option would let the tail record a satisfied session that a policy had refused to honour, for a non-required user the policies allow either way. One place decides both.
  - The `security-policy` delta states this, and both policies' godoc points to the option.
- **Alternatives rejected:**
  - Honouring `Input.MFASatisfied` in post-authentication. That is a plain claim, which `security-policy` refuses.
  - Making `passkey` an exempt kind. The user decided it is not an exemption, and a passkey login without user verification is single-factor.

### D11. User verification

- **Default:** `required` in every ceremony, and an assertion or attestation without the UV flag is refused.
- **Override:** `passkey.WithUserVerification(passkey.UVPreferred)`. It governs all three ceremonies, which are one subsystem.
- **Under `preferred`:**
  - a passwordless login without UV gets no proof (D10);
  - as a second factor, an assertion with user presence only is accepted, since a second factor proves possession.
- **Interpretation recorded.** The proposal says that with UV relaxed, "an assertion without it then never counts as satisfying an MFA requirement". The design reads this as the passkey *login* never meeting the requirement on its own. A UP-only security key after a password is the classic second factor, and refusing it would make `preferred` pointless.

### D12. The passkey MFA method

- **Construction.** `(*Manager).MFAMethod()` returns an `mfa.ChallengeMethod` that also implements `mfa.EnrolmentRemover` and `SupportsEnrolmentPath`. It reports:
  - name `passkey`;
  - channel `public-key`;
  - `Response()`, which is `mfa.JSONBody(16 KiB)`.
- **Behaviour.**
  - `Enrolled` reports whether the user has any active credential. Any store error is returned.
  - `BeginChallenge` builds `RequestOptions` listing the user's active credentials (allowCredentials, with transports).
  - `Verify` parses, requires the credential to be the user's and active, verifies, then runs the login check and the counter write.
  - `RemoveEnrolment` deletes all of the user's passkeys, for the operator reset.
- **Counting at the slot.** A new sentinel, `mfa.ErrAuthenticatorRefused`, means the method refused the authenticator itself, not the response. The verify endpoint does not record a failure for an error matching it. `passkey.ErrCloneSuspected` and `passkey.ErrSuspended` wrap it. Other errors are mapped to `mfa.ErrInvalidCode` and counted, as today.
- **Recovery.** The method is not meant for `recovery.MFAEnrolments`, because the passkey kind (D15) covers it per credential. Its godoc says so. Passing it anyway lists the user's passkeys twice, once as `{"mfa","passkey"}`. The default reset removes them either way. In the reported-loss mode, reporting `mfa:passkey` removes them all. That is coarser but not unsafe, so the design does not add a refusal the specs do not state.

### D13. Clone handling

- **Decided by the write.** `RecordAssertion(ctx, id, newCount, backupState, at)` runs `UPDATE … SET sign_count=$n, backup_state=$bs, last_used_at=$at WHERE id=$id AND state='active' AND (sign_count < $n OR (sign_count = 0 AND $n = 0))` and reports whether a row changed. When no row changed and the credential is still active, the signal is a clone.
  - This is decided by the write, unlike go-webauthn's `CloneWarning`, which compares in memory. Two racing assertions with one counter therefore cannot both pass.
- **Default response.** `ErrCloneSuspected` (403). The core then:
  1. calls `Suspend(id)` (conditional on `active`);
  2. queues `Messages.Suspended`;
  3. writes a sampled warning.
- **Overrides.**
  - `passkey.WithCloneResponse(passkey.CloneSignalOnly)` allows the login, leaves the stored counter as it is, and writes a sampled warning. This is the library's own behaviour.
  - `passkey.WithClonePolicy(func(ctx, CloneSignal) CloneAction)` returns `Allow`, `Refuse` or `RefuseAndSuspend`.
- **An allowed clone still records use.** When signal-only or the consumer's policy allows an assertion whose counter write was refused, the manager calls `RecordUse(ctx, id, backupState, at)`: `UPDATE … SET backup_state=$bs, last_used_at=$at WHERE id=$id AND state='active'`. The stored counter is kept, and the flags and last use are recorded, as for every accepted assertion (decided during implementation).
- **Backup eligibility.** An assertion whose BE flag differs from the stored one is refused as authentication failed. BE is fixed for a credential's life (WebAuthn L3 §6.1.3).

### D14. Attestation and metadata, in the adapter

- **Default:** conveyance `none`, and the adapter accepts every format, keeping only the AAGUID.
- **Overrides:**
  - `webauthn.WithAttestationRecord()` requests `direct`, verifies the statement's signature where the format allows, and returns the format and raw statement for the core to store.
  - `webauthn.WithTrustedAttestation(src webauthn.MetadataSource, allowedAAGUIDs …[16]byte)` requests `direct`, and refuses unless go-webauthn's metadata validation passes against `src`. The refusal is `passkey.ErrAttestationRefused` (403).
- **Metadata sources.**
  - `webauthn.MetadataBlob(func(ctx) ([]byte, error))`: the consumer supplies the MDS3 blob, which is decoded and its signature checked by the library's decoder.
  - `webauthn.MetadataFromMDS(client *outbound.Client, opts…)`: a fetch through scrty's confined client, cached until the blob's `nextUpdate` and at most 24 hours, refetched lazily on the next registration after expiry. A failed refresh keeps refusing trusted attestation rather than accepting unverified, so it fails closed.

  Missing metadata with trusted attestation required is `ErrConfig` at `webauthn.New`.
- **Decided during implementation:**
  - **The BLOB's JWT is checked with `lestrrat-go/jwx`,** the project's JOSE library, as `oidc` does: one key only (the x5c leaf's, or the root's when there is no x5c), an explicit ES/RS/PS algorithm list, no key set and no fetcher, so an embedded `jwk` or a `jku` header is never used. `golang-jwt` stays in the adapter's module graph only as go-webauthn's own dependency.
  - **The BLOB is verified by scrty, not by the library's decoder.** go-webauthn's metadata decoder checks the signing chain's revocation through `http.DefaultClient`, which would send a request past the confined client (reproduced by `TestMetadata_NoRequestLeavesOutsideTheConfinedClient`). The adapter checks the JWT itself (x5c chain to the configured root at the clock's time; ES, RS and PS algorithms only; `x5u` refused) and hands only the verified payload to the library's parser. The cost is that the signing chain's revocation is not looked up online. A consumer who needs it mirrors the BLOB and supplies it through `MetadataBlob`.
  - **Freshness of the BLOB.** A BLOB already past its `nextUpdate`, or whose serial number goes backwards, is refused. On expiry the cached copy is dropped before the refetch, so a failed refetch refuses rather than trusting stale data. A metadata outage in trusted mode is `ErrAttestationRefused`, which fails closed.
  - **Options.** `MetadataBlob(fetch, opts…)` and `MetadataFromMDS(client, opts…)` take `MDSOption`s: `WithMDSURL` (default `DefaultMDSURL`), `WithMDSRoot` (default the FIDO production root) and `WithMDSClock`. `MaxMetadataAge` is 24 hours.
  - **Response size.** The production BLOB is several megabytes, above `outbound`'s default response cap, so a consumer of `MetadataFromMDS` raises `WithMaxResponseBytes`. The godoc and README say so.
  - **Trusted mode accepts** only basic, AttCA or AnonCA attestation with an x5c chain and a non-zero AAGUID. `none`, self attestation and SafetyNet are refused.
  - **AAGUID.** An all-zero AAGUID means the authenticator reported none, so it is stored as nil.
  - **One fetch at a time.** Concurrent registrations share one in-flight metadata fetch, successful or failed. The fetch runs detached from any single caller's cancellation, and each caller still returns on its own context. `MetadataFromMDS` is bounded by the confined client's timeout; a `MetadataBlob` fetch is the consumer's function and must bound its own duration, which its godoc states.
- **Per-user stricter policy** ("the design settles how"). It goes through two core hooks:
  - `passkey.WithRegistrationCheck(func(ctx, RegistrationFacts) error)`, which receives the user, AAGUID, backup flags, format, and whether the attestation was trusted;
  - `passkey.WithLoginCheck(func(ctx, LoginFacts) error)`.

  Both run after verification and before any write, and their errors are returned unchanged. A consumer requiring hardware-bound keys for administrators combines trusted attestation with a check over `RegistrationFacts.BackupEligible`.
- **Alternative rejected:** a per-user attestation mode inside the adapter. It would need the adapter to know users, which is the core's business.

### D15. Recovery integration

- **The reset kind.** `(*Manager).RecoveryKind()` returns the kind `"passkey"`.
  - `Held` lists every credential in any state as `{Kind: "passkey", ID: <library id>}`.
  - `Remove` deletes those IDs for the user.
- **Way-back counting.** `recovery` gains an optional interface:

  ```go
  type UsableLister interface {
      Usable(ctx, user) ([]AuthenticatorRef, error)
  }
  ```

  `WayBackCheck` uses it when a kind implements it, and `Held` otherwise. The passkey kind lists only active credentials there. `MFAEnrolments` needs no change, since enrolled already means usable.
- **The reported-loss mode** names passkeys by library ID. The consumer's interface gets those IDs from the listing endpoint.
- **Wiring.** `Deps.Recovery` takes `{Codes *recovery.Codes; WayBack *recovery.WayBackCheck}`. The way-back check needs the passkey kind before the manager exists, so the kind is also built from the credential store alone: `passkey.NewRecoveryKind(credentials)`, which `(*Manager).RecoveryKind()` returns for the manager's own store. The consumer builds the way-back check with `Kinds` including it, and the godoc's example shows it (decided during implementation, to remove a circular construction).

### D16. Notices

- **The `passkey.Messages` interface:**
  - `Registered(Notice)`;
  - `Removed(Notice)`;
  - `Suspended(Notice)`;
  - `EmailCode(code string, until time.Time)`.

  `Notice` carries the passkey name, the time and the repudiation contact. The defaults are plain text and name no brand.
- **Overrides.**
  - `passkey.WithMessages(m)` replaces the texts.
  - `passkey.WithContactResolver(r)`: the default is `mfa.UsernameAsAddress`. On an enrolment-pending session, the path's resolver is used (D8).
  - `passkey.WithRepudiationContact(s)` is required.
- **Sender.** `Deps.Sender notify.Sender`, which must be non-blocking unless `passkey.WithSynchronousDelivery()` is set.
- **Failures.** A refused binding, removal or suspension notice is logged and does not undo the operation. A refused emailed code fails the finish (D7).

### D17. HTTP surface

`httpsec.EnablePasskeys(deps PasskeyDeps, opts …PasskeyOption)`, where `PasskeyDeps{Passkeys *passkey.Manager; Sessions *session.Manager; Users identity.UserLoader}`.

| Endpoint | Default path | Body | Default response |
|---|---|---|---|
| registration begin | `POST /passkey/register/begin` | none | `{"publicKey":{…creation options…}}` |
| registration finish | `POST /passkey/register/finish` | JSON ≤ 64 KiB | `{"id","name","state","pending":[…],"recovery_codes":[…]\|null,"backup_eligible","no_synced_passkey","recovery_not_set_up"}`, `Cache-Control: no-store` |
| saved-code confirm | `POST /passkey/register/confirm` | form `code` | 204 |
| emailed-code confirm | `POST /passkey/register/confirm-email` | form `code` | 204 |
| list | `GET /passkey/credentials` | — | `{"passkeys":[{id,name,state,created_at,last_used_at,backup_eligible,backup_state,transports,aaguid}]}` |
| rename | `POST /passkey/credentials/rename` | form `id`, `name` | 204 |
| remove | `POST /passkey/credentials/remove` | form `id` | 204 |
| passwordless begin | `POST /passkey/login/begin` | none | `{"publicKey":{…request options…}}` |
| passwordless finish | `POST /passkey/login/finish` | JSON ≤ 16 KiB | form login's credential response |

- **Paths.** Each path group is replaceable by a prefix option: `WithPasskeyRegistrationPrefix`, `WithPasskeyCredentialsPrefix`, `WithPasswordlessPrefix`. A passkey path under the enrolment path's prefix is refused at assembly, since the enrolment interceptor would serve it first.
- **Responders.** Each endpoint has a replaceable responder.
- **Readers.** Bodies are read through `httpsec`'s own readers, `postedJSON` and `postedFieldLimited`, which the MFA slot already uses.
- **Routing.** Other HTTP methods pass through.
- **Placement.** The authenticated endpoints run at a new `OrderPasskeys` (660), after the password-change gate (650), so every gate has already run. Passwordless login runs at `OrderPasskeyLogin` (380), between the one-time link slot and Basic.
- **Logs.** The samplers are flushed with the chain's.

### D18. Refusals

| Error | Wraps | Status |
|---|---|---|
| `passkey.ErrCloneSuspected` | `mfa.ErrAuthenticatorRefused` | 403 |
| `passkey.ErrSuspended` | `mfa.ErrAuthenticatorRefused` | 403 |
| `passkey.ErrPending` | — | 403 |
| `passkey.ErrAttestationRefused` | — | 403 |
| `passkey.ErrLimitReached` | — | 403 |
| `passkey.ErrReauthenticationRequired` | — | 403 |
| `passkey.ErrNotFound` | — | 404 |
| `passkey.ErrRegistrationThrottled` | `ratelimit.ErrThrottled` | 401 |
| `passkey.ErrMalformedResponse` | — | 400 (the chain refuses an unreadable response as missing credentials, as the spec requires) |
| refused ceremony | `authenticate.ErrAuthenticationFailed` | 401 |
| refused emailed or saved code at confirm | `mfa.ErrInvalidCode` | 401 |

`mfa.ErrAuthenticatorRefused` maps to 403 on its own. `TestStatusForErrorCoversEverySentinel` gains every row.

### D19. Durable schema and stores

- **New tables:**
  - `passkey_credentials(id uuid PK, user_id text NOT NULL, credential_id bytea NOT NULL UNIQUE, public_key bytea NOT NULL, sign_count bigint NOT NULL, backup_eligible boolean NOT NULL, backup_state boolean NOT NULL, transports text NOT NULL, aaguid bytea NULL, attestation_format text NULL, attestation_statement bytea NULL, name text NOT NULL, created_at timestamptz NOT NULL, last_used_at timestamptz NULL, state smallint NOT NULL, pending smallint NOT NULL, email_code text NULL, email_code_expires_at timestamptz NULL, email_code_attempts smallint NOT NULL DEFAULT 0)`, indexed by `user_id`.
  - `passkey_user_handles(id uuid PK, user_id text NOT NULL UNIQUE, handle bytea NOT NULL UNIQUE)`.
- **Sessions** gain `mfa_at_first_factor boolean NOT NULL DEFAULT false`.
- **Column choices.**
  - `sign_count` is `bigint` because the WebAuthn counter is an unsigned 32-bit value.
  - `transports` is newline-joined. Transport names never contain a newline.
- **Conditional writes:**
  - insert, where the unique credential ID decides duplicates;
  - `RecordAssertion` (D13);
  - `Suspend` and `ClearReason`, each guarded on state and reason;
  - `ChargeEmailAttempt`, guarded on code non-null, unexpired and attempts < 5;
  - `Assign` as `INSERT … ON CONFLICT (user_id) DO NOTHING` followed by a select of the row. It runs inside a savepoint under a caller transaction, or its own transaction otherwise.
- **Sealing.** `email_code` is sealed with `seal.Cipher` under `seal.PasskeyEmailCodeAAD(id, user)`. `sqlstore`, `pgx` and `gorm` `NewPasskeyCredentialStore(db, cipher, opts…)` require the cipher, as their MFA enrolment stores do. `NewPasskeyHandleStore(db, opts…)` takes `WithTxResolver` and `WithIDGenerator`.
- **Decided during implementation:**
  - **No write aborts a caller's transaction.** The credential insert is `INSERT … ON CONFLICT DO NOTHING`, and zero rows inserted is `ErrDuplicateCredential`. `Assign` is `INSERT … ON CONFLICT DO NOTHING` followed by a select of the user's row, so neither statement can fail on a conflict and no savepoint is needed. A select that finds no row for the user means the offered handle is another user's, which is an error naming no handle bytes.
  - **Identifiers.** The credential store takes no `WithIDGenerator`, since credentials carry the library ID the manager gave them; it is refused, as on the recovery record store. The handle store takes it for the row's own ID.
  - **`RecordUse`** is `UPDATE … SET backup_state, last_used_at WHERE id AND state = active` (D13).
  - **Clearing the emailed-code reason** nulls the code and its expiry.
- **Clocks.** Neither store reads a clock, so `WithClock` is refused, matching the recovery stores.
- **Migration.** The migration is edited in place, as recovery-codes D15 decided while nothing is tagged. The table list in `test/migrate_securitystate_test.go` grows to thirteen.

### D20. Testing without a browser

- **The software authenticator.** `passkey/webauthn/webauthntest` implements a minimal authenticator:
  - an ES256 key pair;
  - `none` attestation, plus a self-signed `packed` attestation for the record mode;
  - a settable counter and settable UV, BE and BS flags;
  - creation and assertion responses built for a given relying party, origin and challenge.

  It is a test-double package that no production package imports, as `module-layout` allows, and the `test` module uses it for chain conformance.
- **Real-world shapes.** The go-webauthn test vectors are not copied. Fixtures recorded from real platform authenticators are out of scope, since scrty verifies through the library, whose conformance is its maintainers' claim (proposal).

## Risks / Trade-offs

- **[go-webauthn is v0 and may break without notice.]** → Its types never escape the adapter (D1), the version is pinned, and upgrades are deliberate. The module-layout scenario fails the build if a library type leaks into the exported API.
- **[A buggy counter suspends a user's own security key.]** → The user keeps other passkeys and recovery. Consumers who distrust counters choose signal-only (D13).
- **[Codes are generated before the credential insert, so a failed insert replaces the user's set with codes they never saw.]** → The user retries, and the retry shows a fresh set. Inserts fail only on a duplicate credential ID or an outage.
- **[The passwordless begin writes a token per anonymous request.]** → It is source-throttled (30 per 15 minutes), purged inline, and the in-memory store's per-replica limit is documented. A consumer at scale shares a limiter.
- **[A copied proof value.]** → Only code that already received a holding proof could copy one, and that code is the library or a consumer's own code handling the result. It is documented on the type.
- **[The enrolment path through passkeys sends the emailed code after a password alone, as it does for TOTP.]** → This is the same assurance the path already states. After a magic-link login the code adds nothing, which is already documented on the path.
- **[Concurrent registration begins can exceed the issuance limit.]** → The count and the issue are separate calls, as in every other begin step that uses `onetime`'s issuance window (magic link, recovery start, MFA begin). The limit is a soft brake on challenge minting, not a security boundary: each challenge is still single-use, session-bound and short-lived. An atomic count-and-issue belongs to `onetime`, for every caller at once.
- **[Removing a user's last passkey.]** → It is allowed and documented. Recovery remains, and the consumer's interface warns.
- **[Removing or suspending a passkey does not end the user's other sessions.]** → OWASP ASVS 5.0 §7.4.3 asks that the user be offered to terminate other sessions after a factor is changed or removed, and a suspected clone suggests an attacker may already hold one. Account recovery and the MFA reset already end the user's sessions. Doing the same here needs a session dependency in the passkey core and a requirement of its own, so it is deferred to a follow-up change (user's decision, 2026-10-01).
- **[Response timing at the passwordless finish can show whether a credential ID is registered.]** → An unknown credential is refused before the signature step. It reveals only the existence of a credential ID to someone who already holds that ID, which is high-entropy and names no user. The refusal itself is uniform, as the spec requires. Accepted.
- **[Browsers may prompt for consent before sharing direct attestation (record mode).]** → Not re-verified (proposal). The godoc says "may", and the claim is checked before it is stated as behaviour.

## Migration Plan

This change lands after `mfa-multi-method` and `recovery-codes` (both archived). Its code order compiles at each step:

1. `factor.Passkey` and `factor.PublicKey`; `internal/assurance` and the `policy.SecondFactorProof` alias plus `Input.SecondFactorAtLogin`; both MFA policies honour it.
2. `session`: `MFAAtFirstFactor`, `WithSecondFactorAtLogin`, `Rotate`, the in-memory store.
3. `mfa.ErrAuthenticatorRefused`, with the verify endpoint not counting it; `recovery.UsableLister` in the way-back check.
4. Core `passkey`: types, ports, in-memory stores, the `Manager` ceremonies with a stub `Verifier` in tests, the MFA method, the recovery kind, and notices.
5. The nested module `passkey/webauthn` and `webauthntest`, with the `go.work` entry and the layout guard updated.
6. Schema and drivers: the migration, `pgschema`, the session column, and both stores on `sqlstore`, `pgx` and `gorm`.
7. `httpsec`: `completeLogin`'s proof, the enrolment and recovery gate exemptions, `EnablePasskeys` with registration, confirmations, management and passwordless login, then the status rows.
8. The `test` module: store suites, races, ambient transactions and the sealed column, the migration test, cross-backend tests, and chain conformance using `webauthntest`.

**Rollback:** revert the change's commits. The schema edit is in the unreleased migration, so a database migrated during development is rebuilt from it.

## References

### Researched

Accessed 2026-09-28 and carried forward from the proposal, unless dated 2026-10-01.

**D1: the library and its placement**
- [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn): Level 3 support, attestation formats, v0 stability warning.
- [webauthn package (pkg.go.dev)](https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn) and [protocol package](https://pkg.go.dev/github.com/go-webauthn/webauthn/protocol): the parse and validate split the `Verifier` port wraps.
- [Go module proxy: go-webauthn @latest](https://proxy.golang.org/github.com/go-webauthn/webauthn/@latest) (2026-10-01): v0.18.2, released 2026-09-19. [Its go.mod](https://raw.githubusercontent.com/go-webauthn/webauthn/master/go.mod) (2026-10-01) declares `go 1.26.0` and requires `fxamacker/cbor/v2`, `golang-jwt/jwt/v5`, `google/go-tpm` and `google/uuid`. [GitHub API](https://api.github.com/repos/go-webauthn/webauthn) (2026-10-01): 1,341 stars, not archived, last push 2026-09-27. [OSV.dev](https://osv.dev) (2026-10-01): no advisory. Live figures drift.

**D3, D4: user handle, challenge length and ceremony timeout**
- [Web Authentication Level 3 (W3C)](https://www.w3.org/TR/webauthn-3/) (re-checked 2026-10-01):
  - §14.6.1: the user handle MUST NOT carry personally identifying information, and 64 random bytes is RECOMMENDED;
  - §13.4.3: challenges SHOULD be at least 16 bytes;
  - §15.1: the recommended timeout range is 300,000–600,000 ms, with 300,000 ms (5 minutes) as the default.

**D4, D5: challenges kept server-side and spent on any attempt**
- [SimpleWebAuthn: storing the challenge (discussion #321)](https://github.com/MasterKale/SimpleWebAuthn/discussions/321) and [Custom challenges](https://simplewebauthn.dev/docs/advanced/server/custom-challenges): keyed by session, expiring, deleted after any attempt.
- [Spring Security `HttpSessionPublicKeyCredentialRequestOptionsRepository`](https://docs.spring.io/spring-security/reference/api/java/org/springframework/security/web/webauthn/authentication/package-summary.html): the challenge is held server-side.
- [GHSA-gjjc-pcwp-c74m (OneUptime)](https://github.com/OneUptime/oneuptime/security/advisories/GHSA-gjjc-pcwp-c74m): a client-supplied challenge allowed replay.

**D6: binding at the account's assurance, and freshness (2026-10-01)**
- [NIST SP 800-63B-4: Authenticator Event Management](https://pages.nist.gov/800-63-4/sp800-63b/events/), §4.1.2.1: binding a new authenticator "requires authentication at either the maximum AAL currently available in the subscriber account or the maximum AAL at which the new authenticator will be used, whichever is lower", and the subscriber is notified by an independent mechanism.
- [Sudo mode (GitHub Docs)](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/sudo-mode): sensitive actions require recent re-authentication, with a two-hour window. That adding a passkey is among GitHub's sudo actions was not confirmed on that page.

**D9: usernameless only**
- [Web Authentication Level 3 (W3C)](https://www.w3.org/TR/webauthn-3/), §14.6.2: username enumeration through ceremonies that begin from a username.

**D10, D11: a user-verified passkey meets both factors**
- [NIST SP 800-63B-4: Authenticators](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/) and [Authentication Assurance Levels](https://pages.nist.gov/800-63-4/sp800-63b/aal/): multi-factor cryptographic authenticators and AAL2.
- [About passkeys (GitHub Docs)](https://docs.github.com/en/authentication/authenticating-with-a-passkey/about-passkeys) and [Sign in with a passkey (Google Account Help)](https://support.google.com/accounts/answer/13548313?hl=en).

**D13: clone handling**
- [Web Authentication Level 3 (W3C)](https://www.w3.org/TR/webauthn-3/): §6.1.1 signature counter, §7.2 relying-party response, §6.1.3 backup flags.
- [webauthn package: `Authenticator.CloneWarning` and `UpdateCounter`](https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#Authenticator): the library only flags, comparing in memory.
- [NIST SP 800-63B-4: Authenticator Event Management](https://pages.nist.gov/800-63-4/sp800-63b/events/): suspend or invalidate compromised authenticators promptly, and notify with repudiation instructions.
- [signCount is dead (MojoAuth)](https://mojoauth.com/blog/signcount-is-dead-why-passkey-clone-detection-doesnt-work-anymore): synced passkeys report 0.

**D14: attestation off by default, metadata only through scrty**
- [Attestation guidance (Yubico)](https://developers.yubico.com/Passkeys/Passkey_relying_party_implementation_guidance/Attestation/): do not require attestation for general audiences; request and store for future reference.
- [Server-side passkey registration (Google for Developers)](https://developers.google.com/identity/passkeys/developer-guides/server-registration).
- [metadata package of go-webauthn](https://pkg.go.dev/github.com/go-webauthn/webauthn/metadata): the `Provider` and `Decoder` over a supplied blob.
- [Why some platforms do not support attestation (Corbado)](https://www.corbado.com/blog/passkey-providers/why-some-platforms-do-not-support-attestation-for-passkeys).

**D6 amendments, D3 name rule and the deferred session revocation: the security audit (2026-10-01)**
- [NIST SP 800-63B-4: Authenticator Event Management](https://pages.nist.gov/800-63-4/sp800-63b/events/), §4.1.2.1: binding at the maximum AAL available in the account, AAL1 only when the account has nothing higher.
- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html): re-authenticate with an existing enrolled factor before changing factors; notify out of band.
- [OWASP ASVS 5.0, V7 Session Management](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/0x16-V7-Session-Management.md), 7.4.3: offer to terminate other sessions after a factor change or removal (the deferred risk).
- [OWASP ASVS 5.0, V6 Authentication](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/0x15-V6-Authentication.md), 6.3.8: timing-based enumeration (the accepted timing risk).
- [Unicode UTS #39: Security Mechanisms](https://www.unicode.org/reports/tr39/): default-ignorable and format characters as restricted identifier characters (the name rule).

**D7, D15: recovery**
- [Passkeys user journeys (Google for Developers)](https://developers.google.com/identity/passkeys/ux/user-journeys) and [Customer support (Passkey Central)](https://www.passkeycentral.org/resources-and-tools/customer-support). The recovery flow itself is referenced in `recovery-codes`.

**D2, D8 (path and gate integration), D12 (slot counting), D16–D19**
- Reasoned from scrty's own settled specs (`identity-model`, `multi-factor-auth`, `security-policy`, `sessions`, `http-security-chain`, `http-error-propagation`, `account-recovery`, `one-time-tokens`, `security-state-stores`, `schema-migrations`, `secrets-at-rest`) and the project's migration practice.

### Primary documentation
- [Web Authentication Level 3 (W3C)](https://www.w3.org/TR/webauthn-3/): the ceremonies the `Verifier` port runs.
- [Web Authentication API (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API): the client calls the default JSON shapes target (`PublicKeyCredential.parseCreationOptionsFromJSON`, `toJSON`).
