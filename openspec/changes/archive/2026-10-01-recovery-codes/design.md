# Design

## Context

See proposal.md for why. The current state that shapes the approach:

- **Sessions.**
  - `session.MFAState` is an appended ordinal (`MFANone`, `MFAPending`, `MFASatisfied`, `MFAEnrolmentPending`). Durable stores keep the ordinal in `mfa_state smallint`, so a new state needs no column.
  - `Manager.MarkEnrolmentPending(s, lifetime)` lowers the deadlines and sets `EnrolmentOriginDeadline`.
  - `Manager.RestoreEnrolmentDeadlines(s)` restores them, and the MFA verify endpoint calls it before rotating.
  - `Manager.DeleteByUser` is the revocation hook.
- **The enrolment path.** The enrolment interceptor at `OrderMFAEnrolment` (599) acts only on `MFAEnrolmentPending`. It serves POSTs under three prefixes plus logout, and refuses everything else with `ChallengeError{Kind: ChallengeMFAEnrolment}`. Confirming an enrolment moves the session to `MFAPending`, and verify restores and rotates.
- **The password-change gate** refuses sessions with `PasswordChangePending`. Its resolve endpoint runs the consumer's function, then clears the marker and saves. It does not rotate, because the consumer's function owns the response.
- **Bearer's per-request phase** marks challenges on the session (`markChallenge`). Marking the enrolment challenge is persisted at once.
- **Reset.** `mfa.ResetEnrolment` removes through `[]EnrolmentRemover`, deletes sessions, then notifies through `notify.Sender` with `mfa.ContactResolver`, whose default is `UsernameAsAddress`. `*mfa.TOTP` is an `EnrolmentRemover`.
- **One-time tokens.** `onetime.NewManager(purpose, …)` provides `Issue`/`Check`/`Consume`/`Redeem` and `IssuedCount`. The default TTL is 15 minutes, with no maximum. The token string is `<id>.<secret>`, and the store holds SHA-256 of the secret.
- **An unauthenticated uniform endpoint.** The magic-link request endpoint is the template: POST only, every failure read as empty values, always 202 with no body, a non-blocking sender required, and issuance limited through `IssuedCount`.
- **Throttles.**
  - Per-user limits are plain `ratelimit.Limiter`s under keys of their own (`mfa.VerifyThrottleKey`).
  - Per-source limits go through `httpsec`'s `sourceGuard` seam, which refuses unattributable addresses with `authenticate.ErrAuthenticationFailed`.
  - Form login has no source guard. It relies on the attempt store and the lockout policy.
- **Password verification.** This is `authenticate.NewUsernamePasswordAuthenticator`, whose timing is even for unknown users. The attempt store and the lockout policy wrap it at form login.
- **Links.** `oidc.LinkStore` finds by external identity and deletes by user. It cannot list a user's links.
- **Migrations.** The security-state set is a single file, `migrate/securitystate/20260926000000_security_state.sql`. The MFA enrolment path added its columns by editing that file in place, since nothing is tagged. `test/migrate_securitystate_test.go` pins the table list and the version count.
- **The established design had no account recovery.** Its only exit was an operator reset of second factors. Everything here is new, and no decision departs from established behaviour. D8 extends the enrolment path's confinement pattern, and D15 extends its migration practice.

## Goals / Non-Goals

**Goals:**
- One core package, `recovery`, that owns code generation, the two-proof rules, the reset plan and the "other way back in" check. `httpsec` only parses, gates and responds.
- Every recovery code is check-then-consume. The only proof spent early is the MFA method's, whose acceptance and spending are one write.
- The confined session reuses the enrolment path's deadline mechanics, so the MFA verify endpoint stays the only resolver of an MFA challenge.
- Stores are durable on all three drivers, with conformance and race suites.

**Non-Goals:**
- Recovery contacts, repeated identity proofing, and passkeys. Passkeys join through the ports defined here, in `passkey-authentication`.
- A challenge method (one with a begin step) as a recovery proof. A recovery has no session to bind a challenge to (D5).
- Rendering. Every response is data, or a bare status by default.
- Sweeping old recovery records (Risks).

## Decisions

### D1. The `recovery` package and its ports

```go
package recovery

// Saved codes
type CodeStore interface {
    ReplaceSet(ctx context.Context, user identity.UserID, hashes [][]byte, at time.Time) error
    Match(ctx context.Context, user identity.UserID, hash []byte) (bool, error) // unspent match, no write
    Spend(ctx context.Context, user identity.UserID, hash []byte, at time.Time) (bool, error)
    Remaining(ctx context.Context, user identity.UserID) (int, error)
    DeleteUser(ctx context.Context, user identity.UserID) (int, error)
}
func NewCodes(opts ...CodesOption) (*Codes, error)
func (c *Codes) Generate(ctx, user) ([]string, error)      // replaces the set, returns it once
func (c *Codes) Confirm(ctx, user, presented string) error // check only, throttled
func (c *Codes) Remaining(ctx, user) (Count, error)        // Count{N int; Low bool}

// Authenticator reset port
type AuthenticatorRef struct{ Kind, ID string }             // e.g. {"mfa", "totp"}
type AuthenticatorKind interface {
    Kind() string
    Held(ctx context.Context, user identity.UserID) ([]AuthenticatorRef, error)
    Remove(ctx context.Context, user identity.UserID, refs []AuthenticatorRef) error
}
func MFAEnrolments(methods ...mfa.Method) (AuthenticatorKind, error) // kind "mfa"

// Recovery records
type RecordStore interface {
    Insert(ctx context.Context, r Record) error
    Find(ctx context.Context, id id.ID) (*Record, error)
    Complete(ctx context.Context, id id.ID, at time.Time) (bool, error)
    Cancel(ctx context.Context, id id.ID, at time.Time) (int, error)
    CancelPending(ctx context.Context, user identity.UserID, at time.Time) (int, error)
    LatestCompletion(ctx context.Context, user identity.UserID) (time.Time, bool, error)
}
```

- **Imports.** `recovery` imports `mfa`, `onetime`, `identity`, `notify`, `ratelimit`, `session` and `policy`. `httpsec` imports `recovery`, and nothing in the core imports `httpsec`.
- **Default:** in-memory `CodeStore` and `RecordStore`.
- **Override:** `WithCodeStore`, `RecoveryDeps.Records`, or the durable stores (D14).
- **Where the options live.** The recovery's own options (proof kinds, reset, holds, messages, contact resolver, lifetimes) are `recovery.With…` options. On a chain they are passed through `httpsec.WithRecoveryCore(opts…)`; the chain adds only what is HTTP-shaped (paths, source guards, responders, the token generator, the freshness window) and wires the password check itself.
- **Alternative rejected:** putting it all in `httpsec`. `passkey-authentication` needs `Codes.Generate`, `Codes.Confirm`, the reset port and the check without the chain.

### D2. Saved code format and hashing

- **Format.** 16 bytes from `crypto/rand`, encoded as 26 Crockford base32 characters. That is 130 bits of capacity, so the first character is always `0`–`7`. The characters are grouped `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XX`.
- **Parsing.** Parsing removes dashes and folds case, then maps `O`→`0` and `I`/`L`→`1`. It refuses any other character outside the alphabet, and any length other than 26 or a first character above `7`. A refused value never reaches the store, and it still counts as a failed presentation.
- **Hashing.** The stored value is SHA-256 over the decoded 16 bytes, not the text, so every accepted spelling hashes alike.
- **Pinning.** A constant `codeBytes = 16`, a test that asserts every generated code is 26 characters and decodes to 16 bytes, and a test that the store receives 32-byte hashes.
- **Lookup.** A code is looked up by (user, hash). Scoping to the user costs nothing, and it keeps one user's presentations from ever probing another's set.
- **Defaults:**
  - `WithSetSize(n)`: 10, allowed range 1–100. The cap only bounds a request's work.
  - `WithLowThreshold(n)`: 2, and a value below 0 is refused.
  - `WithCodeLimiter(l)`: 5 failures per 15 minutes under `recovery-code|<user>`, shared by `Confirm` and recovery.
- **Why these choices** were made in the proposal: 128 bits and plain SHA-256, and the rejection of short codes with Argon2id or a keyed hash.

### D3. Issued codes and the start endpoint

- **Tokens.** Issued codes use `onetime.NewManager("account-recovery", WithTTL(…))`. The emailed code is the token string, and the subject is the user reference.
  - **Default:** a 15-minute TTL, matching magic links.
  - **Override:** `WithIssuedCodeTTL(d)`, where zero or less is refused. A TTL above 24 hours is refused because NIST SP 800-63B-4 §4.2.2.2 caps codes sent to an email address at 24 hours. `WithIssuedCodeStore(onetime.Store)` replaces the token store.
- **Start endpoint.** POST `/recovery/start` exists only when issued codes are enabled; the core reports its enabled proof kinds for this. It is built on the magic-link request template:
  1. It reads `username` from a form field or JSON.
  2. It resolves the user with `LoadByUsername`.
  3. It refuses a disabled user silently.
  4. It checks `IssuedCount` against the issuance limit: 5 by default, replaced by `WithIssuedCodeLimit(n)`, where below 1 is refused.
  5. It issues the code and sends it to `ContactResolver(details)`, by default `mfa.UsernameAsAddress`, replaced by `recovery.WithContactResolver`.

  The endpoint always answers 202 with an empty body.
- **Source guard.** A source guard under flow `account-recovery-start` records every start: 10 per hour by default, with `WithRecoveryStartLimiter(l)`. A throttled source still gets 202.
- **Messages.** A `recovery.Messages` interface builds every message the recovery sends, and `recovery.WithMessages` replaces it. The library always sets the recipient.
  - `IssuedCode(code string, until time.Time)`: sends the code.
  - `Recovered(Notice)`: the recovery notice.
  - `Held(Notice, cancelLink string, until time.Time)`: sent at the start of a hold.
  - `Cancelled(Notice)`: sent on cancellation.
  - `Regenerated(at time.Time)`: sent on a regeneration.

  The default texts are plain and name no brand.
- **Sender.** A non-blocking sender is required, as for magic links, unless `recovery.WithSynchronousDelivery()` is set. Its godoc states that response time then reveals which usernames have accounts.

### D4. The complete endpoint and the proof rules

POST `/recovery/complete`, with URL-encoded form fields only, a 16 KiB body limit, and the query never read:

| Field | Proof kind |
|---|---|
| `username` | the account (required) |
| `saved_code` | saved |
| `issued_code` | issued |
| `password` | password |
| `mfa_method` + `mfa_code` | MFA method |
| `lost` (repeatable, `kind:id`) | reported losses (reported mode only) |

**Shape check.** This runs first and is counted nowhere. It requires exactly two proof kinds, both enabled and different from each other, with at least one of them `saved` or `issued`. In the reported mode it also refuses a request that reports nothing, and one that reports as lost the MFA method it presents as a proof, since neither needs a lookup. Anything else is `recovery.ErrMalformed` (400).

**Order.** This follows the proposal's check-then-consume rule:
1. The source guard (flow `account-recovery`, 10 failures per 15 minutes, `WithRecoveryLimiter`).
2. **Resolve the user.** An unknown or disabled user becomes `ErrRefused` at once. No expensive work runs before the recovery codes pass, for any user: an unknown user is refused before any lookup, and a known user with a wrong code is refused by the code check before the password is verified. So neither pays for a password hash, and the two take about the same time. The residual difference is the code lookups a known user's request makes, stated in godoc. An earlier draft ran the password authenticator's reference hash for unknown users; a review showed that made unknown accounts the slow ones, because a known user with a wrong code never reaches the password. The per-user limiter (`recovery|<user>`, 5 per 15 minutes, `WithRecoveryUserLimiter`) runs right after, before any proof is checked, because its key is the resolved user reference. An unknown username therefore has no per-user count; the source guard covers it. A user at the limit is refused with the same `ErrRefused` as an unknown one, so the limiter cannot be used to find accounts.
3. **Check the recovery codes without spending them.**
   - Saved: parse, then `Codes` check under the saved-code limiter.
   - Issued: `onetime.Check(presented, "")`. The token's subject must equal the resolved user.
4. **The password.** The pre-authentication phase runs first, so lockout refuses before the password is checked. Then the chain's password authenticator runs, from `FormLoginDeps.Authenticator`. A failure is recorded in the attempt store, exactly as at login.
5. **The side-effect-free checks.**
   - The MFA method named must be configured, have a form-field response and no begin step, and be one the user is enrolled on.
   - The reset plan (D6).
   - The risk hook (D10).
   - The consumer's refusal checks: `recovery.WithChecks(…)`, returned unchanged.
6. **Spend.**
   - First, the MFA `Verify(ctx, user, code)`. Accepting and recording the step are one write in TOTP, so a wrong code spends nothing else.
   - Then `Consume` the issued token and `Spend` the saved code.
   - Losing the race on either is `ErrRefused`. The TOTP step already recorded stays recorded, and this is harmless (Risks).

**Reported losses outside the reported mode.** The `lost` refs are parsed in every mode, so a malformed one is `ErrMalformed`. A custom policy receives them, and the default mode ignores them.

**Refusals.** Every refused proof and every unknown or disabled user is `recovery.ErrRefused`, which wraps `authenticate.ErrAuthenticationFailed` (401). It is recorded on the per-user and source limiters. A refusal at step 5 of a request whose recovery codes passed step 3 counts against the source unless `WithRecoveryCountRefusals(false)`.

**Why an MFA challenge method cannot be a proof.** A begin needs a session to bind the challenge to, and a recovery has none yet. `passkey-authentication` may add a begin step for recovery in its own change.

**Why the password goes through the login authenticator.** Recovery must not become a second password oracle outside lockout.

### D5. What the session becomes: state, kind and marker

- **State.** `session.MFARecoveryPending` is appended after `MFAEnrolmentPending`, so the existing ordinals are unchanged.
- **Recovery time.** A new field `RecoveredAt time.Time` holds it, and `Rotate` carries it over.
- **Marker.** `EnrolmentOriginDeadline` is reused as the confinement marker. Its godoc widens, and the field name stays, to avoid churning three drivers for a rename.
- **Marking.** `Manager.MarkRecoveryPending(s, lifetime, at)` sets the state and `RecoveredAt`, and lowers the deadlines exactly as `MarkEnrolmentPending` does.
- **Restoring.** `RestoreEnrolmentDeadlines` serves both states unchanged.
- **Kind.** `factor.Recovery` (`"recovery"`) reports no channel and is not exempt. With no channel, the same-channel checks at enrolment and verify never match it. Being non-exempt, the MFA policies judge its sessions once they are full.
- **Default:** a recovery lifetime of 15 minutes (`recovery.WithSessionLifetime`). Zero or less, or longer than the absolute timeout, is refused.
- **Alternatives rejected:**
  - *Reusing `MFAEnrolmentPending` plus a flag.* The password route would then be refused by the enrolment gate.
  - *No first-factor kind.* The session would then look like an unrecorded login to the enrolment allowlist and to the consumer.

### D6. The reset plan and the authenticator-reset port

- **Building the plan.** Before anything is spent, the plan lists `Held` for every registered `AuthenticatorKind`. A listing error refuses the recovery. The plan is computed as follows:
  - **Default (`ResetAll`):** held minus proven. The MFA-method proof is proven as `{"mfa", name}`.
  - **`WithResetReported()`:** the `lost` refs. Each must be held, or the recovery is `ErrMalformed`. A request that reports nothing is `ErrMalformed` too, so the mode never becomes a built-in way to keep every authenticator. So is a request that reports as lost an authenticator it proved in the same recovery, because the two contradict each other.
  - **`WithResetPolicy(func(ctx, ResetInput{User, Held, Reported, Proven}) ([]AuthenticatorRef, error))`:** the consumer's own. Any ref it returns that is not held is ignored. An error refuses the recovery.
- **Execution.** At completion, `Remove` runs per kind, in registration order. The first error stops and is returned, following the operator reset (`mfa.ResetEnrolment`, D12 of `mfa-multi-method`).
- **`MFAEnrolments(methods…)`.**
  - `Held` is the methods whose `Enrolled` is true. Any lookup error is returned.
  - `Remove` calls the method's `EnrolmentRemover`.
  - A method that is not an `EnrolmentRemover` is `ErrConfig`.
- **Registration.** `WithAuthenticatorKinds(kinds…)` registers the kinds. At least one is required. Duplicate `Kind()`s are refused.
- **Stated limit, in godoc:** no built-in mode keeps everything. A policy returning nothing does, and its godoc states that this leaves possibly-compromised authenticators valid.

### D7. The completion sequence

After the spends, in order:
1. **Record.** `Insert` a completed record, or `Complete` a held one (D10).
2. **Reset** (D6).
3. **Revoke.** `Sessions.DeleteByUser` runs unless `recovery.WithoutSessionRevocation()`, whose godoc says it weakens recovery.
4. **Reissue.** When a saved code was spent, `Codes.Generate` runs and the new set joins the result. The result carries `Remaining` either way: the new set's count after a reissue, the user's unspent count otherwise, with `Low` from the manager's threshold.
5. **Session.** Create it with `WithFirstFactor(factor.Recovery)`, mark it recovery-pending, and save before the token is issued.
6. **Respond.** The core's `Result` carries the user's details it loaded, so the credential is minted without a second lookup that could fail after the codes were reissued. Through `WithRecoveryResponder(func(ex *Exchange, RecoveryResult{Token, Recovery}) error)`, the package's responder pattern, so a replacement receives the minted credential with the result. The default is the JSON `{"access_token","expires_at","recovery_codes":[…]|null,"remaining":n,"low":bool}`, where `remaining` and `low` come from the core's count, after a reissue too. The credential is minted by `WithRecoveryTokens(token.Generator)`, which defaults to the form login's generator and is required configuration on a chain without form login.
7. **Notify** through `Messages.Recovered`. The core sends it as the last step of its completion sequence, so it goes out before the HTTP layer mints the credential and responds; a minting failure leaves the notice sent, which stays true because the recovery stands. A refused queue is logged and does not undo the recovery. Because the notice is mandatory, the recovery's sender is required configuration whichever proof kinds are enabled.

- **Failure.** A failure at steps 1–5 returns that error (500), with the proofs spent and earlier steps done. This matches the operator reset's rule that a failure stops the sequence and is returned. The user retries with a new issued code and another saved code.
- **Why revocation comes before the session.** Step 3 would otherwise delete the new session.
- **Why reissue comes after the reset.** A failed reset must not leave the user holding only a new sheet they never saw.

### D8. The recovery gate and the binding routes

- **Placement.** A gate interceptor at the new slot `OrderAccountRecovery` runs after bearer authentication and before the password-change gate and `OrderMFAEnrolment`.
- **Exemptions.** For `MFARecoveryPending` it lets through only:
  - POSTs under the enrolment prefixes, when the enrolment path is enabled;
  - a POST to the registered password-change resolve path;
  - a POST to logout.
- **Refusals.** Everything else gets `&ChallengeError{Kind: policy.ChallengeAccountRecovery, Session: s}` (403). `ChallengeAccountRecovery` is appended to `policy.ChallengeKind`. Only the recovery gate raises it, and it does so directly as a `ChallengeError`, never through a policy decision. A policy that declares it fails assembly with a configuration error, because nothing would confine an ordinary session it challenged; accepting the declaration and letting the request through would be a silent relaxation.
- **Bearer.** For a recovery-pending session, bearer's per-request phase still refuses on a deny, but `markChallenge` is skipped. The gate is the session's only enforcer until a binding completes.
- **The enrolment route.** The enrolment interceptor serves `MFARecoveryPending` sessions on its endpoints, but does not refuse them elsewhere, since the recovery gate already does. Its confirm moves the session to `MFAPending` with the marker kept. Verify then restores, resolves and rotates, unchanged.
- **The password route.** On the consumer function's success, the resolve endpoint restores the deadlines, sets `MFANone`, clears `PasswordChangePending` and saves. It does not rotate, because the consumer owns the response and the session was minted for this caller by the recovery. This is stated in godoc.
- **The enrolment allowlist.** `factor.Recovery` joins the enrolment path's default first-factor allowlist (a MODIFIED `security-policy` requirement). Without it, the MFA requirement policy denies a required user's recovery-pending session outright, since that user holds no usable method after the reset and the kind is not admitted. Bearer then refuses the session before either binding endpoint. With it, the policy challenges, bearer leaves the challenge unmarked, and the recovery gate stays the session's only enforcer. A consumer who replaces the allowlist and leaves `factor.Recovery` off gives required users no enrolment route after a recovery; the option's godoc says so.
- **Stated limit.** With the enrolment path off, a required user left with no usable second factor after the reset is refused on every request, as their login would be (`multi-factor-auth`). Such a user can complete a recovery only through the enrolment route. The password route serves users who are not required to use MFA, or who kept a method they proved.
- **Wiring.** Recovery fails construction without the enrolment path or a resolve endpoint.
- **Override:** none. Confinement has no opt-out, as the proposal decides.
- **Future binders.** `passkey-authentication` adds its registration path to the exemptions in its own change.

### D9. Saved-code endpoints and the freshness window

- **Endpoints.** POST `/recovery/codes` regenerates, and GET `/recovery/codes` counts. Both require a session.
  - A session with a pending challenge never arrives, because the gates of its challenge refuse it first.
  - A session whose second factor is `MFANone` for a required user is judged by the policies at bearer, as any other.
- **Freshness.** Freshness is `now - max(CreatedAt, MFASatisfiedAt) <= window`. Otherwise the request is refused with `recovery.ErrReauthenticationRequired` (403).
  - **Default window:** 15 minutes.
  - **Override:** `WithRegenerationFreshness(d)`, where zero or less is refused.
  - **Why 15 minutes:** GitHub's sudo window is two hours. scrty's is shorter because a regeneration mints a lasting credential and is rare, and a consumer who wants GitHub's window sets it.
- **Notice.** A regeneration sends `Messages.Regenerated`, and the same non-blocking sender rule applies. The core owns it: `(*Recoverer).Regenerate(ctx, user)` generates the set and sends the notice through the recovery's messages, contact resolver and sender, so the consumer's configuration of those reaches the notice. The endpoint calls it.
- **Responders.** The responses go through replaceable responders.
  - The default regeneration response is `{"recovery_codes":[…]}`, with `Cache-Control: no-store`.
  - The default count response is `{"remaining":n,"low":bool}`.
- **Why the count needs no freshness.** It reveals no secret.

### D10. Holds: the fixed delay, the risk hook, finish and cancel

- **Options.**
  - `recovery.WithDelay(d)` has no default, and zero or less is refused.
  - `recovery.WithRisk(func(ctx, RiskInput{User, Source, Proofs []ProofKind, Now}) (time.Duration, error))` is the risk hook.
  - The hold is the longer of the two. A hook error refuses before anything is spent, behind fixed library text.
- **Start of a hold.** With a hold above zero, after the spends the endpoint:
  1. inserts a pending `Record{User, StartedAt, NotBefore: now+hold, Proven, Reported, SavedSpent}`;
  2. issues a finish token (purpose `account-recovery-finish`, subject the record ID, TTL = hold + window) and a cancel token (purpose `account-recovery-cancel`, same subject and TTL);
  3. when a saved code was spent, deletes the user's remaining saved set at once;
  4. sends `Messages.Held` with a cancel link, saying whether the saved set was voided;
  5. answers 202 with the JSON `{"completion_token","completable_at"}` through a replaceable responder.

  The finish token goes to the client, not the mailbox, so a mailbox thief who cancels nothing still cannot finish.

  **Why the saved set is voided when the hold starts** (the user's decision, 2026-09-30). Both outcomes end the old set anyway: a finish replaces it (D7) and a cancellation voids it. Voiding it at the start means a login, which cancels through `CancelPending` and learns only a count, needs to void nothing. It also means whoever holds a stolen sheet cannot use its other codes while the hold runs. The rejected alternative was a `CancelPending` that also reports whether a cancelled record spent a saved code. That would have changed the record-store contract on every driver, and kept the old codes usable during the hold.
- **The window.** `recovery.WithCompletionWindow(d)` defaults to 24 hours, and zero or less is refused.
- **The cancel link** is `recovery.WithCancelLink(baseURL)`: the consumer's page URL, carrying the token in the query. The page POSTs to `/recovery/cancel`. As for magic links, the URL must be absolute `https`, except `http` on loopback. A hold without it fails construction.
- **Finish.** POST `/recovery/finish` with `completion_token`, in this order:
  1. `Check` the token.
  2. `Find` the record. Unknown, cancelled or completed is `ErrRefused`.
  3. If now is before `NotBefore`, refuse with `ErrNotYetCompletable` (409) and spend nothing.
  4. Load the user. An unknown or disabled user is `ErrRefused`, and the record stays pending.
  5. Recompute the plan over the record's `Proven` and `Reported` and what the user holds now. Holdings may have changed during the hold, and the reset removes what the user holds then. In the reported mode, a reported authenticator the user no longer holds is dropped rather than refused, since its loss is already remedied. A listing failure refuses, and the record stays pending.
  6. `Complete`, conditionally.
  7. `Consume` the token. A failed consume is ignored, since the record's conditional write already refuses any reuse.
  8. Run D7 from step 2 with that plan, detached from the caller's cancellation.

  Planning comes before `Complete` so that a failure to plan leaves the record pending rather than completed with nothing reset.
- **Cancel.** POST `/recovery/cancel` with `cancel_token`. It runs `Check`, then `Cancel(id)` (conditional), then `Consume`, then `Messages.Cancelled`. The saved set, if a saved code was spent, was already voided when the hold started. It always answers 204, so cancel reveals nothing.
- **Login cancels.** When a hold is configured, `completeLogin` calls `RecordStore.CancelPending(user)` as soon as the first factor has authenticated, before the policy phase and before creating the session. A form login the policy then denies still cancels: completing the first factor is what the spec names, and it is evidence the real user still has access. Magic-link and OIDC logins apply the policy inside their redemption check, before their credential is spent; a refused redemption never reaches the login completion step, so it cancels nothing, and its credential stays redeemable. An error refuses the login, which fails closed. The login's credential may already be spent (magic link, handoff), exactly as for a session-store failure at that step.

### D11. The cool-down guard

```go
httpsec.EnableRecoveryCooldown(records recovery.RecordStore, d time.Duration, routes ...httpsec.Route) // Route{Method, Path}
```

- **Where it runs.** It is registered just after bearer and acts only on exact method and path matches that carry a session.
- **What it checks.** It reads `LatestCompletion(user)`. When `now < completion + d`, it refuses with `recovery.ErrCooldown` (403). A lookup error is returned behind fixed text (500).
- **Default:** off.
- **Wiring:** `d <= 0`, no routes, or a nil store fails construction.
- **Why per-user and not per-session.** This was the user's decision: a new login must not end the cool-down.

### D12. The "other way back in" check

```go
func NewWayBackCheck(deps WayBackDeps, opts ...WayBackOption) (*WayBackCheck, error)
type WayBackDeps struct {
    Users        identity.UserLoader
    Codes        *Codes
    Kinds        []AuthenticatorKind
    IssuedCodes  bool                                  // whether issued codes are enabled
    LinkedLogins func(ctx context.Context, user identity.UserID) ([]factor.Kind, error) // optional
    Exempt       func(factor.Kind) bool                // default factor.Kind.MFAExempt, the policies' own rule
}
func (c *WayBackCheck) HasWayBack(ctx context.Context, user identity.UserID) (bool, error)
```

- **What counts.** The check reports yes when any of these holds:
  - the user has a password (`Details.Password` non-empty) or any held authenticator, and issued codes are enabled;
  - `Remaining > 0`;
  - any linked login's kind is `Exempt`.

  Any lookup error is returned.
- **The exemption function.** It is the one the consumer passes to `policy.WithMFAExemption`, so the check and the login cannot disagree. Under `oidc-mfa-assurance`, `LinkedLogins` and `Exempt` take the per-provider decision.
- **Stated limit.** `oidc.LinkStore` cannot list a user's links, so linked logins count only when the consumer supplies `LinkedLogins`. With none, they do not count. This fails safe, since the user is asked for codes. Adding a list-by-user operation would change the identity-linking store contract on every driver, which this change does not take on. The godoc says so.

### D13. New refusals and their status rows

| Error | Where | Status |
|---|---|---|
| `recovery.ErrRefused` (wraps `authenticate.ErrAuthenticationFailed`) | any refused recovery, finish of an unknown, spent or cancelled record | 401 |
| `recovery.ErrMalformed` | the proof shape, a disabled kind, an unheld reported loss | 400 |
| `recovery.ErrNotYetCompletable` | finish before `NotBefore` | 409 |
| `recovery.ErrCooldown` | a marked route during the cool-down | 403 |
| `recovery.ErrReauthenticationRequired` | regeneration outside the freshness window | 403 |
| `ChallengeError{Kind: ChallengeAccountRecovery}` | the recovery gate | 403 |
| `recovery.ErrCodeThrottled` (wraps `ratelimit.ErrThrottled`) | saved-code presentation limiter | 401 |

**Why 409 for "not yet".** The request is well formed and authentic, but it conflicts with the record's state. A client can retry at `completable_at`. A 403 would read as permanent.

### D14. Durable stores and schema

- **Stores.** `sqlstore`, `pgx` and `gorm` each gain `NewRecoveryCodeStore` and `NewRecoveryRecordStore`, with the usual `WithTxResolver`. The code store also takes `WithIDGenerator`, for the row identifiers it mints. Neither store reads a clock, since every time comes from the caller, so `WithClock` is refused as the adapters refuse it on every such store. The record store refuses `WithIDGenerator` too, because a record arrives with its own identifier. No cipher is needed, because only hashes are stored.
- **Tables:**
  - `recovery_codes(id uuid PK, user_id text NOT NULL, code_hash bytea NOT NULL, created_at timestamptz NOT NULL, spent_at timestamptz NULL, UNIQUE(user_id, code_hash))`.
  - `account_recoveries(id uuid PK, user_id text NOT NULL, started_at, not_before timestamptz NOT NULL, completed_at, cancelled_at timestamptz NULL, proven text NOT NULL, reported text NOT NULL, saved_spent boolean NOT NULL DEFAULT false)`, indexed by `user_id`.

  `proven` and `reported` hold the `kind:id` refs newline-joined. Kinds and ids never contain a newline, which the construction checks enforce.
- **Conditional writes:**
  - Spend: `UPDATE … SET spent_at=$now WHERE user_id=$u AND code_hash=$h AND spent_at IS NULL`.
  - Complete: `UPDATE … SET completed_at=$now WHERE id=$id AND completed_at IS NULL AND cancelled_at IS NULL AND not_before <= $now`.
  - Cancel: the same guard on `cancelled_at`.
- **Replace.** `ReplaceSet` is a delete plus an insert within a savepoint when a caller transaction is attached, or its own transaction otherwise. This is the store rule for multi-statement operations. Its first statement takes a per-user transaction advisory lock (`pg_advisory_xact_lock(hashtextextended(user_id, 0))`). Without it, two overlapping replacements at READ COMMITTED both insert, because the second delete cannot see the rows the first inserted, and both new sets stay valid. Under a caller transaction the lock is held until the caller commits.
- **Session column.** `sessions.recovered_at timestamptz NULL`, threaded through `internal/pgschema` and all three drivers' session mapping.

### D15. The migration is edited in place

The new tables and `sessions.recovered_at` are added to the single security-state file, as the MFA enrolment path's columns were. `test/migrate_securitystate_test.go`'s table list gains the two tables, and its version count stays 1.

- **Why:** nothing is tagged. The `schema-migrations` rule against editing covers released files, and a second file now would only fix an ordering that no deployed database has.
- **Alternative rejected:** a new migration file. It would be right after the first tag, and the project would start doing it then.

## Risks / Trade-offs

- **[A TOTP step is spent by a recovery that then loses its race on a code.]** → The only cost is that this one TOTP code cannot be replayed, which is its normal fate. Spending the MFA proof first keeps every recovery code unspent on a wrong MFA code.
- **[A failure after the spends leaves proofs spent and no session.]** → This matches the operator reset's rule. The error is returned rather than swallowed, and the user retries with a new issued code. With the default reissue, a user who spent their last saved code keeps a saved-code route only if the reissue step ran. The step order (D7) puts the reset before the reissue so that no sheet is issued for a recovery that did not happen.
- **[Minting the credential fails after a reissue.]** → The recovery completed and the new saved set replaced the old, but the response carrying the new codes is lost with the error. The user regenerates codes after their next authentication. The window is one token-generator failure, and the core's result already carries the user's details, so no store lookup stands between the reissue and the response.
- **[Recovery records grow by one row per recovery.]** → Recoveries are rare. No sweep is added now, and `expiry-sweeping` can take one later without a contract change beyond a delete-before.
- **[In-memory stores on several replicas.]** → Their godoc states the single-process limit, as for every in-memory default. A held recovery on the in-memory record store is lost on restart, and the godoc says so.
- **[Login cancellation adds a store write to every login when holds are on.]** → The write is only made when a hold is configured, and it is one indexed conditional update.
- **[The password route does not rotate.]** → The session was created by the recovery for this caller alone, and rotation happens on the MFA route. This is documented.
- **[Linked logins do not count without a consumer lookup.]** → This fails safe (D12).

## Migration Plan

This change lands after `mfa-multi-method` (archived). Its code order compiles at each step:
1. `factor.Recovery`, then `session`: the state, `RecoveredAt`, `MarkRecoveryPending`, rotation, the in-memory store.
2. `recovery`: codes, issued codes, the reset port and MFA adapter, the record store contract with in-memory stores, the flow core, and the check.
3. The schema and the drivers: the migration, `pgschema`, and the session column plus the two stores on `sqlstore`, `pgx` and `gorm`.
4. `httpsec`: `policy.ChallengeAccountRecovery`, the gate, bearer, the enrolment interceptor, and password resolve; then start, complete, finish, cancel and codes; then the login-completion cancel, the cool-down, and the status rows.
5. The `test` module: the store suites, races, ambient transactions, the per-driver registration, the migration test, and the chain conformance scenarios.

**Rollback:** revert the change's commits. The schema edit is in the unreleased migration, so a database migrated during development is rebuilt from it.

## References

### Researched (accessed 2026-09-28, carried forward from the proposal, unless dated 2026-09-30)

**D2: 128-bit saved codes stored as SHA-256; ten per set**
- [NIST SP 800-63B-4: Authenticators, §3.1.2.2](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/): look-up secrets below 112 bits need a salted password hashing scheme, and at or above it an approved hash is enough.
- [Sign in with backup codes (Google Account Help)](https://support.google.com/accounts/answer/1187538?hl=en&co=GENIE.Platform%3DDesktop), [Dropbox Help](https://help.dropbox.com/account-access/enable-2-factor-authentication) and [GitHub Docs](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication-recovery-methods): sets of 10 (Google, Dropbox) and 16 (GitHub).

**D3, D4: issued codes and the two-proof combinations**
- [NIST SP 800-63B-4: Authenticator Event Management](https://pages.nist.gov/800-63-4/sp800-63b/events/): the recovery proofs and the combinations AAL2 requires. Issued codes sent to an email address are valid for at most 24 hours (§4.2.2.2, re-checked 2026-09-30).

**D4 (reissue), D7: a new whole set after a saved code is spent (2026-09-30)**
- [NIST SP 800-63B-4: Authenticator Event Management](https://pages.nist.gov/800-63-4/sp800-63b/events/), §4.2.2.1: "Following the use of a saved recovery code, the CSP SHALL invalidate that recovery code and SHALL issue a new saved recovery code", and the reissue "SHALL result in an account recovery notification".

**D5, D8: a confined session completed by binding a new authenticator (2026-09-30)**
- [NIST SP 800-63B-4: Authenticator Event Management](https://pages.nist.gov/800-63-4/sp800-63b/events/), §4.2: after recovery "the subscriber can bind one or more new authenticators".
- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html): recovery no weaker than authentication, and re-authentication after recovery.

**D6, D7: the reset, revocation and notice**
- [NIST SP 800-63B-4: Authenticator Event Management](https://pages.nist.gov/800-63-4/sp800-63b/events/): the mandatory notification with repudiation instructions (§4.6), and the prompt invalidation of compromised authenticators.
- [Revoking sessions and trusted devices after MFA recovery (OneUptime)](https://oneuptime.com/blog/post/2026-08-29-how-to-revoke-sessions-and-trusted-devices-after-mfa-recovery-or-factor-replacement/view): recovery as an account-wide change in security state.

**D9: regeneration needs a recent authentication (2026-09-30)**
- [Sudo mode (GitHub Docs)](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/sudo-mode): viewing or regenerating recovery codes requires re-authentication, with a two-hour window.

**D10, D11: holds and the cool-down**
- [How to use account recovery (Apple Support)](https://support.apple.com/en-us/118574): a fixed, multi-day wait.
- [Why your account recovery request is delayed (Google Account Help)](https://support.google.com/accounts/answer/9412469?hl=en): a risk-based hold.
- [Binance.US: resetting 2FA](https://support.binance.us/en/articles/10128496-how-to-reset-two-factor-authentication): a 48-hour withdrawal hold after a reset.

**D12: the other-way-back-in check**
- [NIST SP 800-63B-4: Authenticator Event Management](https://pages.nist.gov/800-63-4/sp800-63b/events/): a recovery code SHOULD be issued at enrolment (§4.2.1), and subscribers SHOULD keep two means of authentication (§4.1.2.1).
- [NIST SP 800-63C-4](https://pages.nist.gov/800-63-4/sp800-63c.html): a federated login is an assertion, not an authenticator bound at the RP.

**D1, D5 (kind and state), D8 (gate placement), D10 (records and login cancel), D11 (record-based cool-down), D13, D14, D15**
- Reasoned from scrty's own settled specs (`sessions`, `multi-factor-auth`, `http-security-chain`, `http-error-propagation`, `one-time-tokens`, `security-state-stores`, `schema-migrations`, `identity-linking`) and the project's migration practice.
