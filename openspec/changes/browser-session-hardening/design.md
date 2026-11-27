## Context

`browser-session` (archived as `2026-11-27-browser-session`) added the cookie session. After its
final gate, a code review and a security review of PR #160 reported six faults. Each is fixed here,
on the same branch, before the PR leaves draft. The settled `browser-session` spec and the archived
design are the baseline. Decision numbers below are this change's own.

## Goals / Non-Goals

**Goals:** fix the six faults test-first, keeping every guarantee the archived design states.

**Non-Goals:**
- changing the header-bearer chain's rotations;
- reading Fiber cookies through fasthttp's parsed copy;
- any new consumer-facing option. The one new exported symbol, `session.WithSuccessorFromCaller`,
  is a rotation option for the library's own endpoints and for consumers who rotate themselves.

## Decisions

### 1. Second-factor verification and re-authentication rotate with a grace window on a cookie chain

- **Problem:** both endpoints rotate with strict `RotateIssuing`. Once the old identifier is gone,
  a request already sent with the old cookie, such as a double-submitted form or a push-approval
  poll, loads as not found. That is a judged refusal: the cookie is expired and the source charged.
  If that answer reaches the browser after the verify answer, the browser deletes the new cookie.
- **Decision:** on a cookie chain both rotate with `RotateWithGraceIssuing`. The grace is the one
  the role switch uses: the renewal endpoint's grace when the chain has one, otherwise
  `session.DefaultRenewalGrace`. This extends the archived design's decision 10 ("settled during
  implementation") from the two added rotations to all four.
- **Why it is safe:** inside the window the old identifier loads the old record, with its own
  state: second factor still pending, or the old `AuthenticatedAt`. It gains nothing the new
  session holds. After the window it is reuse, exactly as at the role switch.
- **Default:** grace on a cookie chain. A header-bearer chain keeps strict `RotateIssuing`, since
  its client holds both tokens and nothing expires one.
- **Override:** none. The archived design's line stands: these two rotations cannot be turned off,
  and the window is not a separate knob. It follows the renewal grace the consumer already sets
  with `WithRenewalGrace` on the renewal endpoint.
- **Alternatives:** keep the strict rotation and stop expiring the cookie on a not-found refusal.
  Rejected: not found is the commonest judged refusal of a stale or forged cookie, and keeping
  those would leave dead cookies in place everywhere.
- **Settled during implementation (H2 found the gap; user decision, 2026-11-27):**
  - A grace rotation builds its successor from the stored record and ignores the caller's copy, so
    a plain swap would lose the verified state: the second factor would stay pending, and
    `AuthenticatedAt` would never refresh. `Save` cannot repair it either, because it never
    rewrites `AuthenticatedAt`.
  - New `session.RotateOption`: `session.WithSuccessorFromCaller()`, taken by `RotateWithGrace`
    and `RotateWithGraceIssuing`. The successor is built from the caller's `current` as the strict
    rotation builds it. The sign-in state (key binding, CSRF token, sign-in metadata) still comes
    from the stored record (`keepSignInState`), and the grace rotation still sets the identifiers,
    timestamps and idle deadline. The old record keeps its own lower state through the window.
  - With the option, a session that is already superseded (a re-rotation inside its window, or a
    recovery after it) is refused with `session.ErrRenewalConflict` and nothing is stored. This
    keeps today's 409 when a push-approval poll races a renewal. Without the refusal, the
    re-rotation would close the renewal successor's window, and the next presentation of it would
    revoke the whole sign-in.
  - It follows the pattern `WithSuccessorRole` set for the role switch. No store changes: a store
    inserts `Supersession.Successor` as given.
  - Second-factor verification out of an enrolment or recovery confinement restores the sign-in's
    deadline on its copy (`RestoreEnrolmentDeadlines`). H2 reproduced the bug
    (`TestSessionCookie_ExistingRotationsGrace`): the option took the stored, lowered absolute
    deadline, so the unconfined successor still ended at the confinement's deadline. Decision: the
    successor takes the copy's absolute deadline only when the stored record is confined (non-zero
    `EnrolmentOriginDeadline`), the copy has cleared the confinement, and the copy's deadline is
    not after the stored origin deadline. Otherwise the stored deadline stays, so a copy still
    cannot extend a session past its sign-in's own deadline.
    - Rejected: saving the restored deadline after the rotation (an extra write, and a failed save
      leaves the early deadline).
    - Rejected: `WithSuccessorLifetime(origin - now)` (drifts past the origin by the clock gap).
  - Re-authentication with a key binding: superseded by decision 7. H2 showed that the binding can
    be non-empty on a cookie chain.

  - From the H2 review:
    - **Absolute deadline (REPRODUCED, `TestReview_FromCallerConfiningCopyKeepsLoweredDeadline`):**
      a policy can raise an enrolment challenge during verification, and then the copy's absolute
      deadline is lowered by `MarkEnrolmentPending`. The successor took the stored, full deadline,
      so an enrolment-only session outlived its confinement. The successor now takes the earlier of
      the stored and the copy's absolute deadlines, except under the lifted-confinement rule above.
      A copy may lower the deadline but never raise it.
    - **Zero grace:** with `WithRenewalGrace(0)`, a grace rotation's window closes as it opens, so
      an in-flight old cookie would revoke the whole sign-in. When the grace is zero, both
      endpoints use the strict rotation as before this change. The old cookie is then not found,
      not reuse.

### 7. A cookie chain never binds a session to a sender key

- **Problem (found by H2):** a cookie chain may also enable `EnableCertificateBinding` or
  `EnableDPoP`, for its OpenID Provider or resource server. A sign-in or re-proof that arrives over
  mTLS, or with a DPoP header, then takes a key binding from the request through
  `issuingBinding`. The cookie session refuses any sender-bound session, so:
  - **Re-authentication:** refused after the factor was spent. H2 reproduced this
    (`TestSessionCookie_ExistingRotationsGrace`, certificate row).
  - **Login, magic link, passkey, recovery, OIDC redemption:** expected to create a bound session
    whose cookie is refused on the next request. UNREPRODUCED; the first task reproduces it.
- **Decision (user decision, 2026-11-27):** on a cookie chain, every sign-in and re-proof creates
  or rotates an unbound session. The request's mTLS certificate or DPoP proof is not read for the
  session. The provider's and resource server's own tokens still use them.
- **Why:** the settled rule that a cookie session is never sender-bound makes a binding there
  self-defeating. The cookie, held HttpOnly and guarded by CSRF, is the credential.
- **Default / override:** no option. A consumer who wants sender-bound sessions uses a token chain.
- **Alternatives:**
  - Refuse a request carrying a binding proof before the factor is checked. Rejected: a browser
    behind an mTLS-terminating client setup could never sign in.
  - Refuse the combination at construction. Rejected: it breaks the one-binary provider setup.

### 2. A password change keeps the successor's idle deadline

- **Problem:** `adoptResolution` copies the pre-rotation session's `IdleExpiresAt` (and the other
  deadline fields) onto the rotated successor before `Save`, overwriting the fresh idle deadline
  the rotation set.
- **Decision:** the resolution always carries `MFA` and `PasswordChangePending`. It carries the
  deadline fields (`AbsoluteExpiresAt`, `IdleExpiresAt`, `EnrolmentOriginDeadline`,
  `EnrolmentGeneration`) only when it ends a recovery, where `RestoreEnrolmentDeadlines` computed
  them. The rollback after a failed `Save` restores exactly the fields it changed.
- **Default / override:** behaviour fix, with no option.

### 3. An empty q-value fraction is a valid q-value

- RFC 9110 §12.4.2: `qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )`. `1.` and `0.`
  are valid, and `qvalue` accepts them.

### 4. Cookie names are matched exactly, trimming only space and tab

- **Problem:** `presentedCookie` trims names with `strings.TrimSpace`, which removes Unicode
  whitespace (U+00A0, U+0085, U+2000–U+200A, U+205F, U+3000). A browser does not treat
  `" __Host-scrty-session"` as `__Host-` prefixed. A sibling host or a plain-HTTP page can
  therefore plant it with `Domain=parent`, and the chain read it as the session cookie, signing a
  victim with no session into the planter's account. The server-side half was confirmed by a
  scratch program; the browser half rests on the published research and is unverified here.
- **Decision:** name and value are trimmed of space (0x20) and horizontal tab (0x09) only, the
  optional whitespace RFC 6265 allows around a cookie pair. A name that differs from the
  configured one in any other byte is another cookie, and is ignored.
- **Why ignore and not refuse:** refusing a padded twin would let the same planter sign every user
  out (a lockout), which is what decision 5 removes for unprefixed names.
- **Default / override:** behaviour fix, with no option.

### 5. Without a Domain, the cookie name must be `__Host-` prefixed

- **Problem:** `WithSessionCookieName("sid")`, with no Domain, builds. A sibling host can set
  `sid` with `Domain=parent`. Every request then carries the name twice and is refused as
  malformed, so users are locked out. A host-only `__Secure-` name has the same hole: `__Secure-`
  only requires `Secure`, and a sibling serving HTTPS can set it for the parent domain.
- **Decision (user decision, 2026-11-27):** with no `WithSessionCookieDomain`, a name that does
  not start with `__Host-` (matched case-insensitively, as `checkAttributes` already matches
  prefixes) is a configuration error from `New`. The rule with a Domain is unchanged: the name
  must be `__Secure-`, and the godoc states that hosts under that domain can then plant it.
- **Default:** `__Host-scrty-session`, unchanged.
- **Override:** any valid `__Host-` name, or a `__Secure-` name together with a Domain.
- **Compatibility:** there is no tag yet, so this is free (library-design rule 7). It is recorded
  as BREAKING in the proposal.

### 6. Fiber's `encryptcookie` must leave the session cookie out

- **Problem:** the Fiber adapter reads the Cookie header as it arrived on the wire, so it can see
  duplicated, quoted or merged cookies that fasthttp's parser would clean away (a fix in
  `browser-session`). `encryptcookie` decrypts cookies in fasthttp's parsed copy, so the chain
  reads the ciphertext, and a sign-in never sticks.
- **Decision (user decision, 2026-11-27):** keep the raw read. The `fibersec` godoc and the README
  say to list the session cookie's name in `encryptcookie.Config.Except`. The cookie is already an
  opaque random identifier, so encrypting it adds nothing. A `fibersec` test pins that the setup
  with `Except` signs in and that the setup without it is refused.
- **Alternatives:** detect a rewritten header at request time (heuristic, tied to fasthttp's
  parsing rules); read the parsed copy when it differs (reopens the duplicate gap). Both rejected.

- **Settled during implementation (H2b):**
  - Session renewal on a cookie chain also rotates the session, so it follows the same rule: it
    does not read a DPoP proof for the session either.
  - `DPoP.Require` governs the tokens a chain issues, so on a cookie chain it no longer forces a
    proof at sign-in. The godoc says so.
  - The provider's token endpoint on a cookie chain still binds its tokens. A test pins it.

### 8. A grace rotation from a caller's copy refuses a record that changed since the copy was loaded

- **Problem (automated security review of 94e70b32):** the copy is loaded at the start of the
  request. A confinement, a second-factor downgrade or a pending password change that another
  request saves before the rotation would be overwritten by the copy's older state.
- **Decision (user decision, 2026-11-27: fix in this PR):** `WithSuccessorFromCaller(loaded *Session)`
  takes the session as the caller loaded it, before its own changes. Before anything is written,
  the rotation compares the stored record with `loaded` on the security state: `MFA`,
  `MFASatisfiedAt`, `AuthenticatedAt`, `PasswordChangePending`, `EnrolmentOriginDeadline`,
  `EnrolmentGeneration`, `RecoveredAt` and `AbsoluteExpiresAt`. Any difference is refused with
  `ErrRenewalConflict` (409) and nothing is written. The caller's own changes are the difference
  between `loaded` and `current`, so the enrolment marks the verification sets are still taken.
  A nil `loaded`, or one with another identifier, is `ErrConfig`.
- **Residual:** a `Save` landing between the rotation's read and its supersede write is not caught,
  because `Store.Supersede` conditions only on the successor digest. This is accepted: the window
  is the store round-trip, and closing it needs a new store condition on every backend.
- **Default / override:** an option the library's own endpoints pass. No consumer default
  changes. It is a pre-tag API change.

### 9. A strict rotation never extends a session, and never moves it to another user

- **Problem (S1 review, REPRODUCED by `TestReview_StrictRotateTakesCopyAbsolute`):** `Rotate` and
  `RotateIssuing` build the successor from the caller's copy and reset only the family, the sign-in
  state, the persistent mark and the role. The user, first factor and both deadlines come from the
  copy unchecked. A copy with a later deadline extends the session, against the documented rule
  that a strict rotation never extends it. A copy naming another user moves the session to them.
  Only consumer code that edits its copy reaches this. The library's own callers do not.
- **Decision (user decision, 2026-11-27: fix in this PR):**
  - A copy naming another user is refused with `ErrConfig` before anything is written, as
    `WithSuccessorFromCaller` already refuses it.
  - The first factor comes from the stored record. It is fixed by the sign-in.
  - The absolute and idle deadlines are each the earlier of the stored record's and the copy's,
    except when the copy lifted a stored confinement. Then they are the copy's, never past the
    stored origin deadline. This is the rule `WithSuccessorFromCaller` uses, shared through one
    helper.
- **Default / override:** a behaviour fix with no option. Callers that do not edit their copy's
  user, first factor or deadlines see no change.

## Failure modes

| Failure | Category | State | What the caller sees |
|---|---|---|---|
| Request in flight with the old cookie during MFA verify or re-authentication | Concurrency | Handled, tested | inside the grace window it loads the old session's own state; the new cookie is not expired |
| The same old cookie presented after the window | Security | Handled, tested | refused as reuse, family revoked, as at the role switch |
| A policy raising an enrolment challenge during MFA verification | State / Security | Handled, tested | the successor keeps the lowered enrolment deadline (the earlier of the stored and the copy's) |
| `WithRenewalGrace(0)` on a cookie chain | Wiring | Handled, tested | MFA verification and re-authentication rotate strictly; an in-flight old cookie is refused as not found, and nothing is revoked |
| The token issuer outlasts the grace window during MFA verification or re-authentication | Dependency | Accepted | a dependency failure after the factor was spent; nothing is written, and the old cookie keeps working |
| A DPoP header that does not verify, or a client certificate, at a cookie-chain sign-in, re-proof or renewal | Security | Accepted (decision 7) | the proof is never read, so it is neither verified nor recorded: no replay entry, no nonce, no event, no charge; the session is unbound and the sign-in proceeds |
| `DPoP.Require` on a cookie chain | Wiring | Accepted, documented | not enforced at sign-in, re-proof or renewal; it governs the tokens the chain issues. A consumer who wants sender-bound sessions uses a token chain; the godoc on `EnableSessionCookie` and `DPoP.Require` says so |
| The provider's token endpoint on a cookie chain | Security | Handled, tested | still verifies the proof and binds the token it issues |
| Grace successor losing the verified state | State / Security | Handled, tested | `WithSuccessorFromCaller` builds the successor from the caller's copy: MFA satisfied, refreshed `AuthenticatedAt`; sign-in state from the stored record |
| MFA verify or re-authentication on a session a renewal already superseded (push poll racing a renewal) | Concurrency | Handled, tested | `ErrRenewalConflict`, answered 409 as today; nothing stored, nothing revoked |
| A caller's copy claiming another key binding or CSRF token | Security | Handled, tested | ignored; both come from the stored record |
| Double-submitted second-factor form | Concurrency | Handled, tested | the second request loads the old session inside the window. A consumed one-time code is refused as an MFA failure, which neither rotates nor expires a cookie. A code that verifies again tries to rotate an already superseded session, which `WithSuccessorFromCaller` refuses with `ErrRenewalConflict` (409) before anything is written |
| Renewal with the old cookie inside the window after an MFA rotation | Concurrency | Handled, tested | the old cookie's session still owes its second factor, so the gate refuses the renewal before it runs; nothing is written and the new cookie keeps working (found by H2) |
| Renewal with the old cookie inside the window after a re-authentication | Concurrency | Accepted, tested | the renewal re-rotates from the stored record and closes the re-authenticated successor's window; the next request with the new cookie is reuse and the family is revoked. Fails closed, as any re-rotation the archived design accepts |
| A gate another request saved after the caller's copy was loaded | State / Security | Handled, tested | `PasswordChangePending` is raised if either the stored record or the copy has it, so a concurrent `Save` that raises it is never cleared by the rotation. The other caller-owned fields follow the copy, as a strict rotation does (accepted) |
| Confinement or second-factor state saved by another request after the caller's copy was loaded (enrolment or recovery pending, enrolment deadlines) | State / Security | Handled, tested (decision 8) | `ErrRenewalConflict` (409) and nothing written, when the stored security state differs from the state the copy was loaded with. A save between the rotation's read and its write is accepted (residual) |
| Strict `Rotate` given a copy with a later deadline, another user or another first factor | State / Security | Handled, tested (decision 9) | the deadline is not extended, another user is `ErrConfig` with nothing written, and the first factor stays the stored one |
| Client hangs up after the MFA or re-authentication rotation committed | Concurrency | Accepted | the old cookie works through the window and is reuse after it, revoking the sign-in, as the archived design accepts for the role switch; `WithUnusedSuccessorRecovery` softens it. Before this change the old cookie was signed out immediately |
| Password change on a session close to its idle deadline | State | Handled, tested | the saved successor keeps `now + idle` from the rotation |
| Password change ending a recovery | State | Handled, tested (existing) | the restored deadlines are saved, unchanged |
| A recovery-pending session with no origin deadline (only a hand-built session; `MarkRecoveryPending` always sets one) | State | Accepted | nothing is restored, and the gated session's idle deadline is saved over the successor's, which can only be earlier: the session ends sooner (fail-closed) |
| Save fails after the resolution was adopted | Dependency | Handled, tested (existing) | the in-memory successor gets back exactly the fields that were changed |
| `Accept: text/html;q=1.` | Input | Handled, tested | read as q=1; the form gets its 303 |
| Cookie name padded with U+00A0, U+0085, U+2000, U+205F or U+3000 | Security / Input | Handled, tested | ignored; the request is judged as carrying no session cookie |
| A padded twin beside the real cookie | Security | Handled, tested | the real cookie authenticates; no lockout |
| Name with space or tab padding | Input | Handled, tested | still matched (RFC 6265 optional whitespace) |
| Exact name whose value is padded with a Unicode space | Input | Accepted | the value keeps the padding, fails the identifier's shape check, and is refused as malformed and expired: fail-closed. No browser sends it, and a planter cannot reach it, since planting the exact name makes a duplicate |
| A name without `__Host-` and no Domain | Wiring | Handled, tested | `ErrConfig` from `New` naming the rule |
| Fiber `encryptcookie` covering the session cookie | Wiring | Accepted, documented, tested | sign-in never sticks; the godoc names `Config.Except` as the remedy |
| Another Fiber middleware rewriting the Cookie header | Wiring | Accepted | the chain judges the header as received; the same godoc note covers it |

## Risks / Trade-offs

- [Grace widens the time the old identifier answers] → it answers with the old session's own,
  lower state, and only for the renewal grace the consumer already accepts at the renewal
  endpoint.
- [Renaming breaks a consumer's custom unprefixed name] → no tag yet; the error names the rule.
- [The browser half of decision 4 is unverified] → the fix is correct whatever browsers do: the
  name compared is the one the browser will enforce prefixes on.

## Migration Plan

None beyond the rename for an unprefixed custom name without a Domain.

## Open Questions

None.

## References

**Decision 1**
- Reasoned from scrty's own settled specs (`browser-session`, `sessions`) and the archived
  `browser-session` design, decision 10.

**Decision 3**
- Primary documentation: [RFC 9110 §12.4.2, Quality Values](https://www.rfc-editor.org/rfc/rfc9110#section-12.4.2):
  the qvalue grammar allows zero digits after the dot.

**Decisions 4 and 5**
- Primary documentation: [RFC 6265 §5.2 and §5.4](https://www.rfc-editor.org/rfc/rfc6265): the
  cookie-pair grammar and the optional whitespace around it.
- Primary documentation: [RFC 6265bis, cookie name prefixes](https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/):
  `__Host-` (host-only, no Domain) and `__Secure-` (Secure only) rules.
- Researched (2026-11-27, not re-read for this change; cited from the security review):
  PortSwigger Research, "Cookie Chaos" (2025): bypassing cookie prefixes through servers that trim
  Unicode whitespace from names. Its browser claims are unverified here.

**Decision 6**
- Primary documentation: [Fiber v3 encryptcookie middleware](https://docs.gofiber.io/api/middleware/encryptcookie):
  `Config.Except` lists the cookie names it leaves alone.
