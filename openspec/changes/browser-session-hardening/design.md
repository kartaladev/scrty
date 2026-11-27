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
- any new option.

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

## Failure modes

| Failure | Category | State | What the caller sees |
|---|---|---|---|
| Request in flight with the old cookie during MFA verify or re-authentication | Concurrency | Handled, tested | inside the grace window it loads the old session's own state; the new cookie is not expired |
| The same old cookie presented after the window | Security | Handled, tested | refused as reuse, family revoked, as at the role switch |
| Double-submitted second-factor form | Concurrency | Handled, tested | the second request loads the old session inside the window. A consumed one-time code is refused as an MFA failure, which neither rotates nor expires a cookie. A code that verifies again re-rotates, and the earlier successor's window has ended: whoever presents it next is reuse, so the family is revoked. That fails closed, as a re-rotation does at the renewal endpoint (accepted) |
| Client hangs up after the MFA or re-authentication rotation committed | Concurrency | Accepted | the old cookie works through the window and is reuse after it, revoking the sign-in, as the archived design accepts for the role switch; `WithUnusedSuccessorRecovery` softens it. Before this change the old cookie was signed out immediately |
| Password change on a session close to its idle deadline | State | Handled, tested | the saved successor keeps `now + idle` from the rotation |
| Password change ending a recovery | State | Handled, tested (existing) | the restored deadlines are saved, unchanged |
| Save fails after the resolution was adopted | Dependency | Handled, tested (existing) | the in-memory successor gets back exactly the fields that were changed |
| `Accept: text/html;q=1.` | Input | Handled, tested | read as q=1; the form gets its 303 |
| Cookie name padded with U+00A0, U+0085, U+2000, U+205F or U+3000 | Security / Input | Handled, tested | ignored; the request is judged as carrying no session cookie |
| A padded twin beside the real cookie | Security | Handled, tested | the real cookie authenticates; no lockout |
| Name with space or tab padding | Input | Handled, tested | still matched (RFC 6265 optional whitespace) |
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
