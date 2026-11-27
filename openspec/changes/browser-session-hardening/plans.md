# Browser Session Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the six faults the PR #160 reviews found in the cookie session, each test-first.

**Architecture:** Five small, independent edits inside `httpsec` and one doc-and-test edit in
`httpsec/fibersec`. No new exported API. One construction rule is tightened: a host-only cookie
name must be `__Host-`.

**Tech Stack:** Go, `httpsec`, `session`, Fiber v3 (`middleware/encryptcookie`), testify.

**Spec:** `openspec/changes/browser-session-hardening/` (`design.md` decisions 1–6,
`specs/browser-session/spec.md`). Executors read both.

## Global Constraints

- Test-first (`golang-tdd.md`): every red step is run and fails for the intended reason before any
  production edit. A compile error is not a red step.
- Table tests follow the `table-test` skill (`assert` closure, `t.Context()`).
- No agent edits anything under `openspec/`, or runs `git checkout --`, `restore`, `reset --hard`,
  `stash` or `clean`.
- Space (0x20) and horizontal tab (0x09) are the only bytes trimmed around a cookie name or value.
- The rotation grace on a cookie chain is `privilegeRotationGrace(renewal)`
  (`httpsec/session_delivery.go:296`), the helper the role switch uses.
- Header-bearer chains keep strict `RotateIssuing` at second-factor verification and
  re-authentication.

## Review Focus

1. A twin padded cookie beside a real one must not lock the user out (`presentedCookie` counts it
   as a duplicate today). Pinned in Task 1, step 1.
2. A double-submitted second-factor form inside the new grace window must not expire the cookie or
   rotate twice silently. Pinned in Task 2, step 4. A push poll racing a renewal answers 409 and
   never revokes the sign-in. Pinned in Task 2a, step 1, and Task 2, step 4.
3. A password-change rollback after a failed save must restore only the fields changed. The
   existing save-failure test is kept, and Task 3 asserts that `IdleExpiresAt` is restored too.
4. A lower-case `__host-` name must still build, because prefixes match case-insensitively.
   Pinned in Task 1, step 5.
5. A Fiber request whose `encryptcookie` covers the session cookie must be refused, never
   authenticated from ciphertext. Pinned in Task 4.

## Dispatches

| Dispatch | Tasks | Model | Owns | Must not touch |
|---|---|---|---|---|
| H1 | 1.1–1.3 | Sonnet: the fix is stated exactly | `httpsec/session_cookie.go` (`presentedCookie`, `checkAttributes`, `WithSessionCookieName` / `WithSessionCookieDomain` godoc), `httpsec/session_cookie_test.go`, `httpsec/session_cookie_options_test.go`, `httpsec/session_cookie_guard_test.go`, `httpsec/session_cookie_logout_test.go`, `httpsec/session_cookie_nested_resume_test.go`, `httpsec/fibersec/session_cookie_wire_test.go`, any other test naming a host-only cookie without `__Host-` | the H2, H3 and H4 files |
| S1 | 2.0 | Opus: a rotation option that carries verified state, written for the first time | `session/reuse.go` (the `rotation` struct, `RotateOption`, the grace successor build at ~:418, the strict path in `session/sessions.go` ~:938 only to refuse the option), `session/reuse_test.go`, `test/storetest/session_suite.go` (one conformance row) | every `httpsec` file |
| S1b (after S1's review) | 2.0, review follow-up | Sonnet: the fix is stated exactly | `session/reuse.go` (`successorFromCaller` and the option godoc), `session/reuse_test.go` | every `httpsec` file |
| H2b (after H2's review) | 2.4 | Opus: a binding rule across every sign-in path, security-critical | `httpsec/login.go`, `magiclink.go`, `oidc_redeem.go`, `passkey_login.go`, `reauth_resolve.go`, `recovery.go`, `mfa_verify.go`, `dpop.go` (`issuingBinding` and a cookie-chain guard), `session_cookie.go` (godoc), and a new `httpsec/session_cookie_binding_test.go` | `oidc_token.go` (the provider's token endpoint keeps binding its tokens) |
| S2 (after the H2 and H2b review) | 2.5 | Opus: an optimistic check on security state, plus an API another lane compiles against | `session/reuse.go`, `session/reuse_test.go`, `test/storetest/session_suite.go`, `httpsec/mfa_verify.go`, `httpsec/reauth_resolve.go`, `httpsec/session_cookie_rotation_test.go` | `httpsec/session_renewal.go`, `httpsec/dpop.go` |
| H2c (alongside S2) | 2.6 | Sonnet: the rule is stated exactly | `httpsec/session_renewal.go`, `httpsec/dpop.go` (godoc only), new `httpsec/session_cookie_renewal_binding_test.go` | every S2 file |
| H2 (after S1b) | 2.1–2.3 | Opus: rotation ordering under in-flight requests | `httpsec/mfa_verify.go`, `httpsec/reauth_resolve.go`, `httpsec/session_cookie_rotation_test.go`, `httpsec/mfa_verify_test.go`, `httpsec/reauth_resolve_test.go` | `session_cookie.go`, `password_change.go`, `session_cookie_answer.go` |
| H3 | 3.1–3.2 | Sonnet: the fix is stated exactly | `httpsec/password_change.go`, `httpsec/session_cookie_answer.go`, `httpsec/session_cookie_answer_internal_test.go`, `httpsec/password_change_internal_test.go`, a new `httpsec/session_cookie_password_deadline_test.go` | `session_cookie_rotation_test.go` (H2 owns it) |
| H4 | 4.1 | Sonnet: doc and adapter test | new `httpsec/fibersec/session_cookie_encryptcookie_test.go`, `httpsec/fibersec/exchange.go` (godoc only), `README.md` (Fiber note and the cookie name rule) | `session_cookie_wire_test.go` (H1 owns it) |

H1, H3 and H4 run in parallel. S1 runs alongside them, since it touches only `session` and
`test/storetest`. H2 starts once S1 is verified and reviewed, because it consumes S1's option.

**S1 scoped verification.** `session` dependents: `httpsec` and its adapters, the stores, `test`.

```sh
go test -race -count=1 ./session/... ./httpsec/... ./store/...
(cd store/pgxstore && go test -count=1 ./...); (cd store/gormstore && go test -count=1 ./...)
(cd test && go test -count=1 ./...)
go vet ./session/... && gofmt -l session test/storetest
```

**Scoped verification, every dispatch** (`test-scope.md`). `httpsec` dependents are `httpsec/ginsec`,
`httpsec/fibersec`, `httpsec/prblmsec`, `test/httpsecconformance` and `test`:

```sh
go test -race -count=1 ./httpsec/...
(cd httpsec/ginsec && go test -race -count=1 ./...)
(cd httpsec/fibersec && go test -race -count=1 ./...)
(cd httpsec/prblmsec && go test -count=1 ./...)
(cd test && go test -count=1 ./httpsecconformance/... .)
go vet ./httpsec/... && gofmt -l httpsec
```

---

### Task 1: Cookie name matching and the host-only name rule (tasks 1.1–1.3, H1)

**Files:** Modify `httpsec/session_cookie.go` (`presentedCookie` at :349, `checkAttributes` at :569,
godoc at :742 and the domain option). Tests are the files listed for H1.

**Interfaces:** Produces no new symbol. `presentedCookie(r Request, name string) (string, bool)` keeps
its signature.

- [ ] **Step 1: Failing rows.** In `TestSessionCookie_Authenticates`, or a new
  `TestSessionCookie_PaddedNameIgnored` in `session_cookie_test.go`, add rows for each of U+00A0,
  U+0085, U+2000, U+205F and U+3000:
  - the padded name with a live session's identifier, alone: no caller is published and no store
    load happens;
  - the padded name beside the real cookie: the real session authenticates, with no refusal and
    no expiring `Set-Cookie`.

  Add a row with `Cookie: \t__Host-scrty-session =<id> ` that authenticates. Add one padded-twin row
  each to `TestSessionCookie_BothCredentialsRefused` (a padded name with an Authorization header
  is not refused by the guard) and `TestSessionCookie_LogoutExpires` (logout with only a padded
  name does not expire the cookie).
- [ ] **Step 2:** Run `go test -run 'TestSessionCookie_(PaddedNameIgnored|BothCredentialsRefused|LogoutExpires)' -count=1 ./httpsec/`.
  Expected: the padded rows FAIL, because the padded name authenticates or counts as a twin.
- [ ] **Step 3:** In `presentedCookie`, trim with `strings.Trim(x, " \t")` instead of
  `strings.TrimSpace`, for both the pair and the name and value. Update its godoc to say so.
- [ ] **Step 4:** In `httpsec/fibersec/session_cookie_wire_test.go`, add
  `TestSessionCookie_PaddedNameIgnored` (Fiber) with the U+2000 alone and U+00A0 twin rows. Run it,
  and the Step 1 rows, green.
- [ ] **Step 5: Failing construction rows in `TestSessionCookie_Attributes`:**
  - `WithSessionCookieName("sid")` with no Domain: `ErrConfig`, with a message containing `__Host-`;
  - `"__Secure-sid"` with no Domain: `ErrConfig`;
  - `"__Host-app"` with no Domain: builds, and the cookie is set as `__Host-app`;
  - `"__host-app"` with no Domain: builds.

  Run them and see the two refusals fail.
- [ ] **Step 6:** In `checkAttributes`, when `s.domain == ""` and
  `!hasPrefixFold(s.name, cookiePrefixHost)`, return `newConfigError` naming the name, the
  `__Host-` rule, and the `__Secure-` plus `WithSessionCookieDomain` alternative. Move every
  existing test using a host-only `__Secure-app`, `sid` or other unprefixed name to a `__Host-`
  name, keeping what each test asserts. Update the `WithSessionCookieName` godoc line (the default
  it replaces, the `__Host-` rule without a Domain).
- [ ] **Step 7:** Run the scoped verification. Expected: all pass.

### Task 2a: `session.WithSuccessorFromCaller` (task 2.0, S1)

**Files:** Modify `session/reuse.go`, and `session/sessions.go` for the strict refusal. Test in
`session/reuse_test.go` and `test/storetest/session_suite.go`.

**Interfaces:** Produces `func WithSuccessorFromCaller() RotateOption`, accepted by
`RotateWithGrace` and `RotateWithGraceIssuing`. `Rotate` and `RotateIssuing` refuse it with
`ErrConfig`.

- [ ] **Step 1: Failing table `TestRotateWithGrace_SuccessorFromCaller`.** Store a session with
  `MFA: MFAPending` and `AuthenticatedAt: 09:00`. The caller's copy has `MFA: MFASatisfied`,
  `MFASatisfiedAt: 09:01` and `AuthenticatedAt: 09:01`, plus a different `CSRFToken` and
  `KeyBinding`. Rows:
  - **with the option:** the successor stored by the memory store has `MFASatisfied`,
    `MFASatisfiedAt` 09:01 and `AuthenticatedAt` 09:01, and the stored `CSRFToken` and
    `KeyBinding`. Its `IdleExpiresAt` is `now + idle`. The old identifier, loaded inside the
    window, still has `MFAPending` and `AuthenticatedAt` 09:00.
  - **without it:** the successor has `MFAPending` and 09:00. This passes today.
  - **`RotateWithGraceIssuing` with the option:** the issue step sees the successor with
    `MFASatisfied`.
  - **current already superseded inside its window** (rotate it once without the option first):
    `errors.Is(err, ErrRenewalConflict)`. The store holds one successor, and nothing is revoked.
  - **`Rotate(ctx, s, WithSuccessorFromCaller())`:** `ErrConfig`, nothing stored.
- [ ] **Step 2:** Run `go test -run TestRotateWithGrace_SuccessorFromCaller -count=1 ./session/`.
  Expected: FAIL, because `WithSuccessorFromCaller` is undefined. Add the option as a no-op first,
  then rerun to see the "with the option" rows fail on the stored `MFA` value. That second run is
  the real red step.
- [ ] **Step 3:** Implement. With the option, build `next` as `successorOf(current, id)` and then
  `keepSignInState(next, old)`, where `current` is the caller's copy, before the grace rotation's
  `CreatedAt`, `LastAccessedAt`, absolute, idle and role assignments. Refuse a re-rotation or a
  recovery (`kind != first rotation`) with `ErrRenewalConflict` before anything is written. In the
  strict path, refuse the option with `ErrConfig`. The godoc names the default (the stored
  record), what the option takes from where, and the refusals.
- [ ] **Step 4:** Add a conformance row in `test/storetest/session_suite.go`: a grace rotation with
  the option stores the successor's `MFA` and `AuthenticatedAt` as given, on every backend. It
  should pass, since stores insert `Supersession.Successor` as given. Invert its assertion once to
  see it fail, then restore it.
- [ ] **Step 5:** Run S1's scoped verification. Expected: all pass.

**S1b, the review follow-up (same test table, `TestRotateWithGrace_SuccessorFromCaller`).**

- [ ] **Step 6: New rows.** Each one must fail when the guard it pins is deleted. Confirm that by
  deleting the guard in the working copy, running, and putting the line back by editing it in.
  Rows:
  - **Absolute deadline:** a manager with `WithMaxFamilyLifetime(30 * 24 * time.Hour)`, and a copy
    whose `AbsoluteExpiresAt` is 24h later than the stored one. The successor keeps the stored
    absolute deadline.
  - **Role at the issue step:** `RotateWithGraceIssuing` with the copy's `SelectedRole = "admin"`
    and the stored role `"viewer"`. The session the issue step sees has `"viewer"`.
  - **Wrong user, issuing:** `RotateWithGraceIssuing` with a copy naming another user. `ErrConfig`,
    the issue step never runs, and nothing is stored.
  - **Pending password change:** stored `PasswordChangePending = true` (saved after the copy was
    taken) and copy `false`. The successor has `true`. Stored `false` and copy `true`: the
    successor has `true`.
- [ ] **Step 7:** In `successorFromCaller`, set
  `next.PasswordChangePending = next.PasswordChangePending || stored.PasswordChangePending`.
  Rewrite the godoc of `WithSuccessorFromCaller` to state its own rules: what comes from the
  copy, what from the stored record (user, family, binding, CSRF token, client metadata,
  persistent mark, role, absolute deadline), the raise-only `PasswordChangePending`, and the
  refusals. Drop "as Rotate builds it".
- [ ] **Step 8:** Run `go test -race -count=1 ./session/...` and
  `(cd test && go test -count=1 -run Session ./storetest/... ./sqlstore/...)`, plus `go vet` and
  `gofmt`. Expected: all pass.

### Task 2: Grace rotation at second-factor verification and re-authentication (tasks 2.1–2.3, H2, after S1)

Consumes `session.WithSuccessorFromCaller()` from Task 2a. Step 3 below rotates with
`RotateWithGraceIssuing(ctx, &satisfied, privilegeRotationGrace(renewal), issue, session.WithSuccessorFromCaller())`
(re-authentication: `&reproved`). `ErrRenewalConflict` keeps today's answer, 409, through
`rotationRefusal`. A non-empty re-authentication binding on a cookie chain returns an error
wrapping `session.ErrStoreContract`, never dropped. Step 4 adds a row where a renewal superseded
the session inside its window before the verify POST: 409, nothing revoked, no `Max-Age=0`. It
also adds an accepted, fail-closed row: after an MFA rotation, a renewal with the old cookie
inside the window re-rotates. The next request with the new cookie is then reuse, and the family
is revoked.

**The restored deadline (decided during H2).** H2 also owns `session/reuse.go` and
`session/reuse_test.go` for these steps.

- [ ] **Step R1: End-to-end row.** Keep `TestSessionCookie_ExistingRotationsGrace/second-factor
  verification out of an enrolment confinement restores the sign-in's deadline`. It is the
  reproduced failure: the deadline came back as the enrolment deadline, not the sign-in's.
- [ ] **Step R2: Red rows in `TestRotateWithGrace_SuccessorFromCaller`.** The stored record is
  confined (`EnrolmentOriginDeadline` = O, lowered `AbsoluteExpiresAt` = L < O).
  - **The copy cleared the confinement, with `AbsoluteExpiresAt` = O:** the successor's deadline
    is O. This row fails before the change, with L.
  - **The copy cleared it but claims O + 1h:** the successor keeps L.
  - **The copy keeps the confinement, with `AbsoluteExpiresAt` = O:** the successor keeps L.

  Show that the second and third rows fail by temporarily loosening the condition, then restore
  it by editing.
- [ ] **Step R3:** In `successorFromCaller`, take `current.AbsoluteExpiresAt` only when
  `!stored.EnrolmentOriginDeadline.IsZero()`, `current.EnrolmentOriginDeadline.IsZero()`, and
  `!current.AbsoluteExpiresAt.After(stored.EnrolmentOriginDeadline)`. Otherwise keep the stored
  deadline. The family-end cap still applies afterwards. Add the rule to the
  `WithSuccessorFromCaller` godoc.
- [ ] **Step R4:** Run `go test -race -count=1 ./session/...`,
  `(cd test && go test -count=1 -run Session ./storetest/... ./sqlstore/...)` and
  `golangci-lint run ./session/... ./httpsec/...`, then the H2 scoped verification. Expected: all
  pass.

**Files:** Modify `httpsec/mfa_verify.go` (around :579) and `httpsec/reauth_resolve.go` (around :66).
Tests go in `httpsec/session_cookie_rotation_test.go`, extending `TestSessionCookie_ExistingRotationsReset`
or adding `TestSessionCookie_ExistingRotationsGrace`.

**Interfaces:** Consumes `privilegeRotationGrace(renewal *sessionRenewal) time.Duration` and
`session.Sessions.RotateWithGraceIssuing`. How the issuer learns that it is on a cookie chain and
which renewal endpoint it has follows the role switch's wiring (`role_switch.go:338`) and the
delivery the issuer already holds (the `deliver.cookie` pattern in `password_change.go`).

- [ ] **Step 1: Failing rows for second-factor verification on a cookie chain:**
  - Verify, take the old cookie A, then send `GET /protected` with A inside the window: 200. The
    exchange's session has `MFA` still pending (or the protected route answers the MFA-required
    refusal the chain gives a pending session, whichever the existing gate yields; assert it is
    **not** the expired-cookie answer), and the response has no `Set-Cookie` with `Max-Age=0`.
  - Advance the clock to `session.DefaultRenewalGrace + time.Second`, then send A: refused as
    reuse (`errors.Is(err, session.ErrReused)`), and the family is revoked (the new cookie B is
    refused too).
- [ ] **Step 2:** Run `go test -run 'TestSessionCookie_ExistingRotations' -count=1 ./httpsec/`.
  Expected: FAIL, because A is not found and is expired.
- [ ] **Step 3:** On a cookie chain only, rotate with
  `RotateWithGraceIssuing(ctx, &satisfied, privilegeRotationGrace(renewal), issue, opts...)`.
  Header-bearer chains are unchanged. Do the same for re-authentication, keeping
  `reauthRotation(binding)...`. Update both godocs to state the window.
- [ ] **Step 4: Rows for re-authentication** (old `AuthenticatedAt` inside the window, reuse after
  it), and a double-submit row: two verification POSTs with A and the same TOTP code. The second
  is the MFA failure the chain answers for a consumed code, does not rotate (the store holds one
  successor), and carries no `Max-Age=0`.
- [ ] **Step 5: Bearer pin in `TestMFAVerify` and `TestReauthResolve`:** on a session-bearer chain
  the old identifier is not found straight after the rotation. This asserts the strict rotation is
  unchanged, and should pass already.
- [ ] **Step 6:** Run the scoped verification. Expected: all pass, under `-race`.

### Task 2b: A cookie chain never binds a session (task 2.4, H2b, decision 7)

**Files:** a new test `httpsec/session_cookie_binding_test.go`. Modify the sign-in call sites of
`issuingBinding` (`login.go:371`, `magiclink.go:480`, `oidc_redeem.go:46`, `passkey_login.go:576`,
`reauth_resolve.go:147`, `recovery.go:455` and `:863`) and the DPoP path of second-factor
verification (`mfa_verify.go` ~:344). `oidc_token.go:149` is the provider's token endpoint and keeps
binding its tokens. Do not touch it.

**Interfaces:** one guard in place of seven: a cookie chain answers `session.KeyBinding{}` for the
session without reading the certificate or the DPoP header. The implementer picks the seam, for
example a check of the chain's credential delivery inside a wrapper of `issuingBinding` used by
the sign-in paths. The provider's own token path is not routed through it.

- [ ] **Step 1: Failing table `TestSessionCookie_SignInNeverBinds`.** The chain is a cookie chain
  with `EnableCertificateBinding`, and a second chain with `EnableDPoP`. For each, a password login
  sent with a client certificate, or with a valid DPoP proof header:
  - the stored session's `KeyBinding.IsZero()`;
  - the next request with the cookie is authenticated (200).

  Add rows for magic-link redemption and passkey login on the certificate chain, and a
  re-authentication row (with H2's certificate row in `TestSessionCookie_ExistingRotationsGrace`
  moved here or rewritten): re-authentication over mTLS succeeds, the successor is unbound, and the
  new cookie works.
- [ ] **Step 2:** Run `go test -run TestSessionCookie_SignInNeverBinds -count=1 ./httpsec/`.
  Expected: FAIL. Login creates a bound session whose cookie is refused, and re-authentication
  answers `ErrStoreContract`. This is the reproduction decision 7 is waiting on; record the output.
- [ ] **Step 3:** Implement the guard. Remove H2's `errReauthBindsCookieSession` refusal, which is
  no longer reachable. Add a paragraph to the `EnableSessionCookie` godoc: a cookie chain never
  binds its sessions to a sender key; the provider's and resource server's tokens still are.
- [ ] **Step 4: Pin the header-bearer behaviour.** On an `EnableSessionBearer` chain with
  `EnableCertificateBinding`, a login over mTLS still creates a bound session. This should pass
  already; invert it once to see it fail.
- [ ] **Step 5:** Run the H2 scoped verification and `golangci-lint run ./httpsec/...`. Expected:
  all pass.

**H2 review fixes, also in H2b.** H2b also owns `session/reuse.go`, `session/reuse_test.go`,
`httpsec/session_delivery.go` and `httpsec/session_cookie_rotation_test.go`.

- [ ] **Step R5: Keep the copy's lowered deadline.**
  - **Red, session row in `TestRotateWithGrace_SuccessorFromCaller`:** the stored record is not
    confined, with absolute deadline 21:00. The copy has `MarkEnrolmentPending` applied, lowering
    its deadline to 09:15. The successor's `AbsoluteExpiresAt` is 09:15, and it fails today with
    21:00.
  - **Red, end-to-end row in `TestSessionCookie_ExistingRotationsGrace`:** a cookie chain with
    `EnableMFAEnrolment` (15m lifetime) and a policy that raises `ChallengeMFAEnrolment` once the
    second factor is satisfied. After verification, the successor ends by now + 15m.
  - **Implement:** in `successorFromCaller`, set
    `next.AbsoluteExpiresAt = minTime(stored.AbsoluteExpiresAt, current.AbsoluteExpiresAt)` unless
    `liftedConfinement` applies. The godoc says a copy may lower the deadline but never raise it.
- [ ] **Step R6: Zero grace rotates strictly.**
  - **Red row:** a cookie chain with `WithRenewalGrace(0)`. After MFA verification, the in-flight
    old cookie is refused as not found (`session.ErrNotFound`, not `ErrReused`), the family is not
    revoked, and the new cookie authenticates.
  - **Implement:** `credentialDelivery.rotateIssuing` uses strict `RotateIssuing` when the grace is
    zero.
- [ ] **Step R7:** Run `go test -race -count=1 ./session/...` and the session conformance rows,
  then the H2 scoped verification and `golangci-lint run ./session/... ./httpsec/...`. Expected:
  all pass.

### Task 2c: Refuse a record changed since the copy was loaded (task 2.5, S2, decision 8)

**Interfaces:** Produces `func WithSuccessorFromCaller(loaded *Session) RotateOption`, which replaces
the no-argument form. The two callers pass the session as the request loaded it, before their own
changes: in MFA verification the `s` that `satisfied` was copied from, and in re-authentication the
one `reproved` was copied from.

- [ ] **Step 1: Red rows in `TestRotateWithGrace_SuccessorFromCaller`.** Load `loaded`, make the
  copy `current` from it, then `Save` one change on the stored record, then grace-rotate with the
  option. Each row expects `errors.Is(err, ErrRenewalConflict)`, one successor stored, and nothing
  revoked. One row per field that changes on the stored record:
  - `MFA` set to `MFAEnrolmentPending` (through `MarkEnrolmentPending`, which also moves
    `EnrolmentOriginDeadline` and `AbsoluteExpiresAt`);
  - `PasswordChangePending` true;
  - `MFA` downgraded from satisfied to pending;
  - `RecoveredAt` set;
  - `AuthenticatedAt` changed.

  Add a control row: no stored change, and the copy adds its own enrolment marks
  (`MarkEnrolmentPending` on `current`). The rotation succeeds and takes the marks. Add wiring
  rows: a nil `loaded` gives `ErrConfig`, and a `loaded` with another ID gives `ErrConfig`.
  Before implementing, the change rows fail because the rotation succeeds and writes the copy.
  Shim the new signature first, so the red step is not a compile error.
- [ ] **Step 2: Implement.** Compare the stored record with `loaded` on `MFA`, `MFASatisfiedAt`,
  `AuthenticatedAt`, `PasswordChangePending`, `EnrolmentOriginDeadline`, `EnrolmentGeneration`,
  `RecoveredAt` and `AbsoluteExpiresAt`, using `time.Equal` for times. Run the comparison after
  `judge` and before the identifier is generated. Keep the existing raise-only
  `PasswordChangePending` and `minTime` rules. Godoc: the parameter, the compared fields, and the
  accepted residual.
- [ ] **Step 3: Update the callers and the conformance row** to pass `loaded`. Add an end-to-end
  row to `TestSessionCookie_ExistingRotationsGrace`: between loading the session for the
  verification POST and the rotation (a store hook, or a policy that saves a confinement on the
  stored record mid-request), the confinement is saved. The verification answers 409, nothing is
  written, and no cookie is set.
- [ ] **Step 4:** Run S1's scoped verification, then `go test -race -count=1 -timeout 30m ./httpsec/...`
  and `golangci-lint run ./session/... ./httpsec/...`. Expected: all pass.

### Task 2d: Renewal reads no DPoP proof on a cookie chain, and the provider still binds (task 2.6, H2c)

- [ ] **Step 1: Red row in the new `TestSessionCookie_RenewalIgnoresDPoP`.** A cookie chain with
  `EnableDPoP` and `EnableSessionRenewal`: a renewal POST carrying an invalid DPoP header renews.
  The successor is unbound and the new cookie works. Today the renewal is refused with
  `ErrInvalidDPoPProof`.
- [ ] **Step 2:** In `session_renewal.go`, route the renewal's proof check through the cookie-chain
  guard H2b added (`credentialDelivery.continuingProof` / `sessionBinding` in `dpop.go`), without
  editing `dpop.go`'s code. Add godoc: on `DPoP.Require` in `dpop.go`, that it governs issued
  tokens and a cookie chain reads no proof at sign-in or renewal; on `WithRenewalGrace`, that zero
  also makes MFA verification and re-authentication rotate strictly on a cookie chain.
- [ ] **Step 3: Pin `TestSessionCookie_ProviderTokenStillBinds`.** On a cookie chain running the
  OpenID Provider with `EnableDPoP`, a token request with a valid proof gets a token whose `cnf.jkt`
  is the proof's key thumbprint. It should pass already; invert it once to see it fail.
- [ ] **Step 4:** Run the H2 scoped verification and lint. Expected: all pass.

### Task 3: Password-change deadline and the q-value (tasks 3.1–3.2, H3)

**Files:** Modify `httpsec/password_change.go` (`adoptResolution` at :499 and its two call sites at
:379 and :386) and `httpsec/session_cookie_answer.go` (`qvalue` at :163). Tests go in a new
`httpsec/session_cookie_password_deadline_test.go` and in
`httpsec/session_cookie_answer_internal_test.go`.

**Interfaces:** `adoptResolution(dst, src *session.Session, deadlines bool)`. `deadlines` is true
exactly when the resolution ended a recovery (`s.MFA == session.MFARecoveryPending` at :276). The
rollback call passes the same value.

- [ ] **Step 1: Failing test `TestSessionCookie_PasswordChangeKeepsRotationIdle`.** Use a manager
  with idle timeout 30m and a long touch interval. Create the session, advance the clock 29m50s,
  and POST the password change on a cookie chain. The stored successor's `IdleExpiresAt` equals
  `now + 30m`, not the old deadline. A recovery-pending session still saves the restored
  deadlines: keep or extend the existing recovery test, asserting `AbsoluteExpiresAt` and
  `IdleExpiresAt` as restored.
- [ ] **Step 2:** Run it. Expected: FAIL, with the idle deadline 10s away.
- [ ] **Step 3:** Add the `deadlines` parameter. Copy `AbsoluteExpiresAt`, `IdleExpiresAt`,
  `EnrolmentOriginDeadline` and `EnrolmentGeneration` only when it is true. `MFA` and
  `PasswordChangePending` are always copied.
- [ ] **Step 4: `TestQvalue` rows** (internal, table):
  - valid: `1.`→1, `0.`→0, `1.0`→1, `0.5`→0.5, `1.000`→1;
  - invalid: `.5`, `1.1`, `2.`, `1..`, `0.5555`.

  In `TestPrefersHTML`, add a row: `text/html;q=1., application/json;q=0.5` prefers HTML. Run them
  and see `1.` and `0.` fail.
- [ ] **Step 5:** Drop `(dotted && frac == "")` from `qvalue`, and update its godoc to "up to three
  digits, possibly none".
- [ ] **Step 6:** Run the scoped verification. Expected: all pass.

### Task 4: Fiber `encryptcookie` (task 4.1, H4)

**Files:** Create `httpsec/fibersec/session_cookie_encryptcookie_test.go`. Modify
`httpsec/fibersec/exchange.go` (godoc of the adapter or of `HeaderValues`) and `README.md`.

- [ ] **Step 1: Test `TestSessionCookie_EncryptCookie`, two rows:**
  - `encryptcookie.New(encryptcookie.Config{Key: encryptcookie.GenerateKey(32), Except: []string{httpsec.DefaultSessionCookieName}})`
    mounted before the chain: sign-in sets the cookie, and the next request with it is
    authenticated (200).
  - The same without `Except`: the next request is refused (401), never authenticated.

  Check `GenerateKey`'s exact signature with `go doc github.com/gofiber/fiber/v3/middleware/encryptcookie`
  before writing.
- [ ] **Step 2:** Run `(cd httpsec/fibersec && go test -run TestSessionCookie_EncryptCookie -count=1 ./...)`.
  Both rows should pass on today's code, because this pins documented behaviour. Invert one
  assertion temporarily to confirm the test notices, then restore it.
- [ ] **Step 3: Godoc and README.** The Fiber adapter reads the Cookie header as received, so a
  middleware that rewrites cookies in place (`encryptcookie`) must leave the session cookie out
  through `Config.Except`. The cookie is an opaque random identifier, so encrypting it adds
  nothing. Add the same note to the README's Fiber section, and state there that a host-only cookie
  name must be `__Host-` (design decision 5).
- [ ] **Step 4:** Run the scoped verification for `httpsec/fibersec`. Expected: all pass.

### Task 5: Gate (task 5.1, main session)

- [ ] A whole-branch review of this change by a fresh Opus reviewer, against every scenario in
  `specs/browser-session/spec.md`.
- [ ] Run `make check` and `make spec-check`, and read the output after the last code edit.
- [ ] Commit: tests and code together per dispatch, with messages that say what is now guaranteed.
