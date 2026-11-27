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
   rotate twice silently. Pinned in Task 2, step 4.
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
| H2 | 2.1–2.3 | Opus: rotation ordering under in-flight requests | `httpsec/mfa_verify.go`, `httpsec/reauth_resolve.go`, `httpsec/session_cookie_rotation_test.go`, `httpsec/mfa_verify_test.go`, `httpsec/reauth_resolve_test.go` | `session_cookie.go`, `password_change.go`, `session_cookie_answer.go` |
| H3 | 3.1–3.2 | Sonnet: the fix is stated exactly | `httpsec/password_change.go`, `httpsec/session_cookie_answer.go`, `httpsec/session_cookie_answer_internal_test.go`, `httpsec/password_change_internal_test.go`, a new `httpsec/session_cookie_password_deadline_test.go` | `session_cookie_rotation_test.go` (H2 owns it) |
| H4 | 4.1 | Sonnet: doc and adapter test | new `httpsec/fibersec/session_cookie_encryptcookie_test.go`, `httpsec/fibersec/exchange.go` (godoc only), `README.md` (Fiber note and the cookie name rule) | `session_cookie_wire_test.go` (H1 owns it) |

All four run in parallel. The files they own are disjoint.

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

### Task 2: Grace rotation at second-factor verification and re-authentication (tasks 2.1–2.3, H2)

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
