## 1. Cookie name matching and the host-only name rule (decisions 4, 5)

- [x] 1.1 Red: rows in the cookie-reading table for a name padded with U+00A0, U+0085, U+2000, U+205F and U+3000, each alone and as a twin beside the real cookie; a row for space and tab padding that still matches. Fix `presentedCookie` to trim space and tab only.
- [x] 1.2 Red: the same padded-name rows on the Fiber adapter (`fibersec` wire test) and through the both-credentials guard and logout, which share `presentedCookie`.
- [x] 1.3 Red: construction rows for `sid` and `__Secure-sid` with no Domain (refused, naming `__Host-`), `__Host-app` with no Domain (builds), and a lower-case `__host-app` (builds, as prefixes match case-insensitively). Add the rule to `checkAttributes`, move every existing test that names a host-only cookie without `__Host-` to a `__Host-` name, and update the `WithSessionCookieName` and `WithSessionCookieDomain` godoc.

## 2. Rotation at second-factor verification and re-authentication (decision 1)

- [x] 2.0 Red, in `session`: a grace rotation of a caller's copy with MFA satisfied and a refreshed `AuthenticatedAt` stores a successor with neither, unless `WithSuccessorFromCaller()` is given. Add the option, taken by `RotateWithGrace` and `RotateWithGraceIssuing`. The successor takes the caller's state as the strict rotation does, and the sign-in state from the stored record. A superseded current is refused with `ErrRenewalConflict` and nothing is stored. Strict `Rotate` refuses the option with `ErrConfig`. Pin it on the memory store and in the store conformance suite. From the S1 review:
  - pin the stored absolute deadline under `WithMaxFamilyLifetime(30 * 24h)`;
  - pin the stored role, as the issue step sees it;
  - add an issuing row for the user-mismatch refusal (the step does not run);
  - raise `PasswordChangePending` from the stored record, never clearing it, with a stale-copy row;
  - the godoc states the option's own rules, not "as Rotate builds it".
- [ ] 2.1 Red: on a cookie chain, a request with the pre-verification cookie after second-factor verification, inside the window, loads the old session with the factor pending and its answer carries no expiring `Set-Cookie`; after the window it is reuse and the family is revoked. Rotate with `RotateWithGraceIssuing(..., session.WithSuccessorFromCaller())` on a cookie chain, with the role switch's grace; a session a renewal already superseded answers 409 as today. Verification out of an enrolment or recovery confinement restores the sign-in's deadline on the successor: `WithSuccessorFromCaller` takes the copy's absolute deadline only when the stored record is confined, the copy cleared the confinement, and the copy's deadline is not after the stored origin deadline. Session rows pin all three conditions.
- [ ] 2.2 Red: the same pair of rows for re-authentication (old `AuthenticatedAt` inside the window; reuse after it).
- [ ] 2.3 Pin that a header-bearer chain still rotates strictly at both endpoints (the old identifier is not found straight after), and that a double-submitted verification with a consumed code is an MFA failure that rotates nothing and expires no cookie.

## 3. Password change deadline and the q-value (decisions 2, 3)

- [x] 3.1 Red: a cookie-chain password change on a session whose stored idle deadline is seconds away saves a successor whose idle deadline is the rotation's. Carry the deadline fields in the resolution only when it ends a recovery; the rollback after a failed save restores exactly the fields changed. Existing recovery and save-failure tests stay green.
- [x] 3.2 Red: `qvalue` rows for `1.` and `0.` (valid), `1.0`, `0.5` (valid), `.5`, `1.1`, `2.`, `1..` (invalid), and a negotiation row where `Accept: text/html;q=1., application/json;q=0.5` gets the 303.

## 4. Fiber encryptcookie (decision 6)

- [x] 4.1 A `fibersec` test: with `encryptcookie` excluding the session cookie (`Config.Except`), a sign-in sets the cookie and the next request authenticates; without `Except`, the next request is refused. Godoc on the Fiber adapter and a README note naming `Config.Except`.

## 5. Gate

- [ ] 5.1 Whole-branch review of this change, then `make check` and `make spec-check`, output read after the last code edit.
