## Why

The code review and security review of PR #160 (`browser-session`) found six faults in the
cookie session that slipped past the change's own review:
- a browser signed out by a request in flight during second-factor verification or
  re-authentication;
- a password change that stores an older idle deadline than its rotation gave;
- an `Accept` quality value the HTTP grammar allows, read as malformed;
- a cookie name padded with Unicode whitespace, read as the session cookie, which defeats the
  `__Host-` prefix;
- a custom cookie name without a prefix, which lets a sibling host lock users out;
- Fiber's `encryptcookie` middleware, which the raw Cookie-header read cannot see.

All of them ship in the same PR, so they are fixed there before it leaves draft.

## What Changes

- On a cookie chain, second-factor verification and re-authentication rotate with a grace
  window, as the role switch and password change already do. A request still carrying the old
  cookie loads the old session's own state and does not expire the new cookie. A header-bearer
  chain keeps its strict rotation.
- A password change keeps the idle deadline its rotation gave the successor. It takes the old
  session's deadlines only when it ends a recovery and restores them.
- An `Accept` quality value of `1.` or `0.` is read as `1` or `0`.
- A cookie name is matched exactly, after trimming only the space and tab RFC 6265 allows
  around it. A name padded with any other whitespace is a different cookie, and is not read.
- Without `WithSessionCookieDomain`, the cookie name must carry the
  `__Host-` prefix. A name without it fails construction. With a Domain, the `__Secure-` rule is
  unchanged.
- A cookie chain never binds a session to a sender key. Sign-in, re-proof and renewal there read no
  DPoP proof or client certificate for the session. The provider's tokens still bind.
- New `session.WithSuccessorFromCaller(loaded)` rotation option: a rotation carries the verified
  state of the caller's copy, and refuses with 409 when the stored record changed since the load.
- A strict `Rotate` never extends a session, never moves it to another user, and keeps the stored
  first factor.
- The Fiber adapter documents that Fiber's `encryptcookie` must leave the session cookie out
  (`Config.Except`), and a test pins both that setup and the failure without it.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `sessions`: the caller's-copy rotation option, and the strict rotation's rules for a copy.
- `sender-constrained-tokens`: a cookie chain's sessions are never sender-bound.
- `browser-session`: cookie matching ignores Unicode whitespace padding; a cookie name with no
  Domain must be `__Host-`; second-factor verification and re-authentication rotate with a
  grace window on a cookie chain; a password change keeps the rotation's idle deadline; the
  answer negotiation accepts an empty q-value fraction.

## Impact

- `session`: `reuse.go` and `sessions.go` (new exported `WithSuccessorFromCaller`), their tests, and
  the store conformance suite in `test/storetest`.
- `httpsec`: `session_cookie.go`, `mfa_verify.go`, `reauth_*.go`, `password_change.go`,
  `session_cookie_answer.go`, `session_renewal.go`, `session_delivery.go`, `resolve.go`, `exchange.go`,
  `dpop.go`, and the sign-in endpoints (`login.go`, `magiclink.go`, `passkey_login.go`, `recovery.go`,
  `oidc_redeem.go`), with their tests.
- `httpsec/fibersec`: godoc and a test; no change to how the header is read.
- `README.md`: the Fiber note and the cookie name rule.
- Consumers who named the cookie without a prefix and without a Domain must rename it. There
  is no release with the cookie session yet (it is new in `[Unreleased]`), so nothing released breaks.
- Released behaviour that changes, recorded as BREAKING (behaviour) in the CHANGELOG: a strict
  `Rotate` no longer extends a session or accepts a copy of another user, and MFA verification and
  re-authentication answer 409 when the stored security state changed since the request loaded it.
