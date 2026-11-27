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
- **BREAKING (pre-tag):** without `WithSessionCookieDomain`, the cookie name must carry the
  `__Host-` prefix. A name without it fails construction. With a Domain, the `__Secure-` rule is
  unchanged.
- The Fiber adapter documents that Fiber's `encryptcookie` must leave the session cookie out
  (`Config.Except`), and a test pins both that setup and the failure without it.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `browser-session`: cookie matching ignores Unicode whitespace padding; a cookie name with no
  Domain must be `__Host-`; second-factor verification and re-authentication rotate with a
  grace window on a cookie chain; a password change keeps the rotation's idle deadline; the
  answer negotiation accepts an empty q-value fraction.

## Impact

- `httpsec`: `session_cookie.go`, `mfa_verify.go`, `reauth_resolve.go`, `password_change.go`,
  `session_cookie_answer.go`, and their tests.
- `httpsec/fibersec`: godoc and a test; no change to how the header is read.
- `README.md`: the Fiber note and the cookie name rule.
- Consumers who named the cookie without a prefix and without a Domain must rename it. There
  is no tag yet, so this is free under the compatibility policy, and recorded here.
