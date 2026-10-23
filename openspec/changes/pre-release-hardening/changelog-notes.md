# Changelog notes for `release-readiness`

`CHANGELOG.md` does not exist yet; `release-readiness` task 5.2 creates it. These are the entries
this change contributes under `Unreleased`, in Keep a Changelog 1.1.0 sections. Entries marked
**BREAKING** change a public signature, a default, or how existing data behaves. Fold them in when
5.2 runs, then delete this file.

## Changed

- **BREAKING** `onetime.Store` gains `InsertWithin(ctx, tok, since, limit) (bool, error)`, and
  `onetime.Manager` gains `IssueWithin`, which reports the new `onetime.ErrIssueLimitReached`
  (answered 429). Every consumer-written one-time store must implement it.
- **BREAKING** `passkey.CredentialStore` gains `InsertWithin(ctx, cred, limit) (bool, error)`.
  `DeleteAwaitingSavedCodes` stays on the port but the library no longer calls it.
- **BREAKING** The MFA enrolment store's `Confirm` and `AcceptStep` take the enrolment generation
  and write only on it.
- **BREAKING** `apikey.Store.Revoke` returns `(bool, error)`: whether this call revoked the key.
  `apikey.Manager.Rotate` refuses a revoked or expired key with the new `apikey.ErrRotationRefused`
  (answered 409).
- **BREAKING** `seal.MFASecretAAD` takes `(gen id.ID, user identity.UserID)` and binds the
  enrolment generation. TOTP secrets sealed before this release no longer open: affected users
  enrol their authenticator again.
- **BREAKING** Stored password hashes are bounded: scrypt `p ≤ 16`, `(N + p)·128·r ≤ 1 GiB` and a
  power-of-two `N ≥ 2`; bcrypt cost `≤ 16`; Argon2id memory `≤ 1 GiB`, iterations, threads `≤ 16`,
  salt and key `≤ 64` bytes. A hash above them no longer matches, and encoders refuse such
  parameters at construction. bcrypt refuses a password containing NUL. Affected users reset
  their password. The OIDC password-claim cost band tops out at 16.
- **BREAKING** Account recovery refuses an issued code paired with an email-channel MFA proof, and
  the way-back check no longer counts that pairing.
- **BREAKING** The recovery cool-down matches its marked routes ignoring ASCII case and trailing
  slashes, with `HEAD` as `GET`, so on net/http and gin it also holds a differently cased route.
- A refused magic-link redemption answers 401; it answered 500. `apikey.ErrKeyNotFound` answers 404.
- A TOTP period and a token lifetime must be whole seconds, at least one; OIDC clock-skew leeway is
  bounded at 5 minutes and logout-token max age at 1 hour; OIDC redirect allowlist entries and a
  requested `next` are bounded at 2048 bytes; a rate-limit flow name may not contain `:`; magic-link
  and passkey-ceremony cookie TTLs must be whole seconds; the passkey relying-party ID must be a
  lowercase DNS name. Each is refused at construction.
- Ownership and resource guards in `httpsec`, `fibersec` and `ginsec` panic at wiring on a nil
  checker, extractor or `Guards`.
- `fibersec` keeps a route's own error and status, and runs the chain on a context cancelled when
  the request's handling ends (fiber gives no disconnect signal).
- Security-state stores pin READ COMMITTED for every transaction they open; recovery-code replace,
  the streak add and the bounded inserts refuse a caller's stronger transaction with the new
  `storeerr.ErrIsolationTooStrong`. User-wide session deletes stop after 64 passes with
  `session.ErrDeleteDidNotSettle`.
- The default lockout attempt store, the outage hold and the log sampler are bounded and fail closed
  when full (`policy.WithAttemptStoreCapacity`, `logsample.WithMaxKeys`).
- Signing keys: construction, reload and housekeeping share one publishing rule; a future-dated key
  never signs.

- Policies deny a zero `Input.Now` (idle timeout, password age, enrolment path) and `Engine.EvaluatePhase` denies a nil input; they allowed before.
- A nested `authenticate.Manager` whose delegates skip lets the outer manager try its next delegate.
- Default login, magic-link, MFA begin and verify, and passkey login responses carry `Cache-Control: no-store`.
- A WebAuthn backed-up state without backup eligibility is refused at registration and assertion.
- SMTP bodies normalise bare CR and bare LF to CRLF.
- New sentinels: `password.ErrPasswordContainsNUL`, `policy.ErrAttemptStoreFull`, `onetime.ErrIssueLimitReached`, `apikey.ErrRotationRefused`, `session.ErrDeleteDidNotSettle`, `storeerr.ErrIsolationTooStrong`.

## Added

- Package `storeerr`, holding errors every durable store backend shares.
- `password.Recognizer`, an optional encoder interface; a user whose stored hash is empty or
  unrecognised costs the same work as an unknown user.

## Security

- A signed bearer no longer authenticates whoever now holds the session owner's former username;
  a disabled user's sessions are refused.
- One stored scrypt or bcrypt record can no longer exhaust memory or CPU.
- The recovery cool-down can no longer be bypassed on fiber by changing a path's case or adding
  trailing slashes.
- Issuance and passkey limits hold under concurrent requests.

## For the release procedure

- `pgx/go.mod` and `gorm/go.mod` require a root-module version that predates `storeerr`,
  `session.ErrDeleteDidNotSettle` and the new store ports. The workspace hides this; the
  requirements must be bumped to the tagged root version (`release-readiness` task 2.x).
- `layout_test.go` and `layout_guard_test.go` already scan every module `go.work` lists except
  `./test` (`workspaceModules(t, root)`, `workspaceViolations`, `TestModuleLayoutEveryWorkspaceModule`).
  `release-readiness` task 2.1 adds its own test beside them; reuse `workspaceModules` rather than
  reading `go.work` again.
