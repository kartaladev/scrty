# Proposal

## Why

An adversarial audit of the whole library, run on 2026-10-23 before the first tag, reproduced 44 defects with failing tests (34 from the audit, 10 from the sibling sweep). A sibling sweep and a regression-impact review followed it. The worst defects:

- **Account takeover:** a signed bearer token authenticates whoever now holds the session owner's former username.
- **Process kill:** one stored scrypt record exhausts memory and kills the process.
- **Cool-down bypass:** on fiber, the recovery cool-down is bypassed by changing a path's letter case or adding a trailing slash.

The rest are fail-open defaults, limits that concurrent requests can beat, unbounded memory an attacker can grow, and panics on wiring mistakes. They must be fixed before `v0.1.0`. After the tag, every default changed here becomes a compatibility decision (`library-design.md` rule 7).

## What Changes

Each group fixes the reproduced defects and their siblings. A claim the audit could not reproduce starts with its red test, and is dropped if that test passes.

- **Bearer and session identity** (http-security-chain):
  - a bearer whose reloaded user is not the session's owner is refused;
  - so is a disabled user, at resolution and at renewal, including late renewal.
- **Bounded work from stored hashes** (password-encoding):
  - scrypt `p`, bcrypt cost, and the Argon2id threads and key length taken from a stored record are capped;
  - a constructor refuses parameters its own `Match` would refuse.
  - bcrypt refuses passwords containing NUL. **BREAKING** for any stored password that contains NUL or exceeds the new caps.
- **Login timing** (authentication): a known user with no usable password hash costs the same work as an unknown one. Encoders may report that they do not recognise a hash.
- **Exact matching where exactness protects, broad matching where it denies** (http-security-chain, account-recovery):
  - the recovery cool-down matches case-insensitively, ignores trailing slashes, and treats `HEAD` as `GET`;
  - every gate exemption and endpoint path stays exact.
- **One recovery inbox is one factor** (account-recovery):
  - an issued code is never paired with an MFA method that is also delivered by email;
  - the way-back check stops counting that pairing. **BREAKING** for consumers who relied on it.
- **ASCII-only comparison of security names** (identity-linking, authorization, account-recovery): the JIT domain allowlist, privilege names and the cancel-link loopback check compare ASCII case only, and trim only ASCII whitespace.
- **Limits that hold under concurrency** (one-time-tokens, magic-link, account-recovery, multi-factor-auth, passkey-authentication, security-state-stores, store-conformance):
  - issuance limits are decided by one write that counts and inserts atomically, behind a per-subject lock;
  - this covers magic links, recovery codes, MFA challenges, passkey registration challenges, and the 25-passkey limit.
  - **BREAKING** port additions: `onetime.Store`, `passkey.CredentialStore`.
- **Store isolation stated and enforced** (security-state-stores):
  - store-owned transactions and autocommit statements run at READ COMMITTED;
  - an operation whose guarantee needs READ COMMITTED refuses a caller's transaction at a stronger level, rather than silently degrading;
  - user-wide delete loops are bounded.
- **TOTP enrolment generations** (multi-factor-auth, security-state-stores, secrets-at-rest):
  - confirming an enrolment and accepting a time step are conditional on the enrolment generation;
  - the period must be a whole number of seconds;
  - a sealed TOTP secret is bound to its generation.
  - **BREAKING:** the MFA store port changes, and existing sealed TOTP secrets stop opening (there is no released data to migrate).
- **API keys** (api-keys):
  - a revoked or expired key cannot be rotated;
  - concurrent rotations leave exactly one live replacement;
  - an empty digest never verifies.
- **Signing keys** (signing-keys):
  - construction no longer publishes keys past their lifetime, but always keeps the newest key of each configured algorithm;
  - a key dated in the future is never chosen to sign, and housekeeping retires it.
- **Bounded memory and safe clocks** (security-policy, rate-limiting, log-sampling, oidc-login):
  - the default lockout attempt store, the outage hold and the log sampler are bounded, and fail closed when full;
  - the OIDC flow's `next` is length-bounded;
  - sweeps survive a clock stepping backwards;
  - policies deny on a zero `Now` or a nil input.
- **Wiring mistakes fail at construction** (several capabilities):
  - typed-nil and `(nil, nil)` port results are refused, not dereferenced;
  - nil ownership checkers panic at wiring;
  - sub-second TOTP periods and token lifetimes are refused;
  - unbounded OIDC skew and logout max-age are refused;
  - rate-limit flow names containing `:` are refused.
- **Responses and adapters** (http-security-chain, framework-adapters, email-notification):
  - credential-bearing responses carry `Cache-Control: no-store`;
  - fibersec keeps a route's own error status and propagates request cancellation;
  - a bare CR never reaches SMTP DATA;
  - nested `authenticate.Manager`s compose;
  - a WebAuthn backup state without backup eligibility is refused;
  - RP IDs are validated as DNS names.
- **Layout guard:** every nested module is scanned, as the settled `module-layout` requirements already demand.

Out of scope:
- gin's trusted-proxy client IP stays with the active `trusted-proxy-client-ip` change.
- Gorm read-replica routing becomes a stated limit, with no new dependency.
- Nil functional options keep the library-wide skip convention.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `http-security-chain`:
  - bearer and session-reference resolution and renewal refuse a mismatched or disabled user;
  - cool-down route matching;
  - `no-store` on credential responses.
- `account-recovery`:
  - proof shape refuses two proofs sharing a channel;
  - way-back reporting;
  - atomic issued-code limit;
  - ASCII-only loopback check.
- `password-encoding`: stored-hash work bounds; bcrypt refuses NUL.
- `authentication`: no-usable-hash timing; nested managers.
- `api-keys`: rotation refusal and atomicity; empty digest.
- `signing-keys`: restart loading; future-dated keys.
- `security-state-stores`: isolation; atomic bounded insert; MFA generation guards; bounded deletes.
- `store-conformance`: cases for the above.
- `security-policy`: bounded default attempt store; zero `Now` and nil input deny.
- `rate-limiting`: bounded outage hold and backwards-clock sweep; flow-name validation.
- `log-sampling`: memory bounded within a window.
- `oidc-login`: `next` bound; clock-skew bound.
- `oidc-logout`: logout token maximum-age bound.
- `identity-linking`: ASCII-only domain match.
- `authorization`: ASCII-only privilege comparison.
- `multi-factor-auth`: whole-second period; generation-conditional confirm and step acceptance; atomic challenge cap.
- `one-time-tokens`: atomic counted issuance.
- `magic-link`: atomic per-user limit.
- `passkey-authentication`: atomic passkey and challenge limits; backup flags; RP ID validation; nil user details.
- `secrets-at-rest`: MFA secret bound to its generation.
- `token-issuance`: whole-second lifetime; typed-nil verification keys.
- `sessions`: first-use write failure; nil store results.
- `framework-adapters`: fiber route errors and cancellation; nil guard wiring.
- `email-notification`: bare CR normalisation.
- `http-error-propagation`: statuses for the issuance limit (429), a refused rotation (409), an unknown API key (404), and a refused magic-link redemption (401, which answered 500 before).

`module-layout` needs no delta. Its requirements already cover "any scrty module", and the layout-guard fix makes the guard enforce them.

## Impact

- **Packages:**
  - `httpsec`, `fibersec`, `ginsec`;
  - `password`, `authenticate`, `apikey`;
  - `recovery`, `magiclink`, `onetime`, `mfa`, `passkey`, `passkey/webauthn`;
  - `oidc`, `authorize`, `policy`, `ratelimit`;
  - `signingkey`, `token`, `session`, `seal`, `notify`;
  - `internal/unavailable`, `internal/pgschema`, `pkg/logsample`;
  - `pgx`, `sqlstore`, `gorm`;
  - the `test` module's conformance suites and fixtures;
  - the root layout tests.
- **Ports:**
  - `onetime.Store`, `passkey.CredentialStore`, `mfa` enrolment store, `apikey.Store`;
  - `seal.MFASecretAAD`'s signature;
  - an optional password-encoder recogniser.
  - Every backend and generated mock is updated with its port.
- **Data:**
  - stored hashes beyond the new caps, and bcrypt passwords containing NUL, stop matching;
  - existing sealed TOTP secrets stop opening;
  - no schema migration (the existing indexes serve the new locks).
- **Coordination:** the layout-guard fix follows `release-readiness` task 2.1, which also edits `layout_test.go`.
- **Dependencies:** none added.
