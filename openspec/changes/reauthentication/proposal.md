# Proposal

## Why

A consumer cannot protect its own important routes (delete a project, change a payout account, rotate a secret) with a "confirm it is you" step. scrty records when a session last authenticated (`AuthenticatedAt`), and two of its own endpoints, recovery-code regeneration and passkey registration or removal, refuse a stale session. Nothing else uses that time:

- No guard lets a consumer's route ask for a recent authentication.
- No endpoint lets a signed-in user prove themselves again. Once the 15-minute window has passed, the only way back is to sign out and in again.

OWASP asks for re-authentication before sensitive changes, and services such as GitHub ("sudo mode"), Google and Microsoft Entra offer it. A security library without it pushes every consumer to build their own, usually on the weakest factor.

## What Changes

- **A recency guard.** `Guards.RequireRecentAuthentication()` refuses a request whose session authenticated longer ago than the guards' window, 15 minutes by default. `RequireAuthenticationWithin(d)` sets the window for one route. Wiring:
  - The window is fixed: only an authentication moves it, never a renewal or further use of the route.
  - It runs on the guards' shared fail-closed path: principal, then authorizer, then recency.
  - Its refusal is a new `ErrReauthenticationRequired` (403), carrying the window so a consumer can render an RFC 9470-style `max_age`.
  - Guards gain a time source (`WithGuardClock`), a guards-wide window (`WithRecentAuthenticationWindow`) and a replaceable authentication-time source (`WithAuthenticationTime`), so principals without a session can be judged by a consumer's own record.
  - The same guard and options exist in `ginsec` and `fibersec`.
- **Re-proof endpoints for a signed-in session**, opt-in with `httpsec.EnableReauthentication(...)`, under `/reauth` by default:
  - `GET /reauth/methods` lists how this session's user may re-prove;
  - `POST /reauth/begin/{method}` and `POST /reauth/verify/{method}` re-prove with an enrolled second factor (TOTP, passkey);
  - `POST /reauth/password` re-proves with the password, for a user who holds no usable second factor.
  - Success refreshes the session's authentication time, rotates the session and returns the new credential. Failures count against the existing per-user second-factor throttle and the password lockout.
- **The default re-proof policy is "strongest factor held".** A user who holds a usable second factor must re-prove with one, and may not fall back to the password. A user who holds none re-proves with their password.
  - `RequireSecondFactorForReauthentication()` makes it "second factor only".
  - A looser "any factor" option is deliberately not offered (design D3).
  - A user with neither (OIDC-only, magic-link-only) re-proves by signing in again.
- **Re-proof is not bound by the same-channel rule.** A user who signed in with a passkey may re-prove with that passkey. The rule exists to make two factors independent at login. A re-proof is a single factor presented alongside a live session secret, which NIST SP 800-63B-4 allows at AAL2.
- **BREAKING (pre-tag):** the MFA verify and begin endpoints refuse a session that owes no second-factor challenge, with `ErrNoMFAChallengePending`, as the method listing already does. Today a full session can post to `/mfa/verify/{method}` and refresh its authentication time through an unspecified, untested path. Re-proof has one home from now on.
  - Because that path also let a full session meet its second factor, a chain with the MFA slot and passkeys must enable re-authentication: without it a user who signed in without a second factor could never manage passkeys, so construction fails and names the option.
- **Wiring checks that match the endpoints.** Re-proof paths are checked against every endpoint the chain answers, by how each matches: exact paths only collide with what lies under a prefix-matched path, so `/login/reauth` is accepted and `/passkey/register` as the prefix is refused. A chain that gave MFA a shared challenge store must give re-authentication one too.
- **The password re-proof applies the post-authentication policy**, as a login does, so a user whom login refuses cannot refresh a session with the password. The policy input marks it as a re-proof, so the session cap does not count the session being re-proved twice, and a proved password cancels a held account recovery, as a login's does.
- **Every re-proof path binds the same policy, and a failed credential issue signs no one out.** A second-factor re-proof also applies the post-authentication policy's denials, and a re-proof or MFA verification whose credential cannot be issued stores nothing, so the caller's credential keeps working.
- **A strict rotation that lost a race is a renewal conflict across replicas.** The old session is kept, marked, for its 30-second in-flight window instead of being deleted, so any manager sharing the store answers a losing rotation or renewal with 409 rather than 401. This adds one column to the sessions table.
- **One freshness rule.**
  - Recovery-code regeneration, passkey registration and removal, and the guard all judge "the session's authentication time", through one shared check.
  - The authentication time is refreshed by a re-proof as well as by a second factor.
  - The recovery and passkey requirements stop describing freshness as "the later of creation and second-factor satisfaction". A password re-proof moves the authentication time without satisfying a second factor, so that wording would no longer be accurate.

## Capabilities

### New Capabilities

- `reauthentication`: re-proving the user of an already signed-in session:
  - the recency guard and its window, clock and authentication-time source;
  - the re-proof endpoints and the factor policy that decides which proofs a user may present;
  - re-proof throttling, rotation, responses and refusals.

### Modified Capabilities

- `sessions`: the authentication time is also refreshed by a re-authentication, one shared check decides whether a session authenticated within a window, and a strict rotation keeps its old session marked for the in-flight window, so a rotation or renewal that lost the race through any manager sharing the store is a renewal conflict rather than not-found (design D10).
- `security-state-stores`: session stores keep whether a supersession was a rotation without grace.
- `schema-migrations`: a migration adds the session strict-rotation mark.
- `store-conformance`: the session suite covers the mark, across managers sharing a store.
- `multi-factor-auth`: the verify and begin endpoints serve only a session that owes a second-factor challenge, concurrent verifications of one pending session yield one success and one renewal conflict, and a chain with MFA and passkeys needs re-authentication.
- `account-recovery`: regeneration freshness reads the session's authentication time, wording only (the code already reads it); a password re-authentication cancels a held recovery.
- `security-policy`: the concurrent session cap admits the re-authentication of a session it already counts.
- `passkey-authentication`: registration and removal freshness read the session's authentication time, wording only.
- `http-error-propagation`: the new refusals join the public contract and the status table.
- `framework-adapters`: gin and fiber guards offer the recency guard with the same options and outcome.

## Impact

- **Code:**
  - `session`: a shared freshness check; the strict-rotation mark and the end of the old row's delete.
  - Session stores: the in-memory store, `store/sqlstore`, `store/pgxstore`, `store/gormstore`, `internal/pgschema` and `internal/storekit`; a new migration in `store/migrate/securitystate`.
  - `internal/guardauth`: the recency judge shared by the three adapters.
  - `httpsec`:
    - guards and their options;
    - a new re-authentication interceptor at a new slot, `OrderReauthentication` (655), after the password-change gate and before passkeys;
    - errors and the status table;
    - the MFA verify and begin admission;
    - the recovery-code check.
  - `authenticate/passkey`: the management check moves to the shared helper.
  - `httpsec/ginsec` and `httpsec/fibersec`: their guards.
- **Tests:**
  - unit tests per package;
  - the sentinel registry test;
  - `test/httpsecconformance` scenarios on net/http, gin and fiber.
  - the session store suite in `test/storetest` on every backend, and the migration tests.
- **Docs:** godoc on every new option, guard and endpoint; a README section on re-authentication and the defaults table.
- **Builds on** `idiomatic-api-shape` (merged in PR #29, archived in PR #31): `NewGuards` returning an error, and the `GuardOption` and adapter guard shape it settles.
- **Follow-ups, out of scope:**
  - Re-authentication through an OIDC provider (`max_age`, `prompt=login`, `auth_time`). An OIDC session's authentication time today is its local sign-in time.
  - Cookie delivery and CSRF for the re-proof endpoints, which `bff-resource-server` must cover with its other unsafe endpoints.
- **One schema change** (the strict-rotation column, D10) and **no new dependency.**
