## Why

`release-readiness` carried two kinds of work: how scrty is versioned, gated and tagged, and a set of library fixes that must land before the first tag because each would be a breaking change, or a broken promise, after it. The library fixes were split out here on 2026-11-02, so they land as their own change, ahead of `oidc-provider` and of the tag. `oidc-provider`'s `sub` claim depends on the token-subject fix, and `release-readiness` is left with release mechanics and documents only.

Every item was decided in `release-readiness` on 2026-10-31 and moved here unchanged; `design.md` keeps the decisions and their references. On 2026-11-03 the change was checked against `main` once `close-security-gaps` was archived. That check added one thing: the chain's signed bearer gets its own subject option, and a build check against the chain's token generators. The token-subject decision implied both, and the user chose the check that day.

## What Changes

- **Two `notify` defects, older than `idiomatic-api-shape` and found while it was implemented:**
  - a queued sender whose wrapped sender ends its goroutine (`runtime.Goexit`, as `t.FailNow` does) loses that worker. Once every worker is gone it accepts messages it never delivers. The worker is now replaced;
  - an SMTP send with no sender address wraps `ErrConfig`, which `ErrConfig`'s godoc does not admit. The behaviour stays, and the godoc names it.
- **The token subject becomes the user's identifier by default**, with an option on the generator, on the JWT authenticator and on the chain's bearer to keep the username. Issuing with an empty subject fails. The chain reloads a signed bearer's user by the session's user reference, and refuses a token whose subject is not that reference. A chain whose token generators disagree with its bearer fails to build, as do two signed bearers that disagree, so `token.Generator` gains a method reporting its subject mode. A login whose principal has no user identifier fails, in every mode. A provider that returns no authentication fails Basic the same way, and a `JWTAuthenticator` given a generator of the other mode as its verifier fails to build. **BREAKING** for any reader of `sub`, for a reader of `Principal.Username` behind the standalone `JWTAuthenticator`, which is empty by default, for a consumer's own `token.Generator`, for a `JWTAuthenticator` given a generator of the other mode as its verifier, and for an authentication provider that returns no identifier; nothing is tagged yet.
- **A signing key retires when its tokens can have expired**, so a key replaced late stays published for that long. **The key manager then deletes it from the store** one grace later, one key lifetime by default, with options to change the grace or keep retired keys. `signingkey.KeyStore` gains a delete method. **BREAKING** for a consumer's own key store.
- **`passkey.CredentialStore` loses `DeleteAwaitingSavedCodes`**, which the library no longer calls. **BREAKING** for a consumer's own credential store.
- **A race in confirming an MFA enrolment is closed.** It was reproduced on 2026-11-03: a device proof landing inside the single-call confirm left the enrolment confirmed without the emailed code. `EnrolmentStore.Confirm` now refuses an enrolment whose device is proven, decided by its one write. **BREAKING** for a consumer's own store that implements `DeviceProofStore`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `token-issuance`: the subject is the principal's user identifier by default, or the username when configured; issuing with an empty subject fails.
- `authentication`: the bearer-token provider reads the subject the same way the generator writes it, and refuses a token with no subject.
- `http-security-chain`: the signed bearer reloads the session's user by its user reference by default, refuses a subject that is not that reference, and keeps the username lookup under an option, judged before any proof is recorded and on a late renewal too; a chain whose token generators disagree with its bearer, or two of whose bearers disagree, fails to build; a login whose principal has no user identifier fails, and an empty user reference matches no user.
- `signing-keys`: a key retires when its tokens can have expired, housekeeping deletes it from the store one grace later, by default, and the key store contract gains deletion.
- `identity-model`: a signed bearer configured to read usernames is the one exception to loading a recorded user by reference.
- `secrets-at-rest`: a re-seal racing a delete does not bring the key back.
- `email-notification`: the queued sender replaces a worker whose wrapped sender ends its goroutine, so it never accepts a message it cannot deliver; an SMTP send with no sender address anywhere fails with a configuration error, as it already does.
- `multi-factor-auth`: the single-call confirmation confirms only an enrolment whose device is not proven, decided by its write.
- `security-state-stores`: `Confirm` is refused for an enrolment with a device proof, and no longer clears an emailed code; the passkey credential store loses its unused delete.
- `store-conformance`: the enrolment suites prove a store refuses to confirm a proven enrolment, and the key-store suite proves deletion.

## Impact

- **Code, all in the core module except the stores' adapters and the `test` module:**
  - `notify`: the queued sender's worker replacement, and `ErrConfig`'s godoc;
  - `token` and `authenticate`: the subject options, and `token.Generator`'s subject-mode method; `httpsec`: `WithBearerUsernameSubject()`, the build check against every token generator the chain is given, and in `bearer.go` the user reload by the session's user reference under the default;
  - `token/signingkey`: `KeyStore.Delete` and the housekeeping deletion, implemented by the in-memory store, `sqlstore`, `pgxstore`, `gormstore` and the sealing decorator;
  - `authenticate/passkey`: the port method removed from the in-memory store, the three SQL stores, `internal/pgschema`, the conformance suite and the mocks;
  - `authenticate/mfa` and `internal/pgschema`: `Confirm`'s device-proof condition, in the in-memory store, the shared statement and `gormstore`, and `ConfirmEnrolment`'s godoc;
  - `test`: conformance cases for key deletion and for the device-proof condition.
- **No new dependency.** No new migration: key deletion uses the existing key table.
- **Related changes and order:**
  - `close-security-gaps` landed first, and was archived on 2026-11-03 (#45, #66). It *added* a `token-issuance` requirement (the confirmation claim), while this change *modifies* "Issued tokens carry a fixed set of claims". The two do not collide: on 2026-11-03 every delta here was checked against the specs as that change synced them;
  - `oidc-provider` comes next, and issues `sub` as this change defines it;
  - `release-readiness` comes last, and its first changelog entry summarises this change's breaking items.
- **Consumers:** none yet. Nothing is tagged.

## References

Carried from `release-readiness` with the decisions; see `design.md`.

**Primary documentation:**
- [OpenID Connect Core 1.0, §2 ID Token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken): `sub` is a locally unique identifier for the end user that is never reassigned. Not re-checked on this date.
- [RFC 7519, §4.1.2 "sub"](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2): the subject is unique within the issuer's context. Not re-checked on this date.

The `notify` and port decisions are reasoned from scrty's own settled specs and code, and from the follow-up sweep of the archived changes. The key-retention decision also cites researched sources, in `design.md`.
