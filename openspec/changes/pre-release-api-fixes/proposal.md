## Why

`release-readiness` carried two kinds of work: how scrty is versioned, gated and tagged, and a set of library fixes that must land before the first tag because each would be a breaking change, or a broken promise, after it. The library fixes were split out here on 2026-11-02, so they land as their own change, ahead of `oidc-provider` and of the tag. `oidc-provider`'s `sub` claim depends on the token-subject fix, and `release-readiness` is left with release mechanics and documents only.

Nothing in this change is new. Every item was decided in `release-readiness` on 2026-10-31 and moved here unchanged; `design.md` keeps the decisions and their references.

## What Changes

- **Two `notify` defects, older than `idiomatic-api-shape` and found while it was implemented:**
  - a queued sender whose wrapped sender ends its goroutine (`runtime.Goexit`, as `t.FailNow` does) loses that worker. Once every worker is gone it accepts messages it never delivers. The worker is now replaced;
  - an SMTP send with no sender address wraps `ErrConfig`, which `ErrConfig`'s godoc does not admit. The behaviour stays, and the godoc names it.
- **The token subject becomes the user's identifier by default**, with an option on the generator and on the JWT authenticator to keep the username. Issuing with an empty subject fails. **BREAKING** for any reader of `sub`; nothing is tagged yet.
- **The key manager deletes the signing keys it retires for age** from the store, with an option to keep them. `signingkey.KeyStore` gains a delete method. **BREAKING** for a consumer's own key store.
- **`passkey.CredentialStore` loses `DeleteAwaitingSavedCodes`**, which the library no longer calls. **BREAKING** for a consumer's own credential store.
- **A reported race in confirming an MFA enrolment** is reproduced or dropped before the tag. If it reproduces, the fix's decision and a `multi-factor-auth` delta are written before any fix.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `token-issuance`: the subject is the principal's user identifier by default, or the username when configured; issuing with an empty subject fails.
- `authentication`: the bearer-token provider reads the subject the same way the generator writes it.
- `signing-keys`: housekeeping deletes from the store the keys it retires for age, by default.
- `email-notification`: the queued sender replaces a worker whose wrapped sender ends its goroutine, so it never accepts a message it cannot deliver.

## Impact

- **Code, all in the core module except the stores' adapters and the `test` module:**
  - `notify`: the queued sender's worker replacement, and `ErrConfig`'s godoc;
  - `token` and `authenticate`: the subject options; `httpsec/bearer.go`: the user reload by the session's user reference under the default;
  - `token/signingkey`: `KeyStore.Delete` and the housekeeping deletion, implemented by the in-memory store, `sqlstore`, `pgxstore`, `gormstore` and the sealing decorator;
  - `authenticate/passkey`: the port method removed from the three SQL stores, `internal/pgschema`, the conformance suite and the mocks;
  - `test`: conformance cases for key deletion, and the MFA confirmation race test.
- **No new dependency.** No new migration: key deletion uses the existing key table.
- **Related changes and order:**
  - `close-security-gaps` lands first. It *adds* a `token-issuance` requirement (the confirmation claim), while this change *modifies* "Issued tokens carry a fixed set of claims"; the two do not collide, but this change archives after it;
  - `oidc-provider` comes next, and issues `sub` as this change defines it;
  - `release-readiness` comes last, and its first changelog entry summarises this change's breaking items.
- **Consumers:** none yet. Nothing is tagged.

## References

Carried from `release-readiness` with the decisions; see `design.md`.

**Primary documentation:**
- [OpenID Connect Core 1.0, §2 ID Token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken): `sub` is a locally unique identifier for the end user that is never reassigned. Not re-checked on this date.
- [RFC 7519, §4.1.2 "sub"](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2): the subject is unique within the issuer's context. Not re-checked on this date.

The `notify`, key-retention and port decisions are reasoned from scrty's own settled specs and code, and from the follow-up sweep of the archived changes.
