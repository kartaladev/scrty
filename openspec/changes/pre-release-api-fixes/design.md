## Context

See `proposal.md` for the motivation. Every decision below was made in `release-readiness` (decisions 9–14 there, user's choices of 2026-10-31) and moved here unchanged on 2026-11-02, renumbered 1–6. Only their numbering and this context are new.

- **`notify`.** The queued sender recovers a panic in the wrapped sender, but `recover` cannot stop `runtime.Goexit`. `notify/smtp.go` wraps `ErrConfig` for a message with no sender address.
- **Token subject.** `token` issues the principal's username as `sub` (the package doc, "The subject"). The chain's session-backed bearer interceptor reloads the user by username, keyed on `sub` (`lookupByUsername` in `httpsec/bearer.go`). The standalone `authenticate.JWTAuthenticator` builds its principal from the claims alone.
- **Signing keys.** `signingkey.KeyStore` stores and loads records but cannot delete one. Housekeeping stops publishing old keys and leaves them in the store.
- **Passkeys.** `passkey.CredentialStore.DeleteAwaitingSavedCodes` is declared, implemented by every store and never called by the library.
- **MFA.** The single-call `ConfirmEnrolment` reads the pending enrolment and then calls the store's `Confirm`, which checks neither the generation nor the device proof.
- **The established design** carries the username as the token subject. Decision 3 departs from it; the others have no counterpart there to follow or depart from.

## Goals / Non-Goals

**Goals:**

- Every item lands before `v0.1.0`, so no breaking change and no broken promise is left for after the tag.
- The token subject is settled before `oidc-provider` issues `sub` to relying parties.

**Non-Goals:**

- Anything about versioning, tagging, the release gate or the release documents. Those stay in `release-readiness`.
- New behaviour beyond what `release-readiness` decided.

## Decisions

### 1. A queued-sender worker that ends abnormally is replaced

- **The defect.** `recover` cannot stop `runtime.Goexit`, so a wrapped sender that ends its goroutine (as `t.FailNow` does) kills the worker delivering its message. Once every worker is gone, `Send` still queues messages and returns no error, and nothing delivers them. This breaks `email-notification`'s rule that an accepted message is delivered. It was REPRODUCED by a scratch test while `idiomatic-api-shape` was implemented, and is older than that change. The scratch test is not in the tree; task 1.1 writes the red test again.
- **The fix.** A deferred check notices a delivery that did not return normally. It logs the failure and starts a replacement worker, so the pool stays at its configured size. The message being delivered is reported as failed, as a panic's message already is.
- **Default and override:** automatic, with no option. A pool that silently shrinks has no use a consumer could want.
- **Alternative considered:** document the case and leave it. Rejected, because the sender would then accept messages it never delivers.
- **Order:** the `email-notification` delta copies the requirement as `idiomatic-api-shape` modified it. That change is archived (2026-10-31), so the base is current.

### 2. A missing sender address stays a configuration error

- **The mismatch.** `notify/smtp.go` wraps `ErrConfig` when a message has no `From` and the sender was built with no default address. `ErrConfig`'s godoc says it marks wiring mistakes, as opposed to failures at send time, and does not mention this case. UNREPRODUCED: the wording disagrees with the behaviour, and the behaviour is not wrong.
- **The decision.** The case is a wiring mistake: the consumer configured neither a default sender nor a sender on the message. `ErrConfig` keeps wrapping it, and its godoc names it.
- **Default and override:** unchanged. A consumer sets `WithSMTPFrom`, or `Message.From`.
- **Alternative considered:** a new sentinel for a missing address. Rejected, because it adds API for a case the existing sentinel already means.

### 3. The token subject is the user's identifier by default

- **The problem.** Issued tokens carry the principal's username as `sub`. A rename invalidates the user's live tokens, and a username can be reassigned to someone else, while `sub` is the claim every verifier keys on.
- **The decision.** By default the generator writes `Principal.ID` as `sub`, and the JWT authenticator builds the principal with that identifier. This departs from the established design, which carries the username. The departure exists because `sub` is meant to be stable and never reassigned, and a public claim cannot change after the first tag without breaking live tokens and external verifiers. `oidc-provider` relies on it: an OpenID Provider's `sub` must never be reassigned.
- **Default and override.** The default is the user identifier. A consumer whose own systems read the username sets `token.WithUsernameSubject()` on the generator and `authenticate.WithJWTUsernameSubject()` on the authenticator. The two components cannot see each other, so a mismatch cannot fail at construction; both options' godoc says they must agree.
- **Refusal.** Issuing for a principal whose chosen subject is empty fails, instead of minting a token no one can resolve.
- **Two bearer paths, two effects.**
  - The standalone `authenticate.JWTAuthenticator` builds its principal from the claims alone. Under the default it carries the identifier and no username.
  - The `httpsec` chain's session-backed bearer interceptor reloads the user and builds the principal from the reloaded details (`PrincipalFromDetails`), so `Username` stays filled. Today it reloads by username, keyed on `sub` (`lookupByUsername` in `httpsec/bearer.go`). Under the default it reloads by the session's user reference instead (`lookupBySessionUser`), and refuses a token whose `sub` is not that reference. Under the username option it keeps the lookup by username. Either way the user must still own the session, as now.
  - Anything reading `Principal.Username` behind the chain, such as a password re-proof, therefore keeps working.
- **Risk.** A reader of `Principal.Username` behind the standalone authenticator sees an empty name under the default. The first task audits every such reader with gopls before the change, and reports any consumer of the name.
- **User's choice, 2026-10-31:** an option, defaulting to the identifier.

### 4. Housekeeping deletes the keys it retires for age

- **The problem.** `signingkey.KeyStore` has no delete method. Housekeeping stops publishing old keys but leaves them in the store, which gains a row per algorithm per rotation, hourly by default, and every row is loaded at start and on each reload.
- **The decision.** `KeyStore` gains `Delete(ctx context.Context, kids ...string) error`. It is idempotent: a missing key is not an error. Housekeeping deletes every key it stops publishing because it is older than the key lifetime. Such a key can no longer verify a token, since token lifetimes are shorter than the key lifetime. A key it stops publishing because it is dated in the future is only unpublished, never deleted, because that date may come from another replica's clock. A failed delete is reported to the logger and the error hook and retried at the next run.
- **Implementations.** The in-memory store, `sqlstore`, `pgxstore`, `gormstore`, and the sealing decorator, which forwards the call. The store conformance suite gains delete cases.
- **Default and override.** Deletion is on by default. `WithRetiredKeysKept()` keeps retired keys in the store, for a consumer who audits them.
- **User's choice, 2026-10-31:** add the delete method before the tag.

### 5. The unused passkey store method is removed

- `passkey.CredentialStore.DeleteAwaitingSavedCodes` has not been called by the library since an earlier change stopped deleting credentials awaiting saved codes. It is removed from the port, the three SQL stores, the conformance suite and the mocks. Removing a port method after the tag would break every consumer store, so it goes now.
- **Default and override:** none; it is a removal of an unused method.
- **User's choice, 2026-10-31.**

### 6. The reported MFA confirmation race is settled before the tag

- **The claim.** The single-call `ConfirmEnrolment` reads the pending enrolment, then calls the store's `Confirm`, which checks neither the enrolment's generation nor the device proof. A device proof landing in between would go unseen. UNREPRODUCED.
- **The decision.** The first task of its group writes the red test. If it passes, the claim is dropped and recorded here. If it fails, apply pauses so that this decision and a `multi-factor-auth` delta can be written before the fix, because fixing it changes the store's `Confirm` contract.
- **Default and override:** none until the claim is settled.
- **User's choice, 2026-10-31.**

## Risks / Trade-offs

- **[Decision 3 changes what every verifier of a scrty token reads as `sub`]** → Nothing is tagged, so no external verifier exists yet. The username option keeps the old reading for a consumer who needs it, and the changelog's first entry names the change.
- **[A reader of `Principal.Username` behind the standalone authenticator sees an empty name]** → Task 3.1 audits every such reader with gopls before any code changes.
- **[Decision 6 may grow the change]** → If the race reproduces, apply stops for a decision and a `multi-factor-auth` delta. The rest of the change does not depend on it and may land first.
- **[Overlap with `close-security-gaps` on `token-issuance`]** → That change adds a requirement and this one modifies another. They archive in order: `close-security-gaps` first.

## Migration Plan

- Each group lands with its tests. There is no schema migration: key deletion uses the existing key table.
- Rollback before the tag is a revert of the commit.

## References

### Decision 3: the token subject

**Primary documentation:**
- [OpenID Connect Core 1.0, §2 ID Token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken): `sub` is a locally unique identifier for the end user that is never reassigned. Not re-checked on this date.
- [RFC 7519, §4.1.2 "sub"](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2): the subject is unique within the issuer's context. Not re-checked on this date.

Decision 3 departs from the established design, as stated in that decision.

### Decisions 1, 2, 4, 5 and 6

Reasoned from scrty's own settled specs (`email-notification`, `signing-keys`, `passkey-authentication`, `multi-factor-auth`) and code, from the review of `idiomatic-api-shape` that found decisions 1 and 2, and from the follow-up sweep of the archived changes.
